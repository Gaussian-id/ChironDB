use super::*;
use crate::{
    edge_token,
    encryption::{self, Keyring},
    graph::{
        ConfigureEdgeTypeRequest, EdgePropertyMode, GraphRelationScope, RelateRequest,
        UpdateEdgeRequest,
    },
    storage_layout,
    tenant::TenantScope,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{env, path::Path, process::Command};

#[test]
fn graph_generation_archives_and_cold_index_survive_migration_and_rotation() {
    const ROOT: &str = "CHIRONDB_GRAPH_ENCRYPTION_LIFECYCLE_ROOT";
    const TEST: &str = "db::tests::encryption_lifecycle::graph_generation_archives_and_cold_index_survive_migration_and_rotation";
    let Some(root) = env::var_os(ROOT) else {
        let temp = TempDir::new().unwrap();
        assert!(
            Command::new(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(ROOT, temp.path())
                .status()
                .unwrap()
                .success()
        );
        return;
    };
    let root = PathBuf::from(root);
    let data_dir = root.join("data");
    storage_layout::initialize_empty(&data_dir).unwrap();
    let old_keyring_path = root.join("old.json");
    let new_keyring_path = root.join("new.json");
    write_keyring(&old_keyring_path, "key-old1");
    write_keyring(&new_keyring_path, "key-new1");

    let edge_token = {
        let db = Db::open(&data_dir).unwrap();
        let scope = TenantScope::tenant("migration-test", "acme");
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![graph_point("a", 1.0, "acme"), graph_point("b", 2.0, "acme")],
        )
        .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "links".into(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
        let token = db
            .relate_scoped(
                "docs",
                RelateRequest {
                    source_point_id: "a".into(),
                    target_point_id: "b".into(),
                    edge_type: "links".into(),
                    properties: json!({"revision": 1}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: Some("migration-edge".into()),
                },
                true,
                &scope,
            )
            .unwrap()
            .edge_id;

        // First seal carries points and graph. The second mutation leaves an
        // empty vector tail and proves graph-only offline preparation uses a
        // valid unified zero-row seal rather than vector-only compaction.
        db.prepare_encryption_migration().unwrap();
        db.update_edge_scoped(
            "docs",
            &token,
            UpdateEdgeRequest {
                mode: EdgePropertyMode::Merge,
                properties: json!({"revision": 2}),
            },
            true,
            &scope,
        )
        .unwrap();
        db.prepare_encryption_migration().unwrap();
        assert!(db.get_coll("docs").unwrap().read().wal.is_empty().unwrap());
        db.tier_collection_to_cold("docs").unwrap();
        token
    };

    let migration =
        storage_layout::migrate_encryption(&data_dir, &Keyring::load(&old_keyring_path).unwrap())
            .unwrap();
    assert!(migration.rebuilt_archive_manifests >= 1);
    assert!(migration.rebuilt_cold_indexes >= 1);
    assert!(!migration.logical_digest.is_empty());

    encryption::install_process_keyring(Keyring::load(&old_keyring_path).unwrap(), true).unwrap();
    let edge_id = {
        let db = Db::open(&data_dir).unwrap();
        assert_eq!(
            db.get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .len(),
            2
        );
        let edge_id = edge_token::decode(db.graph_database_id(), &edge_token).unwrap();
        let state = super::graph_pitr::state(&db, edge_id);
        assert_eq!(state["properties"], json!({"revision": 2}));
        edge_id
    };

    let new_keyring = Keyring::load(&new_keyring_path).unwrap();
    assert!(encryption::rewrap_tree_resumable(&new_keyring, &data_dir).unwrap() > 0);
    assert_eq!(
        encryption::referenced_key_ids(&data_dir).unwrap(),
        HashSet::from(["key-new1".to_string()])
    );
    let db = Db::open(&data_dir).unwrap();
    let state = super::graph_pitr::state(&db, edge_id);
    assert_eq!(state["properties"], json!({"revision": 2}));
    assert_eq!(
        db.get_points("docs", &["a".into(), "b".into()])
            .unwrap()
            .len(),
        2
    );
}

fn write_keyring(path: &Path, active: &str) {
    fs::write(
        path,
        json!({
            "version": 1,
            "active_key_id": active,
            "keys": [
                {"id": "key-old1", "key_base64": STANDARD.encode([71_u8; 32])},
                {"id": "key-new1", "key_base64": STANDARD.encode([72_u8; 32])},
            ],
        })
        .to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
