use super::*;
use crate::{
    graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest},
    tenant::TenantScope,
};

fn graph_with_reclaimable_edge(root: &std::path::Path) -> (Db, u64) {
    let db = Db::open(root).unwrap();
    let scope = TenantScope::tenant("maintenance-test", "acme");
    let mut config = ls_vec_config("docs");
    config.streamer_max_bytes = usize::MAX;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert(
        "docs",
        vec![
            graph_point("source", 1.0, "acme"),
            graph_point("target", 2.0, "acme"),
        ],
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
    let edge = db
        .relate_scoped(
            "docs",
            RelateRequest {
                source_point_id: "source".into(),
                target_point_id: "target".into(),
                edge_type: "links".into(),
                properties: serde_json::json!({"kind":"test"}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .unwrap()
        .edge_id;
    db.prepare_encryption_migration().unwrap();
    let generation = db
        .graph_maintenance_stats("docs")
        .unwrap()
        .unwrap()
        .generation;
    db.unrelate_scoped("docs", &edge, true, &scope).unwrap();
    assert!(
        db.graph_maintenance_stats("docs")
            .unwrap()
            .unwrap()
            .requires_compaction()
    );
    (db, generation)
}

#[test]
fn db_maintenance_census_tracks_the_current_edge_overlay_across_restart() {
    let temp = TempDir::new().unwrap();
    let scope = TenantScope::tenant("maintenance-test", "acme");
    let edge = {
        let db = Db::open(temp.path()).unwrap();
        let mut config = ls_vec_config("docs");
        config.streamer_max_bytes = usize::MAX;
        db.create_collection(config).unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &scope)
            .unwrap();
        db.upsert(
            "docs",
            vec![
                graph_point("source", 1.0, "acme"),
                graph_point("target", 2.0, "acme"),
            ],
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
        let edge = db
            .relate_scoped(
                "docs",
                RelateRequest {
                    source_point_id: "source".into(),
                    target_point_id: "target".into(),
                    edge_type: "links".into(),
                    properties: serde_json::json!({"kind":"test"}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: None,
                },
                true,
                &scope,
            )
            .unwrap()
            .edge_id;
        db.prepare_encryption_migration().unwrap();

        let clean = db.graph_maintenance_stats("docs").unwrap().unwrap();
        assert_eq!(clean.physical_edge_records, 1);
        assert_eq!(clean.reclaimable_edge_records, 0);
        assert_eq!(clean.directed_entries, 2);
        assert_eq!(clean.p95_fragments_per_node, 1);
        assert!(!clean.requires_compaction());

        db.unrelate_scoped("docs", &edge, true, &scope).unwrap();
        let dirty = db.graph_maintenance_stats("docs").unwrap().unwrap();
        assert_eq!(dirty.generation, clean.generation);
        assert_eq!(dirty.reclaimable_edge_records, 1);
        assert_eq!(dirty.reclaimable_directed_entries, 2);
        assert!(dirty.requires_compaction());
        edge
    };

    let db = Db::open(temp.path()).unwrap();
    let reopened = db.graph_maintenance_stats("docs").unwrap().unwrap();
    assert_eq!(reopened.reclaimable_edge_records, 1);
    assert!(reopened.requires_compaction());
    assert!(
        db.unrelate_scoped("docs", &edge, true, &scope).is_err(),
        "the census must not revive a tombstoned EdgeId"
    );
}

#[test]
fn scheduled_maintenance_uses_graph_debt_below_wal_threshold() {
    let root = TempDir::new().unwrap();
    let (db, generation) = graph_with_reclaimable_edge(root.path());

    let compacted = db.compact_collections_for_maintenance(u64::MAX).unwrap();
    assert_eq!(compacted.len(), 1);
    assert_eq!(compacted[0].collection, "docs");
    let clean = db.graph_maintenance_stats("docs").unwrap().unwrap();
    assert!(clean.generation > generation);
    assert_eq!(clean.physical_edge_records, 0);
    assert_eq!(clean.reclaimable_edge_records, 0);
    assert!(!clean.requires_compaction());
    assert!(
        db.compact_collections_for_maintenance(u64::MAX)
            .unwrap()
            .is_empty(),
        "a clean graph generation must not be compacted again"
    );
}

#[test]
fn scheduled_maintenance_deduplicates_wal_and_graph_triggers() {
    let root = TempDir::new().unwrap();
    let (db, _) = graph_with_reclaimable_edge(root.path());
    assert!(
        db.get_coll("docs")
            .unwrap()
            .read()
            .wal
            .retained_bytes()
            .unwrap()
            > 0
    );

    let compacted = db.compact_collections_for_maintenance(1).unwrap();
    assert_eq!(compacted.len(), 1);
    assert_eq!(compacted[0].collection, "docs");
    assert!(
        !db.graph_maintenance_stats("docs")
            .unwrap()
            .unwrap()
            .requires_compaction()
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn scheduled_maintenance_skips_an_inflight_graph_compaction() {
    use std::{env, fs, path::PathBuf, process::Command, time::Duration};

    const CHILD: &str = "CHIRONDB_GRAPH_MAINTENANCE_BUSY_CHILD";
    const TEST: &str =
        "db::tests::graph_maintenance::scheduled_maintenance_skips_an_inflight_graph_compaction";
    let Some(root) = env::var_os(CHILD) else {
        let root = TempDir::new().unwrap();
        assert!(
            Command::new(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, root.path())
                .status()
                .unwrap()
                .success(),
            "scheduled maintenance busy child failed"
        );
        return;
    };

    let root = PathBuf::from(root);
    let (db, _) = graph_with_reclaimable_edge(&root);
    let marker = root.join("maintenance-compaction-paused");
    let release = root.join("maintenance-compaction-release");
    let _failpoint_guard =
        crate::failpoint::test_env("pause:graph_compaction.after_stage", &marker, &release);
    let compact_db = db.clone();
    let compact = std::thread::spawn(move || compact_db.compact_collection("docs"));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "manual compaction did not reach its staged pause"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let staged_generation = db
        .graph_maintenance_stats("docs")
        .unwrap()
        .unwrap()
        .generation;
    let duplicate = db.compact_collection("docs").unwrap_err();
    assert!(
        matches!(duplicate, GaussError::ResourceExhausted(message) if message.contains("already has compaction in flight")),
        "all Db clones must share the per-collection compaction guard"
    );
    assert!(
        db.compact_collections_for_maintenance(1)
            .unwrap()
            .is_empty(),
        "the scheduled sweep must skip an owned generation build"
    );
    fs::write(&release, b"release").unwrap();
    compact.join().unwrap().unwrap();
    let installed = db.graph_maintenance_stats("docs").unwrap().unwrap();
    assert_eq!(installed.generation, staged_generation + 1);
    assert!(!installed.requires_compaction());
}
