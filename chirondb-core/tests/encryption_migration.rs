use std::{collections::HashMap, fs};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, Point,
    encryption::{self, Keyring},
    storage_layout,
};
use serde_json::json;

#[test]
fn offline_migration_switches_to_verified_encrypted_generation() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    storage_layout::initialize_empty(&data_dir).unwrap();
    {
        let db = Db::open(&data_dir).unwrap();
        db.create_collection(CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: Default::default(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();
        db.upsert(
            "docs",
            vec![Point {
                id: "one".to_string(),
                vector: vec![1.0, 2.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"secret": "MIGRATION-SECRET"}),
            }],
        )
        .unwrap();
        db.compact_collection("docs").unwrap();
    }

    let keyring_path = temp.path().join("keyring.json");
    fs::write(
        &keyring_path,
        json!({
            "version": 1,
            "active_key_id": "2026-08",
            "keys": [{
                "id": "2026-08",
                "key_base64": STANDARD.encode([29_u8; 32]),
            }],
        })
        .to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let keyring = Keyring::load(&keyring_path).unwrap();

    // The local command cannot safely rewrite an independently configured
    // object store. Its durable descriptors must refuse CURRENT publication
    // instead of leaving plaintext remote cold authority behind.
    let external_data = temp.path().join("external-data");
    let external_objects = temp.path().join("external-objects");
    storage_layout::initialize_empty(&external_data).unwrap();
    {
        let db = Db::open(&external_data).unwrap();
        db.create_collection(CollectionConfig {
            name: "remote".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: Default::default(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .unwrap();
        db.upsert(
            "remote",
            vec![Point {
                id: "remote".into(),
                vector: vec![3.0, 4.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            }],
        )
        .unwrap();
        db.compact_collection("remote").unwrap();
        db.set_cold_object_store_dir(Some(external_objects));
        db.tier_collection_to_cold("remote").unwrap();
    }
    let previous_external =
        fs::read_to_string(external_data.join(storage_layout::CURRENT_FILE)).unwrap();
    let error = storage_layout::migrate_encryption(&external_data, &keyring).unwrap_err();
    assert!(error.to_string().contains("external cold-object files"));
    assert_eq!(
        fs::read_to_string(external_data.join(storage_layout::CURRENT_FILE)).unwrap(),
        previous_external
    );

    let previous = fs::read_to_string(data_dir.join(storage_layout::CURRENT_FILE))
        .unwrap()
        .trim()
        .to_string();
    let resumed_generation = "gen-11111111111111111111111111111111";
    fs::create_dir_all(
        data_dir
            .join(storage_layout::GENERATIONS_DIR)
            .join(format!(".{resumed_generation}.encryption-staging")),
    )
    .unwrap();
    fs::write(
        data_dir.join(".generation-migration.json"),
        json!({
            "schema_version": 1,
            "operation": "encryption_migration",
            "generation": resumed_generation,
            "phase": "copying",
            "previous_generation": previous,
        })
        .to_string(),
    )
    .unwrap();
    let migration = storage_layout::migrate_encryption(&data_dir, &keyring).unwrap();
    assert_eq!(migration.active_generation, resumed_generation);
    assert_ne!(migration.previous_generation, migration.active_generation);
    assert!(
        data_dir
            .join(storage_layout::GENERATIONS_DIR)
            .join(&migration.previous_generation)
            .is_dir(),
        "the encrypted rollback generation must be retained"
    );
    let report = encryption::verify_tree(&keyring, &data_dir).unwrap();
    assert_eq!(report.plaintext_files, 0);
    assert!(report.encrypted_files > 0);

    encryption::install_process_keyring(keyring, true).unwrap();
    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(
        reopened
            .get_points("docs", &["one".to_string()])
            .unwrap()
            .len(),
        1
    );
}
