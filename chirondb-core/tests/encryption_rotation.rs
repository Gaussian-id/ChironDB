use std::{collections::HashMap, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, Point, audit,
    encryption::{self, Keyring},
    storage_layout,
};
use serde_json::json;

#[test]
fn offline_rotation_rewraps_segments_wal_and_audit() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    storage_layout::initialize_empty(&data_dir).unwrap();
    let old_path = temp.path().join("old-active.json");
    let new_path = temp.path().join("new-active.json");
    write_keyring(&old_path, "key-old1");
    write_keyring(&new_path, "key-new1");
    encryption::install_process_keyring(Keyring::load(&old_path).unwrap(), true).unwrap();

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
        db.upsert("docs", vec![point("sealed", 1.0)]).unwrap();
        db.compact_collection("docs").unwrap();
        db.upsert("docs", vec![point("wal", 2.0)]).unwrap();
    }

    let new_keyring = Keyring::load(&new_path).unwrap();
    let rotated = encryption::rewrap_tree(&new_keyring, &data_dir).unwrap();
    assert!(rotated > 0);
    encryption::verify_tree(&new_keyring, &data_dir).unwrap();
    assert_eq!(
        encryption::referenced_key_ids(&data_dir).unwrap(),
        ["key-new1".to_string()].into_iter().collect()
    );
    audit::verify_hash_chain(&data_dir).unwrap();

    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(
        reopened
            .get_points("docs", &["sealed".to_string(), "wal".to_string()])
            .unwrap()
            .len(),
        2
    );
}

fn point(id: &str, value: f32) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![value, 0.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"source": id}),
    }
}

fn write_keyring(path: &Path, active: &str) {
    fs::write(
        path,
        json!({
            "version": 1,
            "active_key_id": active,
            "keys": [
                {"id": "key-old1", "key_base64": STANDARD.encode([41_u8; 32])},
                {"id": "key-new1", "key_base64": STANDARD.encode([42_u8; 32])},
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
