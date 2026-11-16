use chirondb_core::{CollectionConfig, Db, Point, snapshot::SnapshotCollection};
use serde_json::json;

fn schema_config() -> CollectionConfig {
    serde_json::from_value(json!({
        "name": "documents", "vector_dim": 3, "metric": "cosine",
        "payload_schema": {
            "category": "string", "title": "string", "source": "string",
            "price": "number", "rank": "number", "active": "bool"
        },
        "named_vector_dims": {"title": 2, "body": 3, "image": 4}
    }))
    .unwrap()
}

#[test]
fn snapshot_config_checksum_survives_map_reordering_and_binds_values() {
    let config = schema_config();
    let marker = SnapshotCollection::new(&config, 1, 0, 0, None).unwrap();
    let bytes = serde_json::to_vec(&config).unwrap();
    for _ in 0..16 {
        let reloaded: CollectionConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            SnapshotCollection::new(&reloaded, 1, 0, 0, None)
                .unwrap()
                .config_crc,
            marker.config_crc,
            "equivalent decoded maps must have the same checksum"
        );
    }
    for changed in ["payload_schema", "named_vector_dims", "metric"] {
        let mut value = serde_json::to_value(&config).unwrap();
        match changed {
            "payload_schema" => value[changed]["category"] = json!("optional_string"),
            "named_vector_dims" => value[changed]["title"] = json!(5),
            _ => value[changed] = json!("dot"),
        }
        let changed: CollectionConfig = serde_json::from_value(value).unwrap();
        assert_ne!(
            SnapshotCollection::new(&changed, 1, 0, 0, None)
                .unwrap()
                .config_crc,
            marker.config_crc,
            "the checksum must still bind configuration values"
        );
    }
}

#[test]
fn schema_and_named_vectors_survive_snapshot_restore_import_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let snapshot = temp.path().join("snapshot");
    let db = Db::open(&data).unwrap();
    let config = db.create_collection(schema_config()).unwrap();
    let point: Point = serde_json::from_value(json!({
        "id": "keep", "vector": [1, 0, 0],
        "vectors": {"title": [1, 0], "body": [0, 1, 0], "image": [0, 0, 1, 0]},
        "payload": {"category": "docs", "title": "Snapshot", "source": "test",
                    "price": 12, "rank": 1, "active": true}
    }))
    .unwrap();
    db.upsert("documents", vec![point.clone()]).unwrap();
    db.compact_collection("documents").unwrap();
    db.snapshot(&snapshot).unwrap();

    let imported = Db::open(&snapshot).unwrap();
    assert_eq!(
        serde_json::to_value(imported.list_collections()).unwrap(),
        serde_json::to_value(vec![config.clone()]).unwrap()
    );
    assert_eq!(
        serde_json::to_value(imported.get_points("documents", &["keep".into()]).unwrap()).unwrap(),
        json!([point])
    );
    drop(imported);

    db.delete("documents", &["keep".into()]).unwrap();
    db.update_payload_schema("documents", Default::default())
        .unwrap();
    db.restore(&snapshot).unwrap();
    drop(db);

    let reopened = Db::open(&data).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.list_collections()).unwrap(),
        serde_json::to_value(vec![config]).unwrap()
    );
    assert_eq!(
        serde_json::to_value(reopened.get_points("documents", &["keep".into()]).unwrap()).unwrap(),
        json!([point])
    );
    reopened
        .snapshot(temp.path().join("second-snapshot"))
        .unwrap();
}

#[test]
fn canonical_checksum_mismatch_refuses_restore_without_changing_live_data() {
    let temp = tempfile::tempdir().unwrap();
    let db = Db::open(temp.path().join("data")).unwrap();
    db.create_collection(schema_config()).unwrap();
    let snapshot = temp.path().join("snapshot");
    db.snapshot(&snapshot).unwrap();
    let mut marker = chirondb_core::snapshot::read_snapshot_marker(&snapshot)
        .unwrap()
        .unwrap();
    assert_eq!(marker.version, 3);
    marker.collections[0].config_crc ^= 1;
    chirondb_core::snapshot::write_snapshot_marker(&snapshot, &marker).unwrap();
    db.update_payload_schema("documents", Default::default())
        .unwrap();
    let before = serde_json::to_value(db.list_collections()).unwrap();
    let error = db.restore(&snapshot).unwrap_err();
    assert!(error.to_string().contains("config checksum"), "{error}");
    assert_eq!(serde_json::to_value(db.list_collections()).unwrap(), before);
}
