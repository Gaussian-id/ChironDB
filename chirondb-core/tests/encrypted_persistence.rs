use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, Point,
    encryption::{
        FileType, Keyring, atomic_write_persistent, install_process_keyring,
        open_persistent_reader, verify_tree,
    },
    storage_layout,
};
use serde_json::json;

#[test]
fn secure_generation_persists_ciphertext_and_reopens() {
    let temp = tempfile::tempdir().unwrap();
    let keyring_path = temp.path().join("keyring.json");
    fs::write(
        &keyring_path,
        json!({
            "version": 1,
            "active_key_id": "test-key",
            "keys": [{
                "id": "test-key",
                "key_base64": STANDARD.encode([17_u8; 32]),
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

    let data_dir = temp.path().join("data");
    storage_layout::initialize_empty(&data_dir).unwrap();
    install_process_keyring(Keyring::load(&keyring_path).unwrap(), true).unwrap();

    let db = Db::open(&data_dir).unwrap();
    db.create_collection(CollectionConfig {
        name: "secure_docs".to_string(),
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
        "secure_docs",
        vec![Point {
            id: "document-1".to_string(),
            vector: vec![1.0, 2.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"secret": "TOP-SECRET-PAYLOAD"}),
        }],
    )
    .unwrap();
    db.compact_collection("secure_docs").unwrap();
    let snapshot = temp.path().join("snapshot");
    db.snapshot(&snapshot).unwrap();
    drop(db);

    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(
        reopened
            .get_points("secure_docs", &["document-1".to_string()])
            .unwrap()
            .len(),
        1
    );
    drop(reopened);

    let streaming_path = temp.path().join("streaming-envelope.bin");
    let streaming_plaintext = vec![0x5a_u8; 10 * 1024 * 1024 + 17];
    atomic_write_persistent(&streaming_path, FileType::Segment, &streaming_plaintext).unwrap();
    let mut recovered = Vec::new();
    open_persistent_reader(&streaming_path)
        .unwrap()
        .read_to_end(&mut recovered)
        .unwrap();
    assert_eq!(recovered, streaming_plaintext);
    fs::OpenOptions::new()
        .append(true)
        .open(&streaming_path)
        .unwrap()
        .write_all(b"trailing-corruption")
        .unwrap();
    let mut rejected = Vec::new();
    assert!(
        open_persistent_reader(&streaming_path)
            .unwrap()
            .read_to_end(&mut rejected)
            .is_err()
    );
    fs::remove_file(streaming_path).unwrap();

    let verifier = Keyring::load(&keyring_path).unwrap();
    let report = verify_tree(&verifier, &data_dir).unwrap();
    assert!(report.encrypted_files > 0);
    assert_eq!(report.plaintext_files, 0);
    verify_tree(&verifier, &snapshot).unwrap();
    assert_tree_excludes(&data_dir, b"TOP-SECRET-PAYLOAD");
    assert_tree_excludes(&snapshot, b"TOP-SECRET-PAYLOAD");
}

fn assert_tree_excludes(root: &Path, needle: &[u8]) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_tree_excludes(&entry.path(), needle);
        } else if entry.file_type().unwrap().is_file() {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "plaintext leaked into {}",
                entry.path().display()
            );
        }
    }
}
