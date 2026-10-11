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
        open_persistent_reader, verify_file, verify_tree,
    },
    storage_layout,
};
use serde_json::json;

#[test]
fn secure_generation_persists_ciphertext_and_reopens() {
    if let Some(root) = std::env::var_os("CHIRONDB_AUDIT_TAIL_WITHOUT_KEY") {
        let root = Path::new(&root);
        let path = chirondb_core::audit::audit_log_path(root);
        let before = fs::read(&path).unwrap();
        assert!(chirondb_core::audit::AuditWriter::open(root).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
        println!("missing-key tail retained");
        return;
    }
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

    let streaming_root = temp.path().join("streaming-verification");
    fs::create_dir(&streaming_root).unwrap();
    let streaming_path = streaming_root.join("streaming-envelope.bin");
    let streaming_plaintext = vec![0x5a_u8; 10 * 1024 * 1024 + 17];
    atomic_write_persistent(&streaming_path, FileType::Segment, &streaming_plaintext).unwrap();
    let verifier = Keyring::load(&keyring_path).unwrap();
    assert_eq!(
        verify_file(&verifier, &streaming_path)
            .unwrap()
            .plaintext_len,
        streaming_plaintext.len() as u64
    );
    assert_eq!(
        verify_tree(&verifier, &streaming_root)
            .unwrap()
            .encrypted_files,
        1
    );
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
    assert!(verify_file(&verifier, &streaming_path).is_err());
    assert!(verify_tree(&verifier, &streaming_root).is_err());
    let mut rejected = Vec::new();
    assert!(
        open_persistent_reader(&streaming_path)
            .unwrap()
            .read_to_end(&mut rejected)
            .is_err()
    );
    fs::remove_file(streaming_path).unwrap();

    let report = verify_tree(&verifier, &data_dir).unwrap();
    assert!(report.encrypted_files > 0);
    assert_eq!(report.plaintext_files, 0);
    verify_tree(&verifier, &snapshot).unwrap();
    assert_tree_excludes(&data_dir, b"TOP-SECRET-PAYLOAD");
    assert_tree_excludes(&snapshot, b"TOP-SECRET-PAYLOAD");
    assert_encrypted_audit_tail_recovery(temp.path());
}

fn assert_encrypted_audit_tail_recovery(parent: &Path) {
    use chirondb_core::audit::{AuditWriter, append_success, audit_log_path, verify_hash_chain};
    let original = tempfile::tempdir_in(parent).unwrap();
    append_success(original.path(), "one", None, json!({"rows": 1})).unwrap();
    append_success(original.path(), "two", None, json!({"rows": 2})).unwrap();
    let bytes = fs::read(audit_log_path(original.path())).unwrap();
    let prefix = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
    let tail = &bytes[prefix..];
    for cut in [
        0,
        1,
        8,
        15,
        31,
        65,
        127,
        tail.len() / 2,
        tail.len() - 3,
        tail.len() - 2,
        tail.len() - 1,
    ] {
        let root = tempfile::tempdir_in(parent).unwrap();
        let path = audit_log_path(root.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, [&bytes[..prefix], &tail[..cut]].concat()).unwrap();
        drop(AuditWriter::open(root.path()).unwrap());
        verify_hash_chain(root.path()).unwrap();
        let recovered = fs::read(&path).unwrap();
        let expected = if cut == tail.len() - 1 {
            bytes.as_slice()
        } else {
            &bytes[..prefix]
        };
        assert_eq!(recovered, expected, "encrypted tail cut {cut}");
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }
    let path = audit_log_path(original.path());
    let mut corrupted = bytes;
    corrupted.pop();
    let offset = prefix + 180;
    corrupted[offset] = if corrupted[offset] == b'A' {
        b'B'
    } else {
        b'A'
    };
    fs::write(&path, &corrupted).unwrap();
    assert!(AuditWriter::open(original.path()).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupted);
    // This executable starts with no process keyring in the child branch.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "secure_generation_persists_ciphertext_and_reopens",
            "--nocapture",
        ])
        .env("CHIRONDB_AUDIT_TAIL_WITHOUT_KEY", original.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("missing-key tail retained"));
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
