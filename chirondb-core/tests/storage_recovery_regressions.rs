use std::{collections::BTreeMap, fs, path::Path};

use chirondb_core::{CollectionConfig, Db, DistanceMetric, Point, encryption};
use serde_json::json;

fn seed(root: &Path) {
    let db = Db::open(root).unwrap();
    db.create_collection(CollectionConfig {
        name: "docs".into(),
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
            id: "acknowledged".into(),
            vector: vec![1.0, 2.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"text": "durable document"}),
        }],
    )
    .unwrap();
    db.flush_wals().unwrap();
}

fn files(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else if path.file_name().unwrap() != ".chirondb.lock" {
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    collect(root, root, &mut result);
    result
}

#[test]
fn missing_committed_collection_wal_must_not_be_recreated() {
    use std::io::Write;
    for remove_directory in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        seed(temp.path());
        fs::OpenOptions::new()
            .append(true)
            .open(temp.path().join("transactions/journal/000000.gdwal"))
            .unwrap()
            .write_all(&[1])
            .unwrap();
        let wal = temp.path().join("collections/docs/wal");
        if remove_directory {
            fs::remove_dir_all(&wal).unwrap();
        } else {
            for entry in fs::read_dir(&wal).unwrap() {
                let path = entry.unwrap().path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "gdwal")
                {
                    fs::remove_file(path).unwrap();
                }
            }
        }
        let before = files(temp.path());
        let Err(error) = Db::open(temp.path()) else {
            panic!("missing committed WAL must refuse startup");
        };
        assert!(error.to_string().contains("wal"), "{error}");
        assert_eq!(
            files(temp.path()),
            before,
            "refused recovery changed persisted data"
        );
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn missing_latest_rotated_collection_wal_refuses_startup() {
    const TEST: &str = "missing_latest_rotated_collection_wal_refuses_startup";
    if std::env::var("CHIRONDB_STORAGE_CHILD_TEST").as_deref() != Ok(TEST) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("CHIRONDB_STORAGE_CHILD_TEST", TEST)
            .env("CHIRONDB_TEST_WAL_SEGMENT_BYTES", "128")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    seed(temp.path());
    {
        let db = Db::open(temp.path()).unwrap();
        for ordinal in 0..5 {
            db.upsert(
                "docs",
                vec![Point {
                    id: format!("durable-{ordinal}"),
                    vector: vec![1.0, 2.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"ordinal": ordinal}),
                }],
            )
            .unwrap();
        }
        db.flush_wals().unwrap();
    }
    let mut segments = fs::read_dir(temp.path().join("collections/docs/wal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "gdwal")
        })
        .collect::<Vec<_>>();
    segments.sort();
    assert!(segments.len() >= 3);
    fs::remove_file(segments.last().unwrap()).unwrap();
    let before = files(temp.path());
    match Db::open(temp.path()) {
        Err(_) => assert_eq!(files(temp.path()), before),
        Ok(db) => {
            let count = db.count("docs", None).unwrap().count;
            drop(db);
            let retained = temp.keep();
            panic!(
                "missing suffix WAL reopened with {count}/6 acknowledged points; retained={}",
                retained.display()
            );
        }
    }
}

#[test]
fn committed_collection_drop_can_finish_before_catalog_checkpoint() {
    use chirondb_core::{
        audit::AuditContext,
        transaction_journal::{TransactionAudit, TransactionJournal, TransactionTarget},
        wal::{Wal, WalEntry},
    };
    use std::io::Write;
    for retain_trash in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        seed(temp.path());
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let mutation = WalEntry::DropCollection {
            name: "docs".into(),
        };
        let transaction = journal
            .commit(
                TransactionTarget::Catalog,
                mutation.clone(),
                TransactionAudit::mutation(
                    "delete_collection",
                    Some("docs"),
                    &AuditContext::embedded(),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
        let mut catalog_wal = Wal::open(&temp.path().join("catalog_wal")).unwrap();
        catalog_wal
            .append(&WalEntry::TransactionApply {
                transaction_id: transaction.prepare.transaction_id,
                entry: Box::new(mutation),
            })
            .unwrap();
        let trash = temp.path().join("collections/.chirondb-drop-docs.trash");
        fs::rename(temp.path().join("collections/docs"), &trash).unwrap();
        if !retain_trash {
            fs::remove_dir_all(&trash).unwrap();
            // A later torn control tail is inspected but only real recovery
            // may repair it, after recognizing the preceding durable DROP.
            fs::OpenOptions::new()
                .append(true)
                .open(temp.path().join("transactions/journal/000000.gdwal"))
                .unwrap()
                .write_all(&[1])
                .unwrap();
        }
        drop((catalog_wal, transaction, journal));
        let db =
            Db::open(temp.path()).expect("durable DROP must finish without recreating its WAL");
        assert!(db.get_points("docs", &["acknowledged".into()]).is_err());
        assert!(!temp.path().join("collections/docs").exists());
    }
}

#[test]
fn uncommitted_drop_cannot_excuse_a_missing_collection_wal() {
    use chirondb_core::{
        audit::AuditContext,
        transaction_journal::{
            TransactionAudit, TransactionId, TransactionPrepare, TransactionTarget,
        },
        wal::{Wal, WalEntry},
    };
    let temp = tempfile::tempdir().unwrap();
    seed(temp.path());
    let dir = temp.path().join("transactions/journal");
    let sequence = Wal::load(&dir)
        .unwrap()
        .into_iter()
        .filter_map(|record| match record.entry {
            WalEntry::TransactionCommit { commit } => Some(commit.commit_sequence),
            _ => None,
        })
        .max()
        .unwrap()
        + 1;
    let mut journal = Wal::open(&dir).unwrap();
    journal
        .append(&WalEntry::TransactionPrepare {
            prepare: TransactionPrepare {
                version: 1,
                transaction_id: TransactionId::new(),
                commit_sequence: sequence,
                target: TransactionTarget::Catalog,
                mutation: Box::new(WalEntry::DropCollection {
                    name: "docs".into(),
                }),
                audit: TransactionAudit::mutation(
                    "delete_collection",
                    Some("docs"),
                    &AuditContext::embedded(),
                    serde_json::Value::Null,
                ),
                idempotency: None,
            },
        })
        .unwrap();
    drop(journal);
    fs::remove_dir_all(temp.path().join("collections/docs/wal")).unwrap();
    let before = files(temp.path());
    assert!(Db::open(temp.path()).is_err());
    assert_eq!(files(temp.path()), before);
}

#[test]
fn pending_key_rotation_refuses_startup_before_any_storage_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("data");
    seed(&root);
    fs::write(root.join(".key-rotation.json"), serde_json::to_vec(&json!({
        "schema_version": 2,
        "operation": "key_rotation",
        "active_key_id": "key-new1",
        "logical_digest": encryption::logical_tree_digest(&root, Some(&keyring(temp.path()))).unwrap(),
        "phase": "rewrapping",
    })).unwrap()).unwrap();
    let before = files(&root);
    let Err(error) = Db::open(&root) else {
        panic!("pending rotation must refuse startup");
    };
    assert!(error.to_string().contains("rotat"), "{error}");
    assert_eq!(files(&root), before);
}

fn keyring(parent: &Path) -> encryption::Keyring {
    use base64::Engine as _;
    let path = parent.join("keyring.json");
    fs::write(&path, serde_json::to_vec(&json!({
        "version": 1,
        "active_key_id": "key-new1",
        "keys": [{"id": "key-new1", "key_base64": base64::engine::general_purpose::STANDARD.encode([71_u8; 32])}],
    })).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    encryption::Keyring::load(path).unwrap()
}

#[test]
fn legacy_compacted_database_can_be_prepared_and_encrypted() {
    if isolated("legacy_compacted_database_can_be_prepared_and_encrypted") {
        return;
    }
    check_legacy_migration(false, false);
}

#[test]
fn previous_legacy_generation_journal_copies_keep_identity() {
    if isolated("previous_legacy_generation_journal_copies_keep_identity") {
        return;
    }
    check_legacy_migration(true, false);
}

#[test]
fn compacted_batch_receipt_survives_encryption_migration() {
    if isolated("compacted_batch_receipt_survives_encryption_migration") {
        return;
    }
    check_legacy_migration(false, true);
}

fn check_legacy_migration(retain_old_copy: bool, with_batch: bool) {
    use chirondb_core::{
        graph::{ConfigureEdgeTypeRequest, RelateBatchRequest, RelateRequest},
        tenant::TenantScope,
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("data");
    seed(&root);
    let batch = {
        let db = Db::open(&root).unwrap();
        let batch = if with_batch {
            let scope = TenantScope::system();
            db.set_graph_lifecycle_scoped("docs", true, true, &scope)
                .unwrap();
            db.configure_edge_type_scoped(
                "docs",
                ConfigureEdgeTypeRequest {
                    name: "cites".into(),
                    weight_property: None,
                },
                true,
                &scope,
            )
            .unwrap();
            let request = RelateBatchRequest {
                edges: vec![RelateRequest {
                    source_point_id: "acknowledged".into(),
                    target_point_id: "acknowledged".into(),
                    edge_type: "cites".into(),
                    properties: json!({"ordinal": 0}),
                    scope: Default::default(),
                    idempotency_key: None,
                }],
                idempotency_key: Some("migrated-batch".into()),
            };
            let first = db
                .relate_batch_scoped("docs", request.clone(), true, &scope)
                .unwrap();
            Some((request, first.edge_ids))
        } else {
            None
        };
        db.compact_collection("docs").unwrap();
        db.prepare_encryption_migration().unwrap();
        batch
    };
    chirondb_core::storage_layout::migrate_legacy(&root).unwrap();
    let layout = chirondb_core::storage_layout::resolve(&root).unwrap();
    assert!(
        !layout.active_root.join("transactions").exists(),
        "installation authority must stay outside content generations"
    );
    if retain_old_copy {
        // Reconstruct a generation produced by the previous legacy migrator.
        // Existing rollback copies remain supported without rewriting LSNs.
        fn copy(source: &Path, destination: &Path) {
            fs::create_dir_all(destination).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let target = destination.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    fs::copy(entry.path(), target).unwrap();
                }
            }
        }
        copy(
            &root.join("transactions"),
            &layout.active_root.join("transactions"),
        );
    }
    let keys = keyring(temp.path());
    chirondb_core::storage_layout::migrate_encryption(&root, &keys).unwrap();
    encryption::verify_tree(&keys, &root).unwrap();
    encryption::install_process_keyring(keys, true).unwrap();
    let db = Db::open(&root).unwrap();
    assert_eq!(
        db.get_points("docs", &["acknowledged".into()])
            .unwrap()
            .len(),
        1
    );
    if let Some((request, ids)) = batch {
        let replay = db
            .relate_batch_scoped("docs", request, true, &TenantScope::system())
            .unwrap();
        assert_eq!(replay.edge_ids, ids);
        assert!(replay.receipt.replayed);
    }
}

#[test]
fn encrypted_restart_removes_only_unpublished_atomic_temp() {
    if isolated("encrypted_restart_removes_only_unpublished_atomic_temp") {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("data");
    encryption::install_process_keyring(keyring(temp.path()), true).unwrap();
    seed(&root);
    let target = root.join("catalog.json");
    let orphan = root.join(format!(".catalog.json.{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&orphan, &fs::read(target).unwrap()[..12]).unwrap();
    let wal_temp = root.join("catalog_wal/wal.base.tmp");
    fs::write(&wal_temp, b"partial frontier").unwrap();
    let unrelated = root.join(".unrelated.tmp");
    let unrelated_bytes = encryption::encrypt_bytes(
        &keyring(temp.path()),
        encryption::FileType::Metadata,
        b"retained",
    )
    .unwrap();
    fs::write(&unrelated, &unrelated_bytes).unwrap();
    let unknown_uuid = root.join(format!(".catalog.json.{}.tmp", uuid::Uuid::nil()));
    fs::write(&unknown_uuid, &unrelated_bytes).unwrap();
    let retained_bundle = root.join("common-frontier/retained");
    fs::create_dir_all(&retained_bundle).unwrap();
    fs::write(retained_bundle.join("manifest.gdx"), &unrelated_bytes).unwrap();
    let retained_file = retained_bundle.join(format!(".catalog.json.{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&retained_file, &unrelated_bytes).unwrap();
    let db = Db::open(&root).unwrap();
    encryption::verify_tree(&keyring(temp.path()), &root).unwrap();
    assert!(!orphan.exists());
    assert!(!wal_temp.exists());
    assert_eq!(fs::read(unrelated).unwrap(), unrelated_bytes);
    assert_eq!(fs::read(unknown_uuid).unwrap(), unrelated_bytes);
    assert_eq!(fs::read(retained_file).unwrap(), unrelated_bytes);
    assert_eq!(
        db.get_points("docs", &["acknowledged".into()])
            .unwrap()
            .len(),
        1
    );
}

fn isolated(test: &str) -> bool {
    if std::env::var("CHIRONDB_STORAGE_CHILD_TEST").is_ok_and(|name| name == test) {
        return false;
    }
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("CHIRONDB_STORAGE_CHILD_TEST", test)
            .status()
            .unwrap()
            .success(),
        "isolated test {test} failed"
    );
    true
}
