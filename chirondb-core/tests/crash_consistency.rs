#![cfg(feature = "fault-injection")]

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, MultiModelTransactionRequest, Point, RelationalValue,
    SqlExecutionRequest, SqlResult, SqlStatementRequest, audit,
    encryption::{self, FileType, Keyring},
    fs_util,
    graph::{
        ConfigureEdgeTypeRequest, GraphDirection, GraphRelationScope, GraphTraverseRequest,
        RelateRequest, TraversalBudget,
    },
    storage_layout,
    tenant::TenantScope,
};
use serde_json::json;

const CHILD_MODE: &str = "CHIRONDB_CRASH_CHILD_MODE";

#[test]
fn atomic_write_is_old_or_new_at_every_crash_boundary() {
    if child_mode("atomic-crash") {
        let target = required_path("CHIRONDB_CRASH_TARGET");
        let _ = fs_util::atomic_write(&target, b"new-value");
        return;
    }

    for boundary in [
        "atomic.after_temp_sync",
        "atomic.after_rename_before_dir_sync",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("state");
        fs::write(&target, b"old-value").unwrap();
        assert_crashed(run_child(
            "atomic_write_is_old_or_new_at_every_crash_boundary",
            "atomic-crash",
            boundary,
            &[("CHIRONDB_CRASH_TARGET", &target)],
        ));
        let bytes = fs::read(&target).unwrap();
        assert!(bytes == b"old-value" || bytes == b"new-value");
    }
}

#[test]
fn injected_fsync_errors_never_publish_unacknowledged_temp_data() {
    if child_mode("atomic-error") {
        let target = required_path("CHIRONDB_CRASH_TARGET");
        assert!(fs_util::atomic_write(&target, b"new-value").is_err());
        return;
    }

    for boundary in ["atomic.before_temp_sync", "atomic.after_temp_sync"] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("state");
        fs::write(&target, b"old-value").unwrap();
        assert_succeeded(run_error_child(
            "injected_fsync_errors_never_publish_unacknowledged_temp_data",
            "atomic-error",
            boundary,
            &[("CHIRONDB_CRASH_TARGET", &target)],
        ));
        assert_eq!(fs::read(&target).unwrap(), b"old-value");
    }
}

#[test]
fn encryption_migration_resumes_from_every_publication_boundary() {
    if child_mode("migration") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let keyring = Keyring::load(required_path("CHIRONDB_KEYRING")).unwrap();
        let _ = storage_layout::migrate_encryption(&data_dir, &keyring);
        return;
    }
    if child_mode("migration-verify") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let keyring = Keyring::load(required_path("CHIRONDB_KEYRING")).unwrap();
        encryption::install_process_keyring(keyring, true).unwrap();
        let db = Db::open(&data_dir).unwrap();
        let selected = db
            .execute_sql(SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "SELECT id, title FROM documents WHERE id = 'doc-1'".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        assert!(matches!(
            &selected.results[0],
            SqlResult::Rows { rows, .. }
                if rows == &vec![vec![
                    RelationalValue::Text("doc-1".into()),
                    RelationalValue::Text("Atomic knowledge".into()),
                ]]
        ));
        let scope = TenantScope::tenant("migration-reader", "acme");
        assert_eq!(
            db.get_points_scoped("chunks", &["chunk-1".into(), "source-1".into()], &scope)
                .unwrap()
                .len(),
            2
        );
        let traversal = db
            .traverse_scoped(
                "chunks",
                GraphTraverseRequest {
                    anchors: vec!["chunk-1".into()],
                    edge_types: vec!["cites".into()],
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        ..TraversalBudget::default()
                    },
                },
                &scope,
            )
            .unwrap();
        assert!(
            traversal
                .nodes
                .iter()
                .any(|node| node.point_id == "source-1")
        );
        return;
    }

    for boundary in [
        "migration.after_copy_journal",
        "migration.after_copy",
        "migration.after_encrypted_sync",
        "migration.after_generation_publish",
        "migration.before_current_switch",
        "migration.after_current_switch",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        prepare_database(&data_dir, "old-point");
        {
            let db = Db::open(&data_dir).unwrap();
            let scope = TenantScope::tenant("migration-writer", "acme");
            let mut chunks = collection_config();
            chunks.name = "chunks".into();
            db.create_collection(chunks).unwrap();
            db.set_graph_lifecycle_scoped("chunks", true, true, &scope)
                .unwrap();
            db.configure_edge_type_scoped(
                "chunks",
                ConfigureEdgeTypeRequest {
                    name: "cites".into(),
                    weight_property: None,
                },
                true,
                &scope,
            )
            .unwrap();
            db.execute_sql(SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL)".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
            db.execute_multimodel_transaction(
                MultiModelTransactionRequest {
                    sql: SqlExecutionRequest {
                        statements: vec![SqlStatementRequest {
                            sql: "INSERT INTO documents (id, title) VALUES ('doc-1', 'Atomic knowledge')".into(),
                            parameters: vec![],
                        }],
                        idempotency_key: Some("migration-doc-1".into()),
                        retry_id: None,
                    },
                    collection: "chunks".into(),
                    points: vec![point("chunk-1"), point("source-1")],
                    point_deletes: vec![],
                    relations: vec![RelateRequest {
                        source_point_id: "chunk-1".into(),
                        target_point_id: "source-1".into(),
                        edge_type: "cites".into(),
                        properties: json!({"kind": "source"}),
                        scope: GraphRelationScope::Local,
                        idempotency_key: None,
                    }],
                    edge_deletes: vec![],
                    edge_updates: vec![],
                },
                &scope,
                &audit::AuditContext::embedded(),
            )
            .unwrap();
            db.prepare_encryption_migration().unwrap();
        }
        let keyring_path = temp.path().join("keyring.json");
        write_keyring(&keyring_path, "key-new1");
        let keyring = Keyring::load(&keyring_path).unwrap();
        let before = storage_layout::resolve(&data_dir).unwrap();
        let before_digest =
            encryption::logical_tree_digest(&before.active_root, Some(&keyring)).unwrap();

        assert_crashed(run_child(
            "encryption_migration_resumes_from_every_publication_boundary",
            "migration",
            boundary,
            &[
                ("CHIRONDB_DATA_DIR", &data_dir),
                ("CHIRONDB_KEYRING", &keyring_path),
            ],
        ));

        let interrupted = storage_layout::resolve(&data_dir).unwrap();
        if boundary == "migration.after_current_switch" {
            assert_ne!(interrupted.generation, before.generation, "{boundary}");
        } else {
            assert_eq!(interrupted.generation, before.generation, "{boundary}");
        }
        assert_eq!(
            encryption::logical_tree_digest(&interrupted.active_root, Some(&keyring)).unwrap(),
            before_digest,
            "active generation changed logically at {boundary}"
        );
        let migration = storage_layout::migrate_encryption(&data_dir, &keyring).unwrap();
        assert_eq!(
            storage_layout::resolve(&data_dir)
                .unwrap()
                .generation
                .as_deref(),
            Some(migration.active_generation.as_str())
        );
        let report = encryption::verify_tree(&keyring, &data_dir).unwrap();
        assert_eq!(report.plaintext_files, 0, "boundary {boundary}");
        assert!(report.encrypted_files > 0, "boundary {boundary}");
        assert!(!data_dir.join(".generation-migration.json").exists());
        assert_succeeded(run_child(
            "encryption_migration_resumes_from_every_publication_boundary",
            "migration-verify",
            "none",
            &[
                ("CHIRONDB_DATA_DIR", &data_dir),
                ("CHIRONDB_KEYRING", &keyring_path),
            ],
        ));
    }
}

#[test]
fn key_rotation_resumes_before_and_after_tree_verification() {
    if child_mode("rotation") {
        let root = required_path("CHIRONDB_DATA_DIR");
        let keyring = Keyring::load(required_path("CHIRONDB_KEYRING")).unwrap();
        let _ = encryption::rewrap_tree_resumable(&keyring, &root);
        return;
    }

    for boundary in ["rotation.after_journal", "rotation.after_verify"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir_all(&root).unwrap();
        let old_keyring_path = temp.path().join("old.json");
        let new_keyring_path = temp.path().join("new.json");
        write_keyring(&old_keyring_path, "key-old1");
        write_keyring(&new_keyring_path, "key-new1");
        let old_keyring = Keyring::load(&old_keyring_path).unwrap();
        let envelope =
            encryption::encrypt_bytes(&old_keyring, FileType::Metadata, b"rotation-secret")
                .unwrap();
        fs_util::atomic_write(&root.join("catalog.json"), &envelope).unwrap();

        assert_crashed(run_child(
            "key_rotation_resumes_before_and_after_tree_verification",
            "rotation",
            boundary,
            &[
                ("CHIRONDB_DATA_DIR", &root),
                ("CHIRONDB_KEYRING", &new_keyring_path),
            ],
        ));

        let new_keyring = Keyring::load(&new_keyring_path).unwrap();
        encryption::rewrap_tree_resumable(&new_keyring, &root).unwrap();
        encryption::verify_tree(&new_keyring, &root).unwrap();
        assert_eq!(
            encryption::referenced_key_ids(&root).unwrap(),
            ["key-new1".to_string()].into_iter().collect()
        );
        assert!(!root.join(".key-rotation.json").exists());
    }
}

#[test]
fn restore_restart_observes_only_complete_old_or_new_generation() {
    if child_mode("restore") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let snapshot = required_path("CHIRONDB_SNAPSHOT_DIR");
        let db = Db::open(&data_dir).unwrap();
        let _ = db.restore(&snapshot);
        return;
    }

    for (boundary, expected_id) in [
        ("restore.after_copy_journal", "old-point"),
        ("restore.after_snapshot_copy", "old-point"),
        // The staged generation is fully synced and journaled before these
        // boundaries, so startup deterministically completes the install.
        ("restore.after_generation_sync", "new-point"),
        ("restore.before_current_switch", "new-point"),
        ("restore.after_current_switch", "new-point"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("live");
        let seed_dir = temp.path().join("seed");
        let snapshot_dir = temp.path().join("snapshot");
        prepare_database(&data_dir, "old-point");
        prepare_database(&seed_dir, "new-point");
        {
            let seed = Db::open(&seed_dir).unwrap();
            seed.snapshot(&snapshot_dir).unwrap();
        }

        assert_crashed(run_child(
            "restore_restart_observes_only_complete_old_or_new_generation",
            "restore",
            boundary,
            &[
                ("CHIRONDB_DATA_DIR", &data_dir),
                ("CHIRONDB_SNAPSHOT_DIR", &snapshot_dir),
            ],
        ));

        let reopened = Db::open(&data_dir).unwrap();
        let ids = ["old-point".to_string(), "new-point".to_string()];
        let points = reopened.get_points("docs", &ids).unwrap();
        assert_eq!(points.len(), 1, "boundary {boundary}");
        assert_eq!(points[0].id, expected_id, "boundary {boundary}");
        let layout = storage_layout::resolve(&data_dir).unwrap();
        assert!(layout.active_root.join("catalog.json").is_file());
    }
}

#[cfg(unix)]
#[test]
fn sql_vector_graph_restore_survives_real_sigkill_and_subsequent_commits() {
    if child_mode("restore-sql-control") {
        let db = Db::open(required_path("CHIRONDB_DATA_DIR")).unwrap();
        let _ = db.restore(required_path("CHIRONDB_SNAPSHOT_DIR"));
        return;
    }

    for generation in [false, true] {
        for (boundary, expected) in [
            ("restore.after_relational_validation", vec![1, 2]),
            ("restore.before_relational_publication", vec![1]),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("live");
            let snapshot = temp.path().join("snapshot");
            if generation {
                storage_layout::initialize_empty(&data).unwrap();
            }
            {
                let db = Db::open(&data).unwrap();
                db.create_collection(collection_config()).unwrap();
                let scope = TenantScope::tenant("restore-writer", "acme");
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
                restore_sql(&db, "CREATE TABLE documents (id BIGINT PRIMARY KEY)");
                restore_knowledge(&db, 1);
                db.snapshot(&snapshot).unwrap();
                restore_knowledge(&db, 2);
            }
            assert_sigkilled(run_sigkill_child(
                "sql_vector_graph_restore_survives_real_sigkill_and_subsequent_commits",
                "restore-sql-control",
                boundary,
                &temp.path().join("marker"),
                &[
                    ("CHIRONDB_DATA_DIR", &data),
                    ("CHIRONDB_SNAPSHOT_DIR", &snapshot),
                ],
                &[],
            ));
            let db = Db::open(&data).unwrap();
            assert_restored_knowledge(&db, &expected);
            restore_knowledge(&db, 3);
            drop(db);
            let mut acknowledged = expected;
            acknowledged.push(3);
            assert_restored_knowledge(&Db::open(&data).unwrap(), &acknowledged);
        }
    }
}

#[cfg(unix)]
fn restore_sql(db: &Db, sql: &str) -> chirondb_core::SqlExecutionResponse {
    db.execute_sql(SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    })
    .unwrap()
}

#[cfg(unix)]
fn restore_knowledge(db: &Db, id: i64) {
    let response = db
        .execute_multimodel_transaction(
            MultiModelTransactionRequest {
                sql: SqlExecutionRequest {
                    statements: vec![SqlStatementRequest {
                        sql: format!("INSERT INTO documents (id) VALUES ({id})"),
                        parameters: vec![],
                    }],
                    idempotency_key: Some(format!("restore-document-{id}")),
                    retry_id: None,
                },
                collection: "docs".into(),
                points: vec![
                    point(&format!("document-{id}")),
                    point(&format!("source-{id}")),
                ],
                point_deletes: vec![],
                relations: vec![RelateRequest {
                    source_point_id: format!("document-{id}"),
                    target_point_id: format!("source-{id}"),
                    edge_type: "cites".into(),
                    properties: json!({"source": id}),
                    scope: GraphRelationScope::Local,
                    idempotency_key: None,
                }],
                edge_deletes: vec![],
                edge_updates: vec![],
            },
            &TenantScope::tenant("restore-writer", "acme"),
            &audit::AuditContext::embedded(),
        )
        .unwrap();
    assert!(response.sql.committed);
}

#[cfg(unix)]
fn assert_restored_knowledge(db: &Db, expected: &[i64]) {
    let response = restore_sql(db, "SELECT id FROM documents ORDER BY id");
    let rows = expected
        .iter()
        .map(|id| vec![RelationalValue::Integer(*id)])
        .collect::<Vec<_>>();
    assert!(
        matches!(&response.results[0], SqlResult::Rows { rows: actual, .. } if actual == &rows)
    );
    assert_eq!(db.count("docs", None).unwrap().count, expected.len() * 2);
    let scope = TenantScope::tenant("restore-reader", "acme");
    for id in expected {
        assert_eq!(
            db.get_points_scoped(
                "docs",
                &[format!("document-{id}"), format!("source-{id}")],
                &scope
            )
            .unwrap()
            .len(),
            2
        );
        let traversal = db
            .traverse_scoped(
                "docs",
                GraphTraverseRequest {
                    anchors: vec![format!("document-{id}")],
                    edge_types: vec!["cites".into()],
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        ..TraversalBudget::default()
                    },
                },
                &scope,
            )
            .unwrap();
        assert!(
            traversal
                .nodes
                .iter()
                .any(|node| node.point_id == format!("source-{id}"))
        );
    }
}

#[cfg(unix)]
#[test]
fn wait_true_write_survives_real_sigkill_after_durable_boundary() {
    if child_mode("acknowledged-upsert") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let db = Db::open(&data_dir).unwrap();
        let _ = db.upsert("docs", vec![point("acked-point")]);
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    prepare_database(&data_dir, "old-point");
    let marker = temp.path().join("acknowledged.marker");
    assert_sigkilled(run_sigkill_child(
        "wait_true_write_survives_real_sigkill_after_durable_boundary",
        "acknowledged-upsert",
        "db.after_upsert_durable",
        &marker,
        &[("CHIRONDB_DATA_DIR", &data_dir)],
        &[],
    ));

    let reopened = Db::open(&data_dir).unwrap();
    let points = reopened
        .get_points("docs", &["acked-point".to_string()])
        .unwrap();
    assert_eq!(points.len(), 1);
}

#[cfg(unix)]
#[test]
fn wal_append_and_rotation_are_recoverable_after_real_sigkill() {
    if child_mode("wal-append") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let db = Db::open(&data_dir).unwrap();
        let _ = db.upsert("docs", vec![point("new-point")]);
        return;
    }
    if child_mode("wal-rotation") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let db = Db::open(&data_dir).unwrap();
        db.upsert("docs", vec![point("rotation-first")]).unwrap();
        let _ = db.upsert("docs", vec![point("rotation-second")]);
        return;
    }

    for boundary in ["wal.after_record_write", "wal.after_sync"] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        prepare_database(&data_dir, "old-point");
        let marker = temp.path().join("wal.marker");
        assert_sigkilled(run_sigkill_child(
            "wal_append_and_rotation_are_recoverable_after_real_sigkill",
            "wal-append",
            boundary,
            &marker,
            &[("CHIRONDB_DATA_DIR", &data_dir)],
            &[],
        ));
        let reopened = Db::open(&data_dir).unwrap();
        let count = reopened.count("docs", None).unwrap().count;
        assert!((1..=2).contains(&count), "boundary {boundary}");
    }

    for boundary in [
        "wal_rotation.after_old_sync",
        "wal_rotation.after_new_sync",
        "wal_rotation.after_directory_sync",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        prepare_database(&data_dir, "old-point");
        let marker = temp.path().join("rotation.marker");
        assert_sigkilled(run_sigkill_child(
            "wal_append_and_rotation_are_recoverable_after_real_sigkill",
            "wal-rotation",
            boundary,
            &marker,
            &[("CHIRONDB_DATA_DIR", &data_dir)],
            &[("CHIRONDB_TEST_WAL_SEGMENT_BYTES", "256")],
        ));
        let reopened = Db::open(&data_dir).unwrap();
        let ids = ["old-point".to_string(), "rotation-first".to_string()];
        assert_eq!(
            reopened.get_points("docs", &ids).unwrap().len(),
            2,
            "boundary {boundary}"
        );
    }
}

#[cfg(unix)]
#[test]
fn compaction_and_wal_archive_survive_real_sigkill_at_every_publication_boundary() {
    if child_mode("compaction") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let db = Db::open(&data_dir).unwrap();
        db.upsert("docs", vec![point("new-point")]).unwrap();
        let _ = db.compact_collection("docs");
        return;
    }

    for boundary in [
        "compaction.after_segment_sync",
        "compaction.after_wal_sync",
        "compaction.after_manifest",
        "compaction.after_checkpoint",
        "wal_archive.after_staging_sync",
        "wal_archive.after_publish_before_dir_sync",
        "wal_archive.after_publish_sync",
        "wal_archive.after_reset",
        "compaction.after_archive",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        prepare_database(&data_dir, "old-point");
        let marker = temp.path().join("compaction.marker");
        assert_sigkilled(run_sigkill_child(
            "compaction_and_wal_archive_survive_real_sigkill_at_every_publication_boundary",
            "compaction",
            boundary,
            &marker,
            &[("CHIRONDB_DATA_DIR", &data_dir)],
            &[],
        ));

        let reopened = Db::open(&data_dir).unwrap();
        let ids = ["old-point".to_string(), "new-point".to_string()];
        assert_eq!(
            reopened.get_points("docs", &ids).unwrap().len(),
            2,
            "boundary {boundary}"
        );
        assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    }
}

#[cfg(unix)]
#[test]
fn cell_checkpointed_compaction_resumes_after_real_sigkill() {
    if child_mode("resumable-cell-compaction") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let db = Db::open(&data_dir).unwrap();
        db.upsert("docs", vec![point("new-point")]).unwrap();
        let _ = db.compact_collection("docs");
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    prepare_database(&data_dir, "old-point");
    let marker = temp.path().join("resumable-cell.marker");
    assert_sigkilled(run_sigkill_child(
        "cell_checkpointed_compaction_resumes_after_real_sigkill",
        "resumable-cell-compaction",
        "seal.after_vamana_cell",
        &marker,
        &[("CHIRONDB_DATA_DIR", &data_dir)],
        &[],
    ));

    let reopened = Db::open(&data_dir).unwrap();
    assert_eq!(reopened.count("docs", None).unwrap().count, 2);
    reopened
        .compact_collection("docs")
        .expect("cell-checkpointed build must resume after SIGKILL");
    assert_eq!(reopened.count("docs", None).unwrap().count, 2);
}

#[cfg(unix)]
#[test]
fn snapshot_marker_never_publishes_a_partial_snapshot_after_real_sigkill() {
    if child_mode("snapshot") {
        let data_dir = required_path("CHIRONDB_DATA_DIR");
        let snapshot = required_path("CHIRONDB_SNAPSHOT_DIR");
        let db = Db::open(&data_dir).unwrap();
        let _ = db.snapshot(&snapshot);
        return;
    }

    for (boundary, published) in [
        ("snapshot.after_tree_sync", false),
        ("snapshot.after_marker_sync", false),
        ("snapshot.after_publish_sync", true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let snapshot = temp.path().join("snapshot");
        prepare_database(&data_dir, "old-point");
        let marker = temp.path().join("snapshot.marker");
        assert_sigkilled(run_sigkill_child(
            "snapshot_marker_never_publishes_a_partial_snapshot_after_real_sigkill",
            "snapshot",
            boundary,
            &marker,
            &[
                ("CHIRONDB_DATA_DIR", &data_dir),
                ("CHIRONDB_SNAPSHOT_DIR", &snapshot),
            ],
            &[],
        ));
        let snapshot_marker = chirondb_core::snapshot::read_snapshot_marker(&snapshot).unwrap();
        assert_eq!(snapshot_marker.is_some(), published, "boundary {boundary}");
        if published {
            let restore_dir = temp.path().join("restore");
            prepare_database(&restore_dir, "replace-me");
            let restored = Db::open(&restore_dir).unwrap();
            restored.restore(&snapshot).unwrap();
            assert_eq!(
                restored
                    .get_points("docs", &["old-point".to_string()])
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}

#[test]
fn snapshot_holds_sql_commits_until_its_tree_is_published() {
    if child_mode("snapshot-sql-barrier") {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        storage_layout::initialize_empty(&data_dir).unwrap();
        let db = Db::open(&data_dir).unwrap();
        db.execute_sql(SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "CREATE TABLE receipts (id BIGINT PRIMARY KEY)".into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .unwrap();
        let snapshot = temp.path().join("snapshot");
        let snapshot_db = db.clone();
        let snapshot_path = snapshot.clone();
        let copying = thread::spawn(move || snapshot_db.snapshot(&snapshot_path));
        let marker = required_path("CHIRONDB_FAILPOINT_MARKER");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "snapshot did not reach publication pause");
        let writer_db = db.clone();
        let (sent, received) = mpsc::channel();
        let writer = thread::spawn(move || {
            sent.send(writer_db.execute_sql(SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "INSERT INTO receipts (id) VALUES (1)".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            }))
            .unwrap();
        });
        let committed_during_snapshot = received.recv_timeout(Duration::from_millis(250)).is_ok();
        fs::write(required_path("CHIRONDB_FAILPOINT_RELEASE"), b"release").unwrap();
        copying.join().unwrap().unwrap();
        writer.join().unwrap();
        if !committed_during_snapshot {
            received
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
        }
        assert!(
            !committed_during_snapshot,
            "SQL commit bypassed the snapshot publication barrier"
        );
        let snapshot_db = Db::open(&snapshot).unwrap();
        let selected = snapshot_db
            .execute_sql(SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "SELECT id FROM receipts".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        assert!(matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
        let live = db
            .execute_sql(SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "SELECT id FROM receipts".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            })
            .unwrap();
        assert!(matches!(&live.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("snapshot.marker");
    let release = temp.path().join("snapshot.release");
    assert_succeeded(run_child_with_action(
        "snapshot_holds_sql_commits_until_its_tree_is_published",
        "snapshot-sql-barrier",
        "pause",
        "snapshot.after_tree_sync",
        &[
            ("CHIRONDB_FAILPOINT_MARKER", &marker),
            ("CHIRONDB_FAILPOINT_RELEASE", &release),
        ],
    ));
}

fn child_mode(expected: &str) -> bool {
    std::env::var(CHILD_MODE).is_ok_and(|mode| mode == expected)
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn run_child(test: &str, mode: &str, boundary: &str, paths: &[(&str, &Path)]) -> Output {
    run_child_with_action(test, mode, "exit", boundary, paths)
}

fn run_error_child(test: &str, mode: &str, boundary: &str, paths: &[(&str, &Path)]) -> Output {
    run_child_with_action(test, mode, "error", boundary, paths)
}

fn run_child_with_action(
    test: &str,
    mode: &str,
    action: &str,
    boundary: &str,
    paths: &[(&str, &Path)],
) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env("CHIRONDB_FAILPOINT", format!("{action}:{boundary}"));
    for (name, path) in paths {
        command.env(name, path);
    }
    command.output().unwrap()
}

#[cfg(unix)]
fn run_sigkill_child(
    test: &str,
    mode: &str,
    boundary: &str,
    marker: &Path,
    paths: &[(&str, &Path)],
    values: &[(&str, &str)],
) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env("CHIRONDB_FAILPOINT", format!("pause:{boundary}"))
        .env("CHIRONDB_FAILPOINT_MARKER", marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, path) in paths {
        command.env(name, path);
    }
    for (name, value) in values {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before failpoint marker: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists(), "child did not reach {boundary} within 30s");
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // SAFETY: the PID belongs to the child spawned immediately above and
    // signal 9 has the same value on every required Unix test platform.
    assert_eq!(unsafe { kill(child.id() as i32, 9) }, 0);
    child.wait_with_output().unwrap()
}

fn assert_crashed(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(86),
        "child did not crash at failpoint; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_succeeded(output: Output) {
    assert!(
        output.status.success(),
        "child failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn assert_sigkilled(output: Output) {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        Some(9),
        "child was not killed by SIGKILL; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn prepare_database(data_dir: &Path, point_id: &str) {
    storage_layout::initialize_empty(data_dir).unwrap();
    let db = Db::open(data_dir).unwrap();
    db.create_collection(collection_config()).unwrap();
    db.upsert(
        "docs",
        vec![Point {
            id: point_id.to_string(),
            vector: vec![1.0, 2.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"source": point_id}),
        }],
    )
    .unwrap();
    db.compact_collection("docs").unwrap();
}

fn point(id: &str) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![1.0, 2.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"source": id}),
    }
}

fn collection_config() -> CollectionConfig {
    CollectionConfig {
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
    }
}

fn write_keyring(path: &Path, active_key_id: &str) {
    fs::write(
        path,
        json!({
            "version": 1,
            "active_key_id": active_key_id,
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
