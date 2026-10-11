use super::*;

#[test]
fn escaped_audit_writer_keeps_installation_lease_until_its_registry_is_dropped() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    let writer = Arc::clone(&db.audit_writer);
    drop(db);
    assert!(Db::open(root.path()).is_err());
    drop(writer);
    drop(Db::open(root.path()).unwrap());
}

#[test]
fn exclusive_reopen_removes_interrupted_audit_cache_and_rebuilds_durable_history() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    drop(db);
    let stale = root.path().join("audit/.chiron-decisions-interrupted");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("unpublished"), b"incomplete derived index").unwrap();
    let db = Db::open(root.path()).unwrap();
    assert!(!stale.exists());
    assert_eq!(db.list_collections().len(), 1);
    audit::verify_hash_chain(root.path()).unwrap();
    drop(db);
    assert!(
        fs::read_dir(root.path().join("audit"))
            .unwrap()
            .all(|entry| entry.unwrap().file_type().unwrap().is_file())
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn flat_and_generation_db_reopen_complete_projections_without_historical_prepare_reads() {
    for generation in [false, true] {
        let temp = TempDir::new().unwrap();
        if generation {
            crate::storage_layout::initialize_empty(temp.path()).unwrap();
        }
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("ack", 1.0, "current")])
            .unwrap();
        let request = |sql: &str| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql(request("CREATE TABLE receipts (id BIGINT PRIMARY KEY)"))
            .unwrap();
        db.execute_sql(request("INSERT INTO receipts VALUES (1)"))
            .unwrap();
        crate::transaction_journal::activate_test_authority(&db.transaction_journal);
        drop(db);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let mut wal = Wal::open_control_journal(journal.dir()).unwrap();
        let end = wal.len().unwrap();
        wal.drop_prefix(end).unwrap();
        drop(wal);
        drop(journal);
        {
            let marker = temp.path().join("marker");
            let release = temp.path().join("release");
            let _env = crate::failpoint::test_env(
                "error:transaction.scan.before_prepare_read",
                &marker,
                &release,
            );
            let db = Db::open(temp.path()).unwrap();
            assert_eq!(
                Wal::retained_base_lsn(db.transaction_journal.dir()).unwrap(),
                end
            );
            assert_eq!(db.count("docs", None).unwrap().count, 1);
            let response = db.execute_sql(request("SELECT id FROM receipts")).unwrap();
            assert!(
                matches!(&response.results[0], crate::SqlResult::Rows { rows, .. } if rows.len() == 1)
            );
        }
        let db = Db::open(temp.path()).unwrap();
        db.execute_sql(request("INSERT INTO receipts VALUES (2)"))
            .unwrap();
        db.upsert("docs", vec![ls_vec_point("later", 2.0, "suffix")])
            .unwrap();
        drop(db);
        let db = Db::open(temp.path()).unwrap();
        assert_eq!(db.count("docs", None).unwrap().count, 2);
        let response = db.execute_sql(request("SELECT id FROM receipts")).unwrap();
        assert!(
            matches!(&response.results[0], crate::SqlResult::Rows { rows, .. } if rows.len() == 2)
        );
        audit::verify_hash_chain(temp.path()).unwrap();
    }
}

#[test]
fn completed_collection_store_is_still_required_after_compact_routing() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("ack", 1.0, "current")])
        .unwrap();
    crate::transaction_journal::activate_test_authority(&db.transaction_journal);
    drop(db);
    fs::remove_dir_all(temp.path().join("collections/docs/wal")).unwrap();
    assert!(matches!(
        Db::open(temp.path()),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn storage_recovery_uses_compact_history_after_journal_prefix_retirement() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("old", 1.0, "retired")])
        .unwrap();
    db.delete_collection("docs").unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("ack", 2.0, "current")])
        .unwrap();
    db.create_collection(ls_vec_config("dropped")).unwrap();
    db.delete_collection("dropped").unwrap();
    crate::transaction_journal::activate_test_authority(&db.transaction_journal);
    drop(db);
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let mut wal = Wal::open_control_journal(journal.dir()).unwrap();
    let end = wal.len().unwrap();
    wal.drop_prefix(end).unwrap();
    drop(wal);
    drop(journal);
    let journal = TransactionJournal::open(temp.path()).unwrap();
    assert_eq!(Wal::retained_base_lsn(journal.dir()).unwrap(), end);
    assert!(!temp.path().join("collections/dropped").exists());
    super::super::recover_transaction_storage_projections(&journal, temp.path()).unwrap();
    let loaded =
        super::super::load_db_root_with_journal(temp.path(), None, Some(&journal)).unwrap();
    let docs = loaded.collections["docs"].read();
    assert_eq!(docs.id_index.len(), 1);
    assert!(docs.id_index.contains_key("ack"));
    assert!(!docs.id_index.contains_key("old"));
}

#[test]
fn collection_replay_rejects_a_changed_committed_projection() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("ack", 1.0, "original")])
        .unwrap();
    crate::transaction_journal::activate_test_authority(&db.transaction_journal);
    let mut transaction_id = None;
    db.transaction_journal
        .for_each_committed(|transaction| {
            if matches!(&transaction.prepare.target, TransactionTarget::Collection { name } if name == "docs") {
                transaction_id = Some(transaction.prepare.transaction_id);
            }
            Ok(())
        })
        .unwrap();
    drop(db);
    let mut wal = Wal::open(&temp.path().join("collections/docs/wal")).unwrap();
    wal.append(&WalEntry::TransactionApply {
        transaction_id: transaction_id.unwrap(),
        entry: Box::new(WalEntry::UpsertBatch {
            points: vec![ls_vec_point("ack", 2.0, "altered")],
        }),
    })
    .unwrap();
    drop(wal);
    assert!(matches!(
        Db::open(temp.path()),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn catalog_replay_rejects_an_orphan_before_deleting_collection_data() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.upsert("docs", vec![ls_vec_point("ack", 1.0, "original")])
        .unwrap();
    crate::transaction_journal::activate_test_authority(&db.transaction_journal);
    drop(db);
    let collection = temp.path().join("collections/docs");
    let mut wal = Wal::open(&temp.path().join(super::super::CATALOG_WAL_DIR)).unwrap();
    wal.append(&WalEntry::TransactionApply {
        transaction_id: crate::transaction_journal::TransactionId::default(),
        entry: Box::new(WalEntry::DropCollection {
            name: "docs".into(),
        }),
    })
    .unwrap();
    drop(wal);
    assert!(matches!(
        Db::open(temp.path()),
        Err(GaussError::WalCorruption { .. })
    ));
    assert!(collection.is_dir());
}

#[test]
fn pending_projection_recovery_rejects_changed_collection_or_relational_bodies() {
    for domain in [
        "collection",
        "multi-model-collection",
        "multi-model-relational",
    ] {
        let temp = TempDir::new().unwrap();
        let collection_wal = temp.path().join("collections/docs/wal");
        let relational_wal = temp.path().join("relational/wal");
        fs::create_dir_all(&collection_wal).unwrap();
        fs::create_dir_all(&relational_wal).unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let graph = GraphBatch {
            point_mutations: vec![crate::wal::GraphPointMutation::Upsert {
                point: ls_vec_point("ack", 1.0, "original"),
            }],
            ..Default::default()
        };
        let relational = RelationalBatch {
            sequence: 1,
            mutations: vec![RelationalMutation::DropTable {
                name: "documents".into(),
            }],
        };
        let (target, mutation) = if domain == "collection" {
            (
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::GraphBatch {
                    batch: graph.clone(),
                },
            )
        } else {
            (
                TransactionTarget::MultiModel {
                    collections: vec!["docs".into()],
                },
                WalEntry::MultiModelBatch {
                    batch: MultiModelBatch {
                        version: MULTI_MODEL_BATCH_VERSION,
                        relational: relational.clone(),
                        collections: vec![MultiModelCollectionBatch {
                            collection: "docs".into(),
                            batch: graph,
                            security: None,
                        }],
                    },
                },
            )
        };
        let committed = journal
            .commit(
                target,
                mutation,
                TransactionAudit::mutation(
                    "projection",
                    None,
                    &audit::AuditContext::embedded(),
                    serde_json::Value::Null,
                ),
            )
            .unwrap();
        let id = committed.prepare.transaction_id;
        let (path, changed) = if domain == "multi-model-relational" {
            (
                &relational_wal,
                WalEntry::RelationalBatch {
                    batch: RelationalBatch {
                        sequence: 1,
                        mutations: vec![RelationalMutation::DropTable {
                            name: "different".into(),
                        }],
                    },
                },
            )
        } else {
            (
                &collection_wal,
                WalEntry::GraphBatch {
                    batch: GraphBatch {
                        point_mutations: vec![crate::wal::GraphPointMutation::Upsert {
                            point: ls_vec_point("ack", 2.0, "changed"),
                        }],
                        ..Default::default()
                    },
                },
            )
        };
        let mut wal = Wal::open(path).unwrap();
        wal.append(&WalEntry::TransactionApply {
            transaction_id: id,
            entry: Box::new(changed),
        })
        .unwrap();
        drop(wal);
        drop(committed);
        drop(journal);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        assert!(
            matches!(
                super::super::recover_transaction_storage_projections(&journal, temp.path()),
                Err(GaussError::WalCorruption { .. })
            ),
            "accepted changed {domain}"
        );
        assert!(!journal.status(id).storage_projected);
        let mut entries = 0;
        Wal::recover_from(path, 0, |_| {
            entries += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(entries, 1);
    }
}

#[test]
fn flat_and_generation_snapshots_keep_sql_and_collection_commit_authority() {
    for generation in [false, true] {
        let temp = TempDir::new().unwrap();
        let data = temp.path().join("live");
        let snapshot = temp.path().join("snapshot");
        if generation {
            crate::storage_layout::initialize_empty(&data).unwrap();
        }
        let db = Db::open(&data).unwrap();
        db.create_collection(ls_vec_config("docs")).unwrap();
        db.upsert("docs", vec![ls_vec_point("ack", 1.0, "original")])
            .unwrap();
        let request = |sql: &str| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql(request("CREATE TABLE receipts (id BIGINT PRIMARY KEY)"))
            .unwrap();
        db.execute_sql(request("INSERT INTO receipts VALUES (1)"))
            .unwrap();
        db.snapshot(&snapshot).unwrap();
        assert!(snapshot.join("transactions/FORMAT").is_file());
        assert!(!snapshot.join(super::super::GRAPH_IDENTITY_FILE).exists());
        db.execute_sql(request("INSERT INTO receipts VALUES (2)"))
            .unwrap();
        db.upsert("docs", vec![ls_vec_point("late", 2.0, "after")])
            .unwrap();
        let fork = Db::open(&snapshot).unwrap();
        let selected = fork
            .execute_sql(request("SELECT id FROM receipts"))
            .unwrap();
        assert!(
            matches!(&selected.results[0], crate::SqlResult::Rows { rows, .. } if rows.len() == 1)
        );
        assert_eq!(fork.count("docs", None).unwrap().count, 1);
        assert_eq!(db.count("docs", None).unwrap().count, 2);
        drop(fork);
        let fork = Db::open(&snapshot).unwrap();
        assert_eq!(fork.count("docs", None).unwrap().count, 1);
    }
}
