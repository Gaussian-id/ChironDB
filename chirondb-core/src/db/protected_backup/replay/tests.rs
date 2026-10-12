use super::*;
use crate::{
    audit::AuditContext,
    transaction_journal::{TransactionAudit, TransactionCommit},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn prepare(sequence: u64, target: TransactionTarget, mutation: WalEntry) -> TransactionPrepare {
    TransactionPrepare {
        version: TRANSACTION_JOURNAL_VERSION,
        transaction_id: TransactionId::new(),
        commit_sequence: sequence,
        target,
        mutation: Box::new(mutation),
        audit: TransactionAudit::mutation(
            "restore-test",
            None,
            &AuditContext::embedded(),
            serde_json::json!({"diagnostic": "x".repeat(4096)}),
        ),
        idempotency: None,
    }
}
fn append(
    wal: &mut Wal,
    prepare: TransactionPrepare,
    committed: bool,
    storage: bool,
) -> TransactionId {
    let id = prepare.transaction_id;
    let sequence = prepare.commit_sequence;
    wal.append_no_sync(&WalEntry::TransactionPrepare { prepare })
        .unwrap();
    if committed {
        wal.append_no_sync(&WalEntry::TransactionCommit {
            commit: TransactionCommit {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id: id,
                commit_sequence: sequence,
            },
        })
        .unwrap();
        for kind in [ProjectionKind::Audit, ProjectionKind::Storage] {
            if kind == ProjectionKind::Storage && !storage {
                continue;
            }
            wal.append_no_sync(&WalEntry::TransactionProjection {
                projection: TransactionProjection {
                    version: TRANSACTION_JOURNAL_VERSION,
                    transaction_id: id,
                    kind,
                },
            })
            .unwrap();
        }
    }
    id
}
fn create(name: &str, dimension: usize) -> WalEntry {
    WalEntry::CreateCollection {
        config: serde_json::from_value(serde_json::json!({
            "name": name, "vector_dim": dimension,
        }))
        .unwrap(),
    }
}
fn scratch_count(staging: &Path) -> usize {
    fs::read_dir(staging.join("transactions"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".chiron-decisions-")
        })
        .count()
}

#[test]
fn restore_replay_spills_history_and_preserves_latest_incarnation_and_pending_state() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let staging = temp.path().join("staging");
    fs::create_dir_all(staging.join("collections")).unwrap();
    let mut wal = Wal::open_control_journal(&source).unwrap();
    let old = append(
        &mut wal,
        prepare(
            1,
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::Delete { id: "old".into() },
        ),
        true,
        true,
    );
    for n in 0..2050 {
        append(
            &mut wal,
            prepare(
                n + 2,
                TransactionTarget::Catalog,
                WalEntry::DropCollection {
                    name: format!("retired-{n}"),
                },
            ),
            true,
            true,
        );
    }
    for (sequence, mutation, projected) in [
        (2052, create("doc", 2), true),
        (2053, create("docs", 2), true),
        (
            2054,
            WalEntry::DropCollection {
                name: "docs".into(),
            },
            true,
        ),
        (2055, create("docs", 3), false),
        (2056, create("docs-long", 4), true),
    ] {
        append(
            &mut wal,
            prepare(sequence, TransactionTarget::Catalog, mutation),
            true,
            projected,
        );
    }
    let new = append(
        &mut wal,
        prepare(
            2057,
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::Delete { id: "new".into() },
        ),
        true,
        true,
    );
    let pending = append(
        &mut wal,
        prepare(2058, TransactionTarget::Catalog, create("pending", 2)),
        false,
        false,
    );
    wal.sync().unwrap();
    drop(wal);
    let before = super::super::hash_files(&source, &source).unwrap();
    let output = staging.join("transactions/output");
    wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
        rebuild(&source, &staging, 1, &output).unwrap();
        assert_eq!(used(), 0);
        assert_eq!(scratch_count(&staging), 0);
    });
    for (name, dimension) in [("doc", 2), ("docs", 3), ("docs-long", 4)] {
        let checkpoint = crate::checkpoint::read_checkpoint(&collection_dir(&staging, name))
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.schema_epoch, 1);
        let WalEntry::CreateCollection { config } = create(name, dimension) else {
            unreachable!()
        };
        assert_eq!(
            checkpoint.schema_crc,
            CollectionCheckpoint::new(&config, 1, 0, 0, None)
                .unwrap()
                .schema_crc
        );
    }
    assert!(!collection_dir(&staging, "pending").exists());
    let mut old_storage = 0;
    let mut new_storage = 0;
    let mut new_audit = 0;
    let mut pending_prepares = 0;
    let mut catalog_projections = 0;
    Wal::scan_journal_from(&output, 0, |record| {
        match &record.entry {
            WalEntry::TransactionPrepare { prepare } if prepare.transaction_id == pending => {
                pending_prepares += 1
            }
            WalEntry::TransactionProjection { projection } => {
                if projection.kind == ProjectionKind::Storage {
                    if projection.transaction_id == old {
                        old_storage += 1;
                    } else if projection.transaction_id == new {
                        new_storage += 1;
                    } else {
                        catalog_projections += 1;
                    }
                } else if projection.transaction_id == new {
                    new_audit += 1;
                }
            }
            _ => {}
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(
        (
            old_storage,
            new_storage,
            new_audit,
            pending_prepares,
            catalog_projections
        ),
        (1, 0, 1, 1, 2055)
    );
    assert_eq!(super::super::hash_files(&source, &source).unwrap(), before);
}

#[test]
fn restore_replay_rejects_invalid_decision_lineage_before_catalog_installation() {
    for case in [
        "mismatch",
        "missing_prepare",
        "early_commit",
        "missing_commit",
        "early_projection",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let staging = temp.path().join("staging");
        fs::create_dir_all(&staging).unwrap();
        let mut wal = Wal::open_control_journal(&source).unwrap();
        let prepare = prepare(1, TransactionTarget::Catalog, create("forbidden", 2));
        let id = prepare.transaction_id;
        let commit = WalEntry::TransactionCommit {
            commit: TransactionCommit {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id: id,
                commit_sequence: if case == "mismatch" { 2 } else { 1 },
            },
        };
        let projection = WalEntry::TransactionProjection {
            projection: TransactionProjection {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id: id,
                kind: ProjectionKind::Storage,
            },
        };
        if case == "early_commit" {
            wal.append_no_sync(&commit).unwrap();
        }
        if case != "missing_prepare" {
            wal.append_no_sync(&WalEntry::TransactionPrepare { prepare })
                .unwrap();
        }
        if case == "early_projection" || case == "missing_commit" {
            wal.append_no_sync(&projection).unwrap();
        }
        if case != "early_commit" && case != "missing_commit" {
            wal.append_no_sync(&commit).unwrap();
        }
        wal.sync().unwrap();
        drop(wal);
        wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            assert!(
                matches!(
                    rebuild(&source, &staging, 0, &staging.join("output")),
                    Err(GaussError::WalCorruption { .. })
                ),
                "{case}"
            );
            assert_eq!(used(), 0, "{case}");
        });
        assert!(!staging.join(CATALOG_WAL_DIR).exists(), "{case}");
        assert!(!collection_dir(&staging, "forbidden").exists(), "{case}");
        assert_eq!(scratch_count(&staging), 0, "{case}");
    }
}

#[test]
fn restore_replay_refusal_and_cancellation_release_all_scratch_and_reservations() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let staging = temp.path().join("staging");
    fs::create_dir_all(&staging).unwrap();
    let mut wal = Wal::open_control_journal(&source).unwrap();
    append(
        &mut wal,
        prepare(1, TransactionTarget::Catalog, create("docs", 2)),
        true,
        true,
    );
    wal.sync().unwrap();
    drop(wal);
    wal_decode::with_test_storage_pool(1, |used| {
        assert!(matches!(
            rebuild(&source, &staging, 0, &staging.join("output")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    let cancellation = Arc::new(AtomicBool::new(true));
    wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
        let result = crate::relational::with_sql_cancellation(Arc::clone(&cancellation), || {
            rebuild(&source, &staging, 0, &staging.join("output"))
        });
        assert!(
            matches!(result, Err(GaussError::InvalidRequest(message)) if message == "query canceled")
        );
        assert_eq!(used(), 0);
    });
    assert!(!collection_dir(&staging, "docs").exists());
    cancellation.store(false, Ordering::Release);
    rebuild(&source, &staging, 0, &staging.join("output")).unwrap();
    assert_eq!(scratch_count(&staging), 0);
}
