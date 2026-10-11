use super::*;
use crate::relational::wal_decode::with_test_storage_pool;

fn commit(
    journal: &TransactionJournal,
    target: TransactionTarget,
    entry: WalEntry,
) -> CommittedTransaction {
    journal
        .commit(
            target,
            entry,
            TransactionAudit::mutation("test", None, &AuditContext::embedded(), Value::Null),
        )
        .unwrap()
}
fn complete(journal: &TransactionJournal, transaction: &CommittedTransaction) {
    for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
        journal
            .mark_projected(transaction.prepare.transaction_id, kind)
            .unwrap();
    }
}
fn delete(journal: &TransactionJournal, id: &str) -> CommittedTransaction {
    commit(
        journal,
        TransactionTarget::Collection {
            name: "docs".into(),
        },
        WalEntry::Delete { id: id.into() },
    )
}
fn retire(journal: &TransactionJournal) {
    let mut wal = Wal::open_control_journal(journal.dir()).unwrap();
    let end = wal.len().unwrap();
    wal.drop_prefix(end).unwrap();
    assert_eq!(Wal::retained_base_lsn(journal.dir()).unwrap(), end);
}

#[test]
fn compact_selection_skips_retired_bodies_and_repairs_only_pending_suffix() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    for n in 0..513 {
        let transaction = delete(&journal, &n.to_string());
        complete(&journal, &transaction);
    }
    authority::tests::activate(&journal);
    retire(&journal);
    drop(journal);
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let storage = delete(&journal, "storage-pending");
    let audit = delete(&journal, "audit-pending");
    journal
        .mark_projected(audit.prepare.transaction_id, ProjectionKind::Storage)
        .unwrap();
    let mut visited = Vec::new();
    let mut selected = Vec::new();
    journal.for_each_recovery(|decision| {
        visited.push((decision.commit_sequence, decision.storage_projected, decision.audit_projected));
        assert!(matches!(decision.target, TransactionTarget::Collection { name } if name == "docs"));
        Ok(!decision.storage_projected)
    }, |transaction| {
        selected.push(transaction.prepare.transaction_id);
        journal.mark_projected(transaction.prepare.transaction_id, ProjectionKind::Storage)
    }).unwrap();
    assert_eq!(visited.len(), 515);
    assert!(visited.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert_eq!(selected, [storage.prepare.transaction_id]);
    selected.clear();
    journal
        .for_each_recovery(
            |decision| Ok(!decision.audit_projected),
            |transaction| {
                selected.push(transaction.prepare.transaction_id);
                journal.mark_projected(transaction.prepare.transaction_id, ProjectionKind::Audit)
            },
        )
        .unwrap();
    assert_eq!(
        selected,
        [storage.prepare.transaction_id, audit.prepare.transaction_id]
    );
    assert_eq!(journal.completed_commit_frontier().unwrap(), Some(515));
    drop(journal);
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let mut count = 0;
    journal
        .for_each_recovery(
            |_| {
                count += 1;
                Ok(false)
            },
            |_| unreachable!(),
        )
        .unwrap();
    assert_eq!(count, 515);
}

#[test]
fn legacy_descriptors_validate_original_prepare_and_never_silently_skip_missing_history() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let transaction = delete(&journal, "one");
    complete(&journal, &transaction);
    let mut count = 0;
    journal
        .for_each_recovery(
            |_| {
                count += 1;
                Ok(false)
            },
            |_| unreachable!(),
        )
        .unwrap();
    assert_eq!(count, 1);
    // This is a low-level corruption fixture, not production prefix retirement.
    retire(&journal);
    assert!(matches!(
        journal.for_each_recovery(|_| Ok(false), |_| unreachable!()),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn malformed_or_future_descriptors_refuse_before_body_selection() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    authority::tests::activate(&journal);
    let transaction = delete(&journal, "one");
    {
        let mut inner = journal.inner.lock().unwrap();
        inner
            .state
            .prepares
            .get_mut(&transaction.prepare.transaction_id)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap()
            .version = VERSION + 1;
    }
    assert!(matches!(
        journal.for_each_recovery(
            |_| panic!("invalid descriptor reached selector"),
            |_| unreachable!()
        ),
        Err(GaussError::WalCorruption { .. })
    ));
    {
        let mut inner = journal.inner.lock().unwrap();
        let descriptor = inner
            .state
            .prepares
            .get_mut(&transaction.prepare.transaction_id)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap();
        descriptor.version = VERSION;
        descriptor.catalog = Some(CatalogChange::Drop {
            name: "foreign".into(),
        });
    }
    assert!(matches!(
        journal.for_each_recovery(
            |_| panic!("invalid target reached selector"),
            |_| unreachable!()
        ),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn selected_descriptor_must_match_original_target_and_catalog_action() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    authority::tests::activate(&journal);
    let transaction = commit(
        &journal,
        TransactionTarget::Catalog,
        WalEntry::DropCollection {
            name: "docs".into(),
        },
    );
    {
        let mut inner = journal.inner.lock().unwrap();
        inner
            .state
            .prepares
            .get_mut(&transaction.prepare.transaction_id)
            .unwrap()
            .recovery
            .as_mut()
            .unwrap()
            .catalog = Some(CatalogChange::Create {
            name: "docs".into(),
        });
    }
    assert!(matches!(
        journal.for_each_recovery(
            |_| panic!("changed pending routing reached selector"),
            |_| unreachable!()
        ),
        Err(GaussError::WalCorruption { .. })
    ));
    assert!(matches!(
        journal.for_each_recovery(|_| Ok(true), |_| panic!("changed routing reached repair")),
        Err(GaussError::WalCorruption { .. })
    ));
}

#[test]
fn descriptor_scan_cancellation_callback_error_and_admission_refusal_release_owners() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let transaction = delete(&journal, "one");
    complete(&journal, &transaction);
    authority::tests::activate(&journal);
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            journal.for_each_recovery(|_| Ok(false), |_| unreachable!()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), 0);
    });
    with_test_storage_pool(4 * 1024 * 1024, |used| {
        assert!(
            journal
                .for_each_recovery(
                    |_| Err(GaussError::InvalidRequest("stop".into())),
                    |_| unreachable!()
                )
                .is_err()
        );
        assert_eq!(used(), 0);
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert!(
            crate::relational::with_sql_cancellation(cancellation, || journal
                .for_each_recovery(|_| Ok(false), |_| unreachable!()))
            .is_err()
        );
        assert_eq!(used(), 0);
        journal
            .for_each_recovery(|_| Ok(false), |_| unreachable!())
            .unwrap();
        assert_eq!(used(), 0);
    });
}

#[cfg(feature = "fault-injection")]
#[test]
fn compact_history_scan_does_not_open_prepare_frames() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let transaction = delete(&journal, "one");
    complete(&journal, &transaction);
    authority::tests::activate(&journal);
    let marker = temp.path().join("marker");
    let release = temp.path().join("release");
    let _env = crate::failpoint::test_env(
        "error:transaction.scan.before_prepare_read",
        &marker,
        &release,
    );
    journal
        .for_each_recovery(|_| Ok(false), |_| unreachable!())
        .unwrap();
    assert!(
        journal
            .for_each_recovery(|_| Ok(true), |_| unreachable!())
            .is_err()
    );
    assert!(journal.for_each_committed(|_| unreachable!()).is_err());
}

#[test]
fn recovery_snapshot_excludes_new_commits_and_allows_projection_publication_from_selector() {
    let temp = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(temp.path()).unwrap();
    let first = delete(&journal, "one");
    complete(&journal, &first);
    authority::tests::activate(&journal);
    let pending = delete(&journal, "pending");
    let mut seen = Vec::new();
    let mut selected = Vec::new();
    journal
        .for_each_recovery(
            |decision| {
                if seen.is_empty() {
                    let later = delete(&journal, "later");
                    complete(&journal, &later);
                }
                seen.push(decision.transaction_id);
                Ok(!decision.storage_projected)
            },
            |transaction| {
                selected.push(transaction.prepare.transaction_id);
                complete(&journal, &transaction);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        seen,
        [first.prepare.transaction_id, pending.prepare.transaction_id]
    );
    assert_eq!(selected, [pending.prepare.transaction_id]);
    let mut count = 0;
    journal
        .for_each_recovery(
            |_| {
                count += 1;
                Ok(false)
            },
            |_| unreachable!(),
        )
        .unwrap();
    assert_eq!(count, 3);
}
