use super::*;
use crate::relational::wal_decode::with_test_storage_pool;

fn audit() -> TransactionAudit {
    TransactionAudit::mutation(
        "delete",
        Some("docs"),
        &AuditContext::embedded(),
        Value::Null,
    )
}
fn transaction(journal: &TransactionJournal) -> CommittedTransaction {
    let t = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::Delete { id: "one".into() },
            audit(),
        )
        .unwrap();
    journal
        .mark_projected(t.prepare.transaction_id, ProjectionKind::Storage)
        .unwrap();
    journal
        .mark_projected(t.prepare.transaction_id, ProjectionKind::Audit)
        .unwrap();
    t
}

#[test]
fn retained_scan_and_consuming_iterator_keep_container_admission() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    for _ in 0..9 {
        drop(transaction(&journal));
    }
    with_test_storage_pool(4 * 1024 * 1024, |used| {
        let scan = journal.committed().unwrap();
        assert_eq!(scan.len(), 9);
        let owned = used();
        let mut iter = scan.into_iter();
        assert_eq!(used(), owned);
        let first = iter.next().unwrap();
        let last = iter.next_back().unwrap();
        assert!(first.prepare.commit_sequence < last.prepare.commit_sequence);
        drop(first);
        drop(last);
        assert_eq!(iter.len(), 7);
        drop(journal);
        assert!(used() > 0);
        let retained = iter.next().unwrap();
        drop(iter);
        assert!(used() > 0 && used() < owned);
        drop(retained);
        assert_eq!(used(), 0);
    });
}

#[test]
fn scan_growth_refusal_preserves_existing_items_and_durable_journal() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let t = transaction(&journal);
    let wal = dir
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join("000000.gdwal");
    let before = std::fs::read(&wal).unwrap();
    with_test_storage_pool(1, |used| {
        let mut scan = CommittedTransactions::default();
        assert_eq!(used(), 0);
        assert!(matches!(
            scan.push(t),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(scan.is_empty());
        assert_eq!(used(), 0);
    });
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    let scan = journal.committed().unwrap();
    assert_eq!(scan.len(), 1);
}

#[test]
fn streaming_callback_error_releases_each_record_without_retained_scan() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    for _ in 0..5 {
        drop(transaction(&journal));
    }
    with_test_storage_pool(4 * 1024 * 1024, |used| {
        let mut visited = 0;
        let result = journal.for_each_committed(|_t| {
            visited += 1;
            assert!(used() > 0);
            if visited == 3 {
                return Err(GaussError::InvalidRequest("stop".into()));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(visited, 3);
        assert_eq!(used(), 0);
        let mut order = 0;
        journal
            .for_each_committed(|t| {
                assert!(t.prepare.commit_sequence > order);
                order = t.prepare.commit_sequence;
                Ok(())
            })
            .unwrap();
        assert_eq!(order, 5);
        assert_eq!(used(), 0);
    });
}

#[test]
fn pinned_commit_snapshot_excludes_new_writes_and_survives_publication_from_callback() {
    let parent = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    let mut oracle = Vec::new();
    for _ in 0..513 {
        oracle.push(transaction(&journal).prepare.transaction_id);
    }
    // Install the recovered generation so the visitor holds real checkpoint
    // pins as later writes merge its inputs and publish another generation.
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    let current = journal.dir().join(".chiron-decision-checkpoint/CURRENT");
    let bytes = std::fs::read(&current).unwrap();
    let manifest: Value = serde_json::from_slice(
        crate::security::storage::decode_metadata(b"CHIRDEC1", &bytes).unwrap(),
    )
    .unwrap();
    let old = journal
        .dir()
        .join(".chiron-decision-checkpoint")
        .join(manifest["generation"].as_str().unwrap());
    let mut seen = Vec::new();
    journal
        .for_each_committed(|t| {
            if seen.is_empty() {
                for _ in 0..512 {
                    drop(transaction(&journal));
                }
                let mut inner = journal.inner.lock().unwrap();
                let end = inner.wal.len().unwrap();
                super::super::checkpoint::publish(journal.dir(), &mut inner.state, end).unwrap();
                assert!(
                    old.exists(),
                    "active decision snapshot pins the old generation"
                );
            }
            seen.push(t.prepare.transaction_id);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, oracle);
    assert!(!old.exists());
    assert_eq!(journal.committed().unwrap().len(), 1025);
}

#[test]
fn missing_or_changed_ordered_decisions_refuse_a_complete_scan() {
    for corrupt_binding in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(parent.path()).unwrap();
        let t = transaction(&journal);
        {
            let mut inner = journal.inner.lock().unwrap();
            inner.state.flush_decisions(journal.dir()).unwrap();
            let mut wrong = crate::relational::disk_map::DiskMap::new(journal.dir()).unwrap();
            if corrupt_binding {
                wrong
                    .insert_batch(|batch| {
                        batch.insert(
                            &decisions::ordered_key(1),
                            &decisions::CommittedRef {
                                transaction_id: t.prepare.transaction_id,
                                lsn: 0,
                                commit_sequence: 2,
                            },
                        )
                    })
                    .unwrap();
            }
            inner.state.decisions = Some(wrong);
        }
        assert!(matches!(
            journal.for_each_committed(|_| Ok(())),
            Err(GaussError::WalCorruption { .. })
        ));
    }
}
