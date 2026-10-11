use super::*;

fn context() -> AuditContext {
    AuditContext {
        principal_id: "alice".into(),
        tenant_id: Some("acme".into()),
        transport: "test".into(),
        request_id: None,
    }
}

fn execute(journal: &Arc<TransactionJournal>, index: u64) -> CommittedTransaction {
    let context = context();
    let IdempotencyAdmission::Execute(guard) = journal
        .begin_idempotent(&format!("key-{index}"), &context, "delete", &index, || {
            Ok(())
        })
        .unwrap()
    else {
        panic!("request executed twice")
    };
    guard
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::DeleteBatch {
                ids: vec![format!("row-{index}")],
            },
            TransactionAudit::mutation("delete", Some("docs"), &context, Value::Null),
            serde_json::json!({"deleted": index}),
        )
        .unwrap()
}

fn complete(journal: &TransactionJournal, transaction: &CommittedTransaction) {
    let id = transaction.prepare.transaction_id;
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
}

#[test]
fn historical_decisions_leave_live_maps_and_replay_across_reopen_and_repair() {
    let parent = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    let pending = execute(&journal, 0);
    let mut ids = vec![pending.prepare.transaction_id];
    for index in 1..=(3 * DECISION_BATCH + 17) as u64 {
        let transaction = execute(&journal, index);
        ids.push(transaction.prepare.transaction_id);
        complete(&journal, &transaction);
        let inner = journal.inner.lock().unwrap();
        assert!(inner.state.prepares.len() <= DECISION_BATCH + 1);
        assert!(inner.state.idempotency.len() <= DECISION_BATCH + 1);
        assert!(inner.state.commits.len() <= DECISION_BATCH + 1);
        assert!(inner.state.projections.len() <= DECISION_BATCH * 2);
    }
    let frontier = ids.len() as u64;
    assert_eq!(journal.completed_commit_frontier().unwrap(), None);
    for index in [1_u64, 512, 513, 1024, 1536, frontier - 1] {
        let id = ids[index as usize];
        let status = journal.status(id);
        assert_eq!(status.state, TransactionState::Committed);
        assert_eq!(status.commit_sequence, Some(index + 1));
        assert!(status.storage_projected && status.audit_projected);
        assert!(
            journal
                .status_for_owner(id, "bob", "acme")
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .status_for_owner(id, "alice", "other")
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .status_for_owner(id, "alice", "acme")
                .unwrap()
                .is_some()
        );
        let IdempotencyAdmission::Replay(receipt) = journal
            .begin_idempotent(
                &format!("key-{index}"),
                &context(),
                "delete",
                &index,
                || Ok(()),
            )
            .unwrap()
        else {
            panic!("evicted key executed again")
        };
        assert_eq!(receipt.status.transaction_id, id);
        assert_eq!(receipt.response.unwrap()["deleted"], index);
        assert!(
            journal
                .begin_idempotent(
                    &format!("key-{index}"),
                    &context(),
                    "delete",
                    &(index + 1),
                    || Ok(())
                )
                .is_err()
        );
        // Marking an already completed disk decision is idempotent.
        journal.mark_projected(id, ProjectionKind::Audit).unwrap();
    }
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    {
        let inner = journal.inner.lock().unwrap();
        assert_eq!(inner.state.prepares.len(), 1);
        assert_eq!(inner.state.idempotency.len(), 1);
        assert_eq!(inner.state.commits.len(), 1);
        assert!(inner.state.projections.is_empty());
        assert_eq!(inner.state.committed_count, ids.len());
        assert_eq!(inner.state.pending_storage, 1);
        assert_eq!(inner.state.pending_audit, 1);
    }
    let mut seen = Vec::new();
    journal
        .for_each_committed(|transaction| {
            seen.push(transaction.prepare.transaction_id);
            if transaction.prepare.transaction_id == pending.prepare.transaction_id {
                assert!(!transaction.storage_projected && !transaction.audit_projected);
                complete(&journal, &transaction);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, ids);
    assert_eq!(journal.completed_commit_frontier().unwrap(), Some(frontier));
    let IdempotencyAdmission::Replay(receipt) = journal
        .begin_idempotent("key-1", &context(), "delete", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!("recovered key executed again")
    };
    assert_eq!(receipt.status.transaction_id, ids[1]);
    assert_eq!(receipt.response.unwrap()["deleted"], 1);
    let next = execute(&journal, frontier);
    assert_eq!(next.prepare.commit_sequence, frontier + 1);
    complete(&journal, &next);
    drop(journal);
    assert!(
        !std::fs::read_dir(parent.path().join(TRANSACTION_JOURNAL_DIR))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".chiron-decisions-"))
    );
}

#[test]
fn recovered_completed_decision_cannot_accept_another_commit_or_projection() {
    for duplicate_commit in [true, false] {
        let parent = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(parent.path()).unwrap();
        let transaction = execute(&journal, 1);
        complete(&journal, &transaction);
        for index in 2..=DECISION_BATCH as u64 {
            let transaction = execute(&journal, index);
            complete(&journal, &transaction);
        }
        drop(journal);
        let journal = TransactionJournal::open(parent.path()).unwrap();
        assert!(journal.inner.lock().unwrap().state.prepares.is_empty());
        drop(journal);
        let mut wal =
            Wal::open_control_journal(&parent.path().join(TRANSACTION_JOURNAL_DIR)).unwrap();
        let id = transaction.prepare.transaction_id;
        let entry = if duplicate_commit {
            WalEntry::TransactionCommit {
                commit: TransactionCommit {
                    version: IDEMPOTENT_JOURNAL_VERSION,
                    transaction_id: id,
                    commit_sequence: transaction.prepare.commit_sequence,
                },
            }
        } else {
            WalEntry::TransactionProjection {
                projection: TransactionProjection {
                    version: IDEMPOTENT_JOURNAL_VERSION,
                    transaction_id: id,
                    kind: ProjectionKind::Audit,
                },
            }
        };
        wal.append(&entry).unwrap();
        drop(wal);
        assert!(matches!(
            TransactionJournal::open(parent.path()),
            Err(GaussError::WalCorruption { .. })
        ));
    }
}

#[test]
fn poisoned_wal_retries_do_not_accumulate_more_prepare_refs_or_consumed_keys() {
    let parent = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    journal.inject_write_failure();
    let fail = |index: u64| {
        let IdempotencyAdmission::Execute(guard) = journal
            .begin_idempotent(
                &format!("key-{index}"),
                &context(),
                "delete",
                &index,
                || Ok(()),
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(
            guard
                .commit(
                    TransactionTarget::Collection {
                        name: "docs".into()
                    },
                    WalEntry::DeleteBatch {
                        ids: vec![format!("row-{index}")]
                    },
                    TransactionAudit::mutation("delete", Some("docs"), &context(), Value::Null),
                    Value::Null
                )
                .is_err()
        );
    };
    fail(0);
    let initial_count = journal.inner.lock().unwrap().state.prepares.len();
    assert_eq!(initial_count, 1);
    for index in 1..=1024 {
        fail(index)
    }
    let inner = journal.inner.lock().unwrap();
    assert_eq!(inner.state.prepares.len(), initial_count);
    assert_eq!(inner.state.idempotency.len(), initial_count);
    assert!(inner.inflight_idempotency.is_empty());
    assert_eq!(inner.state.next_sequence, 1);
}

#[test]
fn stale_or_corrupt_derived_files_cannot_change_the_durable_decision() {
    use std::io::{Seek, SeekFrom, Write};
    let parent = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    let transaction = execute(&journal, 1);
    complete(&journal, &transaction);
    drop(journal);
    let journal = TransactionJournal::open(parent.path()).unwrap();
    // Recovered history is on disk even below the live batch threshold.
    let directory = std::fs::read_dir(journal.dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| crate::relational::disk_map::DiskMap::is_journal_scratch(path))
        .unwrap();
    let child = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let file = std::fs::read_dir(child)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    // Target the consumed-key record, independently of other namespaces
    // (such as the commit-order index) sorting after it in this run.
    let payload = {
        let inner = journal.inner.lock().unwrap();
        let reference = inner
            .state
            .prepare(transaction.prepare.transaction_id)
            .unwrap()
            .unwrap();
        serde_json::to_vec(&ConsumedKeyView {
            key: reference.idempotency_key.as_ref().unwrap(),
            transaction_id: transaction.prepare.transaction_id,
        })
        .unwrap()
    };
    let bytes = std::fs::read(&file).unwrap();
    let position = bytes
        .windows(payload.len())
        .position(|part| part == payload)
        .unwrap();
    let mut output = std::fs::OpenOptions::new().write(true).open(file).unwrap();
    output
        .seek(SeekFrom::Start((position + payload.len() - 1) as u64))
        .unwrap();
    output.write_all(b"!").unwrap();
    output.sync_all().unwrap();
    assert!(
        journal
            .begin_idempotent("key-1", &context(), "delete", &1_u64, || Ok(()))
            .is_err()
    );
    drop(journal);
    // Simulate leftover files from an interrupted writer. They are discarded,
    // rather than accepted as a checkpoint or used to suppress a committed key.
    let orphan = parent
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join(".chiron-decisions-orphan");
    std::fs::create_dir(&orphan).unwrap();
    std::fs::write(orphan.join("index.rseg"), b"incomplete").unwrap();
    let reopened = TransactionJournal::open(parent.path()).unwrap();
    assert!(!orphan.exists());
    let IdempotencyAdmission::Replay(receipt) = reopened
        .begin_idempotent("key-1", &context(), "delete", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!("corrupt index released a committed key")
    };
    assert_eq!(
        receipt.status.transaction_id,
        transaction.prepare.transaction_id
    );
    assert_eq!(receipt.response.unwrap()["deleted"], 1);
}

#[test]
#[cfg(feature = "fault-injection")]
fn failed_index_publication_rejects_the_next_mutation_without_consuming_its_key() {
    let parent = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(parent.path()).unwrap();
    for index in 1..=DECISION_BATCH as u64 {
        let transaction = execute(&journal, index);
        complete(&journal, &transaction);
    }
    let before = journal.inner.lock().unwrap().wal.len().unwrap();
    let IdempotencyAdmission::Execute(guard) = journal
        .begin_idempotent("next", &context(), "delete", &0_u64, || Ok(()))
        .unwrap()
    else {
        panic!()
    };
    {
        let _fault = crate::failpoint::test_env(
            "error:transaction_decisions.before_publish",
            parent.path(),
            parent.path(),
        );
        assert!(
            guard
                .commit(
                    TransactionTarget::Collection {
                        name: "docs".into()
                    },
                    WalEntry::DeleteBatch {
                        ids: vec!["next".into()]
                    },
                    TransactionAudit::mutation("delete", Some("docs"), &context(), Value::Null),
                    Value::Null
                )
                .is_err()
        );
    }
    drop(guard);
    let inner = journal.inner.lock().unwrap();
    assert_eq!(inner.wal.len().unwrap(), before);
    assert_eq!(inner.state.prepares.len(), DECISION_BATCH);
    assert_eq!(inner.state.idempotency.len(), DECISION_BATCH);
    drop(inner);
    let next = execute(&journal, DECISION_BATCH as u64 + 1);
    assert_eq!(next.prepare.commit_sequence, DECISION_BATCH as u64 + 1);
    assert_eq!(journal.inner.lock().unwrap().state.prepares.len(), 1);
    assert!(matches!(
        journal.begin_idempotent("next", &context(), "delete", &0_u64, || Ok(())),
        Ok(IdempotencyAdmission::Execute(_))
    ));
}

#[test]
fn borrowed_decision_and_consumed_key_keep_exact_existing_bytes_and_digest() {
    let key: idempotency::ScopedKey = serde_json::from_value(serde_json::json!({
        "installation_id": uuid::Uuid::new_v4(), "principal_id":"雪", "tenant_id":"acme", "digest":vec![7;32]
    })).unwrap();
    let id = TransactionId::new();
    let view = ConsumedKeyView {
        key: &key,
        transaction_id: id,
    };
    let bytes = serde_json::to_vec(&view).unwrap();
    let ordinary: ConsumedKey = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&ordinary).unwrap());
    let hashed = consumed_key(&key).unwrap();
    assert_eq!(hashed[0], 2);
    assert_eq!(
        hashed[1..],
        Sha256::digest(serde_json::to_vec(&key).unwrap())[..]
    );
    let reference = PreparedRef {
        lsn: 17,
        commit_sequence: 23,
        principal_id: "雪".into(),
        tenant_id: Some("acme".into()),
        idempotency: None,
        idempotency_key: Some(key),
        relational_proof: None,
        storage_proof_version: None,
        recovery: None,
        audit_proof: None,
        hot: None,
    };
    let bytes = serde_json::to_vec(&DecisionView {
        prepare: &reference,
        committed: true,
    })
    .unwrap();
    let ordinary: Decision = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&ordinary).unwrap());
}
