use super::*;
use crate::relational::wal_decode::with_test_storage_pool;

fn audit() -> TransactionAudit {
    TransactionAudit::mutation(
        "delete",
        Some("docs"),
        &AuditContext::embedded(),
        serde_json::Value::Null,
    )
}
fn target() -> TransactionTarget {
    TransactionTarget::Collection {
        name: "docs".into(),
    }
}
fn mutation() -> WalEntry {
    WalEntry::Delete { id: "one".into() }
}
fn project(journal: &TransactionJournal, id: TransactionId) {
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
}
fn capacities(state: &JournalState) -> [usize; 6] {
    [
        state.prepares.capacity(),
        state.commits.capacity(),
        state.projections.capacity(),
        state.unknown.capacity(),
        state.completed.capacity(),
        state.idempotency.capacity(),
    ]
}

#[test]
fn journal_root_refusal_precedes_format_marker_and_recovery_mutations() {
    let dir = tempfile::tempdir().unwrap();
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            TransactionJournal::open(dir.path()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(!dir.path().join(TRANSACTION_FORMAT_MARKER).exists());
        assert!(!dir.path().join(TRANSACTION_JOURNAL_DIR).exists());
        assert_eq!(used(), 0);
    });
}

#[test]
fn journal_root_refusal_preserves_existing_marker_wal_and_interrupted_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let committed = journal.commit(target(), mutation(), audit()).unwrap();
    project(&journal, committed.prepare.transaction_id);
    drop(committed);
    drop(journal);
    let wal = dir
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join("000000.gdwal");
    let bytes = std::fs::read(&wal).unwrap();
    let marker = dir.path().join(TRANSACTION_FORMAT_MARKER);
    let marker_bytes = std::fs::read(&marker).unwrap();
    let scratch = dir
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join(".chiron-decisions-interrupted");
    std::fs::create_dir(&scratch).unwrap();
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            TransactionJournal::open(dir.path()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(std::fs::read(&wal).unwrap(), bytes);
        assert_eq!(std::fs::read(&marker).unwrap(), marker_bytes);
        assert!(scratch.exists());
        assert_eq!(used(), 0);
    });
    let reopened = TransactionJournal::open(dir.path()).unwrap();
    assert!(!scratch.exists());
    assert_eq!(reopened.committed().unwrap().len(), 1);
}

#[test]
fn future_projection_flags_need_no_growth_even_when_pool_is_full() {
    let capacity = 4 * 1024 * 1024;
    with_test_storage_pool(capacity, |used| {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let transactions = (0..3)
            .map(|_| journal.commit(target(), mutation(), audit()).unwrap())
            .collect::<Vec<_>>();
        let before = capacities(&journal.inner.lock().unwrap().state);
        let mut pressure = MetadataCharge::default();
        pressure
            .prepare(capacity - used() - crate::relational::wal_decode::lease_root_bytes())
            .unwrap();
        for transaction in &transactions {
            project(&journal, transaction.prepare.transaction_id);
            assert_eq!(capacities(&journal.inner.lock().unwrap().state), before);
            assert_eq!(
                journal.status(transaction.prepare.transaction_id).state,
                TransactionState::Committed
            );
        }
        drop(pressure);
        drop(transactions);
        assert!(used() > 0, "allocated live map capacities remain admitted");
        journal
            .inner
            .lock()
            .unwrap()
            .state
            .flush_decisions(journal.dir())
            .unwrap();
        assert!(journal.inner.lock().unwrap().state.prepares.is_empty());
        assert!(
            used() > 0,
            "eviction retains allocated map and run metadata"
        );
        drop(journal);
        assert_eq!(used(), 0);
    });
}

#[test]
fn refused_metadata_growth_keeps_maps_and_wal_then_actual_commit_retries() {
    let capacity = 4 * 1024 * 1024;
    with_test_storage_pool(capacity, |used| {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let transactions = (0..3)
            .map(|_| journal.commit(target(), mutation(), audit()).unwrap())
            .collect::<Vec<_>>();
        let id = TransactionId::new();
        let candidate = TransactionPrepare {
            version: 1,
            transaction_id: id,
            commit_sequence: 4,
            target: target(),
            mutation: Box::new(mutation()),
            audit: audit(),
            idempotency: None,
        };
        let wal = dir
            .path()
            .join(TRANSACTION_JOURNAL_DIR)
            .join("000000.gdwal");
        let bytes = std::fs::read(&wal).unwrap();
        let before = capacities(&journal.inner.lock().unwrap().state);
        let mut pressure = MetadataCharge::default();
        pressure
            .prepare(capacity - used() - crate::relational::wal_decode::lease_root_bytes())
            .unwrap();
        assert!(matches!(
            journal
                .inner
                .lock()
                .unwrap()
                .state
                .reserve_prepare_metadata(&candidate),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(capacities(&journal.inner.lock().unwrap().state), before);
        assert_eq!(std::fs::read(&wal).unwrap(), bytes);
        assert_eq!(journal.status(id).state, TransactionState::Expired);
        drop(pressure);
        let transaction = journal
            .commit_inner(target(), mutation(), audit(), None, Some(id), None)
            .unwrap();
        assert_eq!(transaction.prepare.transaction_id, id);
        project(&journal, id);
        for t in &transactions {
            project(&journal, t.prepare.transaction_id);
        }
        drop(transaction);
        drop(transactions);
        drop(journal);
        assert_eq!(used(), 0);
        let reopened = TransactionJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.status(id).state, TransactionState::Committed);
        drop(reopened);
        assert_eq!(used(), 0);
    });
}

#[test]
fn disk_lookup_metadata_keeps_its_lease_after_journal_and_runs_drop() {
    with_test_storage_pool(4 * 1024 * 1024, |used| {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let transaction = journal.commit(target(), mutation(), audit()).unwrap();
        let id = transaction.prepare.transaction_id;
        project(&journal, id);
        drop(transaction);
        let value = {
            let mut inner = journal.inner.lock().unwrap();
            inner.state.flush_decisions(journal.dir()).unwrap();
            let mut key = [0; 17];
            key[0] = 1;
            key[1..].copy_from_slice(id.0.as_bytes());
            inner
                .state
                .decisions
                .as_ref()
                .unwrap()
                .get_owned::<serde_json::Value>(&key)
                .unwrap()
                .unwrap()
        };
        drop(journal);
        assert!(used() > 0);
        assert_eq!(value["prepare"]["principal_id"], "embedded-system");
        assert_eq!(value["committed"], true);
        drop(value);
        assert_eq!(used(), 0);
    });
}

#[test]
fn duplicate_claim_refusal_and_cancellation_release_payloads_and_preserve_retry() {
    let capacity = 256 * 1024;
    with_test_storage_pool(capacity, |used| {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let context = AuditContext::embedded();
        let before = used();
        let mut pressure = MetadataCharge::default();
        pressure
            .prepare(capacity - used() - crate::relational::wal_decode::lease_root_bytes())
            .unwrap();
        assert!(matches!(
            journal.begin_idempotent("one", &context, "delete", &1, || Ok(())),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(
            journal
                .inner
                .lock()
                .unwrap()
                .inflight_idempotency
                .is_empty()
        );
        drop(pressure);
        assert_eq!(used(), before);
        let IdempotencyAdmission::Execute(guard) = journal
            .begin_idempotent("one", &context, "delete", &1, || Ok(()))
            .unwrap()
        else {
            panic!()
        };
        assert!(used() > before);
        assert!(
            journal
                .begin_idempotent("one", &context, "delete", &1, || Err(
                    GaussError::InvalidRequest("cancelled".into())
                ))
                .is_err()
        );
        drop(guard);
        assert!(
            journal
                .inner
                .lock()
                .unwrap()
                .inflight_idempotency
                .is_empty()
        );
        let IdempotencyAdmission::Execute(guard) = journal
            .begin_idempotent("one", &context, "delete", &1, || Ok(()))
            .unwrap()
        else {
            panic!()
        };
        let transaction = guard
            .commit(target(), mutation(), audit(), serde_json::Value::Null)
            .unwrap();
        drop(guard);
        project(&journal, transaction.prepare.transaction_id);
        drop(transaction);
        drop(journal);
        assert_eq!(used(), 0);
    });
}

#[test]
fn evicted_decisions_and_claims_retain_admission_for_allocated_tables() {
    let capacity = 16 * 1024 * 1024;
    with_test_storage_pool(capacity, |used| {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let transactions = (0..64)
            .map(|_| journal.commit(target(), mutation(), audit()).unwrap())
            .collect::<Vec<_>>();
        let allocated = journal.inner.lock().unwrap().state.metadata_capacities;
        for transaction in &transactions[..63] {
            project(&journal, transaction.prepare.transaction_id);
        }
        journal
            .inner
            .lock()
            .unwrap()
            .state
            .flush_decisions(journal.dir())
            .unwrap();
        let minimum_slots = allocated[0] * size_of::<(TransactionId, PreparedRef)>()
            + allocated[1] * size_of::<TransactionId>()
            + allocated[2] * size_of::<(TransactionId, ProjectionKind)>()
            + allocated[3] * size_of::<TransactionId>()
            + allocated[4] * size_of::<TransactionId>();
        assert!(used() >= minimum_slots as u64);
        assert_eq!(
            journal.inner.lock().unwrap().state.metadata_capacities,
            allocated
        );
        let mut pressure = MetadataCharge::default();
        pressure
            .prepare(capacity - used() - crate::relational::wal_decode::lease_root_bytes())
            .unwrap();
        project(&journal, transactions[63].prepare.transaction_id);
        assert!(
            capacities(&journal.inner.lock().unwrap().state)
                .into_iter()
                .zip(allocated)
                .all(|(reported, owned)| reported <= owned)
        );
        drop(pressure);
        drop(transactions);
        journal
            .inner
            .lock()
            .unwrap()
            .state
            .flush_decisions(journal.dir())
            .unwrap();
        let context = AuditContext::embedded();
        let claim_count = crate::resource_profile::current()
            .query_workers
            .saturating_mul(2)
            .clamp(2, 128)
            .min(64);
        let guards = (0..claim_count)
            .map(|n| {
                let IdempotencyAdmission::Execute(guard) = journal
                    .begin_idempotent(&format!("claim-{n}"), &context, "delete", &n, || Ok(()))
                    .unwrap()
                else {
                    panic!()
                };
                guard
            })
            .collect::<Vec<_>>();
        let claim_capacity = journal
            .inner
            .lock()
            .unwrap()
            .inflight_idempotency
            .capacity();
        drop(guards);
        let inner = journal.inner.lock().unwrap();
        assert!(inner.inflight_idempotency.is_empty());
        assert_eq!(inner.claim_capacity, claim_capacity);
        assert!(
            used()
                >= (minimum_slots
                    + claim_capacity * size_of::<(idempotency::ScopedKey, [u8; 32])>())
                    as u64
        );
        drop(inner);
        drop(journal);
        assert_eq!(used(), 0);
    });
}

#[test]
fn native_decision_marker_stays_clear_on_preflight_refusal_then_tracks_commit() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let wal = dir
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join("000000.gdwal");
    let before = std::fs::read(&wal).unwrap();
    let started = AtomicBool::new(false);
    with_test_storage_pool(1, |used| {
        assert!(matches!(
            journal.commit_with_decision(target(), mutation(), audit(), &started),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(!started.load(Ordering::Acquire));
        assert_eq!(used(), 0);
    });
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    let committed = journal
        .commit_with_decision(target(), mutation(), audit(), &started)
        .unwrap();
    assert!(started.load(Ordering::Acquire));
    assert_eq!(
        journal.status(committed.prepare.transaction_id).state,
        TransactionState::Committed
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn native_decision_marker_distinguishes_before_prepare_from_ambiguous_prepare() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for (fault, expected) in [
        ("transaction.before_prepare", false),
        ("transaction.after_prepare", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let wal = dir
            .path()
            .join(TRANSACTION_JOURNAL_DIR)
            .join("000000.gdwal");
        let before = std::fs::read(&wal).unwrap();
        let started = AtomicBool::new(false);
        let env = crate::failpoint::test_env(&format!("error:{fault}"), dir.path(), dir.path());
        assert!(
            journal
                .commit_with_decision(target(), mutation(), audit(), &started)
                .is_err()
        );
        assert_eq!(started.load(Ordering::Acquire), expected);
        drop(env);
        assert_eq!(std::fs::read(&wal).unwrap() == before, !expected);
        if !expected {
            journal
                .commit_with_decision(target(), mutation(), audit(), &started)
                .unwrap();
            assert!(started.load(Ordering::Acquire));
        }
    }
}

#[test]
fn idempotent_decision_marker_preserves_key_on_preflight_refusal_and_retries() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let context = AuditContext::embedded();
    let begin = || {
        journal
            .begin_idempotent("bounded-receipt", &context, "delete", &1_u64, || Ok(()))
            .unwrap()
    };
    let crate::transaction_journal::IdempotencyAdmission::Execute(claim) = begin() else {
        panic!("new claim")
    };
    let wal = dir
        .path()
        .join(TRANSACTION_JOURNAL_DIR)
        .join("000000.gdwal");
    let before = std::fs::read(&wal).unwrap();
    let started = AtomicBool::new(false);
    for capacity in [1, 4096, 16384, 32768] {
        let response = serde_json::json!({"allocated_ids":["one"],"body":"x".repeat(128*1024)});
        with_test_storage_pool(capacity, |used| {
            assert!(matches!(
                claim.commit_with_decision(target(), mutation(), audit(), response, &started),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(!started.load(Ordering::Acquire));
            assert_eq!(used(), 0);
        });
        assert_eq!(std::fs::read(&wal).unwrap(), before);
    }
    let committed = claim
        .commit_with_decision(
            target(),
            mutation(),
            audit(),
            serde_json::json!({"allocated_ids":["one"]}),
            &started,
        )
        .unwrap();
    assert!(started.load(Ordering::Acquire));
    let id = committed.prepare.transaction_id;
    project(&journal, id);
    drop(committed);
    drop(claim);
    let crate::transaction_journal::IdempotencyAdmission::Replay(replay) = begin() else {
        panic!("one consumed decision")
    };
    assert_eq!(replay.status.transaction_id, id);
    assert_eq!(replay.status.state, TransactionState::Committed);
    assert_eq!(
        replay.response.unwrap(),
        serde_json::json!({"allocated_ids":["one"]})
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn idempotent_decision_marker_tracks_prepare_consumption_and_unknown_recovery() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for fault in [
        "transaction.before_prepare",
        "transaction.after_prepare",
        "transaction.before_commit",
        "transaction.before_commit_fsync",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let context = AuditContext::embedded();
        let begin = || {
            journal
                .begin_idempotent("phase-receipt", &context, "delete", &1_u64, || Ok(()))
                .unwrap()
        };
        let crate::transaction_journal::IdempotencyAdmission::Execute(claim) = begin() else {
            panic!("new claim")
        };
        let started = AtomicBool::new(false);
        let before = std::fs::read(
            dir.path()
                .join(TRANSACTION_JOURNAL_DIR)
                .join("000000.gdwal"),
        )
        .unwrap();
        let result = {
            let _fault =
                crate::failpoint::test_env(&format!("error:{fault}"), dir.path(), dir.path());
            claim.commit_with_decision(
                target(),
                mutation(),
                audit(),
                serde_json::json!({"allocated_ids":["one"]}),
                &started,
            )
        };
        let prepared = fault != "transaction.before_prepare";
        assert_eq!(started.load(Ordering::Acquire), prepared);
        let unknown = fault == "transaction.before_commit_fsync";
        if unknown {
            assert!(matches!(
                result,
                Err(GaussError::CommitOutcomeUnknown { .. })
            ));
        } else {
            assert!(matches!(result, Err(GaussError::Io(_))));
        }
        let expected = if !prepared {
            assert_eq!(
                std::fs::read(
                    dir.path()
                        .join(TRANSACTION_JOURNAL_DIR)
                        .join("000000.gdwal")
                )
                .unwrap(),
                before
            );
            let committed = claim
                .commit_with_decision(
                    target(),
                    mutation(),
                    audit(),
                    serde_json::json!({"allocated_ids":["one"]}),
                    &started,
                )
                .unwrap();
            assert!(started.load(Ordering::Acquire));
            project(&journal, committed.prepare.transaction_id);
            TransactionState::Committed
        } else if unknown {
            TransactionState::OutcomeUnknown
        } else {
            TransactionState::Rejected
        };
        drop(claim);
        let crate::transaction_journal::IdempotencyAdmission::Replay(replay) = begin() else {
            panic!("consumed key must not execute twice")
        };
        assert_eq!(replay.status.state, expected);
        assert_eq!(
            replay.response.is_some(),
            expected == TransactionState::Committed
        );
        let id = replay.status.transaction_id;
        drop(replay);
        drop(journal);
        let reopened = TransactionJournal::open(dir.path()).unwrap();
        let crate::transaction_journal::IdempotencyAdmission::Replay(replay) = reopened
            .begin_idempotent("phase-receipt", &context, "delete", &1_u64, || Ok(()))
            .unwrap()
        else {
            panic!("reopen must retain consumed key")
        };
        assert_eq!(replay.status.transaction_id, id);
        assert_eq!(
            replay.status.state,
            if unknown {
                TransactionState::Committed
            } else {
                expected
            }
        );
    }
}
