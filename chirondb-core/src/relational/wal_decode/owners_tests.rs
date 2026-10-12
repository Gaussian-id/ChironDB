use super::*;
use crate::transaction_journal::{IdempotencyAdmission, TransactionState};

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
fn small() -> WalEntry {
    WalEntry::Delete { id: "one".into() }
}
fn large() -> WalEntry {
    WalEntry::DeleteBatch {
        ids: (0..20_000).map(|id| id.to_string()).collect(),
    }
}
fn claim(journal: &Arc<TransactionJournal>) -> crate::transaction_journal::IdempotencyGuard {
    match journal
        .begin_idempotent(
            "owned-receipt",
            &AuditContext::embedded(),
            "delete",
            &17,
            || Ok(()),
        )
        .unwrap()
    {
        IdempotencyAdmission::Execute(guard) => guard,
        _ => panic!("unexpected replay"),
    }
}
fn replay(journal: &Arc<TransactionJournal>) -> crate::transaction_journal::IdempotencyReceipt {
    match journal
        .begin_idempotent(
            "owned-receipt",
            &AuditContext::embedded(),
            "delete",
            &17,
            || Ok(()),
        )
        .unwrap()
    {
        IdempotencyAdmission::Replay(receipt) => receipt,
        _ => panic!("lost consumed key"),
    }
}
fn project(journal: &TransactionJournal, id: TransactionId) {
    journal.mark_projected(id, ProjectionKind::Storage).unwrap();
    journal.mark_projected(id, ProjectionKind::Audit).unwrap();
}

#[test]
fn committed_clone_shares_admission_until_every_prepare_owner_dies() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let transaction = journal.commit(target(), small(), audit()).unwrap();
        let bytes = pool.used();
        assert!(bytes > 0);
        let second = transaction.clone();
        assert!(std::ptr::eq(&*transaction.prepare, &*second.prepare));
        assert_eq!(pool.used(), bytes, "Clone must share the admitted DTO");
        project(&journal, transaction.prepare.transaction_id);
        drop(journal);
        drop(transaction);
        assert_eq!(pool.used(), bytes);
        drop(second);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn expanded_prepare_refuses_before_wal_or_key_consumption_and_retries_same_identity() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let guard = claim(&journal);
    let reserved = TransactionId::new();
    let before = std::fs::read(journal.dir().join("000000.gdwal")).unwrap();
    let mutation = large();
    memory::with_storage_pool(1024 * 1024, |pool| {
        let error = guard
            .commit_with_id(
                reserved,
                target(),
                mutation,
                audit(),
                serde_json::json!({"affected":20_000}),
            )
            .unwrap_err();
        assert!(matches!(error, GaussError::ResourceExhausted(_)), "{error}");
        assert_eq!(pool.used(), 0);
        assert_eq!(journal.status(reserved).state, TransactionState::Expired);
    });
    assert_eq!(
        std::fs::read(journal.dir().join("000000.gdwal")).unwrap(),
        before
    );
    drop(guard);
    let guard = claim(&journal);
    let mutation = large();
    memory::with_storage_pool(32 * 1024 * 1024, |pool| {
        let transaction = guard
            .commit_with_id(
                reserved,
                target(),
                mutation,
                audit(),
                serde_json::json!({"affected":20_000}),
            )
            .unwrap();
        assert_eq!(transaction.prepare.transaction_id, reserved);
        project(&journal, reserved);
        drop(transaction);
        assert_eq!(pool.used(), 0);
    });
    drop(guard);
    drop(journal);
    memory::with_storage_pool(32 * 1024 * 1024, |pool| {
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let receipt = replay(&journal);
        assert_eq!(receipt.status.transaction_id, reserved);
        assert_eq!(receipt.response.as_ref().unwrap()["affected"], 20_000);
        assert!(
            matches!(receipt.mutation.as_deref(), Some(WalEntry::DeleteBatch { ids }) if ids.len()==20_000)
        );
        drop(receipt);
        drop(journal);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn hot_and_cold_receipt_keep_decoded_mutation_reserved_after_loader_returns() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    let guard = claim(&journal);
    let transaction = guard
        .commit(
            target(),
            small(),
            audit(),
            serde_json::json!({"affected":1,"ids":["one"]}),
        )
        .unwrap();
    let id = transaction.prepare.transaction_id;
    drop(guard);
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let receipt = replay(&journal);
        assert!(
            pool.used() > 0,
            "hot replay must preadmit its independent DTO copy"
        );
        assert_eq!(receipt.status.transaction_id, id);
        drop(receipt);
        assert_eq!(pool.used(), 0);
    });
    project(&journal, id);
    drop(transaction);
    drop(journal);
    let journal = TransactionJournal::open(dir.path()).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        let receipt = replay(&journal);
        let bytes = pool.used();
        assert!(bytes > 0);
        drop(journal);
        assert_eq!(
            pool.used(),
            bytes,
            "receipt must own decoded state after journal drop"
        );
        assert_eq!(receipt.response.as_ref().unwrap()["ids"][0], "one");
        drop(receipt);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn committed_scan_transfers_owned_prepares_without_losing_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(dir.path()).unwrap();
    for _ in 0..3 {
        let t = journal.commit(target(), small(), audit()).unwrap();
        project(&journal, t.prepare.transaction_id);
    }
    memory::with_storage_pool(4 * 1024 * 1024, |pool| {
        let transactions = journal.committed().unwrap();
        assert_eq!(transactions.len(), 3);
        let bytes = pool.used();
        assert!(bytes > 0);
        let second = transactions[0].clone();
        assert_eq!(pool.used(), bytes);
        drop(journal);
        drop(transactions);
        assert!(pool.used() > 0 && pool.used() < bytes);
        drop(second);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn owned_record_read_and_scan_refuse_before_expansion_and_release_on_callback_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = Wal::open(dir.path()).unwrap();
    wal.append(&large()).unwrap();
    let before = std::fs::read(dir.path().join("000000.gdwal")).unwrap();
    memory::with_storage_pool(1024 * 1024, |pool| {
        assert!(matches!(
            Wal::read_at_owned(dir.path(), 0),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(matches!(
            Wal::scan_journal_from(dir.path(), 0, |_| panic!("quota visitor")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(
        std::fs::read(dir.path().join("000000.gdwal")).unwrap(),
        before
    );
    memory::with_storage_pool(32 * 1024 * 1024, |pool| {
        let record = Wal::read_at_owned(dir.path(), 0).unwrap();
        assert!(pool.used() > 0);
        assert!(matches!(&record.entry, WalEntry::DeleteBatch { ids } if ids.len()==20_000));
        drop(record);
        assert_eq!(pool.used(), 0);
        Wal::scan_journal_from(dir.path(), 0, |_| Err(invalid("visitor stopped"))).unwrap_err();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn owned_selectors_and_consumers_keep_charge_live_during_unwind() {
    thread_local! {
        static POOL: std::cell::RefCell<Option<Arc<memory::Pool>>> = const { std::cell::RefCell::new(None) };
        static LIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    #[derive(Deserialize)]
    struct Probe {
        body: String,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            POOL.with(|pool| {
                LIVE.with(|live| {
                    live.set(pool.borrow().as_ref().unwrap().used() >= self.body.capacity() as u64)
                })
            });
        }
    }
    let input = serde_json::to_vec(&serde_json::json!({"body":"x".repeat(64*1024)})).unwrap();
    memory::with_storage_pool(2 * 1024 * 1024, |pool| {
        POOL.with(|p| *p.borrow_mut() = Some(pool.clone()));
        for map in [false, true] {
            LIVE.with(|p| p.set(false));
            let owned = decode::<Probe>(&input).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if map {
                    owned
                        .try_map::<()>(|_probe| panic!("map panic"))
                        .map(|_| ())
                } else {
                    owned.consume::<()>(|_probe| panic!("consume panic"))
                }
            }));
            assert!(result.is_err());
            assert!(LIVE.with(std::cell::Cell::get));
            assert_eq!(pool.used(), 0);
        }
        POOL.with(|p| *p.borrow_mut() = None);
    });
}
