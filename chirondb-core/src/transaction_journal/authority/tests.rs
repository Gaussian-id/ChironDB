use super::*;

fn context() -> AuditContext {
    AuditContext {
        principal_id: "writer".into(),
        tenant_id: Some("tenant".into()),
        transport: "test".into(),
        request_id: None,
    }
}
fn execute(
    journal: &Arc<TransactionJournal>,
    key: &str,
    batch: &crate::relational::RelationalBatch,
) -> CommittedTransaction {
    let IdempotencyAdmission::Execute(guard) = journal
        .begin_idempotent(key, &context(), "sql", &batch.sequence, || Ok(()))
        .unwrap()
    else {
        panic!("duplicate executed")
    };
    let transaction = guard
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch {
                batch: batch.clone(),
            },
            TransactionAudit::mutation("sql", None, &context(), Value::Null),
            serde_json::json!({"allocated_ids": [batch.sequence]}),
        )
        .unwrap();
    for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
        journal
            .mark_projected(transaction.prepare.transaction_id, kind)
            .unwrap();
    }
    transaction
}
fn batch(sequence: u64) -> crate::relational::RelationalBatch {
    crate::relational::RelationalBatch {
        sequence,
        mutations: vec![],
    }
}

/// Low-level fixture installs the same complete generation without onboarding
/// a protected Db. Production activation goes through the offline reader fence.
pub(crate) fn activate(journal: &TransactionJournal) {
    let mut inner = journal.inner.lock().unwrap();
    let id = inner.claim_installation_id;
    let mut state = JournalState {
        installation_id: Some(id),
        authoritative: true,
        next_receipt_expiry_ms: u64::MAX,
        decisions: Some(DiskMap::new(&parent(journal.dir())).unwrap()),
        ..JournalState::default()
    };
    let stats = Wal::recover_journal_from(journal.dir(), 0, |record| {
        let lsn = record.lsn;
        record.consume(|record| apply_record(&mut state, lsn, record.entry))?;
        state.flush_completed(journal.dir())
    })
    .unwrap();
    state.finish_recovery(journal.dir()).unwrap();
    publish(journal.dir(), &mut state, stats.end_lsn).unwrap();
    crate::encryption::atomic_write_persistent(
        &journal.data_dir.join(TRANSACTION_FORMAT_MARKER),
        crate::encryption::FileType::Metadata,
        format!("CHIRONTXN3\n{id}\n").as_bytes(),
    )
    .unwrap();
    inner.state = state;
}
fn retire_prefix(journal: &TransactionJournal) {
    let mut inner = journal.inner.lock().unwrap();
    let end = inner.wal.len().unwrap();
    inner.wal.drop_prefix(end).unwrap();
    assert_eq!(Wal::retained_base_lsn(journal.dir()).unwrap(), end);
}

#[test]
fn compact_authority_reopens_decisions_receipts_and_sql_proofs_without_historical_wal() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let first = execute(&journal, "one", &batch(1));
    activate(&journal);
    retire_prefix(&journal);
    let first_id = first.prepare.transaction_id;
    drop(first.prepare);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        0
    );
    assert_eq!(journal.status(first_id).state, TransactionState::Committed);
    journal
        .validate_relational_projection(first_id, &batch(1))
        .unwrap();
    assert!(
        journal
            .validate_relational_projection(first_id, &batch(2))
            .is_err()
    );
    assert!(
        journal
            .status_for_owner(first_id, "foreign", "tenant")
            .unwrap()
            .is_none()
    );
    let IdempotencyAdmission::Replay(receipt) = journal
        .begin_idempotent("one", &context(), "sql", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!("consumed key reexecuted")
    };
    assert_eq!(receipt.response.unwrap()["allocated_ids"][0], 1);
    assert!(
        matches!(receipt.mutation.unwrap().as_ref(), WalEntry::RelationalBatch { batch } if batch.sequence == 1)
    );
    assert!(
        journal
            .begin_idempotent("one", &context(), "sql", &2_u64, || Ok(()))
            .is_err()
    );
    let second = execute(&journal, "two", &batch(2));
    // Before eviction, a completed live decision still reads its original WAL
    // body rather than treating an unflushed receipt as missing authority.
    assert!(matches!(
        journal
            .begin_idempotent("two", &context(), "sql", &2_u64, || Ok(()))
            .unwrap(),
        IdempotencyAdmission::Replay(_)
    ));
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert_eq!(
        journal.status(second.prepare.transaction_id).state,
        TransactionState::Committed
    );
    assert_eq!(
        journal.inner.lock().unwrap().state.recovery_decoded_records,
        4
    );
    retire_prefix(&journal);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert_eq!(journal.status(first_id).state, TransactionState::Committed);
    assert_eq!(
        journal.status(second.prepare.transaction_id).state,
        TransactionState::Committed
    );
}

#[test]
fn relational_store_reopens_its_projection_against_authority_after_journal_prefix_cut() {
    let directory = tempfile::tempdir().unwrap();
    let db = crate::Db::open(directory.path()).unwrap();
    for sql in [
        "CREATE TABLE knowledge (id BIGINT PRIMARY KEY, title TEXT)",
        "INSERT INTO knowledge VALUES (1, 'ack')",
    ] {
        db.execute_sql(
            serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap(),
        )
        .unwrap();
    }
    drop(db);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    activate(&journal);
    retire_prefix(&journal);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let engine = crate::relational::RelationalEngine::open(directory.path(), journal).unwrap();
    let execution = engine
        .execute(
            serde_json::from_value(
                serde_json::json!({"statements":[{"sql":"SELECT id, title FROM knowledge"}]}),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        matches!(&execution.response.results[0], crate::SqlResult::Rows { rows, .. } if rows.len() == 1)
    );
}

#[test]
fn missing_or_corrupt_authority_never_falls_back_to_full_wal() {
    for remove in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        execute(&journal, "one", &batch(1));
        activate(&journal);
        drop(journal);
        let current = directory
            .path()
            .join(TRANSACTION_AUTHORITY_DIR)
            .join(".chiron-decision-checkpoint/CURRENT");
        if remove {
            std::fs::remove_file(&current).unwrap();
        } else {
            std::fs::write(&current, b"corrupt authority").unwrap();
        }
        let pin = directory
            .path()
            .join(TRANSACTION_JOURNAL_DIR)
            .join(".chiron-wal-pins-orphan");
        std::fs::create_dir(&pin).unwrap();
        std::fs::write(pin.join("held"), b"keep").unwrap();
        assert!(crate::Db::open(directory.path()).is_err());
        assert_eq!(std::fs::read(pin.join("held")).unwrap(), b"keep");
        assert!(TransactionJournal::open(directory.path()).is_err());
    }
}

#[test]
fn consumed_keys_survive_receipt_compaction_and_clock_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let transaction = execute(&journal, "one", &batch(1));
    activate(&journal);
    let id = transaction.prepare.transaction_id;
    let expiry = journal
        .inner
        .lock()
        .unwrap()
        .state
        .prepare(id)
        .unwrap()
        .unwrap()
        .idempotency
        .as_ref()
        .unwrap()
        .retained_until_unix_ms;
    {
        let mut inner = journal.inner.lock().unwrap();
        let end = inner.wal.len().unwrap();
        publish_at(journal.dir(), &mut inner.state, end, expiry).unwrap();
        assert!(
            inner
                .state
                .decisions
                .as_ref()
                .unwrap()
                .get_owned::<RetainedReceipt>(&receipt_key(id))
                .unwrap()
                .is_none()
        );
        let key = inner
            .state
            .prepare(id)
            .unwrap()
            .unwrap()
            .idempotency_key
            .as_ref()
            .unwrap()
            .clone();
        let fingerprint = inner
            .state
            .prepare(id)
            .unwrap()
            .unwrap()
            .idempotency
            .as_ref()
            .unwrap()
            .fingerprint;
        let receipt = idempotency::replay(&inner.state, journal.dir(), &key, &fingerprint, 1)
            .unwrap()
            .unwrap();
        assert!(receipt.expired);
        assert!(receipt.response.is_none());
        assert!(receipt.mutation.is_none());
    }
    retire_prefix(&journal);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let IdempotencyAdmission::Replay(receipt) = journal
        .begin_idempotent("one", &context(), "sql", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!("expired consumed key executed")
    };
    assert!(receipt.expired);
    assert_eq!(receipt.status.transaction_id, id);
    assert!(
        journal
            .begin_idempotent("one", &context(), "sql", &2_u64, || Ok(()))
            .is_err()
    );
    journal
        .validate_relational_projection(id, &batch(1))
        .unwrap();
}

#[test]
fn authority_manifest_is_copied_but_its_scratch_is_excluded() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    execute(&journal, "one", &batch(1));
    activate(&journal);
    let authority = directory.path().join(TRANSACTION_AUTHORITY_DIR);
    let current = authority.join(".chiron-decision-checkpoint/CURRENT");
    assert!(!DiskMap::is_journal_scratch(&current));
    let scratch = std::fs::read_dir(&authority)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| DiskMap::is_journal_scratch(path))
        .unwrap();
    assert!(DiskMap::is_journal_scratch(&scratch));
    let output = tempfile::tempdir().unwrap();
    crate::fs_util::copy_dir_all(directory.path(), &output.path().join("copy")).unwrap();
    assert!(
        output
            .path()
            .join("copy")
            .join(TRANSACTION_AUTHORITY_DIR)
            .join(".chiron-decision-checkpoint/CURRENT")
            .is_file()
    );
}

#[test]
fn retained_receipt_owner_is_admitted_until_its_last_drop() {
    crate::relational::wal_decode::with_test_storage_pool(16 * 1024 * 1024, |used| {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let IdempotencyAdmission::Execute(guard) = journal
            .begin_idempotent("large", &context(), "delete", &1, || Ok(()))
            .unwrap()
        else {
            panic!()
        };
        let transaction = guard
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                TransactionAudit::mutation("delete", Some("docs"), &context(), Value::Null),
                Value::String("x".repeat(128 * 1024)),
            )
            .unwrap();
        for kind in [ProjectionKind::Storage, ProjectionKind::Audit] {
            journal
                .mark_projected(transaction.prepare.transaction_id, kind)
                .unwrap();
        }
        drop(guard);
        drop(transaction);
        activate(&journal);
        retire_prefix(&journal);
        let occupied = used();
        let mut pressure = crate::relational::wal_decode::MetadataCharge::default();
        pressure
            .prepare(
                16 * 1024 * 1024 - occupied - crate::relational::wal_decode::lease_root_bytes(),
            )
            .unwrap();
        assert!(matches!(
            journal.begin_idempotent("large", &context(), "delete", &1, || Ok(())),
            Err(GaussError::ResourceExhausted(_))
        ));
        drop(pressure);
        let IdempotencyAdmission::Replay(receipt) = journal
            .begin_idempotent("large", &context(), "delete", &1, || Ok(()))
            .unwrap()
        else {
            panic!("retry reexecuted")
        };
        drop(journal);
        assert!(used() >= 128 * 1024);
        assert_eq!(
            receipt.response.as_ref().unwrap().as_str().unwrap().len(),
            128 * 1024
        );
        drop(receipt);
        assert_eq!(used(), 0);
    });
}

#[test]
fn expired_terminal_receipt_is_evicted_without_loading_its_old_wal_body() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let transaction = execute(&journal, "one", &batch(1));
    let id = transaction.prepare.transaction_id;
    let mut inner = journal.inner.lock().unwrap();
    inner.state.authoritative = true;
    inner.state.receipt_floor_ms = inner
        .state
        .prepare(id)
        .unwrap()
        .unwrap()
        .idempotency
        .as_ref()
        .unwrap()
        .retained_until_unix_ms;
    inner
        .state
        .flush_decisions(&directory.path().join("absent-old-wal"))
        .unwrap();
    assert_eq!(
        inner.state.checked_status(id).unwrap().state,
        TransactionState::Committed
    );
    assert!(
        inner
            .state
            .decisions
            .as_ref()
            .unwrap()
            .get_owned::<RetainedReceipt>(&receipt_key(id))
            .unwrap()
            .is_none()
    );
    assert!(inner.state.prepares.is_empty());
}

#[test]
fn ordinary_mutation_maintenance_does_not_rewrite_history_for_one_due_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    execute(&journal, "one", &batch(1));
    activate(&journal);
    let current = directory
        .path()
        .join(TRANSACTION_AUTHORITY_DIR)
        .join(".chiron-decision-checkpoint/CURRENT");
    let before = std::fs::read(&current).unwrap();
    let mut inner = journal.inner.lock().unwrap();
    // A due expiry hint can also outlive a rejected PREPARE that never stored
    // a receipt body. Neither event should force a history rewrite per request.
    inner.state.next_receipt_expiry_ms = 1;
    checkpoint::maintain(journal.dir(), &mut inner).unwrap();
    assert!(
        std::fs::read(&current).unwrap() == before,
        "CURRENT changed during ordinary maintenance"
    );
    assert_eq!(inner.state.receipt_floor_ms, 0);
}

#[cfg(feature = "fault-injection")]
#[test]
fn rejected_consumed_key_survives_authority_and_prefix_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let IdempotencyAdmission::Execute(guard) = journal
        .begin_idempotent("rejected", &context(), "sql", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!()
    };
    {
        let _env = crate::failpoint::test_env(
            "error:transaction.after_prepare",
            &directory.path().join("marker"),
            &directory.path().join("release"),
        );
        assert!(
            guard
                .commit(
                    TransactionTarget::Relational,
                    WalEntry::RelationalBatch { batch: batch(1) },
                    TransactionAudit::mutation("sql", None, &context(), Value::Null),
                    Value::Null
                )
                .is_err()
        );
    }
    drop(guard);
    activate(&journal);
    retire_prefix(&journal);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let IdempotencyAdmission::Replay(receipt) = journal
        .begin_idempotent("rejected", &context(), "sql", &1_u64, || Ok(()))
        .unwrap()
    else {
        panic!("rejected consumed key executed")
    };
    assert_eq!(receipt.status.state, TransactionState::Rejected);
    assert!(receipt.response.is_none());
    assert!(receipt.mutation.is_none());
    assert!(
        journal
            .begin_idempotent("rejected", &context(), "sql", &2_u64, || Ok(()))
            .is_err()
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn failed_receipt_rewrite_preserves_authority_and_all_unexpired_receipts() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let transaction = execute(&journal, "one", &batch(1));
    activate(&journal);
    let current = directory
        .path()
        .join(TRANSACTION_AUTHORITY_DIR)
        .join(".chiron-decision-checkpoint/CURRENT");
    let before = std::fs::read(&current).unwrap();
    {
        let mut inner = journal.inner.lock().unwrap();
        let end = inner.wal.len().unwrap();
        inner.state.next_receipt_expiry_ms = 0;
        let _env = crate::failpoint::test_env(
            "error:transaction_decisions.before_publish",
            &directory.path().join("marker"),
            &directory.path().join("release"),
        );
        assert!(publish(journal.dir(), &mut inner.state, end).is_err());
        assert_eq!(inner.state.receipt_floor_ms, 0);
        assert!(
            inner
                .state
                .decisions
                .as_ref()
                .unwrap()
                .get_owned::<RetainedReceipt>(&receipt_key(transaction.prepare.transaction_id))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(std::fs::read(&current).unwrap(), before);
    drop(journal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert!(matches!(
        journal
            .begin_idempotent("one", &context(), "sql", &1_u64, || Ok(()))
            .unwrap(),
        IdempotencyAdmission::Replay(_)
    ));
}

#[test]
#[ignore = "requires a verified pre-authority reader executable"]
fn pre_authority_reader_accepts_legacy_control_and_refuses_format3_before_mutation() {
    let binary =
        std::env::var_os("CHIRONDB_PRE_AUTHORITY_READER").expect("CHIRONDB_PRE_AUTHORITY_READER");
    let control = tempfile::tempdir().unwrap();
    drop(crate::Db::open(control.path()).unwrap());
    assert!(
        std::process::Command::new(&binary)
            .arg(control.path())
            .status()
            .unwrap()
            .success()
    );
    let directory = tempfile::tempdir().unwrap();
    drop(crate::Db::open(directory.path()).unwrap());
    let journal = TransactionJournal::open(directory.path()).unwrap();
    execute(&journal, "one", &batch(1));
    activate(&journal);
    drop(journal);
    fn image(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn visit(
            root: &Path,
            path: &Path,
            files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut files = std::collections::BTreeMap::new();
        visit(root, root, &mut files);
        files
    }
    let before = image(directory.path());
    let output = std::process::Command::new(&binary)
        .arg(directory.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported transaction format marker")
    );
    assert_eq!(image(directory.path()), before);
}
