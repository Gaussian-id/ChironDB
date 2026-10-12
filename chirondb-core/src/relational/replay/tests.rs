use super::*;
use crate::relational::memory::with_storage_pool;

fn request(sql: &str) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap()
}
fn open(path: &Path) -> Arc<RelationalEngine> {
    RelationalEngine::open(path, TransactionJournal::open(path).unwrap()).unwrap()
}
fn empty_batch(sequence: u64) -> RelationalBatch {
    RelationalBatch {
        sequence,
        mutations: Vec::new(),
    }
}
fn audit() -> TransactionAudit {
    TransactionAudit::mutation(
        "sql_transaction",
        None,
        &AuditContext::embedded(),
        serde_json::json!({}),
    )
}
fn history_payload(count: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version":RELATIONAL_CHECKPOINT_VERSION,"sequence":0,"next_catalog_id":1,
        "wal_watermark":0,"tables":[],
        "applied_transactions":(0..count).map(|_| TransactionId::new()).collect::<Vec<_>>()
    }))
    .unwrap()
}

#[test]
fn legacy_history_validates_each_uuid_without_retaining_elements_or_decode_charges() {
    let small = history_payload(0);
    let large = history_payload(100_000);
    assert!(large.len() > 3 * 1024 * 1024);
    let (pool, empty, decoded) = with_storage_pool(16 * 1024 * 1024, |pool| {
        let empty = checkpoint::decode::read(small.as_slice(), small.len()).unwrap();
        let decoded = checkpoint::decode::read(large.as_slice(), large.len()).unwrap();
        println!(
            "legacy replay history: input IDs=100000, input bytes={}, retained ID capacity={}, empty metadata bytes={}, decoded metadata bytes={}, scoped retained bytes={}",
            large.len(),
            decoded.applied_transactions.capacity(),
            empty.owned_memory.bytes(),
            decoded.owned_memory.bytes(),
            pool.used()
        );
        assert_eq!(decoded.applied_transactions.capacity(), 0);
        assert_eq!(decoded.owned_memory.bytes(), empty.owned_memory.bytes());
        assert_eq!(
            pool.used(),
            decoded.owned_memory.bytes()
                + empty.owned_memory.bytes()
                + 2 * memory::LEASE_ROOT_BYTES
        );
        assert!(
            pool.used() < 8192,
            "100k legacy IDs must not survive decoding"
        );
        (pool, empty, decoded)
    });
    drop(empty);
    assert!(pool.used() > 0);
    drop(decoded);
    assert_eq!(pool.used(), 0);
}

#[test]
fn legacy_history_rejects_invalid_uuid_and_non_array_shapes_and_cancels_during_read() {
    let base: serde_json::Value = serde_json::from_slice(&history_payload(0)).unwrap();
    for invalid in [
        serde_json::json!(["bad-uuid"]),
        serde_json::json!([1]),
        serde_json::json!({}),
        serde_json::Value::Null,
    ] {
        let mut changed = base.clone();
        changed["applied_transactions"] = invalid;
        let payload = serde_json::to_vec(&changed).unwrap();
        with_storage_pool(1024 * 1024, |pool| {
            assert!(checkpoint::decode::read(payload.as_slice(), payload.len()).is_err());
            assert_eq!(pool.used(), 0);
        });
    }
    struct CancelReader<'a> {
        bytes: &'a [u8],
        cancel: Arc<AtomicBool>,
    }
    impl Read for CancelReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = self.bytes.read(output)?;
            self.cancel.store(true, AtomicOrdering::Release);
            Ok(count)
        }
    }
    let payload = history_payload(1000);
    let cancel = Arc::new(AtomicBool::new(false));
    with_storage_pool(1024 * 1024, |pool| {
        let error = with_sql_cancellation(cancel.clone(), || {
            checkpoint::decode::read(
                CancelReader {
                    bytes: &payload,
                    cancel,
                },
                payload.len(),
            )
        })
        .unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn batch_proof_streams_large_payloads_under_fixed_quota_and_distinguishes_float_encoding() {
    let mut batch = RelationalBatch {
        sequence: 1,
        mutations: vec![RelationalMutation::Insert {
            table: "items".into(),
            rows: vec![StoredRow {
                row_id: 1,
                values: vec![
                    RelationalValue::Text("x".repeat(1024 * 1024)),
                    RelationalValue::Float(-0.0),
                ],
            }],
        }],
    };
    let hash = with_storage_pool(256 + memory::LEASE_ROOT_BYTES, |pool| {
        let hash = fingerprint(&batch).unwrap();
        assert_eq!(pool.used(), 0);
        assert_eq!(hash, fingerprint(&batch).unwrap());
        hash
    });
    let RelationalMutation::Insert { rows, .. } = &mut batch.mutations[0] else {
        unreachable!()
    };
    rows[0].values[1] = RelationalValue::Float(0.0);
    assert_ne!(
        hash,
        fingerprint(&batch).unwrap(),
        "proof compares encoded values, including signed zero"
    );
    with_storage_pool(0, |pool| {
        assert!(matches!(
            fingerprint(&batch),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    let cancel = Arc::new(AtomicBool::new(false));
    with_sql_cancellation(cancel.clone(), || {
        cancel.store(true, AtomicOrdering::Release);
        assert!(
            fingerprint(&batch)
                .unwrap_err()
                .to_string()
                .contains("query canceled")
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn journal_proof_rejects_missing_rejected_foreign_and_changed_decisions() {
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let batch = empty_batch(1);
    let committed = journal
        .commit(
            TransactionTarget::Relational,
            WalEntry::RelationalBatch {
                batch: batch.clone(),
            },
            audit(),
        )
        .unwrap();
    let id = committed.prepare.transaction_id;
    journal.validate_relational_projection(id, &batch).unwrap();
    assert!(matches!(
        journal.validate_relational_projection(TransactionId::new(), &batch),
        Err(GaussError::WalCorruption { .. })
    ));
    assert!(matches!(
        journal.validate_relational_projection(id, &empty_batch(2)),
        Err(GaussError::WalCorruption { .. })
    ));
    let foreign = journal
        .commit(
            TransactionTarget::Collection {
                name: "docs".into(),
            },
            WalEntry::DeleteBatch {
                ids: vec!["one".into()],
            },
            audit(),
        )
        .unwrap();
    assert!(matches!(
        journal.validate_relational_projection(foreign.prepare.transaction_id, &batch),
        Err(GaussError::WalCorruption { .. })
    ));
    let mut rejected = (*committed.prepare).clone();
    rejected.transaction_id = TransactionId::new();
    rejected.commit_sequence = foreign.prepare.commit_sequence + 1;
    let rejected_id = rejected.transaction_id;
    let path = journal.dir().to_path_buf();
    drop(journal);
    let mut wal = Wal::open(&path).unwrap();
    wal.append(&WalEntry::TransactionPrepare { prepare: rejected })
        .unwrap();
    drop(wal);
    let journal = TransactionJournal::open(directory.path()).unwrap();
    assert_eq!(
        journal.status(rejected_id).state,
        crate::transaction_journal::TransactionState::Rejected
    );
    assert!(matches!(
        journal.validate_relational_projection(rejected_id, &batch),
        Err(GaussError::WalCorruption { .. })
    ));
    journal.validate_relational_projection(id, &batch).unwrap();
}

#[test]
fn authentic_duplicates_before_and_after_checkpoint_recover_once_without_id_history() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let create = engine
        .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
        .unwrap()
        .committed
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1)"))
        .unwrap();
    let duplicate = WalEntry::TransactionApply {
        transaction_id: create.prepare.transaction_id,
        entry: create.prepare.mutation.clone(),
    };
    engine.wal.lock().unwrap().append(&duplicate).unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(engine.state.read().sequence, 2);
    engine.checkpoint().unwrap();
    let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.applied_transactions.capacity(), 0);
    engine.wal.lock().unwrap().append(&duplicate).unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(engine.state.read().sequence, 2);
    let result = engine
        .execute(request("SELECT id FROM items"))
        .unwrap()
        .response;
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(1)]]);
    engine
        .execute(request("INSERT INTO items VALUES (2)"))
        .unwrap();
    assert_eq!(engine.state.read().sequence, 3);
    engine.checkpoint().unwrap();
    drop(engine);
    assert_eq!(open(directory.path()).state.read().sequence, 3);
}

#[test]
fn changed_duplicate_below_checkpoint_frontier_fails_before_replay_or_publication() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let create = engine
        .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
        .unwrap()
        .committed
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1)"))
        .unwrap();
    engine.checkpoint().unwrap();
    let checkpoint_bytes = fs::read(&engine.checkpoint_path).unwrap();
    let WalEntry::RelationalBatch { mut batch } = *create.prepare.mutation.clone() else {
        unreachable!()
    };
    batch.mutations = vec![RelationalMutation::DropTable {
        name: "items".into(),
    }];
    engine
        .wal
        .lock()
        .unwrap()
        .append(&WalEntry::TransactionApply {
            transaction_id: create.prepare.transaction_id,
            entry: Box::new(WalEntry::RelationalBatch { batch }),
        })
        .unwrap();
    let checkpoint_path = engine.checkpoint_path.clone();
    drop(engine);
    assert!(matches!(
        RelationalEngine::open(
            directory.path(),
            TransactionJournal::open(directory.path()).unwrap()
        ),
        Err(GaussError::WalCorruption { .. })
    ));
    assert_eq!(fs::read(checkpoint_path).unwrap(), checkpoint_bytes);
}

#[test]
fn committed_projection_with_missing_logical_prefix_fails_closed() {
    for sequence in [0, 2] {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        RelationalEngine::ensure_storage(directory.path()).unwrap();
        let transaction = journal
            .commit(
                TransactionTarget::Relational,
                WalEntry::RelationalBatch {
                    batch: empty_batch(sequence),
                },
                audit(),
            )
            .unwrap();
        let mut wal = Wal::open(&directory.path().join(RELATIONAL_WAL_DIR)).unwrap();
        wal.append(&WalEntry::TransactionApply {
            transaction_id: transaction.prepare.transaction_id,
            entry: transaction.prepare.mutation.clone(),
        })
        .unwrap();
        drop(wal);
        assert!(matches!(
            RelationalEngine::open(directory.path(), journal),
            Err(GaussError::WalCorruption { .. })
        ));
        assert!(!directory.path().join(RELATIONAL_CHECKPOINT_FILE).exists());
    }
}

#[test]
fn snapshot_frontier_stays_fixed_and_checkpoint_history_size_does_not_grow_with_commits() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (0)"))
        .unwrap();
    let frozen = engine.state.read().clone();
    let initial = capture_relational_checkpoint(&frozen, 0).unwrap();
    for id in 1..=128 {
        engine
            .execute(request(&format!("UPDATE items SET id = {id}")))
            .unwrap();
    }
    let current = engine.state.read().clone();
    let later = capture_relational_checkpoint(&current, 0).unwrap();
    assert_eq!(frozen.sequence, 2);
    assert_eq!(current.sequence, 130);
    assert!(initial.manifest.applied_transactions.is_empty());
    assert!(later.manifest.applied_transactions.is_empty());
    assert_eq!(
        initial.manifest.owned_memory.bytes(),
        later.manifest.owned_memory.bytes(),
        "capture does not retain a per-commit UUID vector"
    );
    engine.checkpoint().unwrap();
    drop(initial);
    drop(later);
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(engine.state.read().sequence, 130);
    let result = engine
        .execute(request("SELECT id FROM items"))
        .unwrap()
        .response;
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(128)]]);
}
