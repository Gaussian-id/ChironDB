//! Move typed results from their SQL working-set reservation to a unique output
//! owner before releasing execution admission or recording a mutation decision.
use super::*;
use std::mem::size_of;

/// Typed SQL response with receiving memory retained until consumption/drop.
/// Transport/DTO fields are unchanged. This owner deliberately is not Clone.
#[derive(Debug)]
pub struct SqlResponse {
    value: SqlExecutionResponse,
    _memory: wal_decode::Reservation,
}

impl std::ops::Deref for SqlResponse {
    type Target = SqlExecutionResponse;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl Serialize for SqlResponse {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
impl SqlResponse {
    /// Allocation-free transfer into another admitted core result owner.
    pub(crate) fn into_parts(self) -> (SqlExecutionResponse, wal_decode::Reservation) {
        (self.value, self._memory)
    }
    pub(super) fn new(value: SqlExecutionResponse, memory: wal_decode::Reservation) -> Self {
        Self {
            value,
            _memory: memory,
        }
    }
    /// Legacy embedded DTO handoff: the application assumes ownership and its
    /// memory budget. Servers must retain/consume this owner instead.
    pub fn into_dto(self) -> SqlExecutionResponse {
        self.value
    }
    /// Finish/drop the DTO in the callback, or transfer its allocations into a
    /// separately admitted receiving owner before returning.
    pub fn consume<R>(self, consumer: impl FnOnce(SqlExecutionResponse) -> Result<R>) -> Result<R> {
        let Self { value, _memory } = self;
        consumer(value)
    }
}

pub(super) fn reserve_results(results: &Vec<SqlResult>) -> Result<wal_decode::Reservation> {
    #[cfg(test)]
    if let Some(capacity) = TEST_OUTPUT_CAPACITY.with(|cap| cap.take()) {
        return wal_decode::with_test_storage_pool(capacity, |used| {
            let result = reserve_results(results);
            assert!(result.is_err());
            assert_eq!(used(), 0);
            result
        });
    }
    // Includes response/controller, stable UUID string and allocator alignment.
    let mut bytes = 1024_u64
        .saturating_add((results.capacity() as u64).saturating_mul(size_of::<SqlResult>() as u64));
    let strings = |values: &Vec<String>| {
        values.iter().fold(
            (values.capacity() as u64).saturating_mul(size_of::<String>() as u64),
            |bytes, s| bytes.saturating_add(s.capacity() as u64),
        )
    };
    for result in results {
        check_sql_cancelled()?;
        bytes = bytes.saturating_add(match result {
            SqlResult::Definition { .. } | SqlResult::Mutation { .. } => 0,
            SqlResult::Explain { plan } => strings(plan),
            SqlResult::Rows {
                columns,
                column_types,
                rows,
            } => {
                let mut heap = strings(columns)
                    .saturating_add((column_types.capacity() as u64).saturating_mul(size_of::<
                        RelationalType,
                    >(
                    )
                        as u64))
                    .saturating_add(
                        (rows.capacity() as u64)
                            .saturating_mul(size_of::<Vec<RelationalValue>>() as u64),
                    );
                for data_type in column_types {
                    if let RelationalType::RecordRef { namespace } = data_type {
                        heap = heap.saturating_add(namespace.capacity() as u64);
                    }
                }
                for row in rows {
                    check_sql_cancelled()?;
                    heap = row.iter().fold(
                        heap.saturating_add((row.capacity() as u64).saturating_mul(size_of::<
                            RelationalValue,
                        >(
                        )
                            as u64)),
                        |bytes, value| bytes.saturating_add(memory::value_heap_bytes(value)),
                    );
                }
                heap
            }
        });
    }
    let mut memory = wal_decode::MetadataCharge::default();
    memory.prepare(bytes)?;
    Ok(memory.into_reservation())
}

impl RelationalExecution {
    pub(crate) fn into_output(self) -> SqlResponse {
        SqlResponse::new(self.response, self.response_memory)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_OUTPUT_CAPACITY: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlStatementRequest;

    fn request(sql: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }
    fn dto() -> SqlExecutionResponse {
        SqlExecutionResponse {
            transaction_id: None,
            snapshot: 17,
            committed: false,
            outcome: SqlOutcome::Committed,
            commit_sequence: None,
            retryable: false,
            results: vec![
                SqlResult::Rows {
                    columns: vec!["text".into(), "vector".into(), "json".into(), "ref".into()],
                    column_types: vec![
                        RelationalType::Text,
                        RelationalType::Vector { dimension: 2 },
                        RelationalType::Jsonb,
                        RelationalType::RecordRef {
                            namespace: "documents".into(),
                        },
                    ],
                    rows: vec![vec![
                        RelationalValue::Text("\n日本語".repeat(4096)),
                        RelationalValue::Vector(vec![0.7181532, -0.0]),
                        RelationalValue::Json(
                            serde_json::json!({"max":u64::MAX,"min":i64::MIN,"float":1.2345678901234567e300_f64,"zero":-0.0}),
                        ),
                        RelationalValue::RecordRef(crate::RecordRef {
                            namespace: "documents".into(),
                            id: "opaque-id".into(),
                        }),
                    ]],
                },
                SqlResult::Explain {
                    plan: vec!["scan".into()],
                },
                SqlResult::Definition {
                    affected_objects: 1,
                },
                SqlResult::Mutation { affected_rows: 1 },
            ],
        }
    }

    #[test]
    fn typed_sql_output_adoption_preserves_allocations_and_holds_consumer_overlap() {
        let source = dto();
        let expected = serde_json::to_vec(&source).unwrap();
        for capacity in [1, 4096] {
            wal_decode::with_test_storage_pool(capacity, |used| {
                assert!(matches!(
                    reserve_results(&source.results),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
        }
        wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let rows = match &source.results[0] {
                SqlResult::Rows { rows, .. } => rows.as_ptr(),
                _ => unreachable!(),
            };
            let memory = reserve_results(&source.results).unwrap();
            let owner = SqlResponse::new(source, memory);
            assert_eq!(serde_json::to_vec(&owner).unwrap(), expected);
            let receiving = owner
                .consume(|value| {
                    assert!(used() > 0);
                    assert_eq!(
                        match &value.results[0] {
                            SqlResult::Rows { rows, .. } => rows.as_ptr(),
                            _ => unreachable!(),
                        },
                        rows
                    );
                    let bytes =
                        crate::response_buffer::ResponseBuffer::json_native(&value, 1024 * 1024)?;
                    assert!(
                        used() > bytes.as_ref().len() as u64,
                        "source and receiver overlap"
                    );
                    Ok(bytes)
                })
                .unwrap();
            assert!(used() > 0, "receiving bytes retain admission");
            assert_eq!(receiving.as_ref(), expected);
            drop(receiving);
            assert_eq!(used(), 0);
            let value = dto();
            let memory = reserve_results(&value.results).unwrap();
            let result =
                SqlResponse::new(value, memory).consume::<()>(|_| Err(invalid("consumer error")));
            assert!(result.is_err());
            assert_eq!(used(), 0);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let value = dto();
                let memory = reserve_results(&value.results).unwrap();
                SqlResponse::new(value, memory).consume::<()>(|_| panic!("consumer panic"))
            }));
            assert!(panic.is_err());
            assert_eq!(used(), 0);
            let value = dto();
            assert!(
                with_sql_cancellation(Arc::new(AtomicBool::new(true)), || reserve_results(
                    &value.results
                ))
                .is_err()
            );
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn borrowed_typed_sql_replay_preserves_numeric_bits_and_refuses_without_mutating_source() {
        let encoded = serde_json::to_value(dto()).unwrap();
        let before = serde_json::to_vec(&encoded).unwrap();
        for capacity in [1, 4096] {
            wal_decode::with_test_storage_pool(capacity, |used| {
                let result = wal_decode::borrowed::<SqlExecutionResponse>(&encoded);
                assert!(matches!(result, Err(GaussError::ResourceExhausted(_))));
                assert_eq!(used(), 0);
            });
        }
        wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let decoded = wal_decode::borrowed::<SqlExecutionResponse>(&encoded).unwrap();
            assert!(used() > 0);
            let value = serde_json::to_value(&*decoded).unwrap();
            assert_eq!(value, encoded);
            let SqlResult::Rows { rows, .. } = &decoded.results[0] else {
                panic!()
            };
            let RelationalValue::Vector(v) = &rows[0][1] else {
                panic!()
            };
            assert_eq!(
                v.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                [0.7181532_f32.to_bits(), (-0.0_f32).to_bits()]
            );
            let RelationalValue::Json(j) = &rows[0][2] else {
                panic!()
            };
            assert_eq!(
                j["float"].as_f64().unwrap().to_bits(),
                1.2345678901234567e300_f64.to_bits()
            );
            assert_eq!(j["zero"].as_f64().unwrap().to_bits(), (-0.0_f64).to_bits());
            drop(decoded);
            assert_eq!(used(), 0);
            assert!(
                with_sql_cancellation(Arc::new(AtomicBool::new(true)), || wal_decode::borrowed::<
                    SqlExecutionResponse,
                >(
                    &encoded
                ))
                .is_err()
            );
            assert_eq!(used(), 0);
        });
        assert_eq!(serde_json::to_vec(&encoded).unwrap(), before);
    }

    #[test]
    fn receipt_replay_decodes_each_supported_shape_once_and_never_falls_back_on_refusal() {
        use crate::transaction_journal::{IdempotencyAdmission, IdempotencyReceipt};
        fn replay(journal: &Arc<TransactionJournal>, owner: &AuditContext) -> IdempotencyReceipt {
            match journal
                .begin_idempotent("replay-typed", owner, "sql_batch", &17, || Ok(()))
                .unwrap()
            {
                IdempotencyAdmission::Replay(receipt) => receipt,
                _ => panic!("key must stay consumed"),
            }
        }
        for shape in 0..6 {
            let dir = tempfile::tempdir().unwrap();
            let journal = TransactionJournal::open(dir.path()).unwrap();
            let engine = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
            let owner = AuditContext::embedded();
            let mut expected = dto();
            expected.committed = true;
            expected.commit_sequence = Some(17);
            let response = match shape {
                0 => serde_json::to_value(&expected).unwrap(),
                1 => serde_json::to_value(StandaloneCommitReceipt {
                    version: 1,
                    authorization: None,
                    references: BTreeSet::new(),
                    response: expected.clone(),
                })
                .unwrap(),
                2 | 3 => serde_json::to_value(InteractiveCommitReceipt {
                    version: if shape == 2 { 1 } else { 2 },
                    authorization: None,
                    references: BTreeSet::new(),
                    response: expected.clone(),
                })
                .unwrap(),
                4 => serde_json::to_value(StandaloneCommitReceipt {
                    version: 2,
                    authorization: None,
                    references: BTreeSet::new(),
                    response: expected.clone(),
                })
                .unwrap(),
                _ => serde_json::json!({"version":null,"response":expected}),
            };
            let claim = match journal
                .begin_idempotent("replay-typed", &owner, "sql_batch", &17, || Ok(()))
                .unwrap()
            {
                IdempotencyAdmission::Execute(claim) => claim,
                _ => panic!(),
            };
            let transaction = claim
                .commit(
                    TransactionTarget::Relational,
                    WalEntry::RelationalBatch {
                        batch: RelationalBatch {
                            sequence: 1,
                            mutations: vec![],
                        },
                    },
                    TransactionAudit::mutation(
                        "sql_transaction",
                        None,
                        &owner,
                        serde_json::Value::Null,
                    ),
                    response,
                )
                .unwrap();
            expected.transaction_id = Some(transaction.prepare.transaction_id.to_string());
            drop(transaction);
            drop(claim);
            let before = fs::read(journal.dir().join("000000.gdwal")).unwrap();
            for capacity in [1, 4096] {
                let receipt = replay(&journal, &owner);
                wal_decode::with_test_storage_pool(capacity, |used| {
                    let result = if matches!(shape, 2 | 3) {
                        replay_interactive_sql_receipt(receipt, None, None)
                    } else {
                        replay_standalone_sql_receipt(
                            &engine,
                            receipt,
                            None,
                            &request("SELECT id FROM seed"),
                        )
                    };
                    assert!(
                        matches!(result, Err(GaussError::ResourceExhausted(_))),
                        "decode refusal must retain its classification"
                    );
                    assert_eq!(used(), 0);
                });
                assert_eq!(
                    fs::read(journal.dir().join("000000.gdwal")).unwrap(),
                    before
                );
            }
            let receipt = replay(&journal, &owner);
            wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
                let result = if matches!(shape, 2 | 3) {
                    replay_interactive_sql_receipt(receipt, None, None)
                } else {
                    replay_standalone_sql_receipt(
                        &engine,
                        receipt,
                        None,
                        &request("SELECT id FROM seed"),
                    )
                };
                if shape < 4 {
                    let output = result.unwrap().into_output();
                    assert_eq!(*output, expected);
                    assert!(used() > 0);
                    drop(output);
                } else {
                    assert!(matches!(
                        result,
                        Err(GaussError::InvalidRequest(_) | GaussError::Json(_))
                    ));
                }
                assert_eq!(used(), 0);
            });
            let mut receipt = replay(&journal, &owner);
            receipt.expired = true;
            let result = if matches!(shape, 2 | 3) {
                replay_interactive_sql_receipt(receipt, None, None)
            } else {
                replay_standalone_sql_receipt(
                    &engine,
                    receipt,
                    None,
                    &request("SELECT id FROM seed"),
                )
            };
            assert!(result.err().unwrap().to_string().contains("expired"));
            assert_eq!(
                fs::read(journal.dir().join("000000.gdwal")).unwrap(),
                before
            );
            assert_eq!(journal.committed().unwrap().len(), 1);
        }
    }

    #[test]
    fn embedded_owned_sql_results_outlive_execution_admission_and_legacy_dto_handoff() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        db.execute_sql(request("CREATE TABLE seed (id INTEGER PRIMARY KEY)"))
            .unwrap();
        db.execute_sql(request("INSERT INTO seed VALUES (1)"))
            .unwrap();
        wal_decode::with_test_storage_pool(1024 * 1024, |used| {
            let output = db
                .execute_sql_owned(request("SELECT id AS n FROM seed"))
                .unwrap();
            assert!(used() > 0, "completed execution retains result memory");
            let expected = serde_json::to_vec(&output).unwrap();
            drop(output);
            assert_eq!(used(), 0);
            let legacy = db.execute_sql(request("SELECT id AS n FROM seed")).unwrap();
            assert_eq!(used(), 0, "embedded caller assumes DTO budget");
            assert_eq!(serde_json::to_vec(&legacy).unwrap(), expected);
            let owner = AuditContext::embedded();
            let handle = db.begin_sql_transaction(&owner).unwrap();
            let result = db
                .execute_sql_transaction_owned(
                    &handle.handle,
                    request("SELECT id AS n FROM seed"),
                    &owner,
                )
                .unwrap();
            assert!(used() > 0);
            drop(result);
            // Private history may retain its independent reservation.
            db.rollback_sql_transaction(&handle.handle, &owner).unwrap();
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn interactive_statement_output_refusal_requires_savepoint_recovery_before_retry() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::Db::open(dir.path()).unwrap();
        let owner = AuditContext::embedded();
        db.execute_sql(request("CREATE TABLE accounts (id INTEGER PRIMARY KEY)"))
            .unwrap();
        let handle = db.begin_sql_transaction(&owner).unwrap();
        db.execute_sql_transaction(&handle.handle, request("SAVEPOINT before_output"), &owner)
            .unwrap();
        let before = fs::read(
            dir.path()
                .join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
                .join("000000.gdwal"),
        )
        .unwrap();
        TEST_OUTPUT_CAPACITY.with(|cap| cap.set(Some(1)));
        let refusal = db
            .execute_sql_transaction_owned(
                &handle.handle,
                request("INSERT INTO accounts VALUES (1) RETURNING *"),
                &owner,
            )
            .unwrap_err();
        assert!(matches!(refusal, GaussError::ResourceExhausted(_)));
        assert!(
            db.commit_sql_transaction_owned(&handle.handle, &owner)
                .err()
                .unwrap()
                .to_string()
                .contains("aborted")
        );
        assert_eq!(
            fs::read(
                dir.path()
                    .join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
                    .join("000000.gdwal")
            )
            .unwrap(),
            before
        );
        db.execute_sql_transaction(&handle.handle, request("ROLLBACK TO before_output"), &owner)
            .unwrap();
        let output = db
            .execute_sql_transaction_owned(
                &handle.handle,
                request("INSERT INTO accounts VALUES (1) RETURNING *"),
                &owner,
            )
            .unwrap();
        assert!(!output.committed);
        drop(output);
        db.commit_sql_transaction_owned(&handle.handle, &owner)
            .unwrap();
        let result = db
            .execute_sql_owned(request("SELECT id FROM accounts"))
            .unwrap();
        assert!(
            matches!(&result.results[0],SqlResult::Rows {rows,..} if rows==&[vec![RelationalValue::Integer(1)]])
        );
    }

    #[test]
    fn output_refusal_precedes_sql_commit_and_keeps_interactive_session_retryable() {
        for interactive in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::Db::open(dir.path()).unwrap();
            db.execute_sql(request(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, text TEXT)",
            ))
            .unwrap();
            let owner = AuditContext::embedded();
            let mut insert = request("INSERT INTO accounts VALUES (1, 'large result') RETURNING *");
            insert.idempotency_key = (!interactive).then(|| "typed-output".into());
            let handle = interactive.then(|| db.begin_sql_transaction(&owner).unwrap());
            if let Some(handle) = &handle {
                db.execute_sql_transaction(&handle.handle, insert.clone(), &owner)
                    .unwrap();
            }
            let journal = dir
                .path()
                .join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
                .join("000000.gdwal");
            let before = fs::read(&journal).unwrap();
            TEST_OUTPUT_CAPACITY.with(|cap| cap.set(Some(1)));
            let error = if let Some(handle) = &handle {
                db.commit_sql_transaction_owned(&handle.handle, &owner)
            } else {
                db.execute_sql_owned(insert.clone())
            }
            .unwrap_err();
            assert!(matches!(error, GaussError::ResourceExhausted(_)), "{error}");
            assert_eq!(
                fs::read(&journal).unwrap(),
                before,
                "no durable decision on refusal"
            );
            let committed = if let Some(handle) = &handle {
                db.commit_sql_transaction_owned(&handle.handle, &owner)
                    .unwrap()
            } else {
                db.execute_sql_owned(insert.clone()).unwrap()
            };
            let id = committed.transaction_id.clone();
            drop(committed);
            let replay = if let Some(handle) = &handle {
                db.commit_sql_transaction_owned(&handle.handle, &owner)
                    .unwrap()
            } else {
                db.execute_sql_owned(insert).unwrap()
            };
            assert_eq!(replay.transaction_id, id);
            drop(replay);
            assert_eq!(
                db.execute_sql(request("SELECT count(*) AS n FROM accounts"))
                    .unwrap()
                    .results,
                [SqlResult::Rows {
                    columns: vec!["n".into()],
                    column_types: vec![RelationalType::BigInt],
                    rows: vec![vec![RelationalValue::Integer(1)]]
                }]
            );
            db.shutdown(Instant::now() + Duration::from_secs(10));
            drop(db);
            let db = crate::Db::open(dir.path()).unwrap();
            assert!(db.execute_sql(request("SELECT id FROM accounts")).unwrap().results.iter().any(|r|matches!(r,SqlResult::Rows {rows,..} if rows==&[vec![RelationalValue::Integer(1)]])));
        }
    }
}
