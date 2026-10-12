//! SQL receipts borrow prepared results and authority. The receiving JSON owner
//! stays admitted until the journal consumes it into its own PREPARE owner.
use super::*;

#[derive(Serialize)]
struct ResponseRef<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_id: Option<&'a str>,
    snapshot: u64,
    committed: bool,
    outcome: SqlOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_sequence: Option<u64>,
    retryable: bool,
    results: &'a [SqlResult],
}

impl<'a> ResponseRef<'a> {
    fn committed(sequence: u64, results: &'a [SqlResult]) -> Self {
        Self {
            transaction_id: None,
            snapshot: sequence,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: Some(sequence),
            retryable: false,
            results,
        }
    }
}

#[derive(Serialize)]
struct StandaloneRef<'a> {
    version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<&'a SqlAuthorization>,
    references: &'a BTreeSet<crate::RecordRef>,
    response: ResponseRef<'a>,
}

#[derive(Serialize)]
struct InteractiveRef<'a> {
    version: u16,
    authorization: Option<&'a SqlAuthorization>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    references: &'a BTreeSet<crate::RecordRef>,
    response: ResponseRef<'a>,
}

fn standalone_json(
    sequence: u64,
    results: &[SqlResult],
    authorization: Option<&SqlAuthorization>,
    table_authority: bool,
) -> Result<wal_decode::Owned<serde_json::Value>> {
    let response = ResponseRef::committed(sequence, results);
    if table_authority {
        wal_decode::json(&StandaloneRef {
            version: 2,
            authorization,
            references: &BTreeSet::new(),
            response,
        })
    } else {
        wal_decode::json(&response)
    }
}

fn interactive_json(
    sequence: u64,
    results: &[SqlResult],
    authorization: Option<&SqlAuthorization>,
) -> Result<wal_decode::Owned<serde_json::Value>> {
    wal_decode::json(&InteractiveRef {
        version: 1,
        authorization,
        references: &BTreeSet::new(),
        response: ResponseRef::committed(sequence, results),
    })
}

impl SqlCommitReceipt<'_> {
    pub(super) fn commit(
        self,
        sequence: u64,
        prepared: &PreparedRelationalExecution,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
    ) -> Result<CommittedTransaction> {
        // A one-shot test quota starts after the real session freeze/preparation,
        // isolating receipt refusal from earlier request/history admission.
        #[cfg(test)]
        if let Some(capacity) = TEST_COMMIT_CAPACITY.with(|limit| limit.take()) {
            return wal_decode::with_test_storage_pool(capacity, |used| {
                let result = self.commit(sequence, prepared, target, mutation, audit);
                assert!(result.is_err());
                assert_eq!(used(), 0);
                result
            });
        }
        let response = match &self {
            Self::Standalone {
                table_authority, ..
            } => standalone_json(
                sequence,
                &prepared.results,
                prepared.authorization.as_ref(),
                *table_authority,
            )?,
            Self::Interactive { authorization, .. } => {
                interactive_json(sequence, &prepared.results, *authorization)?
            }
        };
        response.consume(|response| match self {
            Self::Standalone { claim, .. } => claim.commit(target, mutation, audit, response),
            Self::Interactive {
                claim,
                transaction_id,
                decision_started,
                ..
            } => claim.commit_with_id_and_decision(
                transaction_id,
                target,
                mutation,
                audit,
                response,
                decision_started,
            ),
        })
    }
}

#[cfg(test)]
thread_local! {
    static TEST_COMMIT_CAPACITY: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results() -> Vec<SqlResult> {
        vec![
            SqlResult::Definition {
                affected_objects: 1,
            },
            SqlResult::Mutation { affected_rows: 2 },
            SqlResult::Explain {
                plan: vec!["scan 日本語".into()],
            },
            SqlResult::Rows {
                columns: vec![
                    "float".into(),
                    "vector".into(),
                    "json".into(),
                    "reference".into(),
                ],
                column_types: vec![
                    RelationalType::Float,
                    RelationalType::Vector { dimension: 2 },
                    RelationalType::Jsonb,
                    RelationalType::RecordRef {
                        namespace: "docs".into(),
                    },
                ],
                rows: vec![vec![
                    RelationalValue::Float(1.2345678901234567e300),
                    RelationalValue::Vector(vec![0.7181532, -0.0]),
                    RelationalValue::Json(
                        serde_json::json!({"unsigned":u64::MAX,"signed":i64::MIN,"zero":-0.0}),
                    ),
                    RelationalValue::RecordRef(crate::RecordRef {
                        namespace: "docs".into(),
                        id: "opaque-record".into(),
                    }),
                ]],
            },
        ]
    }

    fn authorization() -> SqlAuthorization {
        SqlAuthorization {
            tenant: "tenant".into(),
            schema: true,
            grants: BTreeSet::from([("legacy".into(), SecurityAction::Read)]),
            table_grants: BTreeSet::from([SqlTableRequirement {
                table: "docs".into(),
                table_id: 71,
                incarnation: uuid::Uuid::from_u128(19),
                creator_principal_id: Some("alice".into()),
                action: SecurityAction::Update,
            }]),
        }
    }

    #[test]
    fn borrowed_sql_receipts_preserve_legacy_shapes_bytes_and_numeric_bits() {
        let results = results();
        let authorization = authorization();
        let response = SqlExecutionResponse {
            transaction_id: None,
            snapshot: 17,
            committed: true,
            outcome: SqlOutcome::Committed,
            commit_sequence: Some(17),
            retryable: false,
            results: results.clone(),
        };
        for authorization in [None, Some(&authorization)] {
            for kind in 0..3 {
                let expected = match kind {
                    0 => serde_json::to_value(&response).unwrap(),
                    1 => serde_json::to_value(StandaloneCommitReceipt {
                        version: 2,
                        authorization: authorization.cloned(),
                        references: BTreeSet::new(),
                        response: response.clone(),
                    })
                    .unwrap(),
                    _ => serde_json::to_value(InteractiveCommitReceipt {
                        version: 1,
                        authorization: authorization.cloned(),
                        references: BTreeSet::new(),
                        response: response.clone(),
                    })
                    .unwrap(),
                };
                wal_decode::with_test_storage_pool(256 * 1024, |used| {
                    let actual = match kind {
                        0 | 1 => standalone_json(17, &results, authorization, kind == 1),
                        _ => interactive_json(17, &results, authorization),
                    }
                    .unwrap();
                    assert!(used() > 0);
                    assert_eq!(&*actual, &expected);
                    assert_eq!(
                        serde_json::to_vec(&*actual).unwrap(),
                        serde_json::to_vec(&expected).unwrap()
                    );
                    let result = if kind == 0 {
                        &actual["results"]
                    } else {
                        &actual["response"]["results"]
                    };
                    assert_eq!(
                        result[3]["rows"][0][0]["value"].as_f64().unwrap().to_bits(),
                        1.2345678901234567e300_f64.to_bits()
                    );
                    assert_eq!(
                        result[3]["rows"][0][1]["value"][0]
                            .as_f64()
                            .unwrap()
                            .to_bits(),
                        (0.7181532_f32 as f64).to_bits()
                    );
                    actual
                        .consume(|value| {
                            assert!(used() > 0);
                            let received = match kind {
                                0 => serde_json::from_value::<SqlExecutionResponse>(value).unwrap(),
                                1 => {
                                    serde_json::from_value::<StandaloneCommitReceipt>(value)
                                        .unwrap()
                                        .response
                                }
                                _ => {
                                    serde_json::from_value::<InteractiveCommitReceipt>(value)
                                        .unwrap()
                                        .response
                                }
                            };
                            assert_eq!(received, response);
                            Ok(())
                        })
                        .unwrap();
                    assert_eq!(used(), 0);
                });
            }
        }
    }

    #[test]
    fn borrowed_sql_returning_receipt_growth_is_bounded_and_releases_its_owner() {
        let results = vec![SqlResult::Rows {
            columns: vec!["body".into()],
            column_types: vec![RelationalType::Text],
            rows: (0..128)
                .map(|_| vec![RelationalValue::Text("日本語\n".repeat(128))])
                .collect(),
        }];
        let proof = authorization();
        let before = serde_json::to_vec(&results).unwrap();
        for table_authority in [false, true] {
            for capacity in [1, 4096, 16384] {
                wal_decode::with_test_storage_pool(capacity, |used| {
                    assert!(matches!(
                        standalone_json(17, &results, Some(&proof), table_authority),
                        Err(GaussError::ResourceExhausted(_))
                    ));
                    assert_eq!(used(), 0);
                });
            }
            wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
                let owned = standalone_json(17, &results, Some(&proof), table_authority).unwrap();
                let retained = used();
                assert!(retained >= before.len() as u64);
                owned
                    .consume(|_| {
                        assert_eq!(used(), retained);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(used(), 0);
                let error = standalone_json(17, &results, Some(&proof), table_authority)
                    .unwrap()
                    .consume::<()>(|_| Err(invalid("consumer refused")));
                assert!(error.is_err());
                assert_eq!(used(), 0);
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    standalone_json(17, &results, Some(&proof), table_authority)
                        .unwrap()
                        .consume::<()>(|_| panic!("consumer panic"))
                }));
                assert!(panic.is_err());
                assert_eq!(used(), 0);
                let cancelled = with_sql_cancellation(Arc::new(AtomicBool::new(true)), || {
                    standalone_json(17, &results, Some(&proof), table_authority)
                });
                assert!(
                    cancelled
                        .unwrap_err()
                        .to_string()
                        .contains("query canceled")
                );
                assert_eq!(used(), 0);
            });
        }
        assert_eq!(serde_json::to_vec(&results).unwrap(), before);
    }

    #[test]
    fn sql_receipt_refusal_preserves_decision_bytes_key_and_interactive_identity() {
        use crate::transaction_journal::IdempotencyAdmission;
        for interactive in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let journal = TransactionJournal::open(dir.path()).unwrap();
            let engine = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
            let owner = AuditContext::embedded();
            let request = |sql: &str| SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: sql.into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            };
            engine
                .execute(request(
                    "CREATE TABLE receipts (id BIGINT PRIMARY KEY, body TEXT)",
                ))
                .unwrap();
            let mut mutation = request("INSERT INTO receipts VALUES (1, $1) RETURNING id, body");
            mutation.statements[0].parameters =
                vec![RelationalValue::Text("日本語\n".repeat(4096))];
            mutation.idempotency_key = (!interactive).then(|| "bounded-sql-receipt".into());
            let handle = interactive.then(|| engine.begin_interactive(&owner).unwrap());
            if let Some(handle) = &handle {
                engine
                    .execute_interactive(&handle.handle, mutation.clone(), &owner)
                    .unwrap();
            }
            let mut prepared = prepare_execution(
                engine.state.read().clone(),
                mutation.clone(),
                true,
                true,
                None,
                None,
                false,
            )
            .unwrap();
            if interactive {
                prepared.results.clear();
            }
            let reserved = handle
                .as_ref()
                .map(|handle| handle.handle.parse::<TransactionId>().unwrap());
            let key = reserved
                .map(|id| format!("interactive:{id}"))
                .unwrap_or_else(|| mutation.idempotency_key.clone().unwrap());
            let claim = match reserved {
                Some(id) => {
                    journal.begin_idempotent(&key, &owner, "interactive_sql_commit", &id, || Ok(()))
                }
                None => journal.begin_idempotent(
                    &key,
                    &owner,
                    "sql_batch",
                    &mutation.statements,
                    || Ok(()),
                ),
            }
            .unwrap();
            let IdempotencyAdmission::Execute(claim) = claim else {
                panic!("fresh request must execute")
            };
            let before = fs::read(journal.dir().join("000000.gdwal")).unwrap();
            let marker = fs::read(
                dir.path()
                    .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER),
            )
            .unwrap();
            let frontier = journal.completed_commit_frontier().unwrap();
            for capacity in [1, 4096] {
                let entry = WalEntry::RelationalBatch {
                    batch: RelationalBatch {
                        sequence: prepared.snapshot + 1,
                        mutations: prepared.mutations.clone(),
                    },
                };
                let audit = TransactionAudit::mutation(
                    "sql_transaction",
                    None,
                    &owner,
                    serde_json::Value::Null,
                );
                wal_decode::with_test_storage_pool(capacity, |used| {
                    let decision_started = AtomicBool::new(false);
                    let receipt = match reserved {
                        Some(transaction_id) => SqlCommitReceipt::Interactive {
                            claim: &claim,
                            transaction_id,
                            authorization: None,
                            decision_started: &decision_started,
                        },
                        None => SqlCommitReceipt::Standalone {
                            claim: &claim,
                            table_authority: false,
                        },
                    };
                    let error = receipt
                        .commit(
                            prepared.snapshot + 1,
                            &prepared,
                            TransactionTarget::Relational,
                            entry,
                            audit,
                        )
                        .unwrap_err();
                    assert!(matches!(error, GaussError::ResourceExhausted(_)), "{error}");
                    assert!(!decision_started.load(AtomicOrdering::Acquire));
                    assert_eq!(used(), 0);
                });
                assert_eq!(
                    fs::read(journal.dir().join("000000.gdwal")).unwrap(),
                    before
                );
                assert_eq!(
                    fs::read(
                        dir.path()
                            .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER)
                    )
                    .unwrap(),
                    marker
                );
                assert_eq!(journal.completed_commit_frontier().unwrap(), frontier);
                assert_eq!(journal.committed().unwrap().len(), 1);
            }
            drop(claim);
            drop(prepared);
            let execute = |engine: &RelationalEngine| {
                match &handle {
                    Some(handle) => engine.commit_interactive(&handle.handle, &owner),
                    None => engine.execute_with_audit(mutation.clone(), &owner),
                }
                .unwrap()
                .response
            };
            let first = execute(&engine);
            if let Some(id) = reserved {
                assert_eq!(
                    first.transaction_id.as_deref(),
                    Some(id.to_string().as_str())
                );
            }
            assert_eq!(execute(&engine), first);
            assert_eq!(journal.committed().unwrap().len(), 2);
            drop(engine);
            drop(journal);
            let journal = TransactionJournal::open(dir.path()).unwrap();
            let reopened = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
            assert_eq!(execute(&reopened), first);
            assert_eq!(journal.committed().unwrap().len(), 2);
            let rows = reopened
                .execute(request("SELECT id, body FROM receipts"))
                .unwrap()
                .response;
            assert!(
                matches!(&rows.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1), mutation.statements[0].parameters[0].clone()]])
            );
        }
    }

    #[test]
    fn interactive_receipt_refusal_keeps_the_frozen_session_for_retry_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let engine = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
        let owner = AuditContext::embedded();
        let request = |sql: &str| SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: Vec::new(),
            }],
            retry_id: None,
            idempotency_key: None,
        };
        engine
            .execute(request(
                "CREATE TABLE frozen_receipt (id BIGINT PRIMARY KEY)",
            ))
            .unwrap();
        let handle = engine.begin_interactive(&owner).unwrap();
        engine
            .execute_interactive(
                &handle.handle,
                request("INSERT INTO frozen_receipt VALUES (1)"),
                &owner,
            )
            .unwrap();
        let before = fs::read(journal.dir().join("000000.gdwal")).unwrap();
        let marker = fs::read(
            dir.path()
                .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER),
        )
        .unwrap();
        let frontier = journal.completed_commit_frontier().unwrap();
        for capacity in [1, 4096] {
            TEST_COMMIT_CAPACITY.with(|limit| limit.set(Some(capacity)));
            let error = engine
                .commit_interactive(&handle.handle, &owner)
                .err()
                .expect("receipt quota must refuse the real commit");
            assert!(matches!(error, GaussError::ResourceExhausted(_)), "{error}");
            TEST_COMMIT_CAPACITY.with(|limit| {
                assert!(
                    limit.get().is_none(),
                    "real commit must reach receipt admission"
                )
            });
            assert_eq!(
                fs::read(journal.dir().join("000000.gdwal")).unwrap(),
                before
            );
            assert_eq!(
                fs::read(
                    dir.path()
                        .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER)
                )
                .unwrap(),
                marker
            );
            assert_eq!(journal.completed_commit_frontier().unwrap(), frontier);
            assert_eq!(engine.snapshots.active_count(), 1);
            let entry = engine
                .interactive
                .get(&handle.handle, &owner)
                .expect("pre-PREPARE receipt refusal must keep the original session active");
            let state = entry.lock(&handle.handle).unwrap();
            assert_eq!(state.as_ref().unwrap().history.statements().len(), 1);
            assert_eq!(
                state.as_ref().unwrap().history.statements()[0].sql,
                "INSERT INTO frozen_receipt VALUES (1)"
            );
        }
        let barrier = std::sync::Barrier::new(4);
        let replies = std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        engine
                            .commit_interactive(&handle.handle, &owner)
                            .unwrap()
                            .response
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(replies.iter().all(|reply| reply == &replies[0]));
        assert_eq!(replies[0].transaction_id, handle.transaction_id);
        assert_eq!(journal.committed().unwrap().len(), 2);
        assert_eq!(engine.snapshots.active_count(), 0);
        assert!(engine.interactive.is_empty().unwrap());
        drop(engine);
        drop(journal);
        let journal = TransactionJournal::open(dir.path()).unwrap();
        let reopened = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
        assert_eq!(
            reopened
                .commit_interactive(&handle.handle, &owner)
                .unwrap()
                .response,
            replies[0]
        );
        assert_eq!(journal.committed().unwrap().len(), 2);
        let rows = reopened
            .execute(request("SELECT id FROM frozen_receipt"))
            .unwrap()
            .response;
        assert!(
            matches!(&rows.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
        );
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn interactive_preparation_faults_keep_the_session_only_before_key_consumption() {
        for cut in [
            "transaction.before_prepare",
            "transaction.after_prepare",
            "transaction.before_commit_fsync",
            "transaction.after_commit",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let journal = TransactionJournal::open(dir.path()).unwrap();
            let engine = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
            let owner = AuditContext::embedded();
            let request = |sql: &str| SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: sql.into(),
                    parameters: Vec::new(),
                }],
                retry_id: None,
                idempotency_key: None,
            };
            engine
                .execute(request(
                    "CREATE TABLE receipt_fault (id BIGINT PRIMARY KEY)",
                ))
                .unwrap();
            let handle = engine.begin_interactive(&owner).unwrap();
            engine
                .execute_interactive(
                    &handle.handle,
                    request("INSERT INTO receipt_fault VALUES (1)"),
                    &owner,
                )
                .unwrap();
            let before = fs::read(journal.dir().join("000000.gdwal")).unwrap();
            let fault = crate::failpoint::test_env(
                &format!("error:{cut}"),
                &dir.path().join("marker"),
                &dir.path().join("release"),
            );
            let outcome = engine.commit_interactive(&handle.handle, &owner);
            drop(fault);
            if cut == "transaction.before_commit_fsync" {
                assert!(matches!(
                    outcome,
                    Err(GaussError::CommitOutcomeUnknown { .. })
                ));
                assert_eq!(engine.snapshots.active_count(), 0);
                assert!(engine.interactive.is_empty().unwrap());
                assert!(matches!(
                    engine.commit_interactive(&handle.handle, &owner),
                    Err(GaussError::CommitOutcomeUnknown { .. })
                ));
                assert_eq!(journal.committed().unwrap().len(), 1);
                drop(engine);
                drop(journal);
                // This injected ordinary error leaves the complete COMMIT frame
                // readable. Db recovery projects it; this is not a power-cut test.
                let db = crate::Db::open(dir.path()).unwrap();
                let receipt = db.commit_sql_transaction(&handle.handle, &owner).unwrap();
                assert_eq!(receipt.transaction_id, handle.transaction_id);
                assert!(receipt.committed);
                assert_eq!(
                    db.commit_sql_transaction(&handle.handle, &owner).unwrap(),
                    receipt
                );
                let count = db
                    .execute_sql(request("SELECT COUNT(*) FROM receipt_fault"))
                    .unwrap();
                assert!(
                    matches!(&count.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
                );
                continue;
            }
            let rejected = cut == "transaction.after_prepare";
            if cut == "transaction.before_prepare" {
                assert!(outcome.is_err());
                assert_eq!(
                    fs::read(journal.dir().join("000000.gdwal")).unwrap(),
                    before
                );
                assert_eq!(engine.snapshots.active_count(), 1);
                assert!(engine.interactive.get(&handle.handle, &owner).is_ok());
            } else {
                assert_eq!(outcome.is_err(), rejected);
                assert_eq!(engine.snapshots.active_count(), 0);
                assert!(engine.interactive.is_empty().unwrap());
            }
            let receipt = engine
                .commit_interactive(&handle.handle, &owner)
                .unwrap()
                .response;
            assert_eq!(receipt.transaction_id, handle.transaction_id);
            assert_eq!(receipt.committed, !rejected);
            assert_eq!(
                receipt.outcome,
                if rejected {
                    SqlOutcome::Rejected
                } else {
                    SqlOutcome::Committed
                }
            );
            if let Ok(first) = outcome {
                assert_eq!(first.response, receipt);
            }
            assert_eq!(
                engine
                    .commit_interactive(&handle.handle, &owner)
                    .unwrap()
                    .response,
                receipt
            );
            assert_eq!(
                journal.committed().unwrap().len(),
                if rejected { 1 } else { 2 }
            );
            assert_eq!(engine.snapshots.active_count(), 0);
            drop(engine);
            drop(journal);
            let journal = TransactionJournal::open(dir.path()).unwrap();
            let reopened = RelationalEngine::open(dir.path(), Arc::clone(&journal)).unwrap();
            assert_eq!(
                reopened
                    .commit_interactive(&handle.handle, &owner)
                    .unwrap()
                    .response,
                receipt
            );
            assert_eq!(
                journal.committed().unwrap().len(),
                if rejected { 1 } else { 2 }
            );
            let count = reopened
                .execute(request("SELECT COUNT(*) FROM receipt_fault"))
                .unwrap()
                .response;
            assert!(
                matches!(&count.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(i64::from(!rejected))]])
            );
        }
    }
}
