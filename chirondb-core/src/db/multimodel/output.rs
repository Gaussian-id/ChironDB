//! Full multi-model result lifetime, including SQL, edges and allocated bindings.
use super::*;
use crate::relational::wal_decode::{self, MetadataCharge, Reservation};
use std::mem::size_of;

/// Atomic result and unique receiving reservations. Public DTO fields/versions
/// are unchanged; transports retain this owner through consumption or encoding.
pub struct MultiModelResponse {
    value: MultiModelTransactionResponse,
    _sql: Option<Reservation>,
    _memory: Reservation,
}
impl std::ops::Deref for MultiModelResponse {
    type Target = MultiModelTransactionResponse;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl Serialize for MultiModelResponse {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
impl std::fmt::Debug for MultiModelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}
impl MultiModelResponse {
    pub(super) fn decoded(value: wal_decode::Owned<MultiModelTransactionResponse>) -> Self {
        let (value, memory) = value.into_parts();
        Self {
            value,
            _sql: None,
            _memory: memory,
        }
    }
    pub(in crate::db) fn fresh(
        sql: crate::SqlResponse,
        graph: GraphMutationReceipt,
        edge_ids: Vec<EdgeToken>,
        metadata: ResponseMetadata,
    ) -> Self {
        let (sql, sql_memory) = sql.into_parts();
        let ResponseMetadata { records, _memory } = metadata;
        Self {
            value: MultiModelTransactionResponse {
                sql,
                graph,
                edge_ids,
                records,
                publication: None,
            },
            _sql: Some(sql_memory),
            _memory,
        }
    }
    pub(in crate::db) fn set_publication(&mut self, context: AccessContext) {
        self.value.publication = Some(context);
    }
    /// Embedded DTO handoff: the application assumes its retained memory budget.
    pub fn into_dto(self) -> MultiModelTransactionResponse {
        self.value
    }
    /// Consume synchronously, keeping source reservation through receiving
    /// allocation. Returned data must have its own receiving reservation.
    pub fn consume<T>(
        self,
        consumer: impl FnOnce(MultiModelTransactionResponse) -> Result<T>,
    ) -> Result<T> {
        let Self {
            value,
            _sql,
            _memory,
        } = self;
        consumer(value)
    }
}

pub(in crate::db) struct ResponseMetadata {
    records: BTreeMap<String, crate::RecordRef>,
    _memory: Reservation,
}
impl ResponseMetadata {
    pub(in crate::db) fn prepare(
        edge_ids: &Vec<EdgeToken>,
        records: Option<&BTreeMap<String, crate::RecordRef>>,
    ) -> Result<Self> {
        #[cfg(test)]
        if let Some(capacity) = TEST_METADATA_CAPACITY.with(|cap| cap.take()) {
            return wal_decode::with_test_storage_pool(capacity, |used| {
                let result = Self::prepare(edge_ids, records);
                assert!(matches!(result, Err(GaussError::ResourceExhausted(_))));
                assert_eq!(used(), 0);
                result
            });
        }
        let mut bytes = 1024_u64
            .checked_add(
                (edge_ids.capacity() as u64)
                    .checked_mul(size_of::<EdgeToken>() as u64)
                    .ok_or_else(full)?,
            )
            .ok_or_else(full)?;
        for edge in edge_ids {
            bytes = bytes.checked_add(edge.capacity() as u64).ok_or_else(full)?;
        }
        if let Some(records) = records {
            bytes = bytes
                .checked_add((records.len() as u64).checked_mul(1024).ok_or_else(full)?)
                .ok_or_else(full)?;
            for (binding, record) in records {
                bytes = bytes
                    .checked_add(binding.capacity() as u64)
                    .and_then(|n| n.checked_add(record.namespace.capacity() as u64))
                    .and_then(|n| n.checked_add(record.id.capacity() as u64))
                    .ok_or_else(full)?;
            }
        }
        let mut memory = MetadataCharge::default();
        memory.prepare(bytes)?;
        // Copy binding nodes/strings only after admission and before COMMIT.
        Ok(Self {
            records: records.cloned().unwrap_or_default(),
            _memory: memory.into_reservation(),
        })
    }
}
fn full() -> GaussError {
    GaussError::ResourceExhausted("multi-model result memory limit exceeded".into())
}

#[cfg(test)]
thread_local! {
    static TEST_METADATA_CAPACITY: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{ConfigureEdgeTypeRequest, GraphRelationScope, RelateRequest};
    use crate::response_buffer::ResponseBuffer;
    use crate::tenant::TenantScope;
    use crate::{RelationalValue, SqlExecutionRequest, SqlResult, SqlStatementRequest};

    fn sql(statement: &str) -> SqlExecutionRequest {
        SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: statement.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        }
    }
    fn fixture() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path()).unwrap();
        db.create_collection(
            serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
        )
        .unwrap();
        db.set_graph_lifecycle_scoped("docs", true, true, &TenantScope::system())
            .unwrap();
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: "cites".into(),
                weight_property: None,
            },
            true,
            &TenantScope::system(),
        )
        .unwrap();
        db.execute_sql(sql(
            "CREATE TABLE metadata (id INTEGER PRIMARY KEY, title TEXT) ",
        ))
        .unwrap();
        db.execute_sql(SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "INSERT INTO metadata VALUES (1, $1)".into(),
                parameters: vec![RelationalValue::Text("\n日本語".repeat(4096))],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .unwrap();
        (dir, db)
    }
    fn edges() -> Vec<EdgeToken> {
        let mut value = String::with_capacity(8192);
        value.push_str("opaque-edge");
        let mut edges = Vec::with_capacity(17);
        edges.push(EdgeToken::from_encoded(value));
        edges
    }
    fn records() -> BTreeMap<String, crate::RecordRef> {
        BTreeMap::from([(
            "binding".into(),
            crate::RecordRef {
                namespace: "docs".into(),
                id: "opaque-record".into(),
            },
        )])
    }
    fn graph() -> GraphMutationReceipt {
        GraphMutationReceipt {
            graph_epoch: GraphEpoch::from_raw(17).unwrap(),
            operation_lsn: Some(19),
            durable: true,
            replayed: false,
        }
    }
    fn fresh(db: &Db) -> MultiModelResponse {
        let edge_ids = edges();
        let metadata = ResponseMetadata::prepare(&edge_ids, Some(&records())).unwrap();
        MultiModelResponse::fresh(
            db.execute_sql_owned(sql("SELECT title FROM metadata"))
                .unwrap(),
            graph(),
            edge_ids,
            metadata,
        )
    }
    #[test]
    fn multimodel_output_retains_sql_edges_bindings_and_receiving_overlap() {
        let (_dir, db) = fixture();
        wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let output = fresh(&db);
            let source_bytes = used();
            assert!(source_bytes > 16000);
            let row_ptr = match &output.sql.results[0] {
                SqlResult::Rows { rows, .. } => rows.as_ptr(),
                _ => unreachable!(),
            };
            let edge_ptr = output.edge_ids.as_ptr();
            let expected = serde_json::to_vec(&*output).unwrap();
            assert_eq!(serde_json::to_vec(&output).unwrap(), expected);
            let receiving = output
                .consume(|value| {
                    assert_eq!(used(), source_bytes);
                    assert_eq!(value.edge_ids.as_ptr(), edge_ptr);
                    assert_eq!(
                        match &value.sql.results[0] {
                            SqlResult::Rows { rows, .. } => rows.as_ptr(),
                            _ => unreachable!(),
                        },
                        row_ptr
                    );
                    let encoded = ResponseBuffer::json_native(&value, 1024 * 1024)?;
                    assert!(used() > source_bytes);
                    assert_eq!(encoded.as_ref(), expected);
                    Ok(encoded)
                })
                .unwrap();
            assert!(used() > 0);
            assert!(used() < source_bytes + 1024 * 1024);
            drop(receiving);
            assert_eq!(used(), 0);
            let value = fresh(&db).into_dto();
            assert_eq!(used(), 0);
            assert_eq!(serde_json::to_vec(&value).unwrap(), expected);
        });
    }
    #[test]
    fn multimodel_metadata_counts_spare_capacity_and_refuses_before_binding_copy() {
        let edges = edges();
        let bindings = records();
        let before = serde_json::to_vec(&bindings).unwrap();
        wal_decode::with_test_storage_pool(8192, |used| {
            assert!(matches!(
                ResponseMetadata::prepare(&edges, Some(&bindings)),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        wal_decode::with_test_storage_pool(65536, |used| {
            let metadata = ResponseMetadata::prepare(&edges, Some(&bindings)).unwrap();
            assert!(used() >= edges[0].capacity() as u64);
            assert_eq!(metadata.records, bindings);
            drop(metadata);
            assert_eq!(used(), 0);
        });
        assert_eq!(serde_json::to_vec(&bindings).unwrap(), before);
        assert_eq!(edges[0].as_str(), "opaque-edge");
    }
    #[test]
    fn multimodel_consumer_refusal_and_unwind_release_all_result_reservations() {
        let (_dir, db) = fixture();
        wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let result = fresh(&db).consume(|value| ResponseBuffer::json_native(&value, 8));
            assert!(matches!(result, Err(GaussError::ResourceExhausted(_))));
            assert_eq!(used(), 0);
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fresh(&db).consume::<()>(|_| panic!("receiving consumer unwind"))
            }));
            assert!(caught.is_err());
            assert_eq!(used(), 0);
        });
    }
    fn transaction() -> MultiModelTransactionRequest {
        MultiModelTransactionRequest {
            sql: SqlExecutionRequest {
                idempotency_key: Some("owned-attempt".into()),
                ..sql("INSERT INTO metadata VALUES (2, 'atomic')")
            },
            collection: "docs".into(),
            points: ["chunk", "source"]
                .into_iter()
                .map(|id| crate::Point {
                    id: id.into(),
                    vector: vec![1.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::json!({}),
                })
                .collect(),
            point_deletes: vec![],
            relations: vec![RelateRequest {
                source_point_id: "chunk".into(),
                target_point_id: "source".into(),
                edge_type: "cites".into(),
                properties: serde_json::json!({}),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            }],
            edge_deletes: vec![],
            edge_updates: vec![],
        }
    }
    #[test]
    fn multimodel_metadata_refusal_precedes_commit_and_same_key_can_retry_once() {
        let (dir, db) = fixture();
        let audit = AuditContext::embedded();
        let scope = TenantScope::system();
        let count = db.transaction_journal.committed().unwrap().len();
        let before = std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap();
        TEST_METADATA_CAPACITY.with(|cap| cap.set(Some(1)));
        assert!(matches!(
            db.execute_multimodel_transaction_owned(transaction(), &scope, &audit),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(db.transaction_journal.committed().unwrap().len(), count);
        assert_eq!(
            std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap(),
            before
        );
        assert!(
            db.get_points("docs", &["chunk".into(), "source".into()])
                .unwrap()
                .is_empty()
        );
        assert!(
            matches!(&db.execute_sql(sql("SELECT id FROM metadata WHERE id = 2")).unwrap().results[0],SqlResult::Rows {rows,..} if rows.is_empty())
        );
        let original = db
            .execute_multimodel_transaction_with_sql_rows_owned(transaction(), &scope, &audit, None)
            .unwrap();
        let transaction_id = original.sql.transaction_id.clone();
        let edge_ids = original.edge_ids.clone();
        drop(original);
        assert_eq!(db.transaction_journal.committed().unwrap().len(), count + 1);
        let replay = db
            .execute_multimodel_transaction_owned(transaction(), &scope, &audit)
            .unwrap();
        assert_eq!(replay.sql.transaction_id, transaction_id);
        assert_eq!(replay.edge_ids, edge_ids);
        assert!(replay.graph.replayed);
        assert_eq!(replay.graph.operation_lsn, None);
        drop(replay);
        drop(db);
        let reopened = Db::open(dir.path()).unwrap();
        let replay = reopened
            .execute_multimodel_transaction_owned(transaction(), &scope, &audit)
            .unwrap();
        assert_eq!(replay.sql.transaction_id, transaction_id);
        assert_eq!(replay.edge_ids, edge_ids);
        assert_eq!(
            reopened.transaction_journal.committed().unwrap().len(),
            count + 1
        );
    }
    #[test]
    fn multimodel_replay_is_borrowed_admitted_and_never_reexecutes_after_refusal() {
        let (_dir, db) = fixture();
        let audit = AuditContext::embedded();
        let scope = TenantScope::system();
        let original = db
            .execute_multimodel_transaction_owned(transaction(), &scope, &audit)
            .unwrap();
        let transaction_id = original.sql.transaction_id.clone();
        let edge_ids = original.edge_ids.clone();
        drop(original);
        let before = std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap();
        let count = db.transaction_journal.committed().unwrap().len();
        for capacity in [1, 4096] {
            let receipt = match db
                .admit_multimodel(&transaction(), &audit, None, None, None)
                .unwrap()
                .unwrap()
            {
                IdempotencyAdmission::Replay(receipt) => receipt,
                _ => panic!(),
            };
            let serialized = serde_json::to_vec(&receipt.response).unwrap();
            wal_decode::with_test_storage_pool(capacity, |used| {
                // Keep the original JSON and mutation owner alive through refusal.
                let encoded = receipt.response.as_ref().unwrap();
                assert!(matches!(
                    wal_decode::borrowed::<Receipt>(encoded),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
                assert_eq!(serde_json::to_vec(&receipt.response).unwrap(), serialized);
                assert!(matches!(
                    db.replay_multimodel(receipt, None),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(used(), 0);
            });
        }
        wal_decode::with_test_storage_pool(4 * 1024 * 1024, |used| {
            let replay = db
                .execute_multimodel_transaction_owned(transaction(), &scope, &audit)
                .unwrap();
            assert_eq!(replay.sql.transaction_id, transaction_id);
            assert_eq!(replay.edge_ids, edge_ids);
            assert!(used() > 0);
            drop(replay);
            assert_eq!(used(), 0);
        });
        assert_eq!(
            std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap(),
            before
        );
        assert_eq!(db.transaction_journal.committed().unwrap().len(), count);
    }
    #[test]
    fn multimodel_replay_rejects_bad_version_malformed_proof_and_expiry_without_decision_change() {
        let (_dir, db) = fixture();
        let audit = AuditContext::embedded();
        let scope = TenantScope::system();
        drop(
            db.execute_multimodel_transaction_owned(transaction(), &scope, &audit)
                .unwrap(),
        );
        let before = std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap();
        let replay = || match db
            .admit_multimodel(&transaction(), &audit, None, None, None)
            .unwrap()
            .unwrap()
        {
            IdempotencyAdmission::Replay(receipt) => receipt,
            _ => panic!(),
        };
        for version in [0, 2] {
            let mut receipt = replay();
            receipt.response.as_mut().unwrap()["version"] = serde_json::json!(version);
            assert!(matches!(
                db.replay_multimodel(receipt, None),
                Err(GaussError::WalUnavailable(_))
            ));
        }
        let mut receipt = replay();
        receipt.response.as_mut().unwrap()["authorization"] =
            serde_json::json!({"incarnation":uuid::Uuid::nil()});
        assert!(db.replay_multimodel(receipt, None).is_err());
        for state in [
            TransactionState::Rejected,
            TransactionState::OutcomeUnknown,
            TransactionState::Expired,
        ] {
            let mut receipt = replay();
            receipt.status.state = state;
            receipt.response = Some(serde_json::json!({"invalid":"must not decode"}));
            wal_decode::with_test_storage_pool(1, |used| {
                let error = db.replay_multimodel(receipt, None).unwrap_err();
                assert!(!matches!(error, GaussError::ResourceExhausted(_)));
                assert_eq!(used(), 0);
            });
        }
        let mut receipt = replay();
        receipt.expired = true;
        receipt.response = Some(serde_json::Value::Null);
        assert!(
            db.replay_multimodel(receipt, None)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert_eq!(
            std::fs::read(db.transaction_journal.dir().join("000000.gdwal")).unwrap(),
            before
        );
    }
}
