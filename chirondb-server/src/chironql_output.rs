//! Atomic ChironQL receipts remain typed/admitted until publication. Receiving
//! JSON rows are reserved before construction, without copying the SQL result.
pub(crate) mod query;
pub(crate) mod retrieval;
use crate::response_buffer::ResponseReservation;
use crate::security::AccessContext;
use crate::{GaussError, MultiModelResponse, Result, SqlResult};
use chirondb_types::chironql::{ChironQlKind, ChironQlResponse, ChironQlStats, ExecutionDomain};
pub use query::QueryResult;
use serde_json::Value;
use std::{mem::size_of, time::Instant};

pub(crate) struct AtomicOutput {
    receipt: MultiModelResponse,
    query_id: String,
    point_count: usize,
    graph_count: usize,
    started: Instant,
    _memory: ResponseReservation,
}
impl AtomicOutput {
    pub(crate) fn new(
        receipt: MultiModelResponse,
        point_count: usize,
        graph_count: usize,
        query_id: &str,
        started: Instant,
    ) -> Result<Self> {
        if receipt.publication_context().is_none() {
            return Err(crate::security::SecurityError::Unavailable.into());
        }
        let count = receipt
            .records
            .len()
            .checked_add(receipt.edge_ids.len())
            .ok_or_else(full)?;
        let columns = if receipt.records.is_empty() { 1 } else { 3 };
        // BTreeMap receiving nodes (including nested RECORD_REF fields) and
        // row slots; 1024 per slot conservatively covers node/control overhead.
        let mut bytes = (count as u64)
            .checked_mul(size_of::<Value>() as u64 + columns * 1024)
            .and_then(|n| n.checked_add((receipt.records.len() as u64).checked_mul(2048)?))
            .and_then(|n| n.checked_add(4096))
            .and_then(|n| n.checked_add(query_id.len() as u64))
            .ok_or_else(full)?;
        for (binding, record) in &receipt.records {
            bytes = bytes
                .checked_add(binding.capacity() as u64)
                .and_then(|n| n.checked_add(record.namespace.capacity() as u64))
                .and_then(|n| n.checked_add(record.id.capacity() as u64))
                .ok_or_else(full)?;
        }
        for edge in &receipt.edge_ids {
            bytes = bytes.checked_add(edge.capacity() as u64).ok_or_else(full)?;
        }
        if let Some(id) = &receipt.sql.transaction_id {
            bytes = bytes.checked_add(id.capacity() as u64).ok_or_else(full)?;
        }
        let memory = ResponseReservation::new(bytes)?;
        Ok(Self {
            receipt,
            query_id: query_id.into(),
            point_count,
            graph_count,
            started,
            _memory: memory,
        })
    }
    pub(crate) fn publication_context(&self) -> AccessContext {
        self.receipt
            .publication_context()
            .expect("validated atomic publication context")
            .clone()
    }
    pub(crate) fn publish<T>(self, publish: impl FnOnce(ChironQlResponse) -> T) -> Result<T> {
        let Self {
            receipt,
            query_id,
            point_count,
            graph_count,
            started,
            _memory,
        } = self;
        let _permit = receipt
            .publication_context()
            .expect("validated atomic publication context")
            .publication_permit()?;
        receipt.consume(|receipt| {
            let affected = receipt
                .sql
                .results
                .iter()
                .map(|result| match result {
                    SqlResult::Mutation { affected_rows } => *affected_rows,
                    SqlResult::Rows { rows, .. } => rows.len() as u64,
                    SqlResult::Definition { affected_objects } => *affected_objects,
                    SqlResult::Explain { .. } => 0,
                })
                .sum::<u64>()
                .saturating_add(point_count as u64)
                .saturating_add(graph_count as u64);
            let bound = receipt.records.len() + receipt.edge_ids.len();
            let mut rows = Vec::new();
            rows.try_reserve_exact(bound).map_err(|_| full())?;
            let columns = if !receipt.records.is_empty() {
                for (binding, record) in receipt.records {
                    rows.push(object([
                        ("binding", Value::String(binding)),
                        (
                            "record_ref",
                            object([
                                ("namespace", Value::String(record.namespace)),
                                ("id", Value::String(record.id)),
                            ]),
                        ),
                        ("edge_id", Value::Null),
                    ]));
                }
                for id in receipt.edge_ids {
                    rows.push(object([
                        ("binding", Value::Null),
                        ("record_ref", Value::Null),
                        ("edge_id", Value::String(id.into_encoded())),
                    ]));
                }
                vec!["binding".into(), "record_ref".into(), "edge_id".into()]
            } else if !receipt.edge_ids.is_empty() {
                for id in receipt.edge_ids {
                    rows.push(object([("edge_id", Value::String(id.into_encoded()))]));
                }
                vec!["edge_id".into()]
            } else {
                Vec::new()
            };
            Ok(publish(ChironQlResponse {
                kind: ChironQlKind::Affected,
                columns,
                column_types: Vec::new(),
                rows,
                stats: ChironQlStats {
                    affected: Some(affected),
                    graph_epoch: Some(receipt.graph.graph_epoch.raw()),
                    operation_lsn: receipt.graph.operation_lsn,
                    durable: Some(receipt.graph.durable),
                    replayed: Some(receipt.graph.replayed),
                    took_ms: started.elapsed().as_secs_f64() * 1000.0,
                    ..Default::default()
                },
                next: None,
                query_id,
                domains: vec![
                    ExecutionDomain::Relational,
                    ExecutionDomain::Vector,
                    ExecutionDomain::Graph,
                ],
                snapshot_id: Some(format!("multi-model:{}", receipt.sql.snapshot)),
                transaction_id: receipt.sql.transaction_id,
                committed: Some(receipt.sql.committed),
                trace: None,
                credential: None,
            }))
        })
    }
}
fn full() -> GaussError {
    GaussError::ResourceExhausted("ChironQL result memory limit exceeded".into())
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.into(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::ConfigureEdgeTypeRequest;
    use crate::security::*;
    use crate::{Db, MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    // Product onboarding installs a process keyring. Keep each fixture in a
    // fresh child so it cannot change another test's encryption state.
    fn parent(name: &str) -> bool {
        const CHILD: &str = "CHIRON_TEST_ATOMIC_OUTPUT_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return false;
        }
        let full = format!("chironql_output::tests::{name}");
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &full, "--nocapture"])
                .env(CHILD, name)
                .status()
                .unwrap()
                .success()
        );
        true
    }
    fn fixture() -> (tempfile::TempDir, Db, String) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let data = root.join("data");
        let key_out = root.join("admin.key");
        onboarding::initialize(
            &data,
            "acme",
            "admin",
            &root.join("storage.json"),
            &key_out,
            false,
        )
        .unwrap();
        let key = std::fs::read_to_string(&key_out).unwrap().trim().to_owned();
        let db = Db::open(&data).unwrap();
        let authority = db.identity_authority().unwrap();
        let actor = authority.authenticate(&key).unwrap();
        db.create_protected_collection_authorized(
            &actor,
            db.catalog_revision_authorized(&actor).unwrap(),
            serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap(),
        )
        .unwrap();
        db.execute_sql_authorized(&actor,serde_json::from_value(json!({"statements":[{"sql":"CREATE TABLE metadata (id INTEGER PRIMARY KEY, chunk RECORD_REF('docs'), source RECORD_REF('docs'))"}]})).unwrap(),"output-test").unwrap();
        let mut principal = actor.principal().clone();
        principal.grants.push(ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into(), "metadata".into()]),
            actions: BTreeSet::from([
                Action::Read,
                Action::Create,
                Action::Update,
                Action::Delete,
                Action::Ingest,
                Action::GraphRead,
                Action::GraphWrite,
                Action::Schema,
                Action::PolicyManage,
            ]),
        });
        authority
            .put_principal(&actor, actor.revision(), principal)
            .unwrap();
        let actor = authority.authenticate(&key).unwrap();
        let schema = db
            .bind_access(&actor, "docs", "acme", Action::Schema)
            .unwrap();
        let (revision, _) = db
            .set_graph_lifecycle_authorized(&schema, schema.policy_revision(), true)
            .unwrap()
            .publish(|value| value)
            .unwrap();
        let schema = db
            .bind_access(&actor, "docs", "acme", Action::Schema)
            .unwrap();
        let (revision, _) = db
            .configure_edge_type_authorized(
                &schema,
                revision,
                ConfigureEdgeTypeRequest {
                    name: "cites".into(),
                    weight_property: None,
                },
            )
            .unwrap()
            .publish(|value| value)
            .unwrap();
        let manage = db
            .bind_access(&actor, "docs", "acme", Action::PolicyManage)
            .unwrap();
        db.replace_collection_policy_authorized(
            &manage,
            RevisionUpdate {
                expected_revision: revision,
                value: CollectionPolicy {
                    department_actions: BTreeSet::new(),
                    owner_actions: BTreeSet::from([
                        Action::Read,
                        Action::GraphRead,
                        Action::GraphWrite,
                    ]),
                    templates: BTreeMap::from([(
                        "standard".into(),
                        IngestTemplate {
                            department: "Security".into(),
                            classification: Classification::Internal,
                            properties: BTreeMap::from([(
                                "/text".into(),
                                PropertyRule {
                                    classification: Classification::Internal,
                                    actions: BTreeSet::from([
                                        PropertyAction::Read,
                                        PropertyAction::Query,
                                        PropertyAction::Write,
                                    ]),
                                },
                            )]),
                            representations: BTreeMap::from([(
                                "dense".into(),
                                Representation {
                                    source_fields: BTreeSet::from(["/text".into()]),
                                    classification: Classification::Internal,
                                },
                            )]),
                        },
                    )]),
                },
            },
        )
        .unwrap();
        (directory, db, key)
    }
    fn request() -> MultiModelInsertRequest {
        MultiModelInsertRequest {
            sql:serde_json::from_value(json!({"statements":[{"sql":"INSERT INTO metadata VALUES (1, RECORD_REF('docs', NEW_RECORD('chunk')), RECORD_REF('docs', NEW_RECORD('source')))"}],"idempotency_key":"atomic-output-key"})).unwrap(),
            collection:"docs".into(),template:"standard".into(),
            records:[("chunk",[1.0,0.0]),("source",[0.0,1.0])].into_iter().map(|(binding,vector)|NewRecord {binding:binding.into(),point:NewPoint {vector:vector.to_vec(),vectors:BTreeMap::new(),sparse_vector:None,payload:json!({"text":binding})}}).collect(),
            relations:vec![NewRelation {source:RecordEndpoint::New("chunk".into()),target:RecordEndpoint::New("source".into()),edge_type:"cites".into(),properties:json!({})}],
        }
    }
    fn result(db: &Db, key: &str) -> MultiModelResponse {
        let actor = db.identity_authority().unwrap().authenticate(key).unwrap();
        db.insert_multimodel_authorized_with_sql_rows_owned(
            &actor,
            request(),
            "output-test",
            Some(1),
        )
        .unwrap()
    }
    #[test]
    fn protected_atomic_output_preserves_ids_shape_and_codec_last_frame_ownership() {
        if parent("protected_atomic_output_preserves_ids_shape_and_codec_last_frame_ownership") {
            return;
        }
        let (_directory, db, key) = fixture();
        let receipt = result(&db, &key);
        let transaction_id = receipt.sql.transaction_id.clone();
        let records = receipt.records.clone();
        let edges = receipt.edge_ids.clone();
        let output = AtomicOutput::new(receipt, 2, 1, "query-id", Instant::now()).unwrap();
        let (message, admission) = output
            .publish(crate::response_output::chironql)
            .unwrap()
            .unwrap();
        assert_eq!(message.kind, "affected");
        assert_eq!(message.columns, ["binding", "record_ref", "edge_id"]);
        assert_eq!(message.transaction_id, transaction_id);
        let rows = message
            .rows_json
            .iter()
            .map(|row| serde_json::from_str::<Value>(row).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                json!({"binding":"chunk","record_ref":records["chunk"],"edge_id":null}),
                json!({"binding":"source","record_ref":records["source"],"edge_id":null}),
                json!({"binding":null,"record_ref":null,"edge_id":edges[0]})
            ]
        );
        let stats: Value = serde_json::from_str(&message.stats_json).unwrap();
        assert_eq!(stats["affected"], 4);
        assert_eq!(stats["durable"], true);
        assert_eq!(stats["replayed"], false);
        let weak = std::sync::Arc::downgrade(&admission);
        let frame = crate::response_output::retain_frame(
            axum::body::Bytes::from(prost::Message::encode_to_vec(&message)),
            admission,
        );
        let last = frame.slice(frame.len() - 1..);
        drop(frame);
        drop(message);
        assert!(weak.upgrade().is_some());
        drop(last);
        assert!(weak.upgrade().is_none());
        let replay = result(&db, &key);
        assert_eq!(replay.records, records);
        assert_eq!(replay.edge_ids, edges);
        assert_eq!(replay.sql.transaction_id, transaction_id);
        let output = AtomicOutput::new(replay, 2, 1, "retry", Instant::now()).unwrap();
        assert!(
            output
                .publish(|value| value.stats.replayed.unwrap())
                .unwrap()
        );
    }
    #[test]
    fn protected_atomic_output_rechecks_revoke_before_json_construction_or_publication() {
        if parent("protected_atomic_output_rechecks_revoke_before_json_construction_or_publication")
        {
            return;
        }
        let (_directory, db, key) = fixture();
        let receipt = result(&db, &key);
        let output = crate::chironql_protected::Output::Transaction(
            AtomicOutput::new(receipt, 2, 1, "queued", Instant::now()).unwrap(),
        );
        let guard = output.guard();
        let authority = db.identity_authority().unwrap();
        let actor = authority.authenticate(&key).unwrap();
        let mut principal = actor.principal().clone();
        principal.grants[0].actions.remove(&Action::Create);
        principal.grants[0].actions.remove(&Action::Read);
        authority
            .put_principal(&actor, actor.revision(), principal)
            .unwrap();
        let mut published = false;
        assert!(output.publish(|_| published = true).is_err());
        assert!(!published);
        assert!(guard.publish(|| published = true).is_err());
        assert!(!published);
        let fresh = authority.authenticate(&key).unwrap();
        assert!(
            db.insert_multimodel_authorized_owned(&fresh, request(), "denied-retry")
                .is_err()
        );
    }
    #[test]
    fn receiving_encoding_refusal_preserves_committed_key_and_allocated_ids() {
        if parent("receiving_encoding_refusal_preserves_committed_key_and_allocated_ids") {
            return;
        }
        let (_directory, db, key) = fixture();
        let receipt = result(&db, &key);
        let records = receipt.records.clone();
        let edges = receipt.edge_ids.clone();
        let transaction_id = receipt.sql.transaction_id.clone();
        let output = AtomicOutput::new(receipt, 2, 1, "bounded", Instant::now()).unwrap();
        let refusal = output
            .publish(|value| crate::response_buffer::ResponseBuffer::json(&value, 8))
            .unwrap();
        assert!(matches!(refusal, Err(GaussError::ResourceExhausted(_))));
        let replay = result(&db, &key);
        assert_eq!(replay.sql.transaction_id, transaction_id);
        assert_eq!(replay.records, records);
        assert_eq!(replay.edge_ids, edges);
        assert!(replay.graph.replayed);
    }
}
