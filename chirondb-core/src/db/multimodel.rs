//! Request identity and protected receipt authorization for atomic multi-model writes.
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::{Duration, Instant};

mod insert;
mod output;
pub(super) use insert::InsertCommit;
pub use insert::{MultiModelInsertRequest, NewRecord, NewRelation, RecordEndpoint};
pub use output::MultiModelResponse;
pub(super) use output::ResponseMetadata;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Collection, Db, MultiModelTransactionRequest, MultiModelTransactionResponse};
use crate::audit::AuditContext;
use crate::graph::{EdgeToken, GraphEpoch, GraphMutationReceipt};
use crate::relational::SqlAuthorization;
use crate::security::{AccessContext, Action, AuthenticatedIdentity, SecurityError};
use crate::transaction_journal::{
    CommittedTransaction, IdempotencyAdmission, IdempotencyGuard, IdempotencyReceipt,
    TransactionAudit, TransactionState, TransactionTarget,
};
use crate::wal::WalEntry;
use crate::{GaussError, Result, SqlExecutionResponse};

#[derive(Serialize)]
struct FingerprintPoint<'a> {
    id: &'a str,
    vector: &'a [f32],
    vectors: BTreeMap<&'a str, &'a [f32]>,
    sparse_vector: &'a Option<crate::SparseVector>,
    payload: &'a serde_json::Value,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authorization {
    incarnation: Uuid,
    sql: SqlAuthorization,
    vector_action: Action,
    #[serde(default)]
    read: BTreeSet<(String, Uuid)>,
    #[serde(default)]
    ingest: bool,
    retired: BTreeSet<String>,
    vector: BTreeSet<(String, Uuid)>,
    graph: BTreeSet<(String, Uuid)>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u16,
    authorization: Option<Authorization>,
    response: MultiModelTransactionResponse,
}

#[derive(Serialize)]
struct ReceiptRef<'a> {
    version: u16,
    authorization: Option<&'a Authorization>,
    response: ResponseRef<'a>,
}

#[derive(Serialize)]
struct ResponseRef<'a> {
    sql: &'a SqlExecutionResponse,
    graph: GraphMutationReceipt,
    edge_ids: &'a [EdgeToken],
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    records: &'a BTreeMap<String, crate::RecordRef>,
}

pub(super) struct CommitOptions<'a> {
    pub claim: Option<&'a IdempotencyGuard>,
    pub authorization: Option<&'a Authorization>,
    pub insert: Option<&'a InsertCommit<'a>>,
    pub decision_started: Option<&'a std::sync::atomic::AtomicBool>,
    pub expected_sql_rows: Option<u64>,
    pub references: Option<&'a crate::security::DataReferenceAuthorization<'a>>,
}

pub(crate) struct CommitReceipt<'a> {
    pub claim: Option<&'a IdempotencyGuard>,
    pub authorization: Option<&'a Authorization>,
    pub graph_epoch: GraphEpoch,
    pub edge_ids: &'a [EdgeToken],
    pub insert: Option<&'a InsertCommit<'a>>,
    pub decision_started: Option<&'a std::sync::atomic::AtomicBool>,
    pub expected_sql_rows: Option<u64>,
    pub references: Option<&'a crate::security::DataReferenceAuthorization<'a>>,
}

impl CommitReceipt<'_> {
    pub(crate) fn commit(
        self,
        journal: &crate::transaction_journal::TransactionJournal,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        sql: &SqlExecutionResponse,
        validate_references: impl FnOnce(
            &crate::security::DataReferenceAuthorization<'_>,
            &mut BTreeSet<(String, Uuid)>,
            &BTreeSet<String>,
        ) -> Result<()>,
    ) -> Result<CommittedTransaction> {
        if let Some(expected) = self.expected_sql_rows {
            let actual = sql.results.iter().try_fold(0_u64, |total, result| {
                let rows = match result {
                    crate::SqlResult::Mutation { affected_rows } => *affected_rows,
                    crate::SqlResult::Rows { rows, .. } => rows.len() as u64,
                    _ => {
                        return Err(GaussError::InvalidRequest(
                            "SQL row preconditions require DML statements".into(),
                        ));
                    }
                };
                total.checked_add(rows).ok_or_else(|| {
                    GaussError::ResourceExhausted("SQL affected row count overflow".into())
                })
            })?;
            if actual != expected {
                return Err(GaussError::SqlRowPreconditionFailed { expected, actual });
            }
        }
        let mut authorization = self.authorization.cloned();
        if let Some(references) = self.references {
            let proof = authorization.as_mut().ok_or(SecurityError::Unavailable)?;
            validate_references(references, &mut proof.read, &proof.retired)?;
        }
        if let Some(insert) = self.insert {
            insert.authorize_references(
                &mutation,
                authorization.as_mut().ok_or(SecurityError::Unavailable)?,
            )?;
        }
        // CREATE carries its lease in InsertCommit; UPDATE/DELETE carries it
        // directly. Only the journal knows when PREPARE admission is complete.
        let started = self
            .insert
            .map(|insert| insert.decision_started)
            .or(self.decision_started);
        if let Some(claim) = self.claim {
            let empty_records = BTreeMap::new();
            let response = crate::relational::wal_decode::json(&ReceiptRef {
                version: 1,
                authorization: authorization.as_ref(),
                response: ResponseRef {
                    sql,
                    graph: GraphMutationReceipt {
                        graph_epoch: self.graph_epoch,
                        operation_lsn: None,
                        durable: true,
                        replayed: false,
                    },
                    edge_ids: self.edge_ids,
                    records: self
                        .insert
                        .map(|insert| insert.bindings)
                        .unwrap_or(&empty_records),
                },
            })?;
            // Keep the receiving Value reservation until the journal finishes
            // consuming it and adopts its independently admitted PREPARE DTO.
            response.consume(|response| match started {
                Some(started) => {
                    claim.commit_with_decision(target, mutation, audit, response, started)
                }
                None => claim.commit(target, mutation, audit, response),
            })
        } else {
            match started {
                Some(started) => journal.commit_with_decision(target, mutation, audit, started),
                None => journal.commit(target, mutation, audit),
            }
        }
    }
}

impl Db {
    pub(super) fn admit_multimodel(
        &self,
        request: &MultiModelTransactionRequest,
        audit: &AuditContext,
        protected_action: Option<Action>,
        identity: Option<&AuthenticatedIdentity>,
        expected_sql_rows: Option<u64>,
    ) -> Result<Option<IdempotencyAdmission>> {
        request
            .sql
            .idempotency_key
            .as_deref()
            .map(|key| {
                let points = request
                    .points
                    .iter()
                    .map(|point| FingerprintPoint {
                        id: &point.id,
                        vector: &point.vector,
                        vectors: point
                            .vectors
                            .iter()
                            .map(|(key, value)| (key.as_str(), value.as_slice()))
                            .collect(),
                        sparse_vector: &point.sparse_vector,
                        payload: &point.payload,
                    })
                    .collect::<Vec<_>>();
                // Hash public identities before server allocation or translation.
                // Transport and audit retry_id deliberately do not affect identity.
                let fingerprint = (
                    protected_action,
                    &request.sql.statements,
                    &request.collection,
                    &points,
                    &request.point_deletes,
                    &request.relations,
                    &request.edge_deletes,
                    &request.edge_updates,
                );
                let ready = || {
                    self.ensure_request_admission()?;
                    if let Some(identity) = identity {
                        identity.publication_permit()?;
                    }
                    Ok(())
                };
                // Preserve the exact legacy fingerprint when no guard is supplied.
                match expected_sql_rows {
                    Some(rows) => self.transaction_journal.begin_idempotent(
                        key,
                        audit,
                        "multi_model_transaction",
                        &("sql_rows_v1", rows, &fingerprint),
                        ready,
                    ),
                    None => self.transaction_journal.begin_idempotent(
                        key,
                        audit,
                        "multi_model_transaction",
                        &fingerprint,
                        ready,
                    ),
                }
            })
            .transpose()
    }

    pub(super) fn authorize_multimodel(
        &self,
        request: &MultiModelTransactionRequest,
        collection: &Collection,
        vector: &AccessContext,
        graph: &AccessContext,
    ) -> Result<Authorization> {
        let mut proof = Authorization {
            incarnation: vector.incarnation(),
            sql: self
                .relational
                .read()
                .authorization_requirements(&request.sql, vector.tenant())?,
            vector_action: vector.action(),
            read: BTreeSet::new(),
            ingest: false,
            retired: request.point_deletes.iter().cloned().collect(),
            vector: BTreeSet::new(),
            graph: BTreeSet::new(),
        };
        for id in request
            .points
            .iter()
            .map(|point| &point.id)
            .chain(&request.point_deletes)
        {
            let record = vector.authorize(id)?;
            proof.vector.insert((id.clone(), record.storage_id));
            let record = graph.authorize(id)?;
            proof.graph.insert((id.clone(), record.storage_id));
        }
        for relation in &request.relations {
            for id in [&relation.source_point_id, &relation.target_point_id] {
                let record = graph.authorize(id)?;
                proof.graph.insert((id.clone(), record.storage_id));
            }
        }
        let edges = request
            .edge_deletes
            .iter()
            .chain(request.edge_updates.iter().map(|(id, _)| id))
            .map(|id| crate::edge_token::decode(self.graph_database_id(), id))
            .collect::<Result<HashSet<_>>>()?;
        if !edges.is_empty() {
            let mutable = collection
                .graph_mutable
                .as_ref()
                .ok_or(SecurityError::Unavailable)?;
            let resolver = collection
                .graph_resolver
                .as_ref()
                .ok_or(SecurityError::Unavailable)?;
            let deadline = Instant::now() + Duration::from_secs(30);
            let endpoints = mutable.requested_endpoints(&edges, || {
                self.ensure_request_admission()?;
                graph.publication_permit()?;
                if Instant::now() >= deadline {
                    return Err(SecurityError::BudgetExceeded.into());
                }
                Ok(())
            })?;
            if endpoints.len() != edges.len() {
                return Err(SecurityError::NotFound.into());
            }
            for (source, target) in endpoints.values() {
                for nid in [source, target] {
                    let physical = resolver
                        .live_point_id(*nid)
                        .and_then(|id| id.parse::<Uuid>().ok())
                        .ok_or(SecurityError::NotFound)?;
                    let record = graph.authorize_physical(physical)?;
                    proof.graph.insert((record.key.id, record.storage_id));
                }
            }
        }
        Ok(proof)
    }

    pub(super) fn replay_multimodel(
        &self,
        receipt: IdempotencyReceipt,
        protected: Option<(&AuthenticatedIdentity, &str, Action)>,
    ) -> Result<MultiModelResponse> {
        let transaction_id = receipt.status.transaction_id;
        if receipt.expired {
            return Err(GaussError::InvalidRequest(format!(
                "idempotency receipt expired; key remains consumed; transaction_id={transaction_id}"
            )));
        }
        match receipt.status.state {
            TransactionState::OutcomeUnknown => {
                return Err(GaussError::CommitOutcomeUnknown {
                    transaction_id: transaction_id.to_string(),
                });
            }
            TransactionState::Rejected => {
                return Err(GaussError::CommitRejected {
                    transaction_id: transaction_id.to_string(),
                });
            }
            TransactionState::Expired => {
                return Err(GaussError::InvalidRequest(
                    "consumed key has no decision".into(),
                ));
            }
            TransactionState::Committed => {}
        }
        let encoded = receipt.response.as_ref().ok_or_else(|| {
            GaussError::WalUnavailable("committed multi-model receipt is missing".into())
        })?;
        let mut decoded = crate::relational::wal_decode::borrowed::<Receipt>(encoded)?;
        // Stable UUID output is created only after receiving admission.
        decoded.reserve_extra(128)?;
        let decoded = decoded.try_map(|mut receipt| {
            if receipt.version != 1 {
                return Err(GaussError::WalUnavailable(
                    "unsupported multi-model receipt".into(),
                ));
            }
            match (protected, receipt.authorization) {
                (Some((identity, collection, action)), Some(proof)) => {
                    let _sql = proof.sql.authorize(identity)?;
                    let vector = self.bind_access(
                        identity,
                        collection,
                        &identity.principal().tenant,
                        action,
                    )?;
                    let graph = self.bind_access(
                        identity,
                        collection,
                        &identity.principal().tenant,
                        Action::GraphWrite,
                    )?;
                    let _vector = vector.publication_permit()?;
                    let _graph = graph.publication_permit()?;
                    if vector.incarnation() != proof.incarnation || action != proof.vector_action {
                        return Err(SecurityError::Forbidden.into());
                    }
                    if proof.ingest {
                        self.bind_access(
                            identity,
                            collection,
                            &identity.principal().tenant,
                            Action::Ingest,
                        )?
                        .publication_permit()?;
                    }
                    if !proof.read.is_empty() {
                        let read = self.bind_access(
                            identity,
                            collection,
                            &identity.principal().tenant,
                            Action::Read,
                        )?;
                        for (id, physical) in proof.read {
                            read.authorize_receipt(&id, physical, false)?;
                        }
                    }
                    for (id, physical) in proof.vector {
                        vector.authorize_receipt(&id, physical, proof.retired.contains(&id))?;
                    }
                    for (id, physical) in proof.graph {
                        graph.authorize_receipt(&id, physical, proof.retired.contains(&id))?;
                    }
                    receipt.response.publication = Some(vector);
                }
                (None, None) => {}
                _ => return Err(SecurityError::Forbidden.into()),
            }
            let mut response = receipt.response;
            response.sql.transaction_id = Some(transaction_id.to_string());
            response.graph.operation_lsn = None;
            response.graph.replayed = true;
            Ok(response)
        })?;
        Ok(MultiModelResponse::decoded(decoded))
    }
}

#[cfg(test)]
mod receipt_admission_tests {
    use super::*;
    #[test]
    fn borrowed_multimodel_receipt_preserves_legacy_json_shape_bytes_and_numeric_bits() {
        let sql = SqlExecutionResponse {
            transaction_id: Some("receipt-transaction".into()),
            snapshot: 17,
            committed: true,
            outcome: crate::SqlOutcome::Committed,
            commit_sequence: Some(19),
            retryable: false,
            results: vec![crate::SqlResult::Rows {
                columns: vec!["float".into(), "vector".into(), "json".into()],
                column_types: vec![
                    crate::RelationalType::Float,
                    crate::RelationalType::Vector { dimension: 2 },
                    crate::RelationalType::Jsonb,
                ],
                rows: vec![vec![
                    crate::RelationalValue::Float(1.2345678901234567e300),
                    crate::RelationalValue::Vector(vec![0.1, -0.0]),
                    crate::RelationalValue::Json(
                        serde_json::json!({"unsigned":u64::MAX,"zero":-0.0}),
                    ),
                ]],
            }],
        };
        let graph = GraphMutationReceipt {
            graph_epoch: GraphEpoch::INITIAL,
            operation_lsn: None,
            durable: true,
            replayed: false,
        };
        let edges = vec![EdgeToken::from_encoded("opaque-edge")];
        let incarnation = Uuid::from_u128(17);
        let authorization = Authorization {
            incarnation,
            sql: serde_json::from_value(serde_json::json!({
                "tenant":"tenant", "schema":false, "grants":[]
            }))
            .unwrap(),
            vector_action: Action::Ingest,
            read: BTreeSet::from([("docs".into(), incarnation)]),
            ingest: true,
            retired: BTreeSet::from(["retired".into()]),
            vector: BTreeSet::from([("docs".into(), incarnation)]),
            graph: BTreeSet::from([("docs".into(), incarnation)]),
        };
        for authorization in [None, Some(&authorization)] {
            for records in [
                BTreeMap::new(),
                BTreeMap::from([(
                    "allocated".into(),
                    crate::RecordRef {
                        namespace: "docs".into(),
                        id: "record-id".into(),
                    },
                )]),
            ] {
                let old = serde_json::json!({"version":1,"authorization":authorization,"response":MultiModelTransactionResponse { sql: sql.clone(), graph, edge_ids: edges.clone(), records: records.clone(), publication: None }});
                let borrowed = ReceiptRef {
                    version: 1,
                    authorization,
                    response: ResponseRef {
                        sql: &sql,
                        graph,
                        edge_ids: &edges,
                        records: &records,
                    },
                };
                crate::relational::wal_decode::with_test_storage_pool(1, |used| {
                    assert!(matches!(
                        crate::relational::wal_decode::json(&borrowed),
                        Err(GaussError::ResourceExhausted(_))
                    ));
                    assert_eq!(used(), 0);
                });
                crate::relational::wal_decode::with_test_storage_pool(128 * 1024, |used| {
                    let owned = crate::relational::wal_decode::json(&borrowed).unwrap();
                    assert!(used() > 0);
                    assert_eq!(&*owned, &old);
                    assert_eq!(
                        serde_json::to_vec(&*owned).unwrap(),
                        serde_json::to_vec(&old).unwrap()
                    );
                    assert_eq!(
                        owned["response"]["sql"]["results"][0]["rows"][0][0]["value"]
                            .as_f64()
                            .unwrap()
                            .to_bits(),
                        1.2345678901234567e300_f64.to_bits()
                    );
                    owned
                        .consume(|value| {
                            let received: Receipt = serde_json::from_value(value).unwrap();
                            assert_eq!(received.response.sql, sql);
                            assert_eq!(received.response.records, records);
                            assert_eq!(received.response.edge_ids, edges);
                            assert_eq!(
                                serde_json::to_value(received.authorization).unwrap(),
                                serde_json::to_value(authorization).unwrap()
                            );
                            Ok(())
                        })
                        .unwrap();
                    assert_eq!(used(), 0);
                });
            }
        }
    }
}
