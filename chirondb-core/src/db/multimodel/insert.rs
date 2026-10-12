//! Protected atomic creation. Request bindings never become persistent identities.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

use super::{Authorization, CommitOptions, MultiModelResponse};
use crate::audit::AuditContext;
use crate::graph::{GraphRelationScope, RelateRequest};
use crate::relational::{RelationalEngine, RelationalMutation};
use crate::security::{
    AccessContext, Action, AuthenticatedIdentity, NewPoint, ResourceRecord, SecurityDelta,
    SecurityError,
};
use crate::transaction_journal::IdempotencyAdmission;
use crate::wal::WalEntry;
use crate::{
    Db, GaussError, MultiModelTransactionRequest, MultiModelTransactionResponse, RecordRef, Result,
    SqlExecutionRequest,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewRecord {
    pub binding: String,
    pub point: NewPoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecordEndpoint {
    New(String),
    Existing(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewRelation {
    pub source: RecordEndpoint,
    pub target: RecordEndpoint,
    pub edge_type: String,
    pub properties: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultiModelInsertRequest {
    pub sql: SqlExecutionRequest,
    pub collection: String,
    pub template: String,
    pub records: Vec<NewRecord>,
    pub relations: Vec<NewRelation>,
}

pub(crate) struct InsertCommit<'a> {
    pub read: &'a AccessContext,
    pub created: &'a [ResourceRecord],
    pub bindings: &'a BTreeMap<String, RecordRef>,
    pub decision_started: &'a AtomicBool,
}

impl InsertCommit<'_> {
    pub(super) fn authorize_references(
        &self,
        mutation: &WalEntry,
        proof: &mut Authorization,
    ) -> Result<()> {
        let WalEntry::MultiModelBatch { batch } = mutation else {
            return Err(SecurityError::Unavailable.into());
        };
        for mutation in &batch.relational.mutations {
            let RelationalMutation::Insert { rows, .. } = mutation else {
                return Err(GaussError::InvalidRequest(
                    "atomic create accepts INSERT mutations only".into(),
                ));
            };
            for row in rows {
                for value in &row.values {
                    if let crate::RelationalValue::RecordRef(reference) = value {
                        if reference.namespace != self.read.collection().to_ascii_lowercase() {
                            return Err(SecurityError::Forbidden.into());
                        }
                        let record = match self
                            .created
                            .iter()
                            .find(|record| record.key.id == reference.id)
                        {
                            Some(record) => {
                                self.read.authorize_candidate(record)?;
                                record.clone()
                            }
                            None => self.read.authorize(&reference.id)?,
                        };
                        proof.read.insert((record.key.id, record.storage_id));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Db {
    /// Server-ID INSERT across SQL metadata, protected content and graph.
    /// Save request bindings with the idempotency key; they resolve to the same
    /// public IDs on replay. Adapters retain the returned publication context.
    /// Embedded DTO handoff; transports retain the owned result through encoding.
    pub fn insert_multimodel_authorized(
        &self,
        identity: &AuthenticatedIdentity,
        request: MultiModelInsertRequest,
        transport: &str,
    ) -> Result<MultiModelTransactionResponse> {
        self.insert_multimodel_authorized_owned(identity, request, transport)
            .map(MultiModelResponse::into_dto)
    }
    pub fn insert_multimodel_authorized_with_sql_rows(
        &self,
        identity: &AuthenticatedIdentity,
        request: MultiModelInsertRequest,
        transport: &str,
        expected_sql_rows: Option<u64>,
    ) -> Result<MultiModelTransactionResponse> {
        self.insert_multimodel_authorized_with_sql_rows_owned(
            identity,
            request,
            transport,
            expected_sql_rows,
        )
        .map(MultiModelResponse::into_dto)
    }

    pub fn insert_multimodel_authorized_owned(
        &self,
        identity: &AuthenticatedIdentity,
        request: MultiModelInsertRequest,
        transport: &str,
    ) -> Result<MultiModelResponse> {
        self.insert_multimodel_authorized_with_sql_rows_owned(identity, request, transport, None)
    }

    /// Guard atomic server-ID creation with the directly affected SQL row count.
    pub fn insert_multimodel_authorized_with_sql_rows_owned(
        &self,
        identity: &AuthenticatedIdentity,
        request: MultiModelInsertRequest,
        transport: &str,
        expected_sql_rows: Option<u64>,
    ) -> Result<MultiModelResponse> {
        self.ensure_current_identity(identity)?;
        self.ensure_storage_mutations_available()?;
        validate_bindings(&request)?;
        let audit = AuditContext {
            principal_id: identity.principal().id.clone(),
            tenant_id: Some(identity.principal().tenant.clone()),
            transport: transport.into(),
            request_id: request.sql.retry_id.clone(),
        };
        let claim = match request
            .sql
            .idempotency_key
            .as_deref()
            .map(|key| {
                let fingerprint = (
                    &request.sql.statements,
                    &request.collection,
                    &request.template,
                    &request.records,
                    &request.relations,
                );
                let ready = || {
                    self.ensure_request_admission()?;
                    identity.publication_permit()?;
                    Ok(())
                };
                match expected_sql_rows {
                    Some(rows) => self.transaction_journal.begin_idempotent(
                        key,
                        &audit,
                        "multi_model_insert",
                        &("sql_rows_v1", rows, &fingerprint),
                        ready,
                    ),
                    None => self.transaction_journal.begin_idempotent(
                        key,
                        &audit,
                        "multi_model_insert",
                        &fingerprint,
                        ready,
                    ),
                }
            })
            .transpose()?
        {
            Some(IdempotencyAdmission::Replay(receipt)) => {
                return self.replay_multimodel(
                    receipt,
                    Some((identity, &request.collection, Action::Create)),
                );
            }
            Some(IdempotencyAdmission::Execute(claim)) => Some(claim),
            None => None,
        };
        let sql_authorization = self
            .relational
            .read()
            .authorization_requirements(&request.sql, &identity.principal().tenant)?;
        let _sql_permit = sql_authorization.authorize(identity)?;
        let create = self.bind_access(
            identity,
            &request.collection,
            &identity.principal().tenant,
            Action::Create,
        )?;
        let read = self.bind_access(
            identity,
            &request.collection,
            &identity.principal().tenant,
            Action::Read,
        )?;
        let graph = self.bind_access(
            identity,
            &request.collection,
            &identity.principal().tenant,
            Action::GraphWrite,
        )?;
        let _read_permit = read.publication_permit()?;
        let _graph_permit = graph.publication_permit()?;
        let _lifecycle = self.lifecycle_gate.read();
        let _admission = self.maintenance_barrier.read();
        let max_points = self.max_points_per_collection();
        let collection_ref = self.get_coll_authorized(&create)?;
        let mut collection = collection_ref.write();
        if max_points.is_some_and(|limit| {
            collection
                .live_points()
                .saturating_add(request.records.len())
                > limit
        }) {
            return Err(GaussError::ResourceExhausted(
                "collection point quota exceeded".into(),
            ));
        }
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let points = request
            .records
            .iter()
            .map(|record| record.point.clone())
            .collect::<Vec<_>>();
        for point in &points {
            super::super::validate_point(
                &collection.config,
                &super::super::security_runtime::physical_point(point, "validation".into()),
            )?;
        }
        let decision_started = AtomicBool::new(false);
        let mut response = None;
        authority.create_transaction(
            &create,
            &request.template,
            &points,
            &decision_started,
            |created, generation| {
                let bindings = request
                    .records
                    .iter()
                    .zip(created)
                    .map(|(binding, record)| {
                        (
                            binding.binding.clone(),
                            RecordRef {
                                namespace: request.collection.to_ascii_lowercase(),
                                id: record.key.id.clone(),
                            },
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                let mut proof = Authorization {
                    incarnation: create.incarnation(),
                    sql: sql_authorization.clone(),
                    vector_action: Action::Create,
                    vector: BTreeSet::new(),
                    graph: BTreeSet::new(),
                    retired: BTreeSet::new(),
                    read: BTreeSet::new(),
                    ingest: points.iter().any(|point| {
                        !point.vector.is_empty()
                            || !point.vectors.is_empty()
                            || point.sparse_vector.is_some()
                    }),
                };
                for record in created {
                    read.authorize_candidate(record)?;
                    proof
                        .read
                        .insert((record.key.id.clone(), record.storage_id));
                }
                let mut endpoint = |endpoint: &RecordEndpoint| -> Result<String> {
                    let record = match endpoint {
                        RecordEndpoint::New(binding) => {
                            let position = request
                                .records
                                .iter()
                                .position(|record| &record.binding == binding)
                                .ok_or_else(|| {
                                    GaussError::InvalidRequest(
                                        "unknown graph record binding".into(),
                                    )
                                })?;
                            let record = &created[position];
                            graph.authorize_candidate(record)?;
                            record.clone()
                        }
                        RecordEndpoint::Existing(id) => graph.authorize(id)?,
                    };
                    proof.graph.insert((record.key.id, record.storage_id));
                    Ok(record.storage_id.to_string())
                };
                let relations = request
                    .relations
                    .iter()
                    .map(|relation| {
                        Ok(RelateRequest {
                            source_point_id: endpoint(&relation.source)?,
                            target_point_id: endpoint(&relation.target)?,
                            edge_type: relation.edge_type.clone(),
                            properties: relation.properties.clone(),
                            scope: GraphRelationScope::Local,
                            idempotency_key: None,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let sql = RelationalEngine::bind_new_records(request.sql.clone(), &bindings)?;
                let insert = InsertCommit {
                    read: &read,
                    created,
                    bindings: &bindings,
                    decision_started: &decision_started,
                };
                response = Some(
                    self.execute_multimodel_transaction_locked(
                        MultiModelTransactionRequest {
                            sql,
                            collection: request.collection.clone(),
                            points: points
                                .iter()
                                .zip(created)
                                .map(|(point, record)| {
                                    super::super::security_runtime::physical_point(
                                        point,
                                        record.storage_id.to_string(),
                                    )
                                })
                                .collect(),
                            point_deletes: vec![],
                            relations,
                            edge_deletes: vec![],
                            edge_updates: vec![],
                        },
                        &crate::tenant::TenantScope::system(),
                        &audit,
                        &mut collection,
                        Some((
                            SecurityDelta {
                                incarnation: create.incarnation(),
                                expected_revision: create.policy_revision(),
                                revision: create.policy_revision(),
                                expected_generation: generation - 1,
                                generation,
                                policy: None,
                                bindings: created.to_vec(),
                            },
                            &identity.principal().tenant,
                        )),
                        Some(CommitOptions {
                            claim: claim.as_ref(),
                            authorization: Some(&proof),
                            insert: Some(&insert),
                            decision_started: None,
                            expected_sql_rows,
                            references: None,
                        }),
                    )?,
                );
                Ok(())
            },
        )?;
        let mut response = response.ok_or(SecurityError::Unavailable)?;
        response.set_publication(authority.bind(
            identity,
            &identity.principal().tenant,
            Action::Read,
        )?);
        drop(collection);
        self.refresh_metrics();
        Ok(response)
    }
}

fn validate_bindings(request: &MultiModelInsertRequest) -> Result<()> {
    if request.records.is_empty() || request.records.len() > 1024 {
        return Err(SecurityError::BudgetExceeded.into());
    }
    let mut names = BTreeSet::new();
    for record in &request.records {
        if record.binding.is_empty()
            || record.binding.len() > 64
            || !record
                .binding
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
            || !names.insert(&record.binding)
        {
            return Err(GaussError::InvalidRequest(
                "record bindings must be unique ASCII names of 1–64 bytes".into(),
            ));
        }
    }
    Ok(())
}
