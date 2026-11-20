//! Edge object authority is staged with its graph mutation, never after commit.
use super::*;
use crate::graph::{EdgeId, EdgeMutation, GraphEpoch, Nid};

pub(crate) fn edge_key(epoch: GraphEpoch, edge: EdgeId) -> String {
    format!("@edge/{}/{}", epoch.raw(), edge.raw())
}

impl<'a> DataReferenceAuthorization<'a> {
    pub(super) fn new(
        context: &'a AccessContext,
        initial: &'a [ResourceRecord],
        limit: usize,
    ) -> Self {
        Self {
            context,
            initial,
            staged: Default::default(),
            metadata_bytes: Default::default(),
            metadata_limit: limit,
        }
    }

    /// Called under the collection/update leases before any journal decision.
    pub(crate) fn stage_edges(
        &self,
        batch: &crate::wal::GraphBatch,
        physical: impl Fn(Nid) -> crate::Result<Uuid>,
    ) -> crate::Result<Vec<ResourceRecord>> {
        if batch.edge_mutations.is_empty() {
            return Ok(Vec::new());
        }
        if self.metadata_bytes.get().is_some() {
            return Err(SecurityError::Unavailable.into());
        }
        let context = self.context;
        if !context
            .identity
            .allows(context.tenant(), context.collection(), Action::GraphWrite)
        {
            return Err(SecurityError::Forbidden.into());
        }
        let resources = context.snapshot.resources.read();
        let endpoint = |nid| -> crate::Result<ResourceRecord> {
            let id = physical(nid)?;
            let record = self
                .initial
                .iter()
                .find(|r| r.storage_id == id)
                .or_else(|| {
                    resources
                        .physical
                        .get(&id)
                        .and_then(|key| resources.records.get(key))
                })
                .ok_or(SecurityError::NotFound)?;
            if !record.content.is_point() || record.key.tenant != context.tenant {
                return Err(SecurityError::NotFound.into());
            }
            policy::authorize_resource(
                context.identity.principal(),
                context.identity.groups(),
                record,
                Action::GraphWrite,
                &context.snapshot.checkpoint.policy,
                &resources.records,
            )?;
            Ok(record.clone())
        };
        let mut changed = Vec::new();
        for mutation in &batch.edge_mutations {
            let record = match mutation {
                EdgeMutation::Relate(edge) => {
                    let source = endpoint(edge.source)?;
                    let target = endpoint(edge.target)?;
                    let source_fields = AccessContext::edge_properties_record(&source);
                    let target_fields = AccessContext::edge_properties_record(&target);
                    let properties = source_fields
                        .properties
                        .iter()
                        .filter_map(|(path, left)| {
                            target_fields.properties.get(path).map(|right| {
                                (
                                    path.clone(),
                                    PropertyRule {
                                        classification: left
                                            .classification
                                            .max(right.classification),
                                        actions: left
                                            .actions
                                            .intersection(&right.actions)
                                            .copied()
                                            .collect(),
                                    },
                                )
                            })
                        })
                        .collect();
                    let record = ResourceRecord {
                        key: PointKey {
                            collection: context.incarnation(),
                            tenant: context.tenant.clone(),
                            id: edge_key(batch.graph_epoch, edge.edge_id),
                        },
                        storage_id: Uuid::new_v4(),
                        content: ResourceContent::GraphEdge {
                            edge_id: edge.edge_id.raw(),
                            graph_epoch: batch.graph_epoch.raw(),
                            source: source.storage_id,
                            target: target.storage_id,
                        },
                        labels: ResourceLabels {
                            owner: context.principal_id().into(),
                            department: context.identity.principal().attributes.department.clone(),
                            classification: source
                                .labels
                                .classification
                                .max(target.labels.classification),
                            quarantined: false,
                        },
                        properties,
                        representations: Default::default(),
                        grants: Vec::new(),
                        parent: None,
                        revision: context.policy_revision(),
                        retired: false,
                        create_receipt: None,
                    };
                    if resources.records.contains_key(&record.key)
                        || resources.physical.contains_key(&record.storage_id)
                    {
                        return Err(SecurityError::Conflict.into());
                    }
                    policy::authorize_resource(
                        context.identity.principal(),
                        context.identity.groups(),
                        &record,
                        Action::GraphWrite,
                        &context.snapshot.checkpoint.policy,
                        &resources.records,
                    )?;
                    policy::validate_payload_write(
                        &record,
                        &context.identity.principal().attributes,
                        &edge.properties,
                    )?;
                    record
                }
                EdgeMutation::Unrelate(edge) => {
                    let key = PointKey {
                        collection: context.incarnation(),
                        tenant: context.tenant.clone(),
                        id: edge_key(batch.graph_epoch, edge.edge_id),
                    };
                    let mut record = resources
                        .records
                        .get(&key)
                        .ok_or(SecurityError::NotFound)?
                        .clone();
                    if !matches!(record.content, ResourceContent::GraphEdge { .. }) {
                        return Err(SecurityError::NotFound.into());
                    }
                    policy::authorize_resource(
                        context.identity.principal(),
                        context.identity.groups(),
                        &record,
                        Action::GraphWrite,
                        &context.snapshot.checkpoint.policy,
                        &resources.records,
                    )?;
                    record.retired = true;
                    record
                }
                EdgeMutation::Properties(_) => continue, // Own and endpoint fields checked before preparation.
            };
            policy::validate_resource(&record, context.incarnation(), context.policy_revision())?;
            changed.push(record);
        }
        if self.initial.len().saturating_add(changed.len()) > 1024 {
            return Err(SecurityError::BudgetExceeded.into());
        }
        let all = self
            .initial
            .iter()
            .chain(&changed)
            .cloned()
            .collect::<Vec<_>>();
        let bytes = capacity::overlay_bytes(resources.metadata_bytes, &resources.records, &all)?;
        capacity::check(
            context.collection(),
            context.incarnation(),
            &context.snapshot.checkpoint.policy,
            bytes,
            self.metadata_limit,
        )?;
        super::super::storage::serialized_len(&all, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        *self.staged.borrow_mut() = changed.clone();
        self.metadata_bytes.set(Some(bytes));
        Ok(changed)
    }
}

impl AccessContext {
    pub(crate) fn authorize_edge(&self, edge: EdgeId, epoch: GraphEpoch) -> Result<ResourceRecord> {
        let _permit = self.publication_permit()?;
        if !matches!(
            self.action,
            Action::GraphRead | Action::GraphWrite | Action::LabelsManage | Action::GrantsManage
        ) {
            return Err(SecurityError::Forbidden);
        }
        let key = PointKey {
            collection: self.incarnation(),
            tenant: self.tenant.clone(),
            id: edge_key(epoch, edge),
        };
        let resources = self.snapshot.resources.read();
        let record = resources.records.get(&key).ok_or(SecurityError::NotFound)?;
        if !matches!(record.content, ResourceContent::GraphEdge { edge_id, graph_epoch, .. }
            if edge_id == edge.raw() && graph_epoch == epoch.raw())
        {
            return Err(SecurityError::NotFound);
        }
        policy::authorize_resource(
            self.identity.principal(),
            self.identity.groups(),
            record,
            self.action,
            &self.snapshot.checkpoint.policy,
            &resources.records,
        )?;
        Ok(record.clone())
    }

    pub(crate) fn authorize_edge_fields_change(
        &self,
        record: &ResourceRecord,
        old: &Value,
        new: &Value,
        submitted: Option<&Value>,
    ) -> Result<()> {
        if self.action != Action::GraphWrite {
            return Err(SecurityError::Forbidden);
        }
        let attributes = &self.identity.principal().attributes;
        if let Some(submitted) = submitted {
            policy::validate_payload_write(record, attributes, submitted)?;
        }
        policy::validate_payload_change(record, attributes, old, new)
    }
}
