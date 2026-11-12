//! Explicit migration of pre-authority edges without changing opaque identities.
use super::*;
use crate::security::{
    AccessContext, Action, AuthorizedOutput, PointKey, ProtectedBatch, ProtectedContent,
    ResourceContent, ResourceLabels, ResourceRecord, SecurityDelta, SecurityError,
};
use uuid::Uuid;

impl Db {
    /// A policy manager explicitly assigns a metadata-only template to a legacy
    /// edge. Missing authority is never inferred by a query or normal mutation.
    pub fn register_edge_authorized(
        &self,
        context: &AccessContext,
        token: &crate::graph::EdgeToken,
        template: &str,
        expected: u64,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::GraphWrite
            || !context.identity().allows_installation(Action::PolicyManage)
        {
            return Err(SecurityError::Forbidden.into());
        }
        let _life = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _maintenance = self.maintenance_barrier.read();
        let collection = self.get_coll_authorized(context)?;
        let mut collection = collection.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let _identity = context.identity().publication_permit()?;
        context.publication_permit()?;
        let graph = graph_runtime::active_mutable_graph(&collection)?;
        let edge = crate::edge_token::decode(self.graph_database_id(), token)?;
        let epoch = graph.epoch();
        let endpoints = graph.requested_endpoints(&HashSet::from([edge]), || {
            context.publication_permit()?;
            self.ensure_request_admission()
        })?;
        let (source, target) = endpoints.get(&edge).ok_or(SecurityError::NotFound)?;
        let resolver = collection
            .graph_resolver
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        let endpoint = |nid| -> Result<ResourceRecord> {
            let physical = resolver.live_point_id(nid).ok_or(SecurityError::NotFound)?;
            Ok(context
                .authorize_physical(physical.parse().map_err(|_| SecurityError::Unavailable)?)?)
        };
        let source = endpoint(*source)?;
        let target = endpoint(*target)?;
        let mut checkpoint = authority.checkpoint();
        if expected != context.policy_revision() || checkpoint.revision != expected {
            return Err(SecurityError::Conflict.into());
        }
        let template = checkpoint
            .policy
            .templates
            .get(template)
            .ok_or(SecurityError::Forbidden)?;
        if !template.representations.is_empty()
            || template.classification
                < source
                    .labels
                    .classification
                    .max(target.labels.classification)
            || context.identity().principal().attributes.clearance < template.classification
        {
            return Err(SecurityError::Forbidden.into());
        }
        let revision = expected.checked_add(1).ok_or(SecurityError::Unavailable)?;
        let record = ResourceRecord {
            key: PointKey {
                collection: context.incarnation(),
                tenant: context.tenant().into(),
                id: format!("@edge/{}/{}", epoch.raw(), edge.raw()),
            },
            storage_id: Uuid::new_v4(),
            content: ResourceContent::GraphEdge {
                edge_id: edge.raw(),
                graph_epoch: epoch.raw(),
                source: source.storage_id,
                target: target.storage_id,
            },
            labels: ResourceLabels {
                owner: context.principal_id().into(),
                department: template.department.clone(),
                classification: template.classification,
                quarantined: false,
            },
            properties: template.properties.clone(),
            representations: Default::default(),
            grants: vec![],
            parent: None,
            revision,
            retired: false,
            create_receipt: None,
        };
        if checkpoint
            .resources
            .iter()
            .any(|old| old.key == record.key || old.storage_id == record.storage_id)
        {
            return Err(SecurityError::Conflict.into());
        }
        // Registration neither reads nor writes hidden properties. Their Read,
        // Query and Write rights are checked on subsequent data operations.
        let previous = checkpoint.data_generation;
        checkpoint.data_generation = previous.checked_add(1).ok_or(SecurityError::Unavailable)?;
        checkpoint.revision = revision;
        checkpoint.resources.push(record.clone());
        let audit = audit::AuditContext {
            principal_id: context.principal_id().into(),
            tenant_id: Some(context.tenant().into()),
            transport: "protected".into(),
            request_id: None,
        };
        let mut committed = None;
        authority.install(expected, checkpoint, |next| {
            let entry = WalEntry::ProtectedBatch {
                batch: ProtectedBatch {
                    version: crate::security::SECURITY_VERSION,
                    security: SecurityDelta {
                        incarnation: context.incarnation(),
                        expected_revision: expected,
                        revision,
                        expected_generation: previous,
                        generation: next.data_generation,
                        policy: None,
                        bindings: vec![record],
                    },
                    content: ProtectedContent::EdgeRegistration {
                        graph_epoch: epoch,
                        edge_id: edge,
                    },
                },
            };
            let transaction = self
                .commit_collection_transaction(
                    context.collection(),
                    &mut collection,
                    entry,
                    TransactionAudit::new(
                        "security",
                        "edge.register",
                        Some(context.collection()),
                        &audit,
                        serde_json::json!({"policy_revision":revision}),
                    ),
                )
                .map_err(|_| SecurityError::Unavailable)?
                .0;
            committed = Some(transaction);
            Ok(())
        })?;
        drop(collection);
        if let Some(transaction) = committed {
            self.project_transaction_audit(&transaction);
        }
        let fresh = self.bind_access(
            context.identity(),
            context.collection(),
            context.tenant(),
            Action::GraphWrite,
        )?;
        Ok(AuthorizedOutput::new(fresh, revision))
    }
}
