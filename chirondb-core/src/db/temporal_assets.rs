//! Metadata-only assets reuse the protected object authority and collection WAL.
use super::*;
use crate::security::{
    AccessContext, Action, AuthorizedOutput, CreateOptions, NewPoint, ProtectedBatch,
    ProtectedContent, ResourceContent, RevisionUpdate, SecurityDelta, SecurityError,
};

impl Db {
    /// Allocate a new asset identity. Metadata never enters a vector index.
    pub fn create_temporal_asset_authorized(
        &self,
        context: &AccessContext,
        template: &str,
        metadata: Value,
    ) -> Result<AuthorizedOutput<String>> {
        self.create_temporal_asset(context, template, metadata, None)
    }

    /// Explicitly bind a pre-existing named series to a trusted ingest template.
    /// Only installation policy managers may claim historical asset identities.
    pub fn register_temporal_asset_authorized(
        &self,
        context: &AccessContext,
        id: String,
        template: &str,
        metadata: Value,
    ) -> Result<AuthorizedOutput<String>> {
        if !context.identity().allows_installation(Action::PolicyManage) {
            return Err(SecurityError::Forbidden.into());
        }
        self.create_temporal_asset(context, template, metadata, Some(id))
    }

    fn create_temporal_asset(
        &self,
        context: &AccessContext,
        template: &str,
        metadata: Value,
        id: Option<String>,
    ) -> Result<AuthorizedOutput<String>> {
        if context.action() != Action::Create {
            return Err(SecurityError::Forbidden.into());
        }
        crate::security::storage::serialized_len(&metadata, 64 * 1024)?;
        let _life = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _maintenance = self.maintenance_barrier.read();
        let collection = self.get_coll_authorized(context)?;
        let mut collection = collection.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let ids = id.map(|id| vec![id]);
        // The shared template admission accepts metadata without representations;
        // this input is never passed to point storage or dense-index admission.
        let inputs = [NewPoint {
            vector: Vec::new(),
            vectors: Default::default(),
            sparse_vector: None,
            payload: metadata,
        }];
        let started = AtomicBool::new(false);
        let audit_context = asset_audit(context);
        let mut committed = None;
        let records = authority.create_with_options(
            context,
            template,
            &inputs,
            CreateOptions {
                temporal_assets: true,
                ids: ids.as_deref(),
                request: None,
                decision_started: Some(&started),
            },
            |records, generation, _| {
                let entry = WalEntry::ProtectedBatch {
                    batch: ProtectedBatch {
                        version: crate::security::SECURITY_VERSION,
                        security: SecurityDelta {
                            incarnation: context.incarnation(),
                            expected_revision: context.policy_revision(),
                            revision: context.policy_revision(),
                            expected_generation: generation - 1,
                            generation,
                            policy: None,
                            bindings: records.to_vec(),
                        },
                        content: ProtectedContent::TemporalAssets {
                            ids: records
                                .iter()
                                .map(|record| record.storage_id.to_string())
                                .collect(),
                        },
                    },
                };
                let (transaction, _) = self.commit_collection_transaction_with_decision(
                    context.collection(),
                    &mut collection,
                    entry,
                    TransactionAudit::mutation(
                        if ids.is_some() {
                            "temporal_asset.register"
                        } else {
                            "temporal_asset.create"
                        },
                        Some(context.collection()),
                        &audit_context,
                        serde_json::json!({"affected":1}),
                    ),
                    Some(&started),
                )?;
                committed = Some(transaction);
                Ok(())
            },
        )?;
        drop(collection);
        if let Some(transaction) = committed {
            self.project_transaction_audit(&transaction);
        }
        Ok(AuthorizedOutput::new(
            context.clone(),
            records[0].key.id.clone(),
        ))
    }

    pub fn get_temporal_asset_authorized(
        &self,
        context: &AccessContext,
        id: &str,
    ) -> Result<AuthorizedOutput<Value>> {
        if context.action() != Action::Read {
            return Err(SecurityError::Forbidden.into());
        }
        self.get_coll_authorized(context)?;
        let record = context.authorize(id)?;
        let ResourceContent::TemporalAsset { metadata } = record.content else {
            return Err(SecurityError::NotFound.into());
        };
        let projected = context.project(id, &metadata, false)?;
        Ok(AuthorizedOutput::new(context.clone(), projected))
    }

    pub fn replace_temporal_asset_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        update: RevisionUpdate<Value>,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::Update {
            return Err(SecurityError::Forbidden.into());
        }
        crate::security::storage::serialized_len(&update.value, 64 * 1024)?;
        self.change_temporal_asset(context, id, update.expected_revision, Some(update.value))
    }

    pub fn delete_temporal_asset_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        expected_revision: u64,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::Delete {
            return Err(SecurityError::Forbidden.into());
        }
        self.change_temporal_asset(context, id, expected_revision, None)
    }

    fn change_temporal_asset(
        &self,
        context: &AccessContext,
        id: &str,
        expected: u64,
        metadata: Option<Value>,
    ) -> Result<AuthorizedOutput<u64>> {
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
        let mut record = context.authorize(id)?;
        let ResourceContent::TemporalAsset { metadata: old } = &record.content else {
            return Err(SecurityError::NotFound.into());
        };
        if expected != context.policy_revision() {
            return Err(SecurityError::Conflict.into());
        }
        let operation = if let Some(metadata) = metadata {
            context.authorize_payload_change(id, old, &metadata)?;
            record.content = ResourceContent::TemporalAsset { metadata };
            "temporal_asset.replace"
        } else {
            record.retired = true;
            "temporal_asset.delete"
        };
        let revision = expected.checked_add(1).ok_or(SecurityError::Unavailable)?;
        record.revision = revision;
        let audit_context = asset_audit(context);
        let mut committed = None;
        authority.change_resources(
            context,
            expected,
            std::slice::from_ref(&record),
            |previous_generation, generation, revision| {
                let (transaction, _) = self.commit_collection_transaction(
                    context.collection(),
                    &mut collection,
                    WalEntry::ProtectedBatch {
                        batch: ProtectedBatch {
                            version: crate::security::SECURITY_VERSION,
                            security: SecurityDelta {
                                incarnation: context.incarnation(),
                                expected_revision: expected,
                                revision,
                                expected_generation: previous_generation,
                                generation,
                                policy: None,
                                bindings: vec![record.clone()],
                            },
                            content: ProtectedContent::TemporalAssets {
                                ids: vec![record.storage_id.to_string()],
                            },
                        },
                    },
                    TransactionAudit::mutation(
                        operation,
                        Some(context.collection()),
                        &audit_context,
                        serde_json::json!({"affected":1,"policy_revision":revision}),
                    ),
                )?;
                committed = Some(transaction);
                Ok(())
            },
        )?;
        drop(collection);
        if let Some(transaction) = committed {
            self.project_transaction_audit(&transaction);
        }
        let current = self.bind_access(
            context.identity(),
            context.collection(),
            context.tenant(),
            context.action(),
        )?;
        Ok(AuthorizedOutput::new(current, revision))
    }
}

fn asset_audit(context: &AccessContext) -> audit::AuditContext {
    audit::AuditContext {
        principal_id: context.principal_id().into(),
        tenant_id: Some(context.tenant().into()),
        transport: "protected".into(),
        request_id: None,
    }
}
