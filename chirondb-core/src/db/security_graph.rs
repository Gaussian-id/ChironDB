//! Revision-checked graph schema operations for protected collections.
use super::*;
use crate::security::{AccessContext, Action, AuthorizedOutput, SecurityDelta, SecurityError};

impl Db {
    pub fn set_graph_lifecycle_authorized(
        &self,
        context: &AccessContext,
        expected_revision: u64,
        enabled: bool,
    ) -> Result<AuthorizedOutput<(u64, crate::graph::GraphLifecycleResult)>> {
        validate_context(context, expected_revision)?;
        let lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        let admission = self.maintenance_barrier.read();
        let coll = self.get_coll_authorized(context)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            context.publication_permit()?;
            self.ensure_request_admission()?;
            let collection = coll.read();
            if collection.sealing.is_none() && !collection.generation_build_in_flight {
                break;
            }
            drop(collection);
            if Instant::now() >= deadline {
                return Err(SecurityError::BudgetExceeded.into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut collection = coll.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        if collection.graph_lifecycle.is_enabled() == enabled {
            let _permit = context.publication_permit()?;
            let result = crate::graph::GraphLifecycleResult {
                enabled,
                graph_epoch: collection.graph_lifecycle.epoch(),
                operation_lsn: None,
                durable: true,
                transitioned: false,
                backfill_in_progress: collection.graph_backfill_pending(),
            };
            return Ok(AuthorizedOutput::new(
                context.clone(),
                (expected_revision, result),
            ));
        }
        let epoch = collection.graph_lifecycle.next_epoch()?;
        let mut staged = collection.graph_lifecycle;
        staged.apply_advance(epoch, enabled)?;
        let (revision, (transaction, operation_lsn)) = authority.schema_with_commit(
            context,
            expected_revision,
            |previous, generation, revision| {
                self.commit_collection_transaction(
                    context.collection(),
                    &mut collection,
                    WalEntry::ProtectedBatch {
                        batch: crate::security::ProtectedBatch {
                            version: crate::security::SECURITY_VERSION,
                            security: delta(context, previous, generation, revision),
                            content: crate::security::ProtectedContent::GraphLifecycle { epoch, enabled },
                        },
                    },
                    TransactionAudit::mutation(
                        if enabled { "graph_enable" } else { "graph_drop" },
                        Some(context.collection()),
                        &audit_context(context),
                        serde_json::json!({"enabled":enabled,"graph_epoch":epoch.raw(),"revision":revision}),
                    ),
                )
            },
        )?;
        collection.graph_lifecycle = staged;
        if enabled && collection.graph_resolver.is_none() {
            collection.graph_resolver =
                Some(crate::graph_resolver::PointIncarnationResolver::default());
        }
        collection.graph_mutable =
            enabled.then(|| crate::mutable_graph::MutableGraphState::new(epoch));
        if let Err(error) = collection
            .overlays
            .replace_edges(&roaring::RoaringTreemap::new())
            .and_then(|_| collection.overlays.publish_pending())
        {
            self.mark_durability_degraded("protected_graph_lifecycle_overlay", &error);
        }
        self.project_transaction_audit(&transaction);
        let result = crate::graph::GraphLifecycleResult {
            enabled,
            graph_epoch: Some(epoch),
            operation_lsn: Some(operation_lsn),
            durable: true,
            transitioned: true,
            backfill_in_progress: collection.graph_backfill_pending(),
        };
        let fresh = authority.bind(context.identity(), context.tenant(), Action::Schema)?;
        drop(collection);
        drop(admission);
        drop(lifecycle);
        if result.backfill_in_progress {
            self.start_graph_handle_backfill(context.collection());
        }
        self.refresh_metrics();
        Ok(AuthorizedOutput::new(fresh, (revision, result)))
    }

    pub fn configure_edge_type_authorized(
        &self,
        context: &AccessContext,
        expected_revision: u64,
        request: crate::graph::ConfigureEdgeTypeRequest,
    ) -> Result<AuthorizedOutput<(u64, crate::graph::ConfigureEdgeTypeResult)>> {
        validate_context(context, expected_revision)?;
        graph_runtime::validate_public_catalog_name("edge type", &request.name)?;
        if let Some(weight) = &request.weight_property {
            graph_runtime::validate_public_catalog_name("weight property", weight)?;
        }
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let coll = self.get_coll_authorized(context)?;
        let mut collection = coll.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let mutable = graph_runtime::active_mutable_graph(&collection)?;
        let graph_epoch = mutable.epoch();
        let type_id = mutable
            .types()
            .resolve_name(&request.name)
            .map_or_else(|| mutable.types().next_type_id(), Ok)?;
        let unchanged = mutable.types().get(type_id).is_some_and(|existing| {
            existing.name == request.name && existing.weight_property == request.weight_property
        });
        let (revision, receipt) = if unchanged {
            let _permit = context.publication_permit()?;
            (
                expected_revision,
                crate::graph::GraphMutationReceipt {
                    graph_epoch,
                    operation_lsn: None,
                    durable: true,
                    replayed: true,
                },
            )
        } else {
            let (revision, receipt) = authority.schema_with_commit(
                context,
                expected_revision,
                |previous, generation, revision| {
                    self.commit_graph_batch_audited_locked(
                        &mut collection,
                        crate::wal::GraphBatch {
                            graph_epoch,
                            type_configurations: vec![crate::wal::GraphTypeConfiguration {
                                type_id,
                                name: request.name.clone(),
                                weight_property: request.weight_property.clone(),
                            }],
                            ..Default::default()
                        },
                        true,
                        Some(delta(context, previous, generation, revision)),
                        &audit_context(context),
                        None,
                    )
                },
            )?;
            (
                revision,
                crate::graph::GraphMutationReceipt {
                    graph_epoch: receipt.graph_epoch,
                    operation_lsn: Some(receipt.operation_lsn),
                    durable: receipt.durable,
                    replayed: false,
                },
            )
        };
        let fresh = authority.bind(context.identity(), context.tenant(), Action::Schema)?;
        let result = crate::graph::ConfigureEdgeTypeResult {
            edge_type: crate::graph::GraphEdgeType {
                name: request.name,
                weight_property: request.weight_property,
            },
            receipt,
            changed: !unchanged,
        };
        drop(collection);
        self.refresh_metrics();
        Ok(AuthorizedOutput::new(fresh, (revision, result)))
    }
}

fn validate_context(context: &AccessContext, expected_revision: u64) -> Result<()> {
    if context.action() != Action::Schema {
        return Err(SecurityError::Forbidden.into());
    }
    context.publication_permit()?;
    if context.policy_revision() != expected_revision {
        return Err(SecurityError::Conflict.into());
    }
    Ok(())
}

fn delta(context: &AccessContext, previous: u64, generation: u64, revision: u64) -> SecurityDelta {
    SecurityDelta {
        incarnation: context.incarnation(),
        expected_revision: context.policy_revision(),
        revision,
        expected_generation: previous,
        generation,
        policy: None,
        bindings: vec![],
    }
}

fn audit_context(context: &AccessContext) -> audit::AuditContext {
    audit::AuditContext {
        principal_id: context.principal_id().into(),
        tenant_id: Some(context.tenant().into()),
        transport: "protected-graph-schema".into(),
        request_id: None,
    }
}
