//! Dedicated object security transactions; content writers cannot call through
//! payload mutation to replace labels, grants or an inheritance parent.
use super::*;
use crate::security::{
    AccessContext, Action, AuthorizedOutput, ObjectLabels, ObjectPermissions, ResourceRecord,
    RevisionUpdate, SecurityError,
};
use crate::transaction_journal::TransactionAudit;
use std::collections::BTreeSet;

impl Db {
    /// Build a complete authoritative transaction generation on a stopped,
    /// protected installation. Existing full WAL remains available for repair
    /// until model checkpoints and archival reclamation are qualified.
    pub fn migrate_transaction_authority_offline(data_dir: impl AsRef<Path>) -> Result<bool> {
        let db = Self::open_for_offline_maintenance(data_dir)?;
        let _lifecycle = db.lifecycle_gate.write();
        let _maintenance = db.maintenance_barrier.read();
        db.ensure_storage_mutations_available()?;
        db.relational
            .read()
            .ensure_table_authority_migration_idle()?;
        db.wait_for_storage_idle()?;
        db.flush_wals()?;
        let authority = db
            .identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        let intent = db.audit_writer.operation_with_details(
            "security",
            "transactions.migrate_authority",
            None,
            crate::audit::AuditContext {
                principal_id: "offline-authority-migration".into(),
                tenant_id: None,
                transport: "offline".into(),
                request_id: None,
            },
            serde_json::json!({"identity_revision": authority.revision(), "transaction_format": 3}),
        )?;
        let changed = db
            .transaction_journal
            .migrate_authority_offline()
            .inspect_err(|error| {
                db.mark_durability_degraded("transaction_authority_migration", error)
            })?;
        intent.success(serde_json::json!({"transaction_format": 3, "installation_format": 6, "migrated": changed}))?;
        Ok(changed)
    }

    pub fn sql_table_privileges_authorized(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
    ) -> Result<BTreeSet<(String, Action)>> {
        self.ensure_current_identity(identity)?;
        let _permit = identity.publication_permit()?;
        self.relational.read().current_table_privileges(identity)
    }

    /// Convert legacy SQL name scopes into grants on current table identities.
    /// Collection capabilities remain available exclusively to collection APIs.
    pub fn migrate_sql_scopes_offline(&mut self) -> Result<bool> {
        if Arc::get_mut(&mut self.lifecycle_gate).is_none() {
            return Err(GaussError::InvalidRequest(
                "offline SQL scope migration requires exclusive Db ownership".into(),
            ));
        }
        let _lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        self.relational
            .read()
            .ensure_table_authority_migration_idle()?;
        let bindings = self.relational.read().sql_scope_migration_bindings()?;
        self.identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?
            .migrate_sql_scopes_offline(&bindings)
            .map_err(Into::into)
            .inspect_err(|error| self.mark_durability_degraded("sql_scope_migration", error))
    }

    /// Exclusive offline migration. Authority version 5 fences older binaries
    /// before the catalog publishes the table incarnation fields.
    pub fn migrate_table_authority_offline(&mut self) -> Result<usize> {
        if Arc::get_mut(&mut self.lifecycle_gate).is_none() {
            return Err(GaussError::InvalidRequest(
                "offline table authority migration requires exclusive Db ownership".into(),
            ));
        }
        let _lifecycle = self.lifecycle_gate.write();
        self.ensure_storage_mutations_available()?;
        self.relational
            .read()
            .ensure_table_authority_migration_idle()?;
        let authority = self
            .identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        authority.upgrade_table_authority_offline()?;
        let intent = self.audit_writer.operation_with_details(
            "security",
            "relational.migrate_table_authority",
            None,
            crate::audit::AuditContext {
                principal_id: "offline-authority-migration".into(),
                tenant_id: None,
                transport: "offline".into(),
                request_id: None,
            },
            serde_json::json!({"identity_format": 5}),
        )?;
        let count = self
            .relational
            .read()
            .migrate_table_authority_offline()
            .inspect_err(|error| {
                // An error after manifest replacement can leave publication
                // uncertain. Require reopen before any later mutation.
                self.mark_durability_degraded("table_authority_migration", error);
            })?;
        intent.success(serde_json::json!({"migrated_tables": count}))?;
        Ok(count)
    }

    pub fn change_role_table_privileges_authorized(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
        expected: u64,
        role: &str,
        table: &str,
        actions: BTreeSet<Action>,
        grant: bool,
    ) -> Result<u64> {
        self.ensure_request_admission()?;
        self.ensure_storage_mutations_available()?;
        self.ensure_current_identity(identity)?;
        if !identity.is_installation_admin() {
            return Err(SecurityError::Forbidden.into());
        }
        let _lifecycle = self.lifecycle_gate.read();
        let (table_id, incarnation) = self
            .relational
            .read()
            .table_grant_binding(&identity.principal().tenant, table)?;
        self.identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?
            .change_role_table_privileges(
                identity,
                expected,
                role,
                crate::security::RoleTableGrant {
                    table: table.into(),
                    table_id,
                    incarnation,
                    actions,
                },
                grant,
            )
            .map_err(Into::into)
    }

    pub fn change_role_privileges_authorized(
        &self,
        identity: &crate::security::AuthenticatedIdentity,
        expected: u64,
        role: &str,
        collection: Option<&str>,
        actions: BTreeSet<Action>,
        grant: bool,
    ) -> Result<u64> {
        let authority = self
            .identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?;
        if !authority.accepts(identity) || !identity.allows_installation(Action::IdentityManage) {
            return Err(SecurityError::Forbidden.into());
        }
        let _lifecycle = self.lifecycle_gate.read();
        let scope = collection
            .map(|name| {
                let collection = self
                    .inner
                    .read()
                    .collections
                    .get(name)
                    .cloned()
                    .ok_or(SecurityError::NotFound)?;
                let collection = collection.read();
                let incarnation = collection
                    .security
                    .as_ref()
                    .ok_or(SecurityError::Forbidden)?
                    .incarnation();
                Ok::<_, SecurityError>((name.to_string(), incarnation))
            })
            .transpose()?;
        authority
            .change_role_privileges(
                identity,
                expected,
                role,
                crate::security::RolePrivilegeChanges {
                    collection: scope,
                    actions,
                    grant,
                },
            )
            .map_err(Into::into)
    }

    pub fn alter_object_labels_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        expected: u64,
        changes: crate::security::PointLabelChanges,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::LabelsManage {
            return Err(SecurityError::Forbidden.into());
        }
        self.change_object_security(context, id, expected, |record| {
            let mut labels = record.labels.clone();
            if let Some(name) = changes.owner {
                let authority = self
                    .identity_authority
                    .as_ref()
                    .ok_or(SecurityError::Unavailable)?;
                let crate::security::Subject::Principal(id) = authority.resolve_security_subject(
                    context,
                    &crate::security::Subject::Principal(name),
                )?
                else {
                    return Err(SecurityError::Forbidden.into());
                };
                labels.owner = id;
            }
            if let Some(department) = changes.department {
                labels.department = department;
            }
            if let Some(classification) = changes.classification {
                labels.classification = classification;
            }
            apply_labels(
                context,
                record,
                ObjectLabels {
                    labels,
                    properties: record.properties.clone(),
                },
            )
        })
    }

    pub fn change_object_privileges_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        expected: u64,
        changes: crate::security::PointPrivilegeChanges,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::GrantsManage || changes.actions.is_empty() {
            return Err(SecurityError::Forbidden.into());
        }
        self.change_object_security(context, id, expected, |record| {
            context.authorize_delegated_actions(changes.actions.clone())?;
            let authority = self
                .identity_authority
                .as_ref()
                .ok_or(SecurityError::Unavailable)?;
            let subject = authority.resolve_security_subject(context, &changes.subject)?;
            if changes.grant {
                if let Some(grant) = record.grants.iter_mut().find(|grant| {
                    grant.subject == subject && grant.effect == changes.effect && !grant.inherit
                }) {
                    grant.actions.extend(changes.actions);
                } else {
                    record.grants.push(crate::security::ObjectGrant {
                        subject,
                        effect: changes.effect,
                        actions: changes.actions,
                        inherit: false,
                    });
                }
            } else {
                // This syntax addresses direct grants only, preserving both
                // inherited entries and the opposite effect.
                for grant in record.grants.iter_mut().filter(|grant| {
                    grant.subject == subject && grant.effect == changes.effect && !grant.inherit
                }) {
                    grant
                        .actions
                        .retain(|action| !changes.actions.contains(action));
                }
                record.grants.retain(|grant| !grant.actions.is_empty());
            }
            if record.grants.len() > crate::security::MAX_POLICY_GRANTS {
                return Err(SecurityError::BudgetExceeded.into());
            }
            Ok(())
        })
    }

    pub fn replace_object_labels_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        update: RevisionUpdate<ObjectLabels>,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::LabelsManage {
            return Err(SecurityError::Forbidden.into());
        }
        crate::security::storage::serialized_len(&update, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        self.change_object_security(context, id, update.expected_revision, |record| {
            apply_labels(context, record, update.value)
        })
    }

    pub fn replace_object_permissions_authorized(
        &self,
        context: &AccessContext,
        id: &str,
        update: RevisionUpdate<ObjectPermissions>,
    ) -> Result<AuthorizedOutput<u64>> {
        if context.action() != Action::GrantsManage {
            return Err(SecurityError::Forbidden.into());
        }
        crate::security::storage::serialized_len(&update, crate::wal::MAX_WAL_RECORD_BYTES / 2)?;
        if update.value.grants.len() > crate::security::MAX_POLICY_GRANTS {
            return Err(SecurityError::BudgetExceeded.into());
        }
        self.change_object_security(context, id, update.expected_revision, |record| {
            let actions = record
                .grants
                .iter()
                .filter(|grant| !update.value.grants.contains(grant))
                .chain(
                    update
                        .value
                        .grants
                        .iter()
                        .filter(|grant| !record.grants.contains(grant)),
                )
                .flat_map(|grant| grant.actions.iter().copied())
                .collect();
            context.authorize_delegated_actions(actions)?;
            let parent = update.value.parent.map(|id| crate::security::PointKey {
                collection: context.incarnation(),
                tenant: context.tenant().into(),
                id,
            });
            if parent != record.parent {
                // Reparenting can add permissions or remove inherited denies.
                // Authority is required over both old/new ancestry, and every
                // affected inherited action must fit the delegation ceiling.
                for start in [record.parent.as_ref(), parent.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    let mut current = Some(start.clone());
                    let mut visited = BTreeSet::new();
                    while let Some(key) = current {
                        if !visited.insert(key.clone())
                            || visited.len() > crate::security::MAX_INHERITANCE_DEPTH
                        {
                            return Err(SecurityError::BudgetExceeded.into());
                        }
                        let ancestor = context.authorize(&key.id)?;
                        context.authorize_delegated_actions(
                            ancestor
                                .grants
                                .iter()
                                .filter(|grant| grant.inherit)
                                .flat_map(|grant| grant.actions.iter().copied())
                                .collect(),
                        )?;
                        current = ancestor.parent;
                    }
                }
            }
            record.grants = update.value.grants;
            record.parent = parent;
            Ok(())
        })
    }

    fn change_object_security(
        &self,
        context: &AccessContext,
        id: &str,
        expected: u64,
        edit: impl FnOnce(&mut ResourceRecord) -> Result<()>,
    ) -> Result<AuthorizedOutput<u64>> {
        let operation = match context.action() {
            Action::LabelsManage => "labels.replace",
            Action::GrantsManage => "grants.replace",
            _ => return Err(SecurityError::Forbidden.into()),
        };
        if id.len() > MAX_POINT_ID_BYTES {
            return Err(SecurityError::NotFound.into());
        }
        let _lifecycle = self.lifecycle_gate.read();
        self.ensure_storage_mutations_available()?;
        let _admission = self.maintenance_barrier.read();
        let collection = self.get_coll_authorized(context)?;
        let mut collection = collection.write();
        let authority = collection
            .security
            .clone()
            .ok_or(SecurityError::Unavailable)?;
        let _identity_lease = context.identity().publication_permit()?;
        let mut record = context.authorize(id)?;
        if expected != context.policy_revision() {
            return Err(SecurityError::Conflict.into());
        }
        edit(&mut record)?;
        record.revision = expected.checked_add(1).ok_or(SecurityError::Unavailable)?;
        self.identity_authority
            .as_ref()
            .ok_or(SecurityError::Unavailable)?
            .validate_object_subjects(
                context.identity(),
                context.tenant(),
                &record.labels.owner,
                &record.grants,
            )?;
        let audit_context = audit::AuditContext {
            principal_id: context.principal_id().into(),
            tenant_id: Some(context.tenant().into()),
            transport: "protected".into(),
            request_id: None,
        };
        let audit_details = serde_json::json!({"identity_revision":context.identity_revision(),"expected_policy_revision":expected,"policy_revision":record.revision});
        let mut committed_transaction = None;
        let revision = authority.change_resources(
            context,
            expected,
            std::slice::from_ref(&record),
            |previous, generation, revision| {
                let (transaction, _) = self
                    .commit_collection_transaction(
                        context.collection(),
                        &mut collection,
                        WalEntry::ProtectedBatch {
                            batch: crate::security::ProtectedBatch {
                                version: crate::security::SECURITY_VERSION,
                                security: crate::security::SecurityDelta {
                                    incarnation: context.incarnation(),
                                    expected_revision: expected,
                                    revision,
                                    expected_generation: previous,
                                    generation,
                                    policy: None,
                                    bindings: vec![record.clone()],
                                },
                                content: crate::security::ProtectedContent::Policy,
                            },
                        },
                        TransactionAudit::new(
                            "security",
                            operation,
                            Some(context.collection()),
                            &audit_context,
                            audit_details.clone(),
                        ),
                    )
                    .inspect_err(|error| {
                        self.mark_durability_degraded("security_object_commit", error)
                    })?;
                committed_transaction = Some(transaction);
                Ok(())
            },
        )?;
        if let Some(transaction) = &committed_transaction {
            self.project_transaction_audit(transaction);
        }
        drop(collection);
        let fresh = self.bind_access(
            context.identity(),
            context.collection(),
            context.tenant(),
            context.action(),
        )?;
        Ok(AuthorizedOutput::new(fresh, revision))
    }
}

fn apply_labels(
    context: &AccessContext,
    record: &mut ResourceRecord,
    update: ObjectLabels,
) -> Result<()> {
    context.authorize_label_delegation(record)?;
    let clearance = context.identity().principal().attributes.clearance;
    if update.labels.classification > clearance
        || record
            .properties
            .values()
            .chain(update.properties.values())
            .any(|rule| rule.classification > clearance)
        || record
            .representations
            .values()
            .any(|representation| representation.classification > clearance)
    {
        return Err(SecurityError::Forbidden.into());
    }
    record.labels = update.labels;
    record.properties = update.properties;
    // A source becoming stricter propagates to the derivative in the
    // same WAL transaction. Declassification never weakens a stored
    // representation's attestation; re-ingestion is a separate action.
    for representation in record.representations.values_mut() {
        representation.classification = representation
            .classification
            .max(record.labels.classification);
        for source in &representation.source_fields {
            let property = record.properties.get(source).ok_or_else(|| {
                SecurityError::Invalid("representation source cannot be removed".into())
            })?;
            representation.classification =
                representation.classification.max(property.classification);
        }
    }
    Ok(())
}
