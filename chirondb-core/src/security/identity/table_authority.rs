//! Table scopes use persistent catalog identities, independent of vector collections.
use super::administration::{may_manage_role, validate_role};
use super::*;

impl IdentityAuthority {
    /// Publish the complete conversion in one authority generation. Nothing
    /// grants rights to future tables, and collection scopes retain their
    /// vector/graph meaning. Disabled users retain dormant, exact grants.
    pub(crate) fn migrate_sql_scopes_offline(
        &self,
        tables: &BTreeMap<(String, String), (u64, Uuid)>,
    ) -> Result<bool> {
        let _update = self.update.lock();
        let (mut next, epoch) = {
            let current = self.current.read();
            if current.state.version >= 6 {
                return Ok(false);
            }
            if current.state.version != 5 {
                return Err(SecurityError::Invalid(
                    "complete offline migrate-table-authority before migrate-sql-scopes".into(),
                ));
            }
            (current.state.clone(), Arc::clone(&current.epoch))
        };
        let mut added_bytes = 0usize;
        for role in next.roles.values_mut().filter(|role| !role.retired) {
            for scope in &role.grants {
                if let Some(&(table_id, incarnation)) =
                    tables.get(&(role.tenant.clone(), scope.collection.clone()))
                {
                    merge_migrated_grant(
                        &mut role.table_grants,
                        &scope.collection,
                        table_id,
                        incarnation,
                        &scope.actions,
                        &mut added_bytes,
                    )?;
                }
            }
        }
        for principal in next.principals.values() {
            if next.retired_users.contains(&principal.id) {
                continue;
            }
            let mut grants = Vec::new();
            for scope in &principal.grants {
                if !scope.tenants.contains(&principal.tenant) {
                    continue;
                }
                for name in &scope.collections {
                    if let Some(&(table_id, incarnation)) =
                        tables.get(&(principal.tenant.clone(), name.clone()))
                    {
                        merge_migrated_grant(
                            &mut grants,
                            name,
                            table_id,
                            incarnation,
                            &scope.actions,
                            &mut added_bytes,
                        )?;
                    }
                }
            }
            if !grants.is_empty() {
                let id = Uuid::new_v4();
                // Normal roles make migrated direct grants inspectable and
                // revocable through the existing administration contract.
                let role = RoleRecord {
                    id,
                    name: format!("sql_migrated_{}", id.simple()),
                    tenant: principal.tenant.clone(),
                    retired: false,
                    grants: Vec::new(),
                    table_grants: grants,
                    installation_actions: BTreeSet::new(),
                };
                next.memberships
                    .entry(principal.id.clone())
                    .or_default()
                    .insert(id);
                next.roles.insert(id, role);
            }
        }
        next.version = 6;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        next.validate()?;
        // Reject over-budget conversion before an audit append, reader fence,
        // epoch closure or authority replacement can change durable state.
        let encoded = encode_state(&next)?;
        let tenant = next
            .installation
            .as_ref()
            .ok_or(SecurityError::Unavailable)?
            .tenant
            .clone();
        let intent = self
            .audit
            .operation_with_details(
                "security",
                "identity.migrate_sql_scopes",
                None,
                crate::audit::AuditContext {
                    principal_id: "offline-authority-migration".into(),
                    tenant_id: Some(tenant),
                    transport: "offline".into(),
                    request_id: None,
                },
                serde_json::json!({"identity_format": 6, "next_identity_revision": next.revision}),
            )
            .map_err(|_| SecurityError::Unavailable)?;
        epoch.close_and_drain()?;
        crate::failpoint::check("sql_scopes.before_authority")
            .map_err(|_| SecurityError::Unavailable)?;
        persist_encoded(&self.root, &next, &encoded)?;
        crate::failpoint::check("sql_scopes.after_authority")
            .map_err(|_| SecurityError::Unavailable)?;
        intent
            .success(serde_json::json!({"identity_revision": next.revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        *self.current.write() = Current {
            epoch: Epoch::new(next.revision),
            state: next,
        };
        Ok(true)
    }

    /// Called only by the offline Db migration while it owns the directory lease.
    /// Install the old-reader fence before publishing the versioned authority.
    pub(crate) fn upgrade_table_authority_offline(&self) -> Result<()> {
        let _update = self.update.lock();
        let (mut next, epoch) = {
            let current = self.current.read();
            if current.state.version >= 5 {
                return Ok(());
            }
            (current.state.clone(), Arc::clone(&current.epoch))
        };
        let installation = next.installation.as_ref().ok_or_else(|| {
            SecurityError::Invalid("table authority requires an initialized installation".into())
        })?;
        let tenant = installation.tenant.clone();
        next.version = 5;
        if next.scram_decoy_key.is_none() {
            let mut key = [0; 32];
            SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| SecurityError::Unavailable)?;
            next.scram_decoy_key = Some(key);
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        next.validate()?;
        let intent = self
            .audit
            .operation_with_details(
                "security",
                "identity.migrate_table_authority",
                None,
                crate::audit::AuditContext {
                    principal_id: "offline-authority-migration".into(),
                    tenant_id: Some(tenant),
                    transport: "offline".into(),
                    request_id: None,
                },
                serde_json::json!({"identity_format": 5, "next_identity_revision": next.revision}),
            )
            .map_err(|_| SecurityError::Unavailable)?;
        epoch.close_and_drain()?;
        persist(&self.root, &next)?;
        intent
            .success(serde_json::json!({"identity_revision": next.revision}))
            .map_err(|_| SecurityError::Unavailable)?;
        *self.current.write() = Current {
            epoch: Epoch::new(next.revision),
            state: next,
        };
        Ok(())
    }

    pub(crate) fn change_role_table_privileges(
        &self,
        actor: &AuthenticatedIdentity,
        expected: u64,
        role_name: &str,
        binding: RoleTableGrant,
        grant: bool,
    ) -> Result<u64> {
        if !actor.is_installation_admin() {
            return Err(SecurityError::Forbidden);
        }
        if binding.actions.is_empty()
            || binding.actions.iter().any(|action| {
                !matches!(
                    action,
                    Action::Read | Action::Create | Action::Update | Action::Delete
                )
            })
        {
            return Err(SecurityError::Invalid(
                "table grants accept Read/Create/Update/Delete".into(),
            ));
        }
        self.change(actor, expected, "identity.role_table_privileges", |state| {
            if state.version < 5 {
                return Err(SecurityError::Invalid(
                    "run offline chironctl security migrate-table-authority first".into(),
                ));
            }
            let mut role = state.role(role_name)?.clone();
            may_manage_role(actor, &role)?;
            if let Some(scope) = role.table_grants.iter_mut().find(|scope| {
                scope.table_id == binding.table_id && scope.incarnation == binding.incarnation
            }) {
                scope.table.clone_from(&binding.table);
                if grant {
                    scope.actions.extend(&binding.actions);
                } else {
                    scope
                        .actions
                        .retain(|action| !binding.actions.contains(action));
                }
            } else if grant {
                role.table_grants.push(binding);
            }
            role.table_grants.retain(|scope| !scope.actions.is_empty());
            validate_role(&role)?;
            state.roles.insert(role.id, role);
            Ok(())
        })
        .map(|(_, revision)| revision)
    }
}

fn merge_migrated_grant(
    grants: &mut Vec<RoleTableGrant>,
    name: &str,
    table_id: u64,
    incarnation: Uuid,
    actions: &BTreeSet<Action>,
    added_bytes: &mut usize,
) -> Result<()> {
    let actions: BTreeSet<_> = actions
        .iter()
        .copied()
        .filter(|action| {
            matches!(
                action,
                Action::Read | Action::Create | Action::Update | Action::Delete
            )
        })
        .collect();
    if actions.is_empty() {
        return Ok(());
    }
    if let Some(grant) = grants
        .iter_mut()
        .find(|grant| grant.table_id == table_id && grant.incarnation == incarnation)
    {
        grant.actions.extend(actions);
    } else {
        *added_bytes = added_bytes.saturating_add(name.len() + 512);
        if grants.len() >= MAX_POLICY_GRANTS || *added_bytes as u64 > MAX_IDENTITY_BYTES {
            return Err(SecurityError::BudgetExceeded);
        }
        grants.push(RoleTableGrant {
            table: name.into(),
            table_id,
            incarnation,
            actions,
        });
    }
    Ok(())
}
