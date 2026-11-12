//! Persistent receipt fences and one-way publication revocation.
use super::*;

impl RelationalEngine {
    pub(crate) fn authorize_receipt(
        &self,
        identity: &AuthenticatedIdentity,
        proof: &SqlAuthorization,
    ) -> Result<SqlPublication> {
        let _identity = proof.authorize_replay(identity)?;
        let state = self.state.read();
        proof.validate_row_policies(&state)?;
        SqlPublication::capture(Some(identity), &state, Some(proof))
    }
}

impl SqlAuthorization {
    pub(in crate::relational) fn bind_row_policy(
        &mut self,
        state: &RelationalState,
        name: &str,
    ) -> Result<()> {
        let proof = state
            .tables
            .get(name)
            .map(|table| -> Result<_> {
                if table.definition.tenant_id.as_deref() != Some(self.tenant.as_str()) {
                    return Err(SecurityError::Forbidden.into());
                }
                Ok((
                    table.definition.table_id,
                    table
                        .definition
                        .security_incarnation
                        .unwrap_or(uuid::Uuid::nil()),
                    table
                        .definition
                        .row_policy
                        .as_ref()
                        .map_or(0, |p| p.revision),
                ))
            })
            .transpose()?;
        self.row_policies.insert(name.into(), proof);
        Ok(())
    }
    pub(in crate::relational) fn refresh_row_policies(
        &mut self,
        state: &RelationalState,
    ) -> Result<()> {
        for name in self.row_policies.keys().cloned().collect::<Vec<_>>() {
            self.bind_row_policy(state, &name)?;
        }
        Ok(())
    }
    pub(in crate::relational) fn validate_row_policies(
        &self,
        state: &RelationalState,
    ) -> Result<()> {
        // Historic proofs cannot establish the authority under which row data
        // was saved. Re-executing authorization against today's names is unsafe.
        if (self.schema && self.row_policies.is_empty())
            || self
                .grants
                .iter()
                .map(|(name, _)| name)
                .chain(self.table_grants.iter().map(|grant| &grant.table))
                .any(|name| !self.row_policies.contains_key(name))
        {
            return Err(SecurityError::Forbidden.into());
        }
        let mut current = self.clone();
        current.refresh_row_policies(state)?;
        if current.row_policies != self.row_policies {
            return Err(SecurityError::Conflict.into());
        }
        Ok(())
    }
}

/// Deletion invalidates previously buffered values and receipts, even when
/// object grants did not change. Persist the fence in the same WAL decision.
pub(in crate::relational) fn fence_deletions(
    state: &mut RelationalState,
    sequence: u64,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<()> {
    let names = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            RelationalMutation::Delete { table, row_ids } if !row_ids.is_empty() => {
                Some(table.clone())
            }
            RelationalMutation::AlterTable { definition }
            | RelationalMutation::RenameTable { definition, .. }
            | RelationalMutation::RewriteTable { definition, .. } => Some(definition.name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for name in names {
        let Some(table) = state.tables.get(&name) else {
            continue;
        };
        let Some(mut policy) = table.definition.row_policy.clone() else {
            continue;
        };
        let expected_revision = policy.revision;
        policy.revision = policy
            .revision
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        let delta = chirondb_types::relational::RelationalSecurityDelta {
            table: name,
            incarnation: table
                .definition
                .security_incarnation
                .ok_or(SecurityError::Forbidden)?,
            expected_revision,
            policy,
            records: vec![],
        };
        apply_delta(state, sequence, &delta)?;
        mutations.push(RelationalMutation::RowSecurity { delta });
    }
    Ok(())
}

/// Called under the state write lock, immediately before the durable decision.
/// Failure leaves the old epoch closed: reopen/recovery is required if the
/// decision cannot be reconciled. Old handles never regain authority.
pub(in crate::relational) fn close_replaced_epochs(
    old: &RelationalState,
    candidate: &RelationalState,
) -> Result<()> {
    for (name, table) in old.tables.iter() {
        let Some(epoch) = &table.policy_epoch else {
            continue;
        };
        if !candidate
            .tables
            .get(name)
            .and_then(|table| table.policy_epoch.as_ref())
            .is_some_and(|next| Arc::ptr_eq(epoch, next))
        {
            epoch.close_and_drain()?;
        }
    }
    Ok(())
}

/// A multi-model decision refused before PREPARE can be retried. Restore only
/// fresh readers of the unchanged state; never reopen a drained epoch or reuse
/// the uncommitted candidate's policy. Ambiguous decisions cannot use this path.
pub(in crate::relational) fn renew_uncommitted_epochs(
    old: &mut RelationalState,
    candidate: &RelationalState,
) -> Result<()> {
    let mut restored = old.clone();
    for (name, table) in old.tables.iter() {
        let Some(epoch) = &table.policy_epoch else {
            continue;
        };
        if candidate
            .tables
            .get(name)
            .and_then(|table| table.policy_epoch.as_ref())
            .is_some_and(|next| Arc::ptr_eq(epoch, next))
        {
            continue;
        }
        let replacement = restored
            .tables
            .get_mut(name)?
            .ok_or(SecurityError::Unavailable)?;
        Arc::make_mut(replacement).policy_epoch = Some(crate::security::Epoch::new(
            table
                .definition
                .row_policy
                .as_ref()
                .map_or(0, |policy| policy.revision),
        ));
    }
    *old = restored;
    Ok(())
}
