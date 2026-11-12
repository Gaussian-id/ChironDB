//! Trusted control-plane management. Ordinary SQL cannot supply row labels.
use super::*;
use chirondb_types::relational::RelationalSecurityDelta;

impl RelationalEngine {
    pub(crate) fn inspect_row_security(
        &self,
        identity: &AuthenticatedIdentity,
        name: &str,
        after: u64,
        limit: usize,
    ) -> Result<SqlResponse> {
        let _identity = identity.publication_permit()?;
        if !identity.allows_installation(Action::PolicyManage) || !(1..=128).contains(&limit) {
            return Err(SecurityError::Forbidden.into());
        }
        let state = self.state.read();
        let table = state.tables.get(name).ok_or(SecurityError::NotFound)?;
        if table.definition.tenant_id.as_deref() != Some(identity.principal().tenant.as_str()) {
            return Err(SecurityError::NotFound.into());
        }
        // At most 128 bounded records; admit before constructing JSON copies.
        let mut scratch = memory::Charge::storage();
        let mut bytes = 4096
            + crate::security::storage::serialized_len(&table.definition.row_policy, 256 * 1024)?
                as u64
                * 16;
        scratch.prepare(bytes)?;
        let mut rows = Vec::new();
        for entry in table.rows.visible_versions(state.sequence) {
            let (id, row) = entry?;
            if id <= after {
                continue;
            }
            bytes += 1024
                + crate::security::storage::serialized_len(&row.security, 64 * 1024)? as u64 * 16;
            scratch.prepare(bytes)?;
            rows.push(serde_json::json!({"row_id": id, "authority": row.security}));
            if rows.len() == limit {
                break;
            }
        }
        let value = serde_json::json!({
            "table": name, "table_id": table.definition.table_id,
            "incarnation": table.definition.security_incarnation,
            "policy": table.definition.row_policy, "rows": rows,
        });
        let results = vec![SqlResult::Rows {
            columns: vec!["security".into()],
            column_types: vec![RelationalType::Jsonb],
            rows: vec![vec![RelationalValue::Json(value)]],
        }];
        let memory = output::reserve_results(&results)?;
        Ok(SqlResponse::new(
            SqlExecutionResponse {
                transaction_id: None,
                snapshot: state.sequence,
                committed: true,
                outcome: SqlOutcome::Committed,
                commit_sequence: None,
                retryable: false,
                results,
            },
            memory,
        )
        .with_publication(SqlPublication::management(identity, &state, name)?))
    }

    pub(crate) fn change_row_security(
        &self,
        identity: &AuthenticatedIdentity,
        authority: &crate::security::IdentityAuthority,
        delta: RelationalSecurityDelta,
        audit: &AuditContext,
    ) -> Result<RelationalExecution> {
        let _admission = SQL_ADMISSION.acquire()?;
        let _identity = identity.publication_permit()?;
        if !identity.allows_installation(Action::PolicyManage)
            || (!delta.records.is_empty()
                && (!identity.allows_installation(Action::LabelsManage)
                    || !identity.allows_installation(Action::GrantsManage)))
        {
            return Err(SecurityError::Forbidden.into());
        }
        enforce_serialized_limit(&delta, 8 * 1024 * 1024, "row security change")?;
        self.wait_for_checkpoint_headroom()?;
        let base = self.state.read().clone();
        let table = base
            .tables
            .get(&delta.table)
            .ok_or(SecurityError::NotFound)?;
        if table.definition.tenant_id.as_deref() != Some(identity.principal().tenant.as_str()) {
            return Err(SecurityError::NotFound.into());
        }
        let mut delegated = delta
            .policy
            .policy
            .owner_actions
            .iter()
            .chain(&delta.policy.policy.department_actions)
            .copied()
            .collect::<BTreeSet<_>>();
        if let Some(old) = &table.definition.row_policy {
            delegated.extend(&old.policy.owner_actions);
            delegated.extend(&old.policy.department_actions);
        }
        for record in &delta.records {
            for grant in &record.grants {
                delegated.extend(&grant.actions);
            }
        }
        if !policy::may_delegate_identity(
            identity,
            &[crate::security::ScopeGrant {
                tenants: BTreeSet::from([identity.principal().tenant.clone()]),
                collections: BTreeSet::from([delta.table.clone()]),
                actions: delegated,
            }],
        ) {
            return Err(SecurityError::Forbidden.into());
        }
        let clearance = identity.principal().attributes.clearance;
        if delta.policy.policy.templates.values().any(|template| {
            template.classification > clearance
                || template
                    .properties
                    .values()
                    .any(|field| field.classification > clearance)
        }) {
            return Err(SecurityError::Forbidden.into());
        }
        // The installation policy administrator is the trust root for this
        // tenant. It may explicitly register old unlabeled rows; it gains no
        // ordinary SQL Read rights by doing so.
        for record in &delta.records {
            authority.validate_object_subjects(
                identity,
                &identity.principal().tenant,
                &record.labels.owner,
                &record.grants,
            )?;
            if record.labels.classification > clearance
                || record
                    .properties
                    .values()
                    .any(|field| field.classification > clearance)
            {
                return Err(SecurityError::Forbidden.into());
            }
            let id = record
                .key
                .id
                .parse()
                .map_err(|_| SecurityError::Forbidden)?;
            if let Some(old) = table
                .rows
                .visible(id, base.sequence)?
                .and_then(|row| row.security.clone())
                && (old.labels.classification > clearance
                    || old
                        .properties
                        .values()
                        .any(|field| field.classification > clearance))
            {
                return Err(SecurityError::Forbidden.into());
            }
        }
        let mut candidate = base.clone();
        let sequence = base
            .sequence
            .checked_add(1)
            .ok_or(SecurityError::Unavailable)?;
        apply_delta(&mut candidate, sequence, &delta)?;
        let publication = SqlPublication::management(identity, &base, &delta.table)?;
        let mutations = vec![RelationalMutation::RowSecurity { delta }];
        let intents = collect_transaction_intents(&base, &candidate, base.sequence, &mutations)?;
        let prepared = PreparedRelationalExecution {
            publication,
            snapshot: base.sequence,
            results: vec![SqlResult::Definition {
                affected_objects: 1,
            }],
            mutations,
            reference_writes: BTreeSet::new(),
            catalog: base.tables.clone(),
            write_dependencies: vec![],
            rebasable: false,
            intents,
            authorization: None,
        };
        self.commit_prepared(prepared, audit, 1, None, None, None)
    }
}
