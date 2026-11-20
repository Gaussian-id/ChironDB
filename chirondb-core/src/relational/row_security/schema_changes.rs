//! Column identity changes must move/remove authority with the column.
use super::*;

pub(in crate::relational) fn column_rename(
    statement: &Statement,
) -> Option<(String, String, String)> {
    let Statement::AlterTable(alter) = statement else {
        return None;
    };
    let [
        AlterTableOperation::RenameColumn {
            old_column_name,
            new_column_name,
        },
    ] = alter.operations.as_slice()
    else {
        return None;
    };
    Some((
        normalize_name(&alter.name),
        normalize_ident(&old_column_name.value),
        normalize_ident(&new_column_name.value),
    ))
}

pub(in crate::relational) fn reconcile_columns(
    before: &RelationalState,
    state: &mut RelationalState,
    sequence: u64,
    rename: Option<(String, String, String)>,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<()> {
    for (name, old) in before.tables.iter() {
        let Some(table) = state.tables.get(name).cloned() else {
            continue;
        };
        let Some(policy) = &table.definition.row_policy else {
            continue;
        };
        let mut changes = BTreeMap::new();
        for column in &old.definition.columns {
            if !table
                .definition
                .columns
                .iter()
                .any(|next| next.name == column.name)
            {
                let replacement = rename
                    .as_ref()
                    .filter(|(t, from, _)| t == name && *from == column.name)
                    .map(|(_, _, to)| column_path(to));
                changes.insert(column_path(&column.name), replacement);
            }
        }
        if changes.is_empty() {
            continue;
        }
        let edit = |properties: &mut BTreeMap<String, PropertyRule>| {
            for (from, to) in &changes {
                let rule = properties.remove(from);
                if let Some(to) = to {
                    // A preconfigured rule on an unused target name must not
                    // replace the source's authority during a rename.
                    properties.remove(to);
                    if let Some(rule) = rule {
                        properties.insert(to.clone(), rule);
                    }
                }
            }
        };
        let mut policy = policy.clone();
        for template in policy.policy.templates.values_mut() {
            edit(&mut template.properties);
        }
        let mut records = Vec::new();
        let mut expected = policy.revision;
        policy.revision = expected.checked_add(1).ok_or(SecurityError::Unavailable)?;
        let emit = |state: &mut RelationalState,
                    records: &mut Vec<ResourceRecord>,
                    expected: u64,
                    policy: &chirondb_types::RelationalRowPolicy,
                    mutations: &mut Vec<RelationalMutation>|
         -> Result<()> {
            let delta = chirondb_types::relational::RelationalSecurityDelta {
                table: name.clone(),
                incarnation: table
                    .definition
                    .security_incarnation
                    .ok_or(SecurityError::Forbidden)?,
                expected_revision: expected,
                policy: policy.clone(),
                records: std::mem::take(records),
            };
            apply_delta(state, sequence, &delta)?;
            mutations.push(RelationalMutation::RowSecurity { delta });
            enforce_serialized_limit(mutations, MAX_WRITE_SET_BYTES, "column authority write set")
        };
        for entry in table.rows.visible_versions(sequence) {
            check_sql_cancelled()?;
            let (_, row) = entry?;
            let Some(record) = row.security else { continue };
            let mut record = (*record).clone();
            edit(&mut record.properties);
            record.revision = policy.revision;
            records.push(record);
            if records.len() == crate::security::MAX_POLICY_GRANTS {
                emit(state, &mut records, expected, &policy, mutations)?;
                expected = policy.revision;
                policy.revision = expected.checked_add(1).ok_or(SecurityError::Unavailable)?;
            }
        }
        // Also persist the future-ingest template on an empty table.
        emit(state, &mut records, expected, &policy, mutations)?;
    }
    Ok(())
}
