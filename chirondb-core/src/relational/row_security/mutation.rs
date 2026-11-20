//! Persist authority changes without copying row contents into an admin journal.
use super::*;
use chirondb_types::relational::RelationalSecurityDelta;

pub(in crate::relational) fn apply_delta(
    state: &mut RelationalState,
    sequence: u64,
    delta: &RelationalSecurityDelta,
) -> Result<()> {
    if delta.records.len() > crate::security::MAX_POLICY_GRANTS
        || delta.expected_revision.checked_add(1) != Some(delta.policy.revision)
    {
        return Err(
            SecurityError::Invalid("invalid row security revision or batch size".into()).into(),
        );
    }
    if state.tables.iter().any(|(name, table)| {
        name != &delta.table && table.definition.security_incarnation == Some(delta.incarnation)
    }) {
        return Err(
            SecurityError::Invalid("duplicate relational security incarnation".into()).into(),
        );
    }
    let table = state
        .tables
        .get_mut(&delta.table)?
        .ok_or(SecurityError::NotFound)?;
    let table = Arc::make_mut(table);
    let registration = table.definition.security_incarnation.is_none()
        && table.definition.row_policy.is_none()
        && delta.expected_revision == 0
        && !delta.incarnation.is_nil();
    if (!registration && table.definition.security_incarnation != Some(delta.incarnation))
        || table
            .definition
            .row_policy
            .as_ref()
            .map_or(0, |policy| policy.revision)
            != delta.expected_revision
    {
        return Err(SecurityError::Conflict.into());
    }
    let mut definition = table.definition.as_ref().clone();
    definition.security_incarnation = Some(delta.incarnation);
    definition.row_policy = Some(delta.policy.clone());
    validate_policy(&definition)?;
    let mut seen = BTreeSet::new();
    for record in &delta.records {
        let row_id = record
            .key
            .id
            .parse::<u64>()
            .map_err(|_| SecurityError::Invalid("invalid row authority ID".into()))?;
        if !seen.insert(row_id) || record.revision != delta.policy.revision || record.retired {
            return Err(SecurityError::Invalid("invalid row authority version".into()).into());
        }
        validate_binding(&definition, row_id, Some(record), false)?;
        let security = Metadata::adopt(record.clone())?;
        let mut versions = table
            .rows
            .get(&row_id)?
            .ok_or(SecurityError::NotFound)?
            .into_owned()?;
        let position = versions
            .iter()
            .rposition(|version| {
                version.begin <= sequence && version.end.is_none_or(|end| sequence < end)
            })
            .ok_or(SecurityError::NotFound)?;
        if let Some(prior) = &versions[position].security
            && (prior.key != record.key
                || prior.storage_id != record.storage_id
                || prior.content != record.content)
        {
            return Err(
                SecurityError::Invalid("row authority identity is immutable".into()).into(),
            );
        }
        if versions[position].begin == sequence {
            versions[position].security = Some(security);
        } else {
            let values = versions[position].values.clone();
            versions[position].end = Some(sequence);
            versions.push(RowVersion {
                security: Some(security),
                begin: sequence,
                end: None,
                values,
            })?;
        }
        table.rows.insert(row_id, versions)?;
    }
    table.replace_definition(definition, sequence)?;
    Ok(())
}
