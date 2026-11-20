//! Constraint probes are Query operations, including probes of hidden rows.
use super::*;

pub(in crate::relational) fn preflight_constraints(
    state: &RelationalState,
    statement: &Statement,
    snapshot: u64,
) -> Result<()> {
    let Some(identity) = state.request_identity.as_deref() else {
        return Ok(());
    };
    let analysis = analyze_parsed_statement(statement)?;
    if matches!(
        analysis.kind,
        SqlStatementKind::Select
            | SqlStatementKind::Explain
            | SqlStatementKind::DropTable
            | SqlStatementKind::DropIndex
    ) {
        return Ok(());
    }
    let mut requirements = BTreeSet::new();
    for name in analysis.tables {
        if !state.tables.contains_key(&name) {
            continue;
        }
        let action = match analysis.kind {
            SqlStatementKind::Insert => Action::Create,
            SqlStatementKind::Delete => Action::Delete,
            _ => Action::Update,
        };
        add_relational_requirement(state, &mut requirements, name, action)?;
    }
    let mut fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, _) in &requirements {
        let table = state.tables.get(name).ok_or(SecurityError::Forbidden)?;
        let columns = fields.entry(name.clone()).or_default();
        columns.extend(table.definition.primary_key.iter().cloned());
        for unique in &table.definition.unique_constraints {
            columns.extend(unique.columns.iter().cloned());
        }
        for index in table.definition.indexes.iter().filter(|index| index.unique) {
            columns.extend(index.columns.iter().cloned());
        }
        // CHECK success/failure is also a predicate result. A writable column
        // can be compared with an otherwise hidden value, including during a
        // cascade, so authorize every referenced field before validation.
        for constraint in &table.definition.check_constraints {
            let expression = parse_check_expression(&constraint.expression)?;
            for column in &table.definition.columns {
                if expression_references_column(&expression, &column.name) {
                    columns.insert(column.name.clone());
                }
            }
        }
        if matches!(
            analysis.kind,
            SqlStatementKind::AlterTable | SqlStatementKind::CreateIndex
        ) {
            // Type/check/index DDL validates existing values, potentially on a
            // newly declared key. Authorize before its first value inspection.
            columns.extend(
                table
                    .definition
                    .columns
                    .iter()
                    .map(|column| column.name.clone()),
            );
        }
        for foreign in &table.definition.foreign_keys {
            columns.extend(foreign.columns.iter().cloned());
        }
        for foreign in &table.definition.foreign_keys {
            let parent = state
                .tables
                .get(&foreign.referenced_table)
                .ok_or(SecurityError::Forbidden)?;
            fields
                .entry(foreign.referenced_table.clone())
                .or_default()
                .extend(resolved_referenced_columns(foreign, &parent.definition)?);
        }
    }
    for (name, columns) in fields {
        if columns.is_empty() {
            continue;
        }
        let table = state.tables.get(&name).ok_or(SecurityError::Forbidden)?;
        key_domain(table, snapshot, &columns, identity)?;
    }
    Ok(())
}

pub(in crate::relational) fn key_domain(
    table: &TableState,
    snapshot: u64,
    columns: &BTreeSet<String>,
    identity: &AuthenticatedIdentity,
) -> Result<()> {
    let _epoch = table
        .policy_epoch
        .as_ref()
        .ok_or(SecurityError::Forbidden)?
        .enter()?;
    for row in table.rows.visible_versions(snapshot) {
        check_sql_cancelled()?;
        let (id, row) = row?;
        if !object_allowed(&table.definition, id, &row, identity, Action::Read)?
            && !object_allowed(&table.definition, id, &row, identity, Action::Search)?
        {
            return Err(SecurityError::Forbidden.into());
        }
        let record = resource(&table.definition, id, &row)?;
        for column in columns {
            if !policy::field_allowed(
                record,
                &identity.principal().attributes,
                &column_path(column),
                PropertyAction::Query,
            ) {
                return Err(SecurityError::Forbidden.into());
            }
        }
    }
    Ok(())
}
