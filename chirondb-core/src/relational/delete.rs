//! Full-table deletes retain identities, not payload images, when neither
//! RETURNING nor referential actions need the old values. Row authority, MVCC,
//! constraint validation and WAL publication remain on the ordinary path.
use super::*;

pub(super) fn all_if_unreferenced(
    state: &mut RelationalState,
    table_name: &str,
    sequence: u64,
    mutations: &mut Vec<RelationalMutation>,
) -> Result<Option<SqlResult>> {
    if state.tables.values().any(|table| {
        table
            .definition
            .foreign_keys
            .iter()
            .any(|foreign_key| foreign_key.referenced_table == table_name)
    }) {
        return Ok(None);
    }
    let table = state
        .tables
        .get(table_name)
        .ok_or_else(|| invalid(format!("table {table_name} does not exist")))?;
    let mut deleted = Vec::<u64>::new();
    for row in row_security::visible_rows(table, sequence, state.request_identity.as_deref()) {
        check_sql_cancelled()?;
        let (row_id, values) = row?;
        let current_capacity = deleted.capacity();
        let next_capacity = if deleted.len() == current_capacity {
            current_capacity
                .checked_mul(2)
                .ok_or_else(sql_overloaded)?
                .max(4)
        } else {
            current_capacity
        };
        // Bound the resident identity buffer, its growth overlap and the one
        // row decoded by the iterator. No payload survives this iteration.
        let slots = next_capacity.saturating_add(if next_capacity == current_capacity {
            0
        } else {
            current_capacity
        });
        let mut peak = slots.saturating_mul(std::mem::size_of::<u64>());
        charge_query_operator_row(&mut peak, &values)?;
        if next_capacity != current_capacity {
            deleted
                .try_reserve_exact(next_capacity - deleted.len())
                .map_err(|_| sql_overloaded())?;
        }
        deleted.push(row_id);
    }
    let affected_rows = deleted.len() as u64;
    for row_id in &deleted {
        check_sql_cancelled()?;
        delete_visible_row(state, table_name, *row_id, sequence)?;
    }
    mutations.push(RelationalMutation::Delete {
        table: table_name.into(),
        row_ids: deleted,
    });
    Ok(Some(SqlResult::Mutation { affected_rows }))
}

#[cfg(test)]
mod tests;
