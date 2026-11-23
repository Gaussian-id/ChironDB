//! Atomic, bounded ML input snapshots and committed per-table watermarks.
//! Scheduler policy belongs to the server; all mutation transports share these
//! watermarks through the ordinary relational batch projection.
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MlSourceRevision {
    pub table_id: u64,
    pub data_revision: u64,
    pub schema_revision: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MlSourceMetadata {
    pub table: TableDefinition,
    pub revision: MlSourceRevision,
    /// Installation UUID and durable content lineage, stable across reopen.
    pub lineage: String,
}

/// Exact durable scheduler claim observed before worker dispatch/publication.
#[derive(Clone, Debug)]
pub struct MlPublicationFence {
    pub schedule_name: String,
    pub schedule_state: String,
}

#[derive(Debug)]
pub struct MlSourceSnapshot {
    pub metadata: MlSourceMetadata,
    pub selected_columns: Vec<String>,
    pub rows: Vec<Vec<RelationalValue>>,
    pub sequence: u64,
    // Retain the receiving reservation until the caller consumes the snapshot.
    _memory: wal_decode::Reservation,
}

impl RelationalEngine {
    pub(crate) fn ml_source_lineage(&self) -> uuid::Uuid {
        self.state.read().source_lineage
    }

    /// Upgrade the checkpoint before an enabled automatic schedule is durable.
    /// A v4 binary rejects the v5 manifest, including databases with no rows.
    pub(crate) fn ensure_ml_source_format(&self) -> Result<()> {
        if !self.ml_source_format_ready.load(AtomicOrdering::Acquire) {
            self.checkpoint()?;
            self.ml_source_format_ready
                .store(true, AtomicOrdering::Release);
        }
        Ok(())
    }

    /// Called only on an isolated, validated restore staging root before its
    /// atomic publication. A failed restore cannot alter the live lineage.
    pub(crate) fn rotate_ml_source_lineage_for_restore(&self) -> Result<()> {
        let mut candidate = self.state.read().clone();
        candidate.source_lineage = uuid::Uuid::new_v4();
        let watermark = self
            .wal
            .lock()
            .map_err(|_| GaussError::WalUnavailable("relational WAL lock poisoned".into()))?
            .len()?;
        let captured = capture_relational_checkpoint(&candidate, watermark)?;
        self.publish_checkpoint(&captured)?;
        self.state.write().source_lineage = candidate.source_lineage;
        self.ml_source_format_ready
            .store(true, AtomicOrdering::Release);
        Ok(())
    }

    pub(crate) fn ml_source_revision(&self, source: &str) -> Result<Option<MlSourceMetadata>> {
        let state = self.state.read();
        Ok(state
            .tables
            .get(&normalize_ident(source))
            .map(|table| metadata(table, state.source_lineage)))
    }

    pub(crate) fn ml_source_snapshot(
        &self,
        source: &str,
        columns: &[String],
        max_rows: usize,
    ) -> Result<MlSourceSnapshot> {
        if !(1..=10_000).contains(&max_rows) {
            return Err(invalid(
                "ML source snapshot limit must be between 1 and 10000 rows",
            ));
        }
        let _admission = SQL_ADMISSION.acquire()?;
        let guard = self.state.read();
        let base = guard.clone();
        let _pin = self.snapshots.pin(base.sequence)?;
        drop(guard);
        snapshot(base, source, columns, max_rows)
    }

    pub(crate) fn execute_ml_publication(
        &self,
        request: SqlExecutionRequest,
        audit: &AuditContext,
        expected: &MlSourceMetadata,
        schedule: Option<&MlPublicationFence>,
    ) -> Result<RelationalExecution> {
        if Self::request_is_read_only(&request)? {
            return Err(invalid(
                "ML publication requires a mutating SQL transaction",
            ));
        }
        self.execute_scoped_with_audit_fenced(request, audit, None, None, Some(expected), schedule)
    }
}

fn metadata(table: &TableState, lineage: uuid::Uuid) -> MlSourceMetadata {
    MlSourceMetadata {
        table: table.definition.as_ref().clone(),
        revision: table.source_revision,
        lineage: lineage.to_string(),
    }
}

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn snapshot(
    base: RelationalState,
    source: &str,
    columns: &[String],
    max_rows: usize,
) -> Result<MlSourceSnapshot> {
    let table = base
        .tables
        .get(&normalize_ident(source))
        .ok_or_else(|| invalid(format!("table {source} does not exist")))?;
    let metadata = metadata(table, base.source_lineage);
    if metadata.table.primary_key.is_empty() {
        return Err(invalid("ML source requires a primary key"));
    }
    let mut selected = metadata.table.primary_key.clone();
    for column in columns {
        column_index(&metadata.table, &normalize_ident(column))?;
        if !selected.contains(column) {
            selected.push(column.clone());
        }
    }
    let sql = format!(
        "SELECT {} FROM {} ORDER BY {} LIMIT {}",
        selected
            .iter()
            .map(|name| quoted(name))
            .collect::<Vec<_>>()
            .join(", "),
        quoted(source),
        metadata
            .table
            .primary_key
            .iter()
            .map(|name| quoted(name))
            .collect::<Vec<_>>()
            .join(", "),
        max_rows + 1,
    );
    let request = SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql,
            parameters: Vec::new(),
        }],
        idempotency_key: None,
        retry_id: None,
    };
    let sequence = base.sequence;
    let mut prepared = prepare_execution(base, request, true, true, None, None, true)?;
    let memory = output::reserve_results(&prepared.results)?;
    let SqlResult::Rows { rows, .. } = prepared
        .results
        .pop()
        .ok_or_else(|| invalid("ML source query returned no result"))?
    else {
        return Err(invalid("ML source query did not return rows"));
    };
    if rows.len() > max_rows {
        return Err(GaussError::SqlLimitExceeded(format!(
            "ML source exceeds the {max_rows} row snapshot limit"
        )));
    }
    Ok(MlSourceSnapshot {
        metadata,
        selected_columns: selected,
        rows,
        sequence,
        _memory: memory,
    })
}

pub(super) fn validate_publication(
    state: &RelationalState,
    expected: &MlSourceMetadata,
) -> Result<()> {
    let current = state
        .tables
        .get(&expected.table.name)
        .ok_or_else(|| invalid("ML source was dropped before publication"))?;
    if current.source_revision.table_id != expected.revision.table_id
        || current.source_revision.schema_revision != expected.revision.schema_revision
        || current.definition.as_ref() != &expected.table
    {
        return Err(invalid(
            "ML source identity or schema changed before publication",
        ));
    }
    Ok(())
}

pub(super) fn validate_schedule(
    state: &RelationalState,
    expected: &MlPublicationFence,
) -> Result<()> {
    let table = state
        .tables
        .get("__chiron_ml_schedule")
        .ok_or_else(|| invalid("ML schedule disappeared before publication"))?;
    if !table.definition.managed_by_ml || table.definition.primary_key != ["name"] {
        return Err(invalid("ML schedule authority changed before publication"));
    }
    let name_index = column_index(&table.definition, "name")?;
    let value_index = column_index(&table.definition, "state")?;
    let key = RelationalValue::Text(expected.schedule_name.clone());
    if let Some(entries) = table.indexed_entries(&table.definition.primary_key, &[&key])? {
        for entry in entries {
            let (_, row_id) = entry?;
            if let Some(row) = table.rows.visible(row_id, state.sequence)?
                && row.values[name_index] == key
                && row.values[value_index] == RelationalValue::Text(expected.schedule_state.clone())
            {
                return Ok(());
            }
        }
    }
    Err(invalid(
        "ML schedule epoch or claim changed before publication",
    ))
}

pub(super) fn validate_checkpoint_revision(
    table: &RelationalCheckpointTable,
    version: u32,
    sequence: u64,
) -> Result<()> {
    match table.source_revision {
        Some(revision)
            if revision.table_id == table.definition.table_id
                && revision.data_revision > 0
                && revision.data_revision <= sequence
                && revision.schema_revision > 0
                && revision.schema_revision <= sequence =>
        {
            Ok(())
        }
        None if version < RELATIONAL_CHECKPOINT_VERSION => Ok(()),
        _ => Err(invalid(format!(
            "invalid ML source revision in checkpoint for table {}",
            table.definition.name
        ))),
    }
}

/// Determine change from just the affected rows before applying the mutation.
/// Empty writes and UPDATEs that leave all values unchanged do not dirty ML.
pub(super) fn mutation_change<'a>(
    state: &RelationalState,
    mutation: &'a RelationalMutation,
    sequence: u64,
) -> Result<Option<(&'a str, bool, bool)>> {
    Ok(match mutation {
        RelationalMutation::CreateTable { definition } => Some((&definition.name, true, true)),
        RelationalMutation::DropTable { .. } => None,
        RelationalMutation::AlterTable { definition } => Some((
            &definition.name,
            false,
            state
                .tables
                .get(&definition.name)
                .is_none_or(|table| table.definition.as_ref() != definition),
        )),
        RelationalMutation::RenameTable { definition, .. } => Some((&definition.name, false, true)),
        RelationalMutation::RewriteTable { definition, .. } => Some((&definition.name, true, true)),
        RelationalMutation::RowSecurity { delta } => Some((&delta.table, false, true)),
        RelationalMutation::Insert { table, rows } => Some((table, !rows.is_empty(), false)),
        RelationalMutation::Delete { table, row_ids } => Some((table, !row_ids.is_empty(), false)),
        RelationalMutation::Update { table, rows } => {
            let current = state
                .tables
                .get(table)
                .ok_or_else(|| invalid(format!("table {table} does not exist")))?;
            let mut changed = false;
            for row in rows {
                let versions = current.rows.get(&row.row_id)?;
                if versions
                    .as_ref()
                    .and_then(|versions| visible_version(versions, sequence))
                    .is_none_or(|version| version.values.as_slice() != row.values.as_slice())
                {
                    changed = true;
                    break;
                }
            }
            Some((table, changed, false))
        }
    })
}

pub(super) fn stamp(
    state: &mut RelationalState,
    name: &str,
    sequence: u64,
    data: bool,
    schema: bool,
) -> Result<()> {
    if !data && !schema {
        return Ok(());
    }
    let table = state
        .tables
        .get_mut(name)?
        .ok_or_else(|| invalid(format!("table {name} does not exist")))?;
    let table = Arc::make_mut(table);
    table.source_revision.table_id = table.definition.table_id;
    if data {
        table.source_revision.data_revision = sequence;
    }
    if schema {
        table.source_revision.schema_revision = sequence;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
