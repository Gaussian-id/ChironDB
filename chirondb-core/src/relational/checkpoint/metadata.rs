//! Admission for owned checkpoint metadata copies. Runtime catalog ownership is
//! separate; borrowing a segment-reference slice never creates an owned copy.
use super::*;
use std::mem::size_of;

#[cfg(test)]
mod tests;

const OWNER_BYTES: u64 = 256;

struct Bytes(u64);

impl Bytes {
    fn add(&mut self, bytes: u64) -> Result<()> {
        check_sql_cancelled()?;
        self.0 = self.0.checked_add(bytes).ok_or_else(sql_overloaded)?;
        Ok(())
    }

    fn slots<T>(&mut self, count: usize) -> Result<()> {
        self.add((count as u64).saturating_mul(size_of::<T>() as u64))
    }

    fn definition(&mut self, definition: &TableDefinition) -> Result<()> {
        self.add(schema::copy_bytes(definition)?)
    }

    fn reference(&mut self, reference: &RelationalSegmentReference) -> Result<()> {
        self.add(reference.file_name.capacity() as u64)?;
        for key in reference.min_key.iter().chain(&reference.max_key) {
            self.add(key.capacity() as u64)?;
        }
        Ok(())
    }

    fn references(&mut self, references: &[RelationalSegmentReference]) -> Result<()> {
        self.slots::<RelationalSegmentReference>(references.len())?;
        for reference in references {
            self.reference(reference)?;
        }
        Ok(())
    }

    fn table(&mut self, table: &RelationalCheckpointTable, projection: bool) -> Result<()> {
        self.definition(&table.definition)?;
        for reference in table.row_segment.iter().chain(&table.index_segment) {
            self.reference(reference)?;
        }
        self.references(&table.row_segments)?;
        self.references(&table.index_segments)?;
        if !projection {
            self.add(memory::tree_bytes(table.rows.len()))?;
            for versions in table.rows.values() {
                self.slots::<RowVersion>(versions.len())?;
                // RowValues clones share their independently admitted payload.
            }
        }
        Ok(())
    }

    fn reserve(self) -> Result<memory::Charge> {
        let mut memory = memory::Charge::storage();
        memory.prepare(self.0)?;
        Ok(memory)
    }
}

pub(in crate::relational) fn capture(
    state: &RelationalState,
    wal_watermark: u64,
) -> Result<CapturedRelationalCheckpoint> {
    let mut bytes = Bytes(OWNER_BYTES);
    bytes.slots::<RelationalCheckpointTable>(state.tables.len())?;
    bytes.slots::<Arc<TableState>>(state.tables.len())?;
    for table in state.tables.values() {
        bytes.definition(&table.definition)?;
    }
    let owned_memory = bytes.reserve()?;
    let mut tables = Vec::new();
    let mut pins = Vec::new();
    tables
        .try_reserve_exact(state.tables.len())
        .map_err(|_| sql_overloaded())?;
    pins.try_reserve_exact(state.tables.len())
        .map_err(|_| sql_overloaded())?;
    for table in state.tables.values() {
        check_sql_cancelled()?;
        tables.push(RelationalCheckpointTable {
            definition: table.definition.as_ref().clone(),
            rows: BTreeMap::new(),
            next_row_id: table.next_row_id,
            row_segment: None,
            index_segment: None,
            row_segments: Vec::new(),
            index_segments: Vec::new(),
        });
        pins.push(Arc::clone(table));
    }
    Ok(CapturedRelationalCheckpoint {
        manifest: RelationalCheckpoint {
            version: RELATIONAL_CHECKPOINT_VERSION,
            sequence: state.sequence,
            next_catalog_id: state.next_catalog_id,
            wal_watermark,
            tables,
            applied_transactions: Vec::new(),
            owned_memory: owned_memory.clone(),
        },
        tables: pins,
        // Keep the same reservation until both the manifest and pin Vec drop.
        _owned_memory: owned_memory,
    })
}

pub(super) fn copy(
    checkpoint: &RelationalCheckpoint,
    projection: bool,
) -> Result<RelationalCheckpoint> {
    let mut bytes = Bytes(OWNER_BYTES);
    bytes.slots::<RelationalCheckpointTable>(checkpoint.tables.len())?;
    if !projection {
        bytes.slots::<TransactionId>(checkpoint.applied_transactions.len())?;
    }
    for table in &checkpoint.tables {
        bytes.table(table, projection)?;
    }
    let owned_memory = bytes.reserve()?;
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(checkpoint.tables.len())
        .map_err(|_| sql_overloaded())?;
    for table in &checkpoint.tables {
        check_sql_cancelled()?;
        tables.push(RelationalCheckpointTable {
            definition: table.definition.clone(),
            rows: if projection {
                BTreeMap::new()
            } else {
                table.rows.clone()
            },
            next_row_id: table.next_row_id,
            row_segment: table.row_segment.clone(),
            index_segment: table.index_segment.clone(),
            row_segments: table.row_segments.clone(),
            index_segments: table.index_segments.clone(),
        });
    }
    Ok(RelationalCheckpoint {
        version: checkpoint.version,
        sequence: checkpoint.sequence,
        next_catalog_id: checkpoint.next_catalog_id,
        wal_watermark: checkpoint.wal_watermark,
        tables,
        applied_transactions: if projection {
            Vec::new()
        } else {
            checkpoint.applied_transactions.clone()
        },
        owned_memory,
    })
}

/// Reserve a fresh exact-size reference vector and its owned strings/key bounds
/// before copying. Its reservation belongs to the destination manifest.
pub(super) fn references(
    previous: &[RelationalSegmentReference],
    appended: Option<(String, &SegmentMetadata)>,
    memory: &mut memory::Charge,
) -> Result<Vec<RelationalSegmentReference>> {
    let mut bytes = Bytes(0);
    bytes.references(previous)?;
    if let Some((name, metadata)) = &appended {
        bytes.slots::<RelationalSegmentReference>(1)?;
        bytes.add(name.capacity() as u64)?;
        for key in metadata.min_key.iter().chain(&metadata.max_key) {
            bytes.add(key.capacity() as u64)?;
        }
    }
    memory.prepare(
        memory
            .bytes()
            .checked_add(bytes.0)
            .ok_or_else(sql_overloaded)?,
    )?;
    let mut references = Vec::new();
    references
        .try_reserve_exact(previous.len() + usize::from(appended.is_some()))
        .map_err(|_| sql_overloaded())?;
    references.extend_from_slice(previous);
    if let Some((name, metadata)) = appended {
        references.push(segment_reference(name, metadata));
    }
    Ok(references)
}
