//! Delta projection and bounded immutable-run compaction. Ordinary checkpoints
//! encode only versions changed since the table's installed disk base.

pub(super) mod decode;
pub(super) mod encode;
pub(super) mod metadata;

use super::*;

pub(super) mod sort;
use sort::RecordSource;

pub(super) fn cleanup_interrupted(directory: &Path, checkpoint_path: &Path) -> Result<()> {
    sort::cleanup_interrupted(directory)?;
    // Startup holds the installation lease. Runs omitted from the durable
    // manifest are private output from a failed checkpoint or migration; WAL
    // replay recreates any committed changes that were not checkpointed.
    let retained = read_relational_checkpoint(checkpoint_path)?
        .as_ref()
        .map(checkpoint_segment_names)
        .unwrap_or_default();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if entry.file_type()?.is_file()
            && (name.starts_with("row-") || name.starts_with("index-"))
            && name.ends_with(".rseg")
            && !retained.contains(name)
        {
            remove_segment_if_exists(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// A private disk index belongs to its table generation until a durable
/// checkpoint replaces it. Its reader/cursors pin the scratch directory.
pub(super) fn rebuild_indexes(table: &TableState, sequence: u64) -> Result<TableSegmentBacking> {
    sort::project(table, &table.directory, SegmentKind::Index, sequence, false)?
        .into_index_backing(table, sequence)
}

/// Replay may publish a complete prefix while scanning the unchanged WAL. The
/// watermark is the next record's start (or final end), never an in-record LSN.
/// WAL reclamation happens only after the scanner has closed all input files.
pub(super) fn flush_recovery_prefix(
    state: &mut RelationalState,
    watermark: u64,
    path: &Path,
    directory: &Path,
    generation: &mut Option<RelationalCheckpoint>,
) -> Result<()> {
    let captured = capture_relational_checkpoint(state, watermark)?;
    let persisted = materialize(&captured, generation.as_ref(), directory)?;
    crate::failpoint::check("relational_recovery.after_segments")?;
    let projected = projection_manifest(&persisted)?;
    let backings = prepare_checkpoint_backings(&persisted, directory)?;
    let permit = state.tables.prepare_install()?;
    write_relational_checkpoint(path, &persisted)?;
    crate::failpoint::check("relational_recovery.after_manifest")?;
    assert!(install_checkpoint_backings(
        state, &persisted, backings, permit
    ));
    drop(captured);
    cleanup_unreferenced_checkpoint_segments(
        directory,
        &persisted,
        &recovered_index_segment_names(state),
    );
    metrics::counter!("chirondb_relational_recovery_checkpoints_total").increment(1);
    *generation = Some(projected);
    Ok(())
}

/// Only projection metadata is needed while replaying; legacy inline rows and
/// the serialized replay-ID list are already represented by the recovered state.
pub(super) fn projection_manifest(
    checkpoint: &RelationalCheckpoint,
) -> Result<RelationalCheckpoint> {
    metadata::copy(checkpoint, true)
}

impl RelationalCheckpoint {
    pub(in crate::relational) fn try_clone(&self) -> Result<Self> {
        metadata::copy(self, false)
    }
}

/// Spill a private part of one already-committed WAL batch. Its generation is
/// never published until the complete batch passes constraints and owns its
/// replay ID. Unique names and coupled compaction keep partial runs distinct
/// from the last authoritative checkpoint, including repeated same-sequence
/// updates to one physical row key.
pub(super) fn stage_recovery_rows(
    state: &mut RelationalState,
    sequence: u64,
    generation: &mut Option<RelationalCheckpoint>,
    directory: &Path,
    checkpoint_path: &Path,
) -> Result<()> {
    let mut captured = capture_relational_checkpoint(state, 0)?;
    captured.manifest.sequence = sequence;
    let tag = format!("migration-{}", uuid::Uuid::new_v4());
    let staged = materialize_with_tag(&captured, generation.as_ref(), directory, Some(&tag))?;
    crate::failpoint::check("relational_recovery.after_staged_segments")?;
    let projected = projection_manifest(&staged)?;
    let backings = prepare_checkpoint_backings(&staged, directory)?;
    let permit = state.tables.prepare_install()?;
    assert!(install_checkpoint_backings(
        state, &staged, backings, permit
    ));
    let sequence = state.sequence;
    state.tables.try_update_all(|table| {
        let mut table = table.clone();
        Arc::make_mut(&mut table)
            .rows
            .replay_base_frontier(sequence);
        Ok(Some(table))
    })?;
    drop(captured);
    let authoritative = read_relational_checkpoint(checkpoint_path)?;
    let retained = authoritative
        .as_ref()
        .map(checkpoint_segment_names)
        .unwrap_or_default();
    cleanup_unreferenced_checkpoint_segments(directory, &staged, &retained);
    *generation = Some(projected);
    metrics::counter!("chirondb_relational_recovery_spills_total").increment(1);
    Ok(())
}

pub(super) fn materialize(
    captured: &CapturedRelationalCheckpoint,
    existing: Option<&RelationalCheckpoint>,
    directory: &Path,
) -> Result<RelationalCheckpoint> {
    materialize_with_tag(captured, existing, directory, None)
}

/// An offline catalog migration may keep the same commit sequence. Give its
/// immutable runs distinct names so a failed attempt cannot replace the runs
/// still named by the authoritative manifest.
pub(super) fn materialize_migration(
    captured: &CapturedRelationalCheckpoint,
    existing: Option<&RelationalCheckpoint>,
    directory: &Path,
) -> Result<RelationalCheckpoint> {
    let tag = uuid::Uuid::new_v4().to_string();
    materialize_with_tag(captured, existing, directory, Some(&tag))
}

/// A live checkpoint may carry forward an already published table generation
/// when that table has no row or scalar-index delta. Recovery still verifies
/// every referenced generation from disk before it becomes queryable.
pub(super) fn reuses_generation(
    table: &TableState,
    previous: Option<&RelationalCheckpointTable>,
) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    table.rows.has_disk_base()
        && &previous.definition == table.definition.as_ref()
        && !checkpoint_row_references(previous).is_empty()
        && table.rows.checkpoint_delta().next().is_none()
        && table
            .indexes
            .values()
            .all(|index| index.retained_bytes() == 0)
        && table.index_segments.len() == checkpoint_index_references(previous).len()
        && table
            .index_segments
            .iter()
            .zip(checkpoint_index_references(previous))
            .all(|(backing, reference)| {
                backing.file_name == reference.file_name && backing.sequence == reference.sequence
            })
}

/// During a live append-only checkpoint, the old generation was validated
/// when it was installed. Compare every new row and index record with the
/// captured mutation projection before publishing the next manifest. A
/// compacted or otherwise replaced generation still needs full validation.
pub(super) fn validate_appended_generation(
    source: &TableState,
    persisted: &RelationalCheckpointTable,
    previous: &RelationalCheckpointTable,
    previous_sequence: u64,
    directory: &Path,
    sequence: u64,
) -> Result<bool> {
    let old_rows = checkpoint_row_references(previous);
    let old_indexes = checkpoint_index_references(previous);
    let new_rows = checkpoint_row_references(persisted);
    let new_indexes = checkpoint_index_references(persisted);
    let source_indexes_match = source.index_segments.len() == old_indexes.len()
        && source
            .index_segments
            .iter()
            .zip(old_indexes)
            .all(|(backing, reference)| {
                backing.file_name == reference.file_name && backing.sequence == reference.sequence
            });
    if old_rows.is_empty()
        || source.definition.as_ref() != &previous.definition
        || persisted.definition != previous.definition
        || source.next_row_id != persisted.next_row_id
        || source.rows.installed_sequence() != Some(previous_sequence)
        || !source_indexes_match
        || source.rows.checkpoint_delta().next().is_none()
        || new_rows.len() != old_rows.len() + 1
        || !new_rows.starts_with(old_rows)
        || !new_indexes.starts_with(old_indexes)
        || new_indexes.len() > old_indexes.len() + 1
    {
        return Ok(false);
    }
    validate_appended_run(
        source,
        directory,
        sequence,
        SegmentKind::Row,
        new_rows.last(),
    )?;
    validate_appended_run(
        source,
        directory,
        sequence,
        SegmentKind::Index,
        new_indexes.get(old_indexes.len()),
    )?;
    Ok(true)
}

fn validate_appended_run(
    source: &TableState,
    directory: &Path,
    sequence: u64,
    kind: SegmentKind,
    reference: Option<&RelationalSegmentReference>,
) -> Result<()> {
    let expected = sort::project(source, directory, kind, sequence, true)?;
    let Some(reference) = reference else {
        return if expected.is_empty() {
            Ok(())
        } else {
            Err(invalid("live checkpoint omitted a delta segment"))
        };
    };
    let path = directory.join(&reference.file_name);
    let mut actual = segment::SegmentCursor::open(&path)?;
    validate_segment_reference(reference, actual.metadata())?;
    let mut expected = expected.cursor()?;
    loop {
        match (expected.next().transpose()?, actual.next().transpose()?) {
            (None, None) => return Ok(()),
            (Some(left), Some(right)) if left == right => {}
            _ => return Err(invalid("live checkpoint delta projection is inconsistent")),
        }
    }
}

fn materialize_with_tag(
    captured: &CapturedRelationalCheckpoint,
    existing: Option<&RelationalCheckpoint>,
    directory: &Path,
    tag: Option<&str>,
) -> Result<RelationalCheckpoint> {
    fs::create_dir_all(directory)?;
    let mut manifest = captured.manifest.try_clone()?;
    for (persisted, table) in manifest.tables.iter_mut().zip(&captured.tables) {
        let previous = existing.and_then(|checkpoint| {
            checkpoint
                .tables
                .iter()
                .find(|old| old.definition.table_id == table.definition.table_id)
        });
        // Offline migration writes a distinct generation even at the same
        // commit sequence; only live checkpoints may retain old run names.
        if tag.is_none() && reuses_generation(table, previous) {
            let previous = previous.expect("reuse requires a published generation");
            persisted.row_segments = metadata::references(
                checkpoint_row_references(previous),
                None,
                &mut manifest.owned_memory,
            )?;
            persisted.index_segments = metadata::references(
                checkpoint_index_references(previous),
                None,
                &mut manifest.owned_memory,
            )?;
            persisted.row_segment = None;
            persisted.index_segment = None;
            persisted.rows.clear();
            continue;
        }
        let compatible = table.rows.has_disk_base()
            && previous.is_some_and(|old| &old.definition == table.definition.as_ref());
        let rows = sort::project(
            table,
            directory,
            SegmentKind::Row,
            manifest.sequence,
            compatible,
        )?;
        let indexes = sort::project(
            table,
            directory,
            SegmentKind::Index,
            manifest.sequence,
            compatible,
        )?;
        let mode = if compatible {
            RunMode::Delta {
                reclaim_before: table.rows.retention_frontier(),
            }
        } else {
            RunMode::Replace
        };
        let writer = RunWriter {
            directory,
            sequence: manifest.sequence,
            table_id: table.definition.table_id,
        };
        let previous_rows = previous.map(checkpoint_row_references).unwrap_or_default();
        let previous_indexes = previous
            .map(checkpoint_index_references)
            .unwrap_or_default();
        // Row and scalar projections must retain exactly the same versions.
        // A size/garbage trigger in either projection compacts both together.
        let compact_rows = writer.needs_compaction(SegmentKind::Row, &rows, previous_rows, mode)?;
        let compact_indexes =
            writer.needs_compaction(SegmentKind::Index, &indexes, previous_indexes, mode)?;
        let same_sequence = previous_rows
            .last()
            .is_some_and(|r| r.sequence == manifest.sequence)
            || previous_indexes
                .last()
                .is_some_and(|r| r.sequence == manifest.sequence);
        let compact = compact_rows || compact_indexes || same_sequence;
        let replaced_rows =
            same_sequence.then(|| table.rows.changed_row_ids().collect::<BTreeSet<_>>());
        let output = RunOutput {
            compact,
            tag,
            replaced_rows: replaced_rows.as_ref().map(|rows| (manifest.sequence, rows)),
        };
        persisted.row_segments = writer.write_tagged(
            SegmentKind::Row,
            &rows,
            previous_rows,
            mode,
            output,
            &mut manifest.owned_memory,
        )?;
        persisted.index_segments = writer.write_tagged(
            SegmentKind::Index,
            &indexes,
            previous_indexes,
            mode,
            output,
            &mut manifest.owned_memory,
        )?;
        persisted.row_segment = None;
        persisted.index_segment = None;
        persisted.rows.clear();
    }
    Ok(manifest)
}

#[cfg(test)]
fn delta_records(table: &TableState) -> Result<(Vec<SegmentRecord>, Vec<SegmentRecord>)> {
    let physical = catalog_index_owners(&table.definition)
        .map(|(id, columns)| {
            Ok((
                id,
                columns
                    .iter()
                    .map(|column| column_index(&table.definition, column))
                    .collect::<Result<Vec<_>>>()?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut rows = Vec::new();
    let mut indexes = Vec::new();
    for (row_id, version) in table.rows.checkpoint_delta() {
        check_sql_cancelled()?;
        rows.push(SegmentRecord {
            key: (row_segment_key(&table.definition, row_id, version)?).into(),
            value: (serde_json::to_vec(&PersistedRowVersion {
                row_id,
                version: version.clone(),
            })?)
            .into(),
        });
        for (id, columns) in &physical {
            if columns
                .iter()
                .any(|column| matches!(version.values[*column], RelationalValue::Null))
            {
                continue;
            }
            let values = columns
                .iter()
                .map(|column| {
                    (
                        &table.definition.columns[*column].data_type,
                        &version.values[*column],
                    )
                })
                .collect::<Vec<_>>();
            indexes.push(SegmentRecord {
                key: (encode_index_key_v1(*id, &values, row_id, version.begin)?).into(),
                value: (serde_json::to_vec(&PersistedIndexVersion {
                    row_id,
                    begin: version.begin,
                    end: version.end,
                })?)
                .into(),
            });
        }
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    indexes.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((rows, indexes))
}

#[derive(Clone, Copy)]
pub(super) enum RunMode {
    Replace,
    Delta { reclaim_before: u64 },
}

pub(super) struct RunWriter<'a> {
    pub directory: &'a Path,
    pub sequence: u64,
    pub table_id: u64,
}

#[derive(Clone, Copy)]
struct RunOutput<'a> {
    compact: bool,
    tag: Option<&'a str>,
    replaced_rows: Option<(u64, &'a BTreeSet<u64>)>,
}

impl RunWriter<'_> {
    #[cfg(test)]
    pub(super) fn publish(
        &self,
        kind: SegmentKind,
        delta: &[SegmentRecord],
        previous: Vec<RelationalSegmentReference>,
        mode: RunMode,
    ) -> Result<Vec<RelationalSegmentReference>> {
        let compact = self.needs_compaction(kind, delta, &previous, mode)?;
        self.write(kind, delta, previous, mode, compact)
    }

    fn needs_compaction(
        &self,
        kind: SegmentKind,
        delta: &(impl RecordSource + ?Sized),
        previous: &[RelationalSegmentReference],
        mode: RunMode,
    ) -> Result<bool> {
        // Exhaust both sources for integrity. Merge the delta cursor alongside
        // old keys instead of retaining all encoded records for binary search.
        let delta_bytes = delta.cursor()?.try_fold(0_u64, |bytes, record| {
            bytes
                .checked_add(record_bytes(&record?)?)
                .ok_or_else(sql_overloaded)
        })?;
        let mut changed = delta.cursor()?;
        let mut head = changed.next().transpose()?;
        let mut old_bytes = 0_u64;
        let mut obsolete_bytes = 0_u64;
        for record in runs::RunMerge::open(self.directory, kind, previous)? {
            check_sql_cancelled()?;
            let record = record?;
            let bytes = record_bytes(&record)?;
            old_bytes = old_bytes.checked_add(bytes).ok_or_else(sql_overloaded)?;
            while head.as_ref().is_some_and(|next| next.key < record.key) {
                head = changed.next().transpose()?;
            }
            let current = head
                .as_ref()
                .filter(|next| next.key == record.key)
                .unwrap_or(&record);
            if !retain(kind, current, mode)? {
                obsolete_bytes = obsolete_bytes
                    .checked_add(bytes)
                    .ok_or_else(sql_overloaded)?;
            }
        }
        // The first cursor already validated the whole immutable delta, and no
        // mutation of the private sorted source can occur between these passes.
        let mut sizes = previous.iter().map(|reference| {
            fs::metadata(self.directory.join(&reference.file_name)).map(|metadata| metadata.len())
        });
        let base_bytes = sizes.next().transpose()?.unwrap_or(0);
        let accumulated_delta_bytes = sizes.try_fold(delta_bytes, |sum, bytes| {
            sum.checked_add(bytes?)
                .ok_or_else(|| io::Error::other("run byte count overflow"))
        })?;
        let size_pressure = !delta.is_empty() && accumulated_delta_bytes >= base_bytes;
        let garbage_pressure = old_bytes > 0 && obsolete_bytes >= old_bytes.div_ceil(2);
        Ok(matches!(mode, RunMode::Replace)
            || previous.is_empty()
            || (!delta.is_empty() && previous.len() >= RELATIONAL_MAX_RUNS_PER_TABLE)
            || size_pressure
            || garbage_pressure)
    }

    #[cfg(test)]
    fn write(
        &self,
        kind: SegmentKind,
        delta: &[SegmentRecord],
        previous: Vec<RelationalSegmentReference>,
        mode: RunMode,
        compact: bool,
    ) -> Result<Vec<RelationalSegmentReference>> {
        self.write_tagged(
            kind,
            delta,
            &previous,
            mode,
            RunOutput {
                compact,
                tag: None,
                replaced_rows: None,
            },
            &mut memory::Charge::storage(),
        )
    }

    fn write_tagged(
        &self,
        kind: SegmentKind,
        delta: &(impl RecordSource + ?Sized),
        previous: &[RelationalSegmentReference],
        mode: RunMode,
        output: RunOutput<'_>,
        memory: &mut memory::Charge,
    ) -> Result<Vec<RelationalSegmentReference>> {
        let RunOutput {
            compact,
            tag,
            replaced_rows,
        } = output;
        if !compact && delta.is_empty() {
            return metadata::references(previous, None, memory);
        }
        let mut names = memory::Charge::storage();
        names.prepare(
            4096_u64
                .saturating_add(self.directory.as_os_str().len() as u64 * 2)
                .saturating_add(tag.map_or(0, |tag| tag.len() as u64 * 2)),
        )?;
        let prefix = match kind {
            SegmentKind::Row => "row",
            SegmentKind::Index => "index",
        };
        let suffix = tag.map(|tag| format!("-{tag}")).unwrap_or_default();
        let name = format!(
            "{prefix}-{:020}-{:020}{suffix}.rseg",
            self.sequence, self.table_id
        );
        let path = self.directory.join(&name);
        let metadata = if compact {
            segment::write_segment_stream(&path, kind, self.sequence, || {
                ProjectionMerge::new(self.directory, kind, previous, delta, mode, replaced_rows)
            })?
        } else {
            segment::write_segment_stream(&path, kind, self.sequence, || delta.cursor())?
        };
        if compact && !previous.is_empty() {
            metrics::counter!("chirondb_relational_compactions_total").increment(1);
        }
        metadata::references(
            if compact { &[] } else { previous },
            Some((name, &metadata)),
            memory,
        )
    }
}

fn record_bytes(record: &SegmentRecord) -> Result<u64> {
    (record.key.len() as u64)
        .checked_add(record.value.len() as u64)
        .and_then(|bytes| bytes.checked_add(12))
        .ok_or_else(sql_overloaded)
}

fn retain(kind: SegmentKind, record: &SegmentRecord, mode: RunMode) -> Result<bool> {
    let RunMode::Delta { reclaim_before } = mode else {
        return Ok(false);
    };
    if reclaim_before == 0 {
        return Ok(true);
    }
    let end = match kind {
        SegmentKind::Row => values::persisted_row(&record.value)?.version.end,
        SegmentKind::Index => serde_json::from_slice::<PersistedIndexVersion>(&record.value)?.end,
    };
    Ok(end.is_none_or(|end| end > reclaim_before))
}

/// Ordered old/new merge retains one decoded head per source.
/// Replacement consumes old input for integrity but emits only the new image.
struct ProjectionMerge<'a> {
    old: runs::RunMerge,
    head: Option<SegmentRecord>,
    delta: Box<dyn Iterator<Item = Result<SegmentRecord>> + 'a>,
    delta_head: Option<SegmentRecord>,
    kind: SegmentKind,
    mode: RunMode,
    replaced_rows: Option<(u64, &'a BTreeSet<u64>)>,
    finished: bool,
}

impl<'a> ProjectionMerge<'a> {
    fn new(
        directory: &Path,
        kind: SegmentKind,
        references: &[RelationalSegmentReference],
        delta: &'a (impl RecordSource + ?Sized),
        mode: RunMode,
        replaced_rows: Option<(u64, &'a BTreeSet<u64>)>,
    ) -> Result<Self> {
        let mut old = runs::RunMerge::open(directory, kind, references)?;
        let head = old.next().transpose()?;
        let mut delta = delta.cursor()?;
        let delta_head = delta.next().transpose()?;
        Ok(Self {
            old,
            head,
            delta,
            delta_head,
            kind,
            mode,
            replaced_rows,
            finished: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<SegmentRecord>> {
        loop {
            check_sql_cancelled()?;
            let next = self.delta_head.as_ref();
            let take_old = match (&self.head, next) {
                (Some(old), Some(new)) => old.key < new.key,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return Ok(None),
            };
            let (record, from_delta) = if take_old {
                (self.head.take().expect("selected old record"), false)
            } else {
                let new = self.delta_head.take().expect("selected delta record");
                self.delta_head = self.delta.next().transpose()?;
                if self.head.as_ref().is_some_and(|old| old.key == new.key) {
                    self.head = None;
                }
                (new, true)
            };
            if self.head.is_none() {
                self.head = self.old.next().transpose()?;
            }
            if !from_delta && self.replaced_in_batch(&record)? {
                continue;
            }
            if (from_delta && matches!(self.mode, RunMode::Replace))
                || retain(self.kind, &record, self.mode)?
            {
                return Ok(Some(record));
            }
        }
    }

    fn replaced_in_batch(&self, record: &SegmentRecord) -> Result<bool> {
        let Some((sequence, rows)) = self.replaced_rows else {
            return Ok(false);
        };
        // Ignore row values while decoding the identity; a key-changing edit
        // and a delete may have no new record under the old physical key.
        #[derive(Deserialize)]
        struct Version {
            begin: u64,
        }
        #[derive(Deserialize)]
        struct Row {
            row_id: u64,
            version: Version,
        }
        let (id, begin) = match self.kind {
            SegmentKind::Row => {
                let row: Row = serde_json::from_slice(&record.value)?;
                (row.row_id, row.version.begin)
            }
            SegmentKind::Index => {
                let index: PersistedIndexVersion = serde_json::from_slice(&record.value)?;
                (index.row_id, index.begin)
            }
        };
        Ok(begin == sequence && rows.contains(&id))
    }
}

impl Iterator for ProjectionMerge<'_> {
    type Item = Result<SegmentRecord>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.read_next() {
            Ok(Some(record)) => Some(Ok(record)),
            result => {
                self.finished = true;
                result.transpose()
            }
        }
    }
}
