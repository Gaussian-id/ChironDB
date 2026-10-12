//! Bounded record batches and two-way external merge for checkpoint projections.
//! Scratch runs use the same authenticated storage envelope as final segments.
//! No file list or decoded output grows with the number of projected records.

use super::*;

#[cfg(test)]
mod tests;

const BATCH_ROWS: usize = 1_024;
const SCRATCH_PREFIX: &str = ".chiron-relational-sort-";
const LOCATOR_PREFIX: &str = ".chiron-relational-locator-";

pub(super) trait RecordSource {
    fn cursor(&self) -> Result<Box<dyn Iterator<Item = Result<SegmentRecord>> + '_>>;
    fn is_empty(&self) -> bool;
}

#[cfg(test)]
impl RecordSource for [SegmentRecord] {
    fn cursor(&self) -> Result<Box<dyn Iterator<Item = Result<SegmentRecord>> + '_>> {
        if self.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err(invalid("projection requires unique ascending keys"));
        }
        Ok(Box::new(self.iter().cloned().map(Ok)))
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

#[cfg(test)]
impl RecordSource for Vec<SegmentRecord> {
    fn cursor(&self) -> Result<Box<dyn Iterator<Item = Result<SegmentRecord>> + '_>> {
        self.as_slice().cursor()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

struct Run {
    path: PathBuf,
    count: u64,
}

pub(in crate::relational) struct SortedRun {
    run: Run,
    _directory: tempfile::TempDir,
}

impl SortedRun {
    pub(in crate::relational) fn into_reader(self) -> Result<segment::SegmentReader> {
        segment::SegmentReader::open_scratch(&self.run.path, self._directory)
    }

    pub(super) fn into_index_backing(
        self,
        table: &TableState,
        sequence: u64,
    ) -> Result<TableSegmentBacking> {
        let name = self
            .run
            .path
            .file_name()
            .expect("private run filename")
            .to_string_lossy()
            .into_owned();
        let cursor = segment::SegmentCursor::open(&self.run.path)?;
        let reference = segment_reference(name.clone(), cursor.metadata());
        drop(cursor);
        indexes::validate_projection(table, self._directory.path(), &[reference], sequence)?;
        crate::failpoint::check("relational_index_rebuild.before_install")?;
        let reader = segment::SegmentReader::open_scratch(&self.run.path, self._directory)?;
        Ok(TableSegmentBacking {
            sequence,
            file_name: name,
            #[cfg(test)]
            path: self.run.path,
            reader: Arc::new(reader),
        })
    }
}

impl RecordSource for SortedRun {
    fn cursor(&self) -> Result<Box<dyn Iterator<Item = Result<SegmentRecord>> + '_>> {
        Ok(Box::new(segment::SegmentCursor::open(&self.run.path)?))
    }

    fn is_empty(&self) -> bool {
        self.run.count == 0
    }
}

pub(in crate::relational) struct Sorter {
    buffer: Vec<SegmentRecord>,
    bytes: usize,
    byte_limit: usize,
    kind: SegmentKind,
    sequence: u64,
    serial: u64,
    // Binary carry bounds the file inventory by log2(batch count). A fixed
    // array also makes pathological overflow a resource error, not an allocation.
    levels: [Option<Run>; 64],
    directory: tempfile::TempDir,
    // Buffer allocations drop before their aggregate reservation.
    memory: memory::Charge,
    #[cfg(test)]
    peak_rows: usize,
    #[cfg(test)]
    peak_bytes: usize,
}

impl Sorter {
    pub(in crate::relational) fn locator(directory: &Path, sequence: u64) -> Result<Self> {
        Self::with_prefix(directory, SegmentKind::Row, sequence, LOCATOR_PREFIX)
    }

    pub(in crate::relational) fn new(
        directory: &Path,
        kind: SegmentKind,
        sequence: u64,
    ) -> Result<Self> {
        Self::with_prefix(directory, kind, sequence, SCRATCH_PREFIX)
    }

    fn with_prefix(
        directory: &Path,
        kind: SegmentKind,
        sequence: u64,
        prefix: &str,
    ) -> Result<Self> {
        let byte_limit =
            (crate::resource_profile::current().sql_request_working_set_bytes / 16).max(1) as usize;
        let mut memory = memory::Charge::storage();
        memory.prepare((BATCH_ROWS * std::mem::size_of::<SegmentRecord>()) as u64)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(BATCH_ROWS)
            .map_err(|_| sql_overloaded())?;
        Ok(Self {
            buffer,
            bytes: 0,
            byte_limit,
            kind,
            sequence,
            serial: 0,
            levels: std::array::from_fn(|_| None),
            directory: tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in(directory)?,
            memory,
            #[cfg(test)]
            peak_rows: 0,
            #[cfg(test)]
            peak_bytes: 0,
        })
    }

    pub(in crate::relational) fn push(&mut self, record: SegmentRecord) -> Result<()> {
        check_sql_cancelled()?;
        let bytes = record
            .key
            .capacity()
            .checked_add(record.value.capacity())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SegmentRecord>()))
            .ok_or_else(sql_overloaded)?;
        // One record can exceed the batch target, up to the existing segment
        // record limit. It is written alone, never alongside a full batch.
        if !self.buffer.is_empty()
            && (self.buffer.len() == BATCH_ROWS
                || bytes > self.byte_limit.saturating_sub(self.bytes))
        {
            self.flush()?;
        }
        let next_bytes = self.bytes.checked_add(bytes).ok_or_else(sql_overloaded)?;
        // Each immutable key/value owner already carries its storage lease.
        // Only the sorter's slot array belongs to this reservation.
        self.bytes = next_bytes;
        self.buffer.push(record);
        #[cfg(test)]
        {
            self.peak_rows = self.peak_rows.max(self.buffer.len());
            self.peak_bytes = self.peak_bytes.max(self.bytes);
        }
        if self.bytes >= self.byte_limit {
            self.flush()?;
        }
        Ok(())
    }

    fn path(&mut self) -> Result<PathBuf> {
        self.serial = self.serial.checked_add(1).ok_or_else(sql_overloaded)?;
        Ok(self.directory.path().join(format!("{}.rseg", self.serial)))
    }

    fn flush(&mut self) -> Result<()> {
        check_sql_cancelled()?;
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.buffer.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let path = self.path()?;
        let metadata = write_segment(&path, self.kind, self.sequence, &self.buffer)?;
        self.buffer.clear();
        self.bytes = 0;
        self.memory
            .prepare((self.buffer.capacity() * std::mem::size_of::<SegmentRecord>()) as u64)?;
        crate::failpoint::check("relational_sort.after_batch")?;
        metrics::counter!("chirondb_relational_sort_batches_total").increment(1);
        let mut run = Run {
            path,
            count: metadata.record_count,
        };
        // Drop output metadata before opening two inputs for the next merge.
        drop(metadata);
        for level in 0..self.levels.len() {
            let Some(previous) = self.levels[level].take() else {
                self.levels[level] = Some(run);
                return Ok(());
            };
            run = self.merge(previous, run)?;
        }
        Err(sql_overloaded())
    }

    fn merge(&mut self, left: Run, right: Run) -> Result<Run> {
        let path = self.path()?;
        let metadata = segment::write_segment_stream(&path, self.kind, self.sequence, || {
            Merge::open(&left.path, &right.path)
        })?;
        let count = left
            .count
            .checked_add(right.count)
            .ok_or_else(sql_overloaded)?;
        if metadata.record_count != count {
            return Err(invalid("projection merge changed its record count"));
        }
        crate::failpoint::check("relational_sort.after_merge")?;
        // Every writer pass has closed its readers before unlinking, including
        // on Windows. TempDir owns all files if a read/write/delete fails.
        fs::remove_file(left.path)?;
        fs::remove_file(right.path)?;
        metrics::counter!("chirondb_relational_sort_merges_total").increment(1);
        Ok(Run { path, count })
    }

    pub(in crate::relational) fn finish(mut self) -> Result<SortedRun> {
        self.flush()?;
        let mut output = None;
        for level in 0..self.levels.len() {
            if let Some(run) = self.levels[level].take() {
                output = Some(match output {
                    Some(previous) => self.merge(previous, run)?,
                    None => run,
                });
            }
        }
        let run = match output {
            Some(run) => run,
            None => {
                let path = self.path()?;
                write_segment(&path, self.kind, self.sequence, &[])?;
                Run { path, count: 0 }
            }
        };
        Ok(SortedRun {
            run,
            _directory: self.directory,
        })
    }
}

/// Write an already ordered locator without creating hundreds of tiny merge
/// runs. The source is replayable because the segment writer counts and then
/// writes records. A failed attempt owns only private scratch files.
pub(in crate::relational) fn ordered_locator<I>(
    directory: &Path,
    sequence: u64,
    source: impl Fn() -> Result<I>,
) -> Result<SortedRun>
where
    I: Iterator<Item = Result<SegmentRecord>>,
{
    let scratch = tempfile::Builder::new()
        .prefix(LOCATOR_PREFIX)
        .tempdir_in(directory)?;
    let path = scratch.path().join("ordered.rseg");
    let metadata = segment::write_segment_stream(&path, SegmentKind::Row, sequence, source)?;
    Ok(SortedRun {
        run: Run {
            path,
            count: metadata.record_count,
        },
        _directory: scratch,
    })
}

/// Strict merge: duplicate physical keys are corruption, even across batches.
/// Unlike the persisted generation merge, this must never silently pick a winner.
pub(in crate::relational) struct Merge {
    cursors: [segment::SegmentCursor; 2],
    heads: [Option<SegmentRecord>; 2],
    finished: bool,
}

impl Merge {
    pub(in crate::relational) fn readers(
        left: &segment::SegmentReader,
        right: &segment::SegmentReader,
    ) -> Result<Self> {
        Self::from_cursors([left.cursor(), right.cursor()])
    }

    fn open(left: &Path, right: &Path) -> Result<Self> {
        Self::from_cursors([
            segment::SegmentCursor::open(left)?,
            segment::SegmentCursor::open(right)?,
        ])
    }

    fn from_cursors(mut cursors: [segment::SegmentCursor; 2]) -> Result<Self> {
        let heads = [
            cursors[0].next().transpose()?,
            cursors[1].next().transpose()?,
        ];
        Ok(Self {
            cursors,
            heads,
            finished: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<SegmentRecord>> {
        check_sql_cancelled()?;
        let index = match (&self.heads[0], &self.heads[1]) {
            (Some(left), Some(right)) => match left.key.cmp(&right.key) {
                std::cmp::Ordering::Less => 0,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => {
                    return Err(invalid("projection contains duplicate physical keys"));
                }
            },
            (Some(_), None) => 0,
            (None, Some(_)) => 1,
            (None, None) => return Ok(None),
        };
        let record = self.heads[index].take();
        self.heads[index] = self.cursors[index].next().transpose()?;
        Ok(record)
    }
}

impl Iterator for Merge {
    type Item = Result<SegmentRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.read_next() {
            Ok(Some(record)) => Some(Ok(record)),
            result => {
                self.finished = true;
                result.err().map(Err)
            }
        }
    }
}

pub(super) fn project(
    table: &TableState,
    directory: &Path,
    kind: SegmentKind,
    sequence: u64,
    delta: bool,
) -> Result<SortedRun> {
    let mut sorter = Sorter::new(directory, kind, sequence)?;
    let mut physical = BTreeMap::new();
    if kind == SegmentKind::Index {
        for (id, columns) in catalog_index_owners(&table.definition) {
            let columns = columns
                .iter()
                .map(|column| column_index(&table.definition, column))
                .collect::<Result<Vec<_>>>()?;
            if let Some(previous) = physical.insert(id, columns.clone())
                && previous != columns
            {
                return Err(invalid("physical index ID has conflicting columns"));
            }
        }
    }
    let mut emit = |row_id, version: &RowVersion| -> Result<()> {
        check_sql_cancelled()?;
        if kind == SegmentKind::Row {
            #[derive(Serialize)]
            struct BorrowedRow<'a> {
                row_id: u64,
                version: &'a RowVersion,
            }
            sorter.push(SegmentRecord::json_admitted(
                row_segment_key_admitted(&table.definition, row_id, version)?,
                &BorrowedRow { row_id, version },
            )?)?;
        } else {
            for (id, columns) in &physical {
                if columns
                    .iter()
                    .any(|column| matches!(version.values[*column], RelationalValue::Null))
                {
                    continue;
                }
                let mut charge = memory::Charge::storage();
                let bytes = columns
                    .len()
                    .checked_mul(std::mem::size_of::<(&RelationalType, &RelationalValue)>())
                    .and_then(|n| n.checked_add(64))
                    .ok_or_else(sql_overloaded)?;
                charge.prepare(bytes as u64)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(columns.len())
                    .map_err(|_| sql_overloaded())?;
                for column in columns {
                    values.push((
                        &table.definition.columns[*column].data_type,
                        &version.values[*column],
                    ));
                }
                charge.prepare(
                    (values.capacity() * std::mem::size_of::<(&RelationalType, &RelationalValue)>()
                        + 64) as u64,
                )?;
                let key = key_encoding::encode_index_key_v1_admitted(
                    *id,
                    &values,
                    row_id,
                    version.begin,
                )?;
                drop(values);
                drop(charge);
                sorter.push(SegmentRecord::json_admitted(
                    key,
                    &PersistedIndexVersion {
                        row_id,
                        begin: version.begin,
                        end: version.end,
                    },
                )?)?;
            }
        }
        Ok(())
    };
    if delta {
        for (id, version) in table.rows.checkpoint_delta() {
            emit(id, version)?;
        }
    } else {
        for row in table.rows.iter() {
            let (id, versions) = row?;
            for version in versions.iter() {
                emit(id, version)?;
            }
        }
    }
    sorter.finish()
}

/// Startup owns the data directory lock; no live checkpoint sorter exists yet.
/// Never follow a symlink or remove another storage namespace.
pub(in crate::relational) fn cleanup_interrupted(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry.file_name().to_str().is_some_and(|name| {
                name.starts_with(SCRATCH_PREFIX) || name.starts_with(LOCATOR_PREFIX)
            })
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
