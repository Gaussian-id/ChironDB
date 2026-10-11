//! Encrypted, bounded external runs for the single-table ordered LIMIT path.
//! A run contains a sorted subset of the best OFFSET+LIMIT rows observed so
//! far. Keeping that many rows from each run preserves the global top window.

use super::*;
use crate::encryption::{
    DEFAULT_CHUNK_SIZE, atomic_write_persistent_stream, open_persistent_reader_bounded,
};
use zeroize::Zeroizing;

mod decode;
#[cfg(test)]
mod tests;

const SPILL_PREFIX: &str = ".chiron-query-spill-";
const MAX_SPILL_RUNS: usize = 128;
static SPILL_DISK_RESERVED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
// Each reader retains one authenticated chunk, its tag capacity, layout, key
// and box. Active header/frame/decryption scratch is a separate merge share.
const READER_BYTES: usize = DEFAULT_CHUNK_SIZE + 4096;
// Encrypted headers have u16 key/wrapped-DEK lengths. Two headers plus two
// chunk buffers cover header validation and old/new plaintext during a read.
const READ_SCRATCH_BYTES: usize = 2 * (u16::MAX as usize + 4096) + 2 * DEFAULT_CHUNK_SIZE;

#[derive(Serialize)]
struct SpillRecordRef<'a> {
    position: usize,
    values: &'a [RelationalValue],
}

#[derive(Debug)]
struct SpillRecord {
    position: usize,
    values: Vec<RelationalValue>,
    charge: usize,
}

struct SpillRun {
    path: PathBuf,
    count: usize,
}

pub(super) struct QuerySpill {
    directory: Option<tempfile::TempDir>,
    runs: Vec<SpillRun>,
    disk_bytes: u64,
    disk_limit: u64,
    memory_limit: usize,
}

impl QuerySpill {
    pub(super) fn new(segment_directory: &Path, memory_limit: usize) -> Result<Self> {
        if !crate::encryption::encryption_enabled() {
            return Err(invalid("SQL spill requires an encryption keyring"));
        }
        let parent = segment_directory
            .parent()
            .ok_or_else(|| invalid("relational segment directory has no parent"))?
            .join("query-spill");
        fs::create_dir_all(&parent)?;
        let directory = tempfile::Builder::new()
            .prefix(SPILL_PREFIX)
            .tempdir_in(&parent)?;
        let disk_limit = crate::resource_profile::current()
            .sql_request_working_set_bytes
            .saturating_mul(8);
        Ok(Self {
            directory: Some(directory),
            runs: Vec::new(),
            disk_bytes: 0,
            disk_limit,
            memory_limit,
        })
    }

    pub(super) fn push_run(&mut self, rows: Vec<RankedQueryRow<'_>>) -> Result<()> {
        check_sql_cancelled()?;
        if rows.is_empty() {
            return Ok(());
        }
        if self.runs.len() == MAX_SPILL_RUNS {
            return Err(spill_exhausted());
        }
        // The heap itself is limited to memory_limit. Its 64-byte per-row
        // overhead also covers the position and frame length in this encoding.
        // The extra serialization buffer occupies a second operator share of
        // the already admitted SQL request working set.
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve(self.memory_limit)
            .map_err(|_| sql_overloaded())?;
        for row in &rows {
            check_sql_cancelled()?;
            let record = SpillRecordRef {
                position: row.source_position,
                values: &row.values,
            };
            let remaining = self.memory_limit.saturating_sub(bytes.len());
            let mut counter = BoundedCounter {
                written: 0,
                limit: remaining.saturating_sub(4),
            };
            serde_json::to_writer(&mut counter, &record).map_err(|_| spill_exhausted())?;
            let frame_length = u32::try_from(counter.written).map_err(|_| spill_exhausted())?;
            if bytes.len().saturating_add(4 + counter.written) > self.memory_limit {
                return Err(spill_exhausted());
            }
            bytes.extend_from_slice(&frame_length.to_le_bytes());
            serde_json::to_writer(&mut *bytes, &record)?;
        }
        let estimated = (bytes.len() as u64).saturating_add(4096);
        if self.disk_bytes.saturating_add(estimated) > self.disk_limit {
            return Err(spill_exhausted());
        }
        reserve_disk(estimated)?;
        self.disk_bytes += estimated;
        let path = self
            .directory
            .as_ref()
            .expect("spill directory exists until drop")
            .path()
            .join(format!("{}.run", self.runs.len()));
        atomic_write_persistent_stream(
            &path,
            FileType::Metadata,
            bytes.len() as u64,
            bytes.as_slice(),
        )?;
        let file_bytes = fs::metadata(&path)?.len();
        if file_bytes > estimated {
            return Err(spill_exhausted());
        }
        crate::failpoint::check("relational_query_spill.after_run")?;
        self.runs.push(SpillRun {
            path,
            count: rows.len(),
        });
        metrics::counter!("chirondb_sql_spill_runs_total").increment(1);
        Ok(())
    }

    pub(super) fn for_each_window(
        self,
        memory_rows: Vec<RankedQueryRow<'_>>,
        ordering: &[QueryOrderSpec],
        offset: usize,
        limit: usize,
        mut emit: impl FnMut(&[RelationalValue]) -> Result<()>,
    ) -> Result<()> {
        if READ_SCRATCH_BYTES > self.memory_limit.saturating_mul(2) {
            return Err(spill_exhausted());
        }
        let mut loaded = self
            .runs
            .len()
            .saturating_mul(std::mem::size_of::<RunReader>());
        if loaded > self.memory_limit {
            return Err(spill_exhausted());
        }
        let mut readers = Vec::new();
        readers
            .try_reserve_exact(self.runs.len())
            .map_err(|_| sql_overloaded())?;
        for run in &self.runs {
            check_sql_cancelled()?;
            if READER_BYTES > self.memory_limit.saturating_sub(loaded) {
                return Err(spill_exhausted());
            }
            loaded += READER_BYTES;
            // Admit each head against what earlier readers already retain.
            // Never decode every run and check the aggregate afterwards.
            let mut reader = RunReader::open(run)?;
            reader.advance(self.memory_limit.saturating_sub(loaded), self.memory_limit)?;
            loaded += reader.current.as_ref().map_or(0, |row| row.charge);
            readers.push(reader);
        }
        let mut memory_index = 0;
        for ordinal in 0..offset.saturating_add(limit) {
            check_sql_cancelled()?;
            let mut best = None;
            for (index, reader) in readers.iter().enumerate() {
                if let Some(candidate) = &reader.current {
                    let better = best.is_none_or(|prior| {
                        let prior = candidate_at(prior, &readers, &memory_rows, memory_index);
                        compare_spill(candidate, prior, ordering) == Ordering::Less
                    });
                    if better {
                        best = Some(index);
                    }
                }
            }
            if let Some(candidate) = memory_rows.get(memory_index) {
                let better = best.is_none_or(|prior| {
                    let prior = candidate_at(prior, &readers, &memory_rows, memory_index);
                    compare_query_order(
                        &candidate.values,
                        candidate.source_position,
                        prior.0,
                        prior.1,
                        ordering,
                    ) == Ordering::Less
                });
                if better {
                    best = Some(readers.len());
                }
            }
            let Some(best) = best else {
                break;
            };
            if best == readers.len() {
                if ordinal >= offset {
                    emit(&memory_rows[memory_index].values)?;
                }
                memory_index += 1;
            } else {
                let reader = &mut readers[best];
                let row = reader.current.take().expect("selected run has a row");
                let charge = row.charge;
                if ordinal >= offset {
                    emit(&row.values)?;
                }
                // The old values must be freed before returning their quota.
                drop(row);
                loaded -= charge;
                reader.advance(self.memory_limit.saturating_sub(loaded), self.memory_limit)?;
                if let Some(next) = &reader.current {
                    loaded += next.charge;
                }
            }
        }
        Ok(())
    }
}

impl Drop for QuerySpill {
    fn drop(&mut self) {
        // Delete files before releasing the shared reservation so another
        // concurrent query never sees free quota while our files still exist.
        if let Some(directory) = self.directory.take()
            && directory.close().is_err()
        {
            metrics::counter!("chirondb_sql_spill_cleanup_failures_total").increment(1);
            return;
        }
        let remaining = SPILL_DISK_RESERVED
            .fetch_sub(self.disk_bytes, AtomicOrdering::AcqRel)
            .saturating_sub(self.disk_bytes);
        metrics::gauge!("chirondb_sql_spill_reserved_bytes").set(remaining as f64);
    }
}

fn reserve_disk(bytes: u64) -> Result<()> {
    let limit = crate::resource_profile::current()
        .sql_pool_bytes
        .saturating_mul(8);
    let mut used = SPILL_DISK_RESERVED.load(AtomicOrdering::Acquire);
    loop {
        let next = used
            .checked_add(bytes)
            .filter(|next| *next <= limit)
            .ok_or_else(spill_exhausted)?;
        match SPILL_DISK_RESERVED.compare_exchange_weak(
            used,
            next,
            AtomicOrdering::AcqRel,
            AtomicOrdering::Acquire,
        ) {
            Ok(_) => {
                metrics::gauge!("chirondb_sql_spill_reserved_bytes").set(next as f64);
                return Ok(());
            }
            Err(actual) => used = actual,
        }
    }
}

fn candidate_at<'a>(
    index: usize,
    readers: &'a [RunReader],
    memory_rows: &'a [RankedQueryRow<'_>],
    memory_index: usize,
) -> (&'a [RelationalValue], usize) {
    if index == readers.len() {
        let row = &memory_rows[memory_index];
        (&row.values, row.source_position)
    } else {
        let row = readers[index]
            .current
            .as_ref()
            .expect("candidate run has a row");
        (&row.values, row.position)
    }
}

fn compare_spill(
    candidate: &SpillRecord,
    prior: (&[RelationalValue], usize),
    ordering: &[QueryOrderSpec],
) -> Ordering {
    compare_query_order(
        &candidate.values,
        candidate.position,
        prior.0,
        prior.1,
        ordering,
    )
}

struct RunReader {
    reader: Box<dyn Read>,
    remaining: usize,
    current: Option<SpillRecord>,
}

impl RunReader {
    fn open(run: &SpillRun) -> Result<Self> {
        Ok(Self {
            reader: open_persistent_reader_bounded(&run.path, DEFAULT_CHUNK_SIZE)?,
            remaining: run.count,
            current: None,
        })
    }

    fn advance(&mut self, available: usize, memory_limit: usize) -> Result<()> {
        check_sql_cancelled()?;
        debug_assert!(
            self.current.is_none(),
            "drop the prior head before advancing"
        );
        if self.remaining == 0 {
            let mut trailing = [0];
            if self.reader.read(&mut trailing)? != 0 {
                return Err(invalid("SQL spill run has trailing bytes"));
            }
            self.current = None;
            return Ok(());
        }
        let mut size = [0_u8; 4];
        self.reader.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as usize;
        if size > memory_limit || size == 0 {
            return Err(invalid("SQL spill frame exceeds memory budget"));
        }
        // A separate two-operator share covers the encoded frame, up to two
        // simultaneous serde scratch vectors (each needs <=3x input including
        // old/new blocks during growth), and
        // active encryption scratch. Raw envelopes borrow the frame. Owned
        // values are admitted individually against `available` before growth.
        let scratch = size
            .checked_mul(7)
            .and_then(|n| n.checked_add(READ_SCRATCH_BYTES));
        if available < std::mem::size_of::<SpillRecord>()
            || scratch.is_none_or(|n| n > memory_limit.saturating_mul(2))
        {
            return Err(spill_exhausted());
        }
        let mut payload = Zeroizing::new(Vec::new());
        payload
            .try_reserve_exact(size)
            .map_err(|_| sql_overloaded())?;
        payload.resize(size, 0);
        self.reader.read_exact(&mut payload)?;
        let row = decode::record(&payload, available)?;
        self.current = Some(row);
        self.remaining -= 1;
        Ok(())
    }
}

fn spill_exhausted() -> GaussError {
    GaussError::ResourceExhausted("SQL encrypted spill quota is exhausted".into())
}

/// Called while the data-directory lock is held, before any query can start.
pub(super) fn cleanup_interrupted(parent: &Path) -> Result<()> {
    if !parent.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(SPILL_PREFIX))
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
