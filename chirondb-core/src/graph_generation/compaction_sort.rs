//! Fixed-memory external sorting for graph compaction scratch rows.
//!
//! Runs are anonymous, block framed, checksummed, and encoded through the
//! normal persistent envelope so encrypted installations never spill graph
//! topology as plaintext. Binary carry merging retains at most one run per
//! level and therefore never opens an unbounded fan-in.

use std::{
    cmp::Ordering,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    GaussError, Result,
    encryption::{self, FileType},
};

pub(super) const SORT_BUFFER_BYTES: usize = 1024 * 1024;
const BLOCK_PLAINTEXT_BYTES: usize = 48 * 1024;
const FRAME_HEADER_BYTES: usize = 28; // run UUID, block ordinal, row count
const FRAME_CRC_BYTES: usize = 4;
const MAX_ENCODED_FRAME_BYTES: usize = 64 * 1024;

pub(super) trait SortRow: Copy + Eq + Ord {
    const WIDTH: usize;

    fn encode(self, output: &mut Vec<u8>);
    fn decode(bytes: &[u8]) -> Result<Self>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SortStats {
    pub(crate) spill_runs: u64,
    pub(crate) max_merge_levels: usize,
    pub(crate) buffer_capacity_bytes: usize,
}

pub(super) struct ExternalSort<T: SortRow> {
    rows: Vec<T>,
    run_rows: usize,
    levels: Vec<Option<Run<T>>>,
    input_rows: u64,
    spill_runs: u64,
    max_merge_levels: usize,
}

impl<T: SortRow> ExternalSort<T> {
    pub(super) fn new() -> Result<Self> {
        if T::WIDTH == 0 || T::WIDTH > BLOCK_PLAINTEXT_BYTES {
            return Err(invalid("scratch row width is outside the fixed frame cap"));
        }
        let run_rows = (SORT_BUFFER_BYTES / T::WIDTH).max(1);
        Ok(Self {
            rows: Vec::with_capacity(run_rows),
            run_rows,
            levels: Vec::new(),
            input_rows: 0,
            spill_runs: 0,
            max_merge_levels: 0,
        })
    }

    #[cfg(test)]
    fn with_run_rows(run_rows: usize) -> Result<Self> {
        let mut sort = Self::new()?;
        if run_rows == 0 {
            return Err(invalid("scratch run row budget cannot be zero"));
        }
        sort.run_rows = run_rows;
        sort.rows = Vec::with_capacity(run_rows);
        Ok(sort)
    }

    pub(super) fn push(&mut self, row: T) -> Result<()> {
        self.input_rows = self
            .input_rows
            .checked_add(1)
            .ok_or_else(|| invalid("scratch input row count overflow"))?;
        self.rows.push(row);
        if self.rows.len() == self.run_rows {
            self.flush(true)?;
        }
        Ok(())
    }

    fn normalize_rows(&mut self) {
        self.rows.sort_unstable();
        self.rows.dedup();
    }

    fn flush(&mut self, budget_spill: bool) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        self.normalize_rows();
        let rows = std::mem::replace(&mut self.rows, Vec::with_capacity(self.run_rows));
        let mut writer = RunWriter::<T>::new()?;
        for row in rows {
            writer.push(row)?;
        }
        let mut run = writer.finish()?;
        if budget_spill {
            self.spill_runs = self
                .spill_runs
                .checked_add(1)
                .ok_or_else(|| invalid("scratch spill count overflow"))?;
        }
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                if level >= u64::BITS as usize {
                    return Err(invalid("scratch merge level exceeds u64 input bound"));
                }
                self.levels.push(Some(run));
                self.max_merge_levels = self.max_merge_levels.max(self.levels.len());
                return Ok(());
            }
            match self.levels[level].take() {
                Some(previous) => run = merge(previous, run)?,
                None => {
                    self.levels[level] = Some(run);
                    return Ok(());
                }
            }
            level += 1;
        }
    }

    pub(super) fn finish(mut self) -> Result<(SortedRun<T>, SortStats)> {
        self.flush(false)?;
        drop(self.rows);
        let mut merged = None;
        for run in self.levels.into_iter().flatten() {
            merged = Some(match merged {
                None => run,
                Some(previous) => merge(previous, run)?,
            });
        }
        let run = match merged {
            Some(run) => run,
            None => RunWriter::<T>::new()?.finish()?,
        };
        let stats = SortStats {
            spill_runs: self.spill_runs,
            max_merge_levels: self.max_merge_levels,
            buffer_capacity_bytes: self
                .run_rows
                .checked_mul(T::WIDTH)
                .ok_or_else(|| invalid("scratch buffer byte count overflow"))?,
        };
        Ok((SortedRun::new(run)?, stats))
    }
}

struct Run<T: SortRow> {
    file: File,
    id: [u8; 16],
    rows: u64,
    bytes: u64,
    marker: PhantomData<T>,
}

struct RunWriter<T: SortRow> {
    run: Run<T>,
    block: u64,
    pending: usize,
    block_rows: usize,
    bytes: Zeroizing<Vec<u8>>,
}

impl<T: SortRow> RunWriter<T> {
    fn new() -> Result<Self> {
        let block_rows =
            ((BLOCK_PLAINTEXT_BYTES - FRAME_HEADER_BYTES - FRAME_CRC_BYTES) / T::WIDTH).max(1);
        Ok(Self {
            run: Run {
                file: tempfile::tempfile()?,
                id: *uuid::Uuid::new_v4().as_bytes(),
                rows: 0,
                bytes: 0,
                marker: PhantomData,
            },
            block: 0,
            pending: 0,
            block_rows,
            bytes: Zeroizing::new(Vec::with_capacity(
                FRAME_HEADER_BYTES + block_rows * T::WIDTH + FRAME_CRC_BYTES,
            )),
        })
    }

    fn push(&mut self, row: T) -> Result<()> {
        if self.pending == 0 {
            self.bytes.extend_from_slice(&self.run.id);
            self.bytes.extend_from_slice(&self.block.to_le_bytes());
            self.bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        row.encode(&mut self.bytes);
        if self.bytes.len() != FRAME_HEADER_BYTES + (self.pending + 1) * T::WIDTH {
            return Err(invalid("scratch row encoder emitted a non-canonical width"));
        }
        self.pending += 1;
        self.run.rows = self
            .run
            .rows
            .checked_add(1)
            .ok_or_else(|| invalid("scratch output row count overflow"))?;
        if self.pending == self.block_rows {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending == 0 {
            return Ok(());
        }
        let count = u32::try_from(self.pending)
            .map_err(|_| invalid("scratch block row count exceeds u32"))?;
        self.bytes[24..28].copy_from_slice(&count.to_le_bytes());
        let crc = crc32fast::hash(&self.bytes);
        self.bytes.extend_from_slice(&crc.to_le_bytes());
        let encoded = Zeroizing::new(
            encryption::encode_persistent(FileType::Segment, &self.bytes)?.into_owned(),
        );
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_FRAME_BYTES {
            return Err(invalid("scratch encoded frame exceeds fixed cap"));
        }
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| invalid("scratch encoded frame length exceeds u32"))?;
        self.run.file.write_all(&encoded_len.to_le_bytes())?;
        self.run.file.write_all(&encoded)?;
        self.bytes.zeroize();
        self.bytes.clear();
        self.pending = 0;
        self.block = self
            .block
            .checked_add(1)
            .ok_or_else(|| invalid("scratch block ordinal overflow"))?;
        Ok(())
    }

    fn finish(mut self) -> Result<Run<T>> {
        self.flush()?;
        self.run.bytes = self.run.file.stream_position()?;
        Ok(self.run)
    }
}

pub(super) struct SortedRun<T: SortRow> {
    run: Run<T>,
    offsets: Vec<u64>,
    block_rows: usize,
}

impl<T: SortRow> SortedRun<T> {
    fn new(mut run: Run<T>) -> Result<Self> {
        if run.file.metadata()?.len() != run.bytes {
            return Err(invalid("scratch run length changed"));
        }
        let block_rows =
            ((BLOCK_PLAINTEXT_BYTES - FRAME_HEADER_BYTES - FRAME_CRC_BYTES) / T::WIDTH).max(1);
        let block_count = usize::try_from(run.rows.div_ceil(block_rows as u64))
            .map_err(|_| invalid("scratch block count exceeds usize"))?;
        let mut offsets = Vec::with_capacity(block_count);
        run.file.seek(SeekFrom::Start(0))?;
        let mut position = 0_u64;
        for _ in 0..block_count {
            offsets.push(position);
            let mut length = [0; 4];
            run.file.read_exact(&mut length)?;
            let length = u64::from(u32::from_le_bytes(length));
            if length == 0 || length > MAX_ENCODED_FRAME_BYTES as u64 {
                return Err(invalid("invalid scratch frame length"));
            }
            position = position
                .checked_add(4)
                .and_then(|value| value.checked_add(length))
                .ok_or_else(|| invalid("scratch frame range overflow"))?;
            run.file.seek(SeekFrom::Start(position))?;
        }
        if position != run.bytes {
            return Err(invalid("scratch run has unowned trailing bytes"));
        }
        Ok(Self {
            run,
            offsets,
            block_rows,
        })
    }

    pub(super) fn rows(&self) -> u64 {
        self.run.rows
    }

    fn read_block(&mut self, block: usize) -> Result<Vec<T>> {
        let offset = *self
            .offsets
            .get(block)
            .ok_or_else(|| invalid("scratch block index is out of bounds"))?;
        self.run.file.seek(SeekFrom::Start(offset))?;
        let mut length = [0; 4];
        self.run.file.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_ENCODED_FRAME_BYTES {
            return Err(invalid("invalid scratch frame length"));
        }
        let mut encoded = Zeroizing::new(vec![0; length]);
        self.run.file.read_exact(&mut encoded)?;
        let first_row = (block as u64)
            .checked_mul(self.block_rows as u64)
            .ok_or_else(|| invalid("scratch block row range overflow"))?;
        let count = usize::try_from(
            self.run
                .rows
                .saturating_sub(first_row)
                .min(self.block_rows as u64),
        )
        .map_err(|_| invalid("scratch block row count exceeds usize"))?;
        let expected_len = FRAME_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(T::WIDTH)
                    .ok_or_else(|| invalid("scratch block payload length overflow"))?,
            )
            .and_then(|value| value.checked_add(FRAME_CRC_BYTES))
            .ok_or_else(|| invalid("scratch block plaintext length overflow"))?;
        if encoded.starts_with(encryption::MAGIC) {
            let layout = encryption::EncryptedLayout::from_header(&encoded)?;
            if layout.info().plaintext_len != expected_len as u64
                || layout.info().file_type != FileType::Segment
            {
                return Err(invalid("scratch envelope length/type mismatch"));
            }
        }
        let bytes = Zeroizing::new(encryption::decode_persistent(&encoded)?.into_owned());
        if bytes.len() != expected_len
            || bytes[..16] != self.run.id
            || bytes[16..24] != (block as u64).to_le_bytes()
            || bytes[24..28] != (count as u32).to_le_bytes()
        {
            return Err(invalid("scratch block identity/count mismatch"));
        }
        let crc_start = bytes.len() - FRAME_CRC_BYTES;
        if bytes[crc_start..] != crc32fast::hash(&bytes[..crc_start]).to_le_bytes() {
            return Err(invalid("scratch block checksum mismatch"));
        }
        let mut rows = Vec::with_capacity(count);
        for index in 0..count {
            let start = FRAME_HEADER_BYTES + index * T::WIDTH;
            rows.push(T::decode(&bytes[start..start + T::WIDTH])?);
        }
        Ok(rows)
    }

    pub(super) fn visit_range(
        &mut self,
        start: u64,
        end: u64,
        mut visit: impl FnMut(T) -> Result<()>,
    ) -> Result<()> {
        if start > end || end > self.run.rows {
            return Err(invalid("scratch visit range exceeds row count"));
        }
        if start == end {
            return Ok(());
        }
        let first_block = usize::try_from(start / self.block_rows as u64)
            .map_err(|_| invalid("scratch first block exceeds usize"))?;
        let last_block = usize::try_from((end - 1) / self.block_rows as u64)
            .map_err(|_| invalid("scratch last block exceeds usize"))?;
        for block in first_block..=last_block {
            let rows = self.read_block(block)?;
            let block_start = block as u64 * self.block_rows as u64;
            let local_start = usize::try_from(start.saturating_sub(block_start))
                .unwrap_or(0)
                .min(rows.len());
            let local_end = usize::try_from(end.saturating_sub(block_start))
                .unwrap_or(usize::MAX)
                .min(rows.len());
            for row in rows[local_start..local_end].iter().copied() {
                visit(row)?;
            }
        }
        Ok(())
    }

    pub(super) fn visit_all(&mut self, mut visit: impl FnMut(T) -> Result<()>) -> Result<()> {
        let mut previous = None;
        let mut emitted = 0_u64;
        for block in 0..self.offsets.len() {
            for row in self.read_block(block)? {
                if previous.is_some_and(|value| value >= row) {
                    return Err(invalid("scratch keys are not strictly ordered"));
                }
                previous = Some(row);
                emitted = emitted
                    .checked_add(1)
                    .ok_or_else(|| invalid("scratch visit row count overflow"))?;
                visit(row)?;
            }
        }
        if emitted != self.run.rows {
            return Err(invalid("scratch visit row count mismatch"));
        }
        Ok(())
    }

    pub(super) fn cursor(self) -> RunCursor<T> {
        RunCursor {
            sorted: self,
            block: 0,
            rows: Vec::new(),
            position: 0,
            previous: None,
            emitted: 0,
        }
    }

    #[cfg(test)]
    pub(super) fn first_frame_is_encrypted(&mut self) -> Result<bool> {
        if self.run.rows == 0 {
            return Ok(false);
        }
        self.run.file.seek(SeekFrom::Start(4))?;
        let mut prefix = [0; 8];
        self.run.file.read_exact(&mut prefix)?;
        Ok(prefix == *encryption::MAGIC)
    }
}

pub(super) struct RunCursor<T: SortRow> {
    sorted: SortedRun<T>,
    block: usize,
    rows: Vec<T>,
    position: usize,
    previous: Option<T>,
    emitted: u64,
}

impl<T: SortRow> RunCursor<T> {
    pub(super) fn next(&mut self) -> Result<Option<T>> {
        if self.position == self.rows.len() {
            if self.block == self.sorted.offsets.len() {
                if self.emitted != self.sorted.run.rows {
                    return Err(invalid("scratch cursor row count mismatch"));
                }
                return Ok(None);
            }
            self.rows = self.sorted.read_block(self.block)?;
            self.block += 1;
            self.position = 0;
        }
        let row = self.rows[self.position];
        if self
            .previous
            .is_some_and(|previous| previous.cmp(&row) != Ordering::Less)
        {
            return Err(invalid("scratch keys are not strictly ordered"));
        }
        self.previous = Some(row);
        self.position += 1;
        self.emitted = self
            .emitted
            .checked_add(1)
            .ok_or_else(|| invalid("scratch cursor row count overflow"))?;
        Ok(Some(row))
    }
}

fn merge<T: SortRow>(left: Run<T>, right: Run<T>) -> Result<Run<T>> {
    let mut left = SortedRun::new(left)?.cursor();
    let mut right = SortedRun::new(right)?.cursor();
    let mut writer = RunWriter::<T>::new()?;
    let (mut a, mut b) = (left.next()?, right.next()?);
    while a.is_some() || b.is_some() {
        match (a, b) {
            (Some(x), Some(y)) if x == y => {
                writer.push(x)?;
                a = left.next()?;
                b = right.next()?;
            }
            (Some(x), Some(y)) if x < y => {
                writer.push(x)?;
                a = left.next()?;
            }
            (Some(x), None) => {
                writer.push(x)?;
                a = left.next()?;
            }
            (_, Some(y)) => {
                writer.push(y)?;
                b = right.next()?;
            }
            (None, None) => unreachable!(),
        }
    }
    writer.finish()
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph compaction scratch: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{env, fs, process::Command};

    const MODE: &str = "CHIRONDB_GRAPH_COMPACTION_SORT_TEST_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_COMPACTION_SORT_TEST_ROOT";
    const TEST: &str = "graph_generation::compaction_sort::tests::binary_external_sort_is_bounded_deduplicated_and_fail_closed";

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct TestRow(u64);

    impl SortRow for TestRow {
        const WIDTH: usize = 8;

        fn encode(self, output: &mut Vec<u8>) {
            output.extend_from_slice(&self.0.to_le_bytes());
        }

        fn decode(bytes: &[u8]) -> Result<Self> {
            Ok(Self(u64::from_le_bytes(
                bytes.try_into().expect("fixed test row"),
            )))
        }
    }

    #[test]
    fn binary_external_sort_is_bounded_deduplicated_and_fail_closed() {
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = tempfile::tempdir().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, root.path())
                        .status()
                        .unwrap()
                        .success(),
                    "{mode} graph compaction sort child failed"
                );
            }
            return;
        };
        if mode == "encrypted" {
            let keyring = std::path::PathBuf::from(env::var_os(ROOT).unwrap()).join("keyring.json");
            fs::write(
                &keyring,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "graph-compaction-sort",
                    "keys": [{
                        "id": "graph-compaction-sort",
                        "key_base64": STANDARD.encode([91_u8; 32])
                    }]
                })
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(&keyring).unwrap(),
                true,
            )
            .unwrap();
        }

        let mut sort = ExternalSort::<TestRow>::with_run_rows(3).unwrap();
        for value in (1..=257).rev() {
            sort.push(TestRow(value)).unwrap();
            sort.push(TestRow(value)).unwrap();
            assert!(sort.rows.len() <= 3);
            assert!(sort.rows.capacity() <= 3);
            assert!(sort.levels.len() <= u64::BITS as usize);
        }
        let (mut run, stats) = sort.finish().unwrap();
        assert!(stats.spill_runs > 1);
        assert!(stats.max_merge_levels > 1);
        assert_eq!(stats.buffer_capacity_bytes, 24);
        assert_eq!(run.first_frame_is_encrypted().unwrap(), mode == "encrypted");
        let mut cursor = run.cursor();
        for expected in 1..=257 {
            assert_eq!(cursor.next().unwrap(), Some(TestRow(expected)));
        }
        assert_eq!(cursor.next().unwrap(), None);

        let mut sort = ExternalSort::<TestRow>::with_run_rows(2).unwrap();
        for value in [3, 2, 1] {
            sort.push(TestRow(value)).unwrap();
        }
        let (mut run, _) = sort.finish().unwrap();
        let last = run.run.bytes - 1;
        run.run.file.seek(SeekFrom::Start(last)).unwrap();
        let mut byte = [0];
        run.run.file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        run.run.file.seek(SeekFrom::Start(last)).unwrap();
        run.run.file.write_all(&byte).unwrap();
        assert!(run.cursor().next().is_err());
    }
}
