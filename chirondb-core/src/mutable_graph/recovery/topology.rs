//! Exact, bounded-buffer topology reconciliation for recovery and compaction
//! input. Sorted temporary runs never become graph authority and are deleted
//! on close.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Result,
    encryption::{self, FileType},
    graph::{EdgeId, Nid, TypeId},
    graph_group::AdjacencyEdge,
};

use super::invalid;

const RUN_ROWS: usize = 16_384;
const BLOCK_ROWS: usize = 2_048;
const ROW_BYTES: usize = 28;
const HEADER_BYTES: usize = 28; // run UUID, block ordinal, row count
const MAX_FRAME_BYTES: usize = 64 * 1024;

/// One fixed sorting buffer and at most one finished run per binary merge level.
/// The checked u64 input count bounds the number of levels to 64. Merges read
/// two blocks and write one block; neither fan-in nor row buffers grow with E.
pub(crate) struct TopologySort {
    rows: Vec<AdjacencyEdge>,
    run_rows: usize,
    levels: Vec<Option<Run>>,
    input_rows: u64,
}

impl TopologySort {
    pub(crate) fn new() -> Self {
        Self {
            rows: Vec::new(),
            run_rows: RUN_ROWS,
            levels: Vec::new(),
            input_rows: 0,
        }
    }

    pub(crate) fn push(&mut self, mut row: AdjacencyEdge) -> Result<()> {
        // Physical base provenance is not part of logical topology authority,
        // and scratch runs intentionally do not persist it.
        row.local_base = None;
        self.input_rows = self
            .input_rows
            .checked_add(1)
            .ok_or_else(|| invalid("topology input count overflow"))?;
        self.rows.push(row);
        if self.rows.len() == self.run_rows {
            self.flush()?;
        }
        Ok(())
    }

    fn sort_rows(&mut self) -> Result<()> {
        self.rows.sort_unstable_by_key(|edge| edge.edge_id);
        for pair in self.rows.windows(2) {
            if pair[0].edge_id == pair[1].edge_id && pair[0] != pair[1] {
                return Err(invalid(
                    "selected adjacency fragments disagree about an EdgeId",
                ));
            }
        }
        self.rows.dedup();
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        self.sort_rows()?;
        let mut writer = RunWriter::new()?;
        for row in self.rows.drain(..) {
            writer.push(row)?;
        }
        let mut run = writer.finish()?;
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                self.levels.push(Some(run));
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

    pub(crate) fn visit_unique(
        mut self,
        mut visit: impl FnMut(AdjacencyEdge) -> Result<()>,
    ) -> Result<()> {
        // Small generations need no scratch I/O at all.
        if self.levels.is_empty() {
            self.sort_rows()?;
            for row in self.rows {
                visit(row)?;
            }
            return Ok(());
        }
        self.flush()?;
        drop(self.rows);
        let mut merged = None;
        for run in self.levels.into_iter().flatten() {
            merged = Some(match merged {
                None => run,
                Some(previous) => merge(previous, run)?,
            });
        }
        if let Some(run) = merged {
            let mut reader = RunReader::new(run)?;
            while let Some(row) = reader.next()? {
                visit(row)?;
            }
        }
        Ok(())
    }
}

struct Run {
    file: File,
    id: [u8; 16],
    rows: u64,
    bytes: u64,
}

struct RunWriter {
    run: Run,
    block: u64,
    pending: u32,
    bytes: Zeroizing<Vec<u8>>,
}

impl RunWriter {
    fn new() -> Result<Self> {
        Ok(Self {
            run: Run {
                // Anonymous/delete-on-close: no path is added to the manifest,
                // snapshot or archive, and errors cannot leave a named run.
                file: tempfile::tempfile()?,
                id: *uuid::Uuid::new_v4().as_bytes(),
                rows: 0,
                bytes: 0,
            },
            block: 0,
            pending: 0,
            bytes: Zeroizing::new(Vec::with_capacity(
                HEADER_BYTES + BLOCK_ROWS * ROW_BYTES + 4,
            )),
        })
    }

    fn push(&mut self, row: AdjacencyEdge) -> Result<()> {
        if self.pending == 0 {
            self.bytes.extend_from_slice(&self.run.id);
            self.bytes.extend_from_slice(&self.block.to_le_bytes());
            self.bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        self.bytes
            .extend_from_slice(&row.edge_id.raw().to_le_bytes());
        self.bytes
            .extend_from_slice(&row.source.raw().to_le_bytes());
        self.bytes
            .extend_from_slice(&row.target.raw().to_le_bytes());
        self.bytes
            .extend_from_slice(&row.type_id.raw().to_le_bytes());
        self.pending += 1;
        self.run.rows = self
            .run
            .rows
            .checked_add(1)
            .ok_or_else(|| invalid("scratch row count overflow"))?;
        if self.pending as usize == BLOCK_ROWS {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending == 0 {
            return Ok(());
        }
        self.bytes[24..28].copy_from_slice(&self.pending.to_le_bytes());
        let crc = crc32fast::hash(&self.bytes);
        self.bytes.extend_from_slice(&crc.to_le_bytes());
        // Encode before the first disk write. In encrypted mode even temporary
        // topology is never written as plaintext. Reuse the existing envelope.
        let encoded = encryption::encode_persistent(FileType::Segment, &self.bytes)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(invalid("topology scratch frame exceeds fixed cap"));
        }
        self.run
            .file
            .write_all(&(encoded.len() as u32).to_le_bytes())?;
        self.run.file.write_all(&encoded)?;
        drop(encoded);
        self.bytes.zeroize();
        self.bytes.clear();
        self.pending = 0;
        self.block += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<Run> {
        self.flush()?;
        self.run.bytes = self.run.file.stream_position()?;
        Ok(self.run)
    }
}

struct RunReader {
    run: Run,
    remaining: u64,
    block: u64,
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    previous: Option<EdgeId>,
}

impl RunReader {
    fn new(mut run: Run) -> Result<Self> {
        if run.file.metadata()?.len() != run.bytes {
            return Err(invalid("topology scratch length changed"));
        }
        run.file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            remaining: run.rows,
            run,
            block: 0,
            bytes: Zeroizing::new(Vec::new()),
            position: 0,
            previous: None,
        })
    }

    fn next(&mut self) -> Result<Option<AdjacencyEdge>> {
        if self.remaining == 0 {
            if self.run.file.stream_position()? != self.run.bytes {
                return Err(invalid("unconsumed topology scratch bytes"));
            }
            return Ok(None);
        }
        if self.position + ROW_BYTES + 4 > self.bytes.len() {
            let mut length = [0; 4];
            self.run.file.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(invalid("invalid topology scratch frame length"));
            }
            let mut encoded = Zeroizing::new(vec![0; length]);
            self.run.file.read_exact(&mut encoded)?;
            let count = self.remaining.min(BLOCK_ROWS as u64) as usize;
            let expected_len = HEADER_BYTES + count * ROW_BYTES + 4;
            if encoded.starts_with(encryption::MAGIC) {
                let layout = encryption::EncryptedLayout::from_header(&encoded)?;
                if layout.info().plaintext_len != expected_len as u64
                    || layout.info().file_type != FileType::Segment
                {
                    return Err(invalid("topology scratch envelope length/type mismatch"));
                }
            }
            self.bytes = Zeroizing::new(encryption::decode_persistent(&encoded)?.into_owned());
            if self.bytes.len() != expected_len
                || self.bytes[..16] != self.run.id
                || self.bytes[16..24] != self.block.to_le_bytes()
                || self.bytes[24..28] != (count as u32).to_le_bytes()
            {
                return Err(invalid("topology scratch block identity/count mismatch"));
            }
            let end = self.bytes.len() - 4;
            if self.bytes[end..] != crc32fast::hash(&self.bytes[..end]).to_le_bytes() {
                return Err(invalid("topology scratch checksum mismatch"));
            }
            self.block += 1;
            self.position = HEADER_BYTES;
        }
        let bytes = &self.bytes[self.position..self.position + ROW_BYTES];
        let row = AdjacencyEdge {
            edge_id: EdgeId::from_raw(u64::from_le_bytes(bytes[..8].try_into().unwrap())),
            source: Nid::from_raw(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
            target: Nid::from_raw(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
            type_id: TypeId::from_raw(u32::from_le_bytes(bytes[24..28].try_into().unwrap())),
            local_base: None,
        };
        if self
            .previous
            .is_some_and(|previous| previous >= row.edge_id)
        {
            return Err(invalid("topology scratch keys are not strictly ordered"));
        }
        self.previous = Some(row.edge_id);
        self.remaining -= 1;
        self.position += ROW_BYTES;
        Ok(Some(row))
    }
}

fn merge(left: Run, right: Run) -> Result<Run> {
    let mut left = RunReader::new(left)?;
    let mut right = RunReader::new(right)?;
    let mut writer = RunWriter::new()?;
    let (mut a, mut b) = (left.next()?, right.next()?);
    while a.is_some() || b.is_some() {
        match (a, b) {
            (Some(x), Some(y)) if x.edge_id == y.edge_id => {
                if x != y {
                    return Err(invalid(
                        "selected adjacency fragments disagree about an EdgeId",
                    ));
                }
                writer.push(x)?;
                a = left.next()?;
                b = right.next()?;
            }
            (Some(x), Some(y)) if x.edge_id < y.edge_id => {
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

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn row(id: u64) -> AdjacencyEdge {
        AdjacencyEdge {
            edge_id: EdgeId::from_parts(1, id).unwrap(),
            source: Nid::from_parts(1, id + 1).unwrap(),
            target: Nid::from_parts(1, id + 2).unwrap(),
            type_id: TypeId::from_raw(1),
            local_base: None,
        }
    }

    // Called in both isolated plaintext/encrypted recovery subprocesses, too.
    pub(crate) fn exercise_sort() {
        for run_rows in [RUN_ROWS, 1] {
            let mut sort = TopologySort::new();
            sort.run_rows = run_rows;
            let mut from_base = row(1);
            from_base.local_base = Some(7);
            sort.push(from_base).unwrap();
            sort.push(row(1)).unwrap();
            let mut unique = Vec::new();
            sort.visit_unique(|edge| {
                unique.push(edge);
                Ok(())
            })
            .unwrap();
            assert_eq!(unique, vec![row(1)]);
        }

        for count in [0, 1, RUN_ROWS - 1, RUN_ROWS, 5 * RUN_ROWS + 17] {
            let mut sort = TopologySort::new();
            for id in (1..=count as u64).rev() {
                sort.push(row(id)).unwrap();
                sort.push(row(id)).unwrap();
                assert!(sort.rows.len() < RUN_ROWS);
                assert!(sort.rows.capacity() <= RUN_ROWS);
                assert!(sort.levels.len() <= 64);
            }
            // Repetition across both run and block boundaries must count once.
            if count > 0 {
                sort.push(row(1)).unwrap();
            }
            let mut next = 1;
            sort.visit_unique(|edge| {
                assert_eq!(edge, row(next));
                next += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(next, count as u64 + 1);
        }
        for field in 0..3 {
            let mut changed = row(1);
            match field {
                0 => changed.source = Nid::from_parts(1, 90).unwrap(),
                1 => changed.target = Nid::from_parts(1, 90).unwrap(),
                _ => changed.type_id = TypeId::from_raw(2),
            }
            // Same in-memory buffer, a binary carry merge, and final folding.
            for distance in [0, 3, 7] {
                let mut sort = TopologySort::new();
                sort.run_rows = 3;
                let result = (|| {
                    sort.push(row(1))?;
                    for id in 2..distance + 2 {
                        sort.push(row(id))?;
                    }
                    sort.push(changed)?;
                    sort.visit_unique(|_| Ok(()))
                })();
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("fragments disagree")
                );
            }
        }

        let make_run = || {
            let mut writer = RunWriter::new().unwrap();
            for id in 1..=BLOCK_ROWS as u64 + 1 {
                writer.push(row(id)).unwrap();
            }
            writer.finish().unwrap()
        };
        for case in 0..8 {
            let mut run = make_run();
            match case {
                0 => run.file.set_len(run.bytes - 1).unwrap(),
                1 => {
                    run.file.write_all(&[1]).unwrap();
                }
                2 => {
                    run.id[0] ^= 1;
                }
                3 => run.rows += 1,
                4 => {
                    run.file.seek(SeekFrom::Start(0)).unwrap();
                    run.file.write_all(&u32::MAX.to_le_bytes()).unwrap();
                }
                5 => {
                    run.file.seek(SeekFrom::Start(run.bytes - 1)).unwrap();
                    let mut byte = [0];
                    run.file.read_exact(&mut byte).unwrap();
                    byte[0] ^= 1;
                    run.file.seek(SeekFrom::Start(run.bytes - 1)).unwrap();
                    run.file.write_all(&byte).unwrap();
                }
                6 => {
                    // Replace with a valid run of the same length: UUID binds it.
                    let other = make_run();
                    run.file = other.file;
                }
                _ => run.rows = 0,
            }
            let result = (|| {
                let mut reader = RunReader::new(run)?;
                while reader.next()?.is_some() {}
                Ok::<_, crate::GaussError>(())
            })();
            assert!(result.is_err(), "corruption case {case}");
        }
        let mut run = make_run();
        run.file.seek(SeekFrom::Start(4)).unwrap();
        let mut prefix = [0; 8];
        run.file.read_exact(&mut prefix).unwrap();
        assert_eq!(
            prefix == *encryption::MAGIC,
            encryption::encryption_enabled()
        );

        // Equal-sized, valid authenticated frames from the SAME run cannot be
        // reordered: the plaintext block ordinal is checked after decoding.
        let mut writer = RunWriter::new().unwrap();
        for id in 1..=2 * BLOCK_ROWS as u64 {
            writer.push(row(id)).unwrap();
        }
        let mut run = writer.finish().unwrap();
        run.file.seek(SeekFrom::Start(0)).unwrap();
        let mut frames = Vec::new();
        for _ in 0..2 {
            let mut length = [0; 4];
            run.file.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_le_bytes(length) as usize];
            run.file.read_exact(&mut bytes).unwrap();
            frames.push((length, bytes));
        }
        run.file.seek(SeekFrom::Start(0)).unwrap();
        for (length, bytes) in frames.iter().rev() {
            run.file.write_all(length).unwrap();
            run.file.write_all(bytes).unwrap();
        }
        assert!(
            RunReader::new(run)
                .unwrap()
                .next()
                .unwrap_err()
                .to_string()
                .contains("block identity")
        );

        let mut writer = RunWriter::new().unwrap();
        writer.push(row(2)).unwrap();
        writer.push(row(1)).unwrap();
        let mut reader = RunReader::new(writer.finish().unwrap()).unwrap();
        assert_eq!(reader.next().unwrap(), Some(row(2)));
        assert!(
            reader
                .next()
                .unwrap_err()
                .to_string()
                .contains("strictly ordered")
        );

        // Late I/O failure and write refusal must propagate, not terminate a
        // stream as if it were a successful EOF. No full-disk simulation here.
        let mut reader = RunReader::new(make_run()).unwrap();
        reader.run.file.set_len(0).unwrap();
        assert!(reader.next().is_err());
        let read_only = tempfile::NamedTempFile::new().unwrap();
        let mut writer = RunWriter::new().unwrap();
        writer.run.file = File::open(read_only.path()).unwrap();
        writer.push(row(1)).unwrap();
        assert!(writer.finish().is_err());

        // A callback failure is not converted to a partial successful restore.
        let mut sort = TopologySort::new();
        sort.push(row(1)).unwrap();
        assert!(
            sort.visit_unique(|_| Err(invalid("test callback failure")))
                .is_err()
        );
    }

    #[test]
    fn topology_sort_is_exact_bounded_and_fail_closed() {
        exercise_sort();
    }
}
