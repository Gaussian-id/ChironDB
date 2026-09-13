//! RaBitQ kernels for LS-VEC.
//!
//! Persisted `rabitq.gdx` is metric-aligned: graph-first L2 keeps the
//! ordinal-major v2 layout, while posting-scan cosine/dot use cell-major v3.
//! Both store orthogonally rotated IVF residuals, two bits per dimension, the
//! reference multi-bit asymmetric estimator, and its confidence bounds.
//! Vamana navigation reads these range-backed codes and only the final `ρk`
//! candidates touch the full-precision store.
//!
//! The standalone [`RabitqBackend`] below retains the earlier one-bit
//! in-memory implementation for internal compatibility and tests. It is not a
//! user-selectable collection index; LS-VEC is the sole public index family.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use chirondb_types::distance::squared_l2;

use crate::index::ivf::{IvfArtifact, VectorSource};
use crate::index::{
    IndexBackend, IndexKind, IndexParams, encode_sign_bits, next_pow2, rotate_for_cascade,
    sign_word_count,
};
use crate::model::Point;
use crate::{GaussError, Result};

pub const RABITQ_FILE: &str = "rabitq.gdx";
const RABITQ_V1_MAGIC: &[u8; 8] = b"GAUSRQ21";
const RABITQ_V2_MAGIC: &[u8; 8] = b"GAUSRQ22";
const RABITQ_V3_MAGIC: &[u8; 8] = b"GAUSRQ23";
const RABITQ_MAGIC: &[u8; 8] = b"GAUSRQ24";
const RABITQ_HEADER_BYTES: usize = 56;
const RABITQ_RECORD_META_BYTES: usize = 16;
const RABITQ_ERROR_EPSILON: f32 = 1.9;

/// Mmap-backed 2-bit multi-bit RaBitQ codes. Versions 3 and 4 follow the exact
/// cell-major posting order of `ivf.gdx`; version 2 is ordinal-major and stays
/// active for graph-first L2. V4 translates the additive factor into a global
/// query basis so one lookup table serves every cell. Each row stores the IVF
/// cell, three estimator factors, then four dimensions per code byte.
#[derive(Debug)]
pub struct RabitqArtifact {
    file: crate::encryption::PersistentFile,
    count: usize,
    vector_dim: usize,
    padded_dim: usize,
    nlist: usize,
    code_bytes: usize,
    record_bytes: usize,
    ordinal_to_record: Option<Vec<u32>>,
    query_basis: RabitqQueryBasis,
}

/// Query-side terms for the multi-bit estimator. Residual-basis v2/v3 tables
/// keep the compact split-nibble form because they are rebuilt per IVF cell.
/// Global-basis v4 pays once per query for a fused byte lookup shared by every
/// visited cell.
#[derive(Debug)]
pub(crate) struct RabitqDistanceTable {
    estimate_offset: f32,
    error_norm_sq: f32,
    split_dot: Arc<[RabitqChunkTable]>,
    combined_dot: Arc<[RabitqCombinedChunkTable]>,
}

#[derive(Debug)]
struct RabitqChunkTable {
    low: [f32; 16],
    high: [f32; 16],
}

#[derive(Debug)]
struct RabitqCombinedChunkTable {
    packed: [f32; 256],
}

#[derive(Debug)]
pub(crate) struct RabitqGlobalQueryTable {
    query_norm_sq: f32,
    dot: Arc<[RabitqCombinedChunkTable]>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RabitqDistanceEstimate {
    pub estimate: f32,
    pub lower_bound: f32,
    pub upper_bound: f32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RabitqRecord(usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RabitqQueryBasis {
    Residual,
    Global,
}

#[derive(Clone, Copy)]
enum RabitqLayout {
    OrdinalResidual,
    #[allow(dead_code)] // retained to generate v3 compatibility fixtures
    CellMajorResidual,
    CellMajorGlobal,
}

impl RabitqArtifact {
    pub(crate) fn is_legacy_v1(path: &Path) -> Result<bool> {
        let file = crate::encryption::PersistentFile::open(path)?;
        if file.len() < 12 {
            return Ok(false);
        }
        let header = file.read_range(0..12)?;
        Ok(&header[..8] == RABITQ_V1_MAGIC
            && u32::from_le_bytes(header[8..12].try_into().expect("fixed header")) == 1)
    }

    pub fn open(path: &Path, ivf: &IvfArtifact) -> Result<Self> {
        let file = crate::encryption::PersistentFile::open(path)?;
        if file.len() < RABITQ_HEADER_BYTES {
            return Err(rabitq_corrupt(path, "bad or truncated RaBitQ header"));
        }
        let header = file.read_range(0..RABITQ_HEADER_BYTES)?;
        let version = rq_u32(&header, 8).ok_or_else(|| rabitq_corrupt(path, "missing version"))?;
        let (cell_major, query_basis) = match (&header[..8], version) {
            (magic, 2) if magic == RABITQ_V2_MAGIC => (false, RabitqQueryBasis::Residual),
            (magic, 3) if magic == RABITQ_V3_MAGIC => (true, RabitqQueryBasis::Residual),
            (magic, 4) if magic == RABITQ_MAGIC => (true, RabitqQueryBasis::Global),
            _ => return Err(rabitq_corrupt(path, "unsupported RaBitQ version")),
        };
        let count = rq_usize(&header, 12, path, "point count")?;
        let vector_dim = rq_usize(&header, 20, path, "vector dimension")?;
        let padded_dim = rq_usize(&header, 28, path, "padded dimension")?;
        let nlist = rq_usize(&header, 36, path, "cell count")?;
        let code_bytes =
            rq_u32(&header, 44).ok_or_else(|| rabitq_corrupt(path, "missing code width"))? as usize;
        let record_bytes = rq_u32(&header, 48)
            .ok_or_else(|| rabitq_corrupt(path, "missing record width"))?
            as usize;
        let expected_crc =
            rq_u32(&header, 52).ok_or_else(|| rabitq_corrupt(path, "missing CRC"))?;
        if count != ivf.len()
            || vector_dim != ivf.vector_dim()
            || nlist != ivf.cells()
            || padded_dim != next_pow2(vector_dim)
            || code_bytes != padded_dim.div_ceil(4)
            || record_bytes != code_bytes + RABITQ_RECORD_META_BYTES
        {
            return Err(rabitq_corrupt(path, "RaBitQ metadata disagrees with IVF"));
        }
        let expected_len = count
            .checked_mul(record_bytes)
            .and_then(|bytes| bytes.checked_add(RABITQ_HEADER_BYTES))
            .ok_or_else(|| rabitq_corrupt(path, "RaBitQ artifact length overflow"))?;
        if file.len() != expected_len {
            return Err(rabitq_corrupt(path, "RaBitQ artifact length mismatch"));
        }
        if file.crc32(RABITQ_HEADER_BYTES..file.len())? != expected_crc {
            return Err(rabitq_corrupt(path, "RaBitQ payload CRC mismatch"));
        }
        let mut ordinal_to_record = cell_major.then(|| vec![u32::MAX; count]);
        let mut expected_cell = 0usize;
        let mut expected_cell_end = ivf
            .posting_range(expected_cell)
            .expect("validated IVF cell")
            .end;
        for record in 0..count {
            while record >= expected_cell_end {
                expected_cell += 1;
                expected_cell_end = ivf
                    .posting_range(expected_cell)
                    .expect("validated IVF cell")
                    .end;
            }
            let start = RABITQ_HEADER_BYTES + record * record_bytes;
            let row = file.read_range(start..start + record_bytes)?;
            let cell = rq_u32(&row, 0)
                .ok_or_else(|| rabitq_corrupt(path, "truncated RaBitQ cell"))?
                as usize;
            let f_add = f32::from_le_bytes(
                row[4..8]
                    .try_into()
                    .map_err(|_| rabitq_corrupt(path, "truncated RaBitQ f_add"))?,
            );
            let f_rescale = f32::from_le_bytes(
                row[8..12]
                    .try_into()
                    .map_err(|_| rabitq_corrupt(path, "truncated RaBitQ f_rescale"))?,
            );
            let f_error = f32::from_le_bytes(
                row[12..16]
                    .try_into()
                    .map_err(|_| rabitq_corrupt(path, "truncated RaBitQ f_error"))?,
            );
            if cell >= nlist
                || (cell_major && cell != expected_cell)
                || !f_add.is_finite()
                || (query_basis == RabitqQueryBasis::Residual && f_add < 0.0)
                || !f_rescale.is_finite()
                || f_rescale > 0.0
                || !f_error.is_finite()
                || f_error < 0.0
            {
                return Err(rabitq_corrupt(path, "invalid RaBitQ cell or factors"));
            }
            if let Some(inverse) = &mut ordinal_to_record {
                let ordinal = ivf
                    .posting_ordinal(record)
                    .ok_or_else(|| rabitq_corrupt(path, "missing IVF posting ordinal"))?
                    as usize;
                inverse[ordinal] = u32::try_from(record)
                    .map_err(|_| rabitq_corrupt(path, "RaBitQ record exceeds u32"))?;
            }
        }
        Ok(Self {
            file,
            count,
            vector_dim,
            padded_dim,
            nlist,
            code_bytes,
            record_bytes,
            ordinal_to_record,
            query_basis,
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn cells(&self) -> usize {
        self.nlist
    }

    pub fn cell(&self, ordinal: usize) -> Option<usize> {
        let record = self.record_for_ordinal(ordinal)?;
        rq_u32(&self.record(record)?, 0).map(|cell| cell as usize)
    }

    fn record_for_ordinal(&self, ordinal: usize) -> Option<usize> {
        if ordinal >= self.count {
            return None;
        }
        self.ordinal_to_record
            .as_ref()
            .map_or(Some(ordinal), |inverse| {
                inverse
                    .get(ordinal)
                    .copied()
                    .filter(|record| *record != u32::MAX)
                    .map(|record| record as usize)
            })
    }

    fn record(&self, record: usize) -> Option<std::borrow::Cow<'_, [u8]>> {
        if record >= self.count {
            return None;
        }
        let start = RABITQ_HEADER_BYTES.checked_add(record.checked_mul(self.record_bytes)?)?;
        self.file
            .read_range(start..start.checked_add(self.record_bytes)?)
            .ok()
    }

    pub(crate) fn record_for_ordinal_key(&self, ordinal: usize) -> Option<RabitqRecord> {
        self.record_for_ordinal(ordinal).map(RabitqRecord)
    }

    pub(crate) fn record_at(&self, record: usize) -> Option<RabitqRecord> {
        (record < self.count).then_some(RabitqRecord(record))
    }

    pub(crate) fn record_index(record: RabitqRecord) -> usize {
        record.0
    }

    pub(crate) fn record_cell(&self, record: RabitqRecord) -> Option<usize> {
        rq_u32(&self.record(record.0)?, 0).map(|cell| cell as usize)
    }

    pub(crate) fn record_for_ordinal_in_cell(
        &self,
        ordinal: usize,
        expected_cell: usize,
    ) -> Option<RabitqRecord> {
        let record = self.record_for_ordinal(ordinal)?;
        (rq_u32(&self.record(record)?, 0)? as usize == expected_cell)
            .then_some(RabitqRecord(record))
    }

    /// Estimate squared L2 from a query residual to one persisted residual.
    /// This compatibility helper applies to residual-basis v2/v3 artifacts;
    /// global-query-basis v4 artifacts are evaluated by `IvfSegmentIndex`,
    /// which also has the cell centroid required by that format. The
    /// orthogonal cascade rotation preserves L2; the estimator never
    /// reconstructs or touches the full vector mmap.
    pub fn estimate_squared_l2(&self, ordinal: usize, query_residual: &[f32]) -> Option<f32> {
        if ordinal >= self.count || query_residual.len() != self.vector_dim {
            return None;
        }
        let query = rotate_for_cascade(query_residual);
        self.estimate_rotated_squared_l2(ordinal, &query)
    }

    /// Hot-path twin for residual-basis v2/v3 callers that rotate one query
    /// residual per IVF cell and reuse it across every posting and graph hop
    /// in that cell. Returns `None` for global-query-basis v4 artifacts.
    pub fn estimate_rotated_squared_l2(
        &self,
        ordinal: usize,
        rotated_query_residual: &[f32],
    ) -> Option<f32> {
        if ordinal >= self.count || rotated_query_residual.len() != self.padded_dim {
            return None;
        }
        let table = self.prepare_distance_table(rotated_query_residual)?;
        self.estimate_squared_l2_with_table(ordinal, &table)
    }

    pub(crate) fn prepare_distance_table(
        &self,
        rotated_query_residual: &[f32],
    ) -> Option<RabitqDistanceTable> {
        if self.query_basis != RabitqQueryBasis::Residual
            || rotated_query_residual.len() != self.padded_dim
        {
            return None;
        }
        let query_norm_sq = norm_sq(rotated_query_residual);
        Some(RabitqDistanceTable {
            estimate_offset: query_norm_sq,
            error_norm_sq: query_norm_sq,
            split_dot: Arc::from(prepare_dot_table(rotated_query_residual)),
            combined_dot: Arc::from(Vec::<RabitqCombinedChunkTable>::new()),
        })
    }

    pub(crate) fn prepare_global_query_table(
        &self,
        rotated_query: &[f32],
    ) -> Option<RabitqGlobalQueryTable> {
        if self.query_basis != RabitqQueryBasis::Global || rotated_query.len() != self.padded_dim {
            return None;
        }
        Some(RabitqGlobalQueryTable {
            query_norm_sq: norm_sq(rotated_query),
            dot: Arc::from(prepare_combined_dot_table(rotated_query)),
        })
    }

    pub(crate) fn prepare_global_cell_distance_table(
        &self,
        rotated_query: &[f32],
        rotated_centroid: &[f32],
        global: &RabitqGlobalQueryTable,
    ) -> Option<RabitqDistanceTable> {
        if self.query_basis != RabitqQueryBasis::Global
            || rotated_query.len() != self.padded_dim
            || rotated_centroid.len() != self.padded_dim
            || global.dot.len() != self.code_bytes
        {
            return None;
        }
        let query_centroid_dot = rotated_query
            .iter()
            .zip(rotated_centroid)
            .map(|(query, centroid)| query * centroid)
            .sum::<f32>();
        let estimate_offset = global.query_norm_sq - 2.0 * query_centroid_dot;
        let error_norm_sq = rotated_query
            .iter()
            .zip(rotated_centroid)
            .map(|(query, centroid)| {
                let residual = query - centroid;
                residual * residual
            })
            .sum();
        Some(RabitqDistanceTable {
            estimate_offset,
            error_norm_sq,
            split_dot: Arc::from(Vec::<RabitqChunkTable>::new()),
            combined_dot: Arc::clone(&global.dot),
        })
    }

    pub(crate) fn uses_global_query_table(&self) -> bool {
        self.query_basis == RabitqQueryBasis::Global
    }

    fn distance_estimate_for_record_with_basis<const GLOBAL: bool>(
        &self,
        record: usize,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        debug_assert_eq!(GLOBAL, self.query_basis == RabitqQueryBasis::Global);
        let table_len = if GLOBAL {
            table.combined_dot.len()
        } else {
            table.split_dot.len()
        };
        if record >= self.count || table_len != self.code_bytes {
            return None;
        }
        let row = self.record(record)?;
        let f_add = f32::from_le_bytes(row[4..8].try_into().ok()?);
        let f_rescale = f32::from_le_bytes(row[8..12].try_into().ok()?);
        let f_error = f32::from_le_bytes(row[12..16].try_into().ok()?);
        if !f_add.is_finite()
            || (!GLOBAL && f_add < 0.0)
            || !f_rescale.is_finite()
            || f_rescale > 0.0
            || !f_error.is_finite()
            || f_error < 0.0
            || !table.estimate_offset.is_finite()
            || !table.error_norm_sq.is_finite()
            || table.error_norm_sq < 0.0
        {
            return None;
        }
        let codes =
            row.get(RABITQ_RECORD_META_BYTES..RABITQ_RECORD_META_BYTES + self.code_bytes)?;
        let dot = if GLOBAL {
            lookup_combined_code_dot(codes, &table.combined_dot)
        } else {
            lookup_split_code_dot(codes, &table.split_dot)
        };
        Some(distance_estimate_from_dot(
            f_add,
            f_rescale,
            f_error,
            table.estimate_offset,
            table.error_norm_sq,
            dot,
        ))
    }

    pub(crate) fn estimate_squared_l2_with_table(
        &self,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<f32> {
        match self.query_basis {
            RabitqQueryBasis::Residual => {
                self.estimate_squared_l2_with_table_for_basis::<false>(ordinal, table)
            }
            RabitqQueryBasis::Global => {
                self.estimate_squared_l2_with_table_for_basis::<true>(ordinal, table)
            }
        }
    }

    pub(crate) fn estimate_squared_l2_with_table_for_basis<const GLOBAL: bool>(
        &self,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<f32> {
        let record = self.record_for_ordinal(ordinal)?;
        self.estimate_squared_l2_for_record_with_table_for_basis::<GLOBAL>(
            RabitqRecord(record),
            table,
        )
    }

    pub(crate) fn estimate_squared_l2_for_record_with_table_for_basis<const GLOBAL: bool>(
        &self,
        record: RabitqRecord,
        table: &RabitqDistanceTable,
    ) -> Option<f32> {
        debug_assert_eq!(GLOBAL, self.query_basis == RabitqQueryBasis::Global);
        let record = record.0;
        let table_len = if GLOBAL {
            table.combined_dot.len()
        } else {
            table.split_dot.len()
        };
        if table_len != self.code_bytes {
            return None;
        }
        let row = self.record(record)?;
        let f_add = f32::from_le_bytes(row[4..8].try_into().ok()?);
        let f_rescale = f32::from_le_bytes(row[8..12].try_into().ok()?);
        if !f_add.is_finite()
            || (!GLOBAL && f_add < 0.0)
            || !f_rescale.is_finite()
            || f_rescale > 0.0
            || !table.estimate_offset.is_finite()
        {
            return None;
        }
        let codes =
            row.get(RABITQ_RECORD_META_BYTES..RABITQ_RECORD_META_BYTES + self.code_bytes)?;
        let dot = if GLOBAL {
            lookup_combined_code_dot(codes, &table.combined_dot)
        } else {
            lookup_split_code_dot(codes, &table.split_dot)
        };
        Some((f_add + table.estimate_offset + f_rescale * dot).max(0.0))
    }

    /// Scores graph-adjacent records in a four-lane stack batch while
    /// preserving each record's scalar code-index accumulation order.
    pub(crate) fn estimate_squared_l2_for_records_with_table_for_basis<const GLOBAL: bool>(
        &self,
        records: &[RabitqRecord],
        table: &RabitqDistanceTable,
        distances: &mut [f32],
    ) -> Option<()> {
        debug_assert_eq!(GLOBAL, self.query_basis == RabitqQueryBasis::Global);
        let table_len = if GLOBAL {
            table.combined_dot.len()
        } else {
            table.split_dot.len()
        };
        if table_len != self.code_bytes || distances.len() < records.len() {
            return None;
        }
        for (record_chunk, output_chunk) in records.chunks(4).zip(distances.chunks_mut(4)) {
            let mut rows: [Option<std::borrow::Cow<'_, [u8]>>; 4] = std::array::from_fn(|_| None);
            let mut f_add = [0.0f32; 4];
            let mut f_rescale = [0.0f32; 4];
            let mut dot = [0.0f32; 4];
            for (lane, record) in record_chunk.iter().enumerate() {
                let row = self.record(record.0)?;
                f_add[lane] = f32::from_le_bytes(row.get(4..8)?.try_into().ok()?);
                f_rescale[lane] = f32::from_le_bytes(row.get(8..12)?.try_into().ok()?);
                if !f_add[lane].is_finite()
                    || (!GLOBAL && f_add[lane] < 0.0)
                    || !f_rescale[lane].is_finite()
                    || f_rescale[lane] > 0.0
                {
                    return None;
                }
                rows[lane] = Some(row);
            }
            for code_index in 0..self.code_bytes {
                for lane in 0..record_chunk.len() {
                    let packed = *rows[lane]
                        .as_deref()?
                        .get(RABITQ_RECORD_META_BYTES + code_index)?;
                    dot[lane] += if GLOBAL {
                        table.combined_dot[code_index].packed[packed as usize]
                    } else {
                        let lookup = &table.split_dot[code_index];
                        lookup.low[(packed & 0x0f) as usize] + lookup.high[(packed >> 4) as usize]
                    };
                }
            }
            for lane in 0..record_chunk.len() {
                output_chunk[lane] =
                    (f_add[lane] + table.estimate_offset + f_rescale[lane] * dot[lane]).max(0.0);
            }
        }
        Some(())
    }

    #[cfg(test)]
    pub(crate) fn distance_estimate_with_table(
        &self,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        match self.query_basis {
            RabitqQueryBasis::Residual => {
                self.distance_estimate_with_table_for_basis::<false>(ordinal, table)
            }
            RabitqQueryBasis::Global => {
                self.distance_estimate_with_table_for_basis::<true>(ordinal, table)
            }
        }
    }

    pub(crate) fn distance_estimate_with_table_for_basis<const GLOBAL: bool>(
        &self,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        let record = self.record_for_ordinal(ordinal)?;
        self.distance_estimate_for_record_with_table_for_basis::<GLOBAL>(
            RabitqRecord(record),
            table,
        )
    }

    pub(crate) fn distance_estimate_for_record_with_table_for_basis<const GLOBAL: bool>(
        &self,
        record: RabitqRecord,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        self.distance_estimate_for_record_with_basis::<GLOBAL>(record.0, table)
    }

    #[cfg(test)]
    pub(crate) fn distance_estimate_for_posting_with_table(
        &self,
        posting: usize,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        match self.query_basis {
            RabitqQueryBasis::Residual => self
                .distance_estimate_for_posting_with_table_for_basis::<false>(
                    posting, ordinal, table,
                ),
            RabitqQueryBasis::Global => self
                .distance_estimate_for_posting_with_table_for_basis::<true>(
                    posting, ordinal, table,
                ),
        }
    }

    pub(crate) fn distance_estimate_for_posting_with_table_for_basis<const GLOBAL: bool>(
        &self,
        posting: usize,
        ordinal: usize,
        table: &RabitqDistanceTable,
    ) -> Option<RabitqDistanceEstimate> {
        let record = if self.ordinal_to_record.is_some() {
            posting
        } else {
            ordinal
        };
        self.distance_estimate_for_record_with_basis::<GLOBAL>(record, table)
    }
}

fn prepare_dot_table(rotated_query: &[f32]) -> Vec<RabitqChunkTable> {
    let mut dot = Vec::with_capacity(rotated_query.len().div_ceil(4));
    for query_chunk in rotated_query.chunks(4) {
        let mut low = [0.0f32; 16];
        let mut high = [0.0f32; 16];
        for packed in 0usize..16 {
            for local_lane in 0..2 {
                let code = (packed >> (local_lane * 2)) & 0b11;
                let level = code as f32 - 1.5;
                if let Some(&query_value) = query_chunk.get(local_lane) {
                    low[packed] += query_value * level;
                }
                if let Some(&query_value) = query_chunk.get(local_lane + 2) {
                    high[packed] += query_value * level;
                }
            }
        }
        dot.push(RabitqChunkTable { low, high });
    }
    dot
}

fn prepare_combined_dot_table(rotated_query: &[f32]) -> Vec<RabitqCombinedChunkTable> {
    prepare_dot_table(rotated_query)
        .into_iter()
        .map(|split| {
            let mut packed = [0.0f32; 256];
            for (value, entry) in packed.iter_mut().enumerate() {
                *entry = split.low[value & 0x0f] + split.high[value >> 4];
            }
            RabitqCombinedChunkTable { packed }
        })
        .collect()
}

#[inline]
fn lookup_split_code_dot(codes: &[u8], table: &[RabitqChunkTable]) -> f32 {
    codes
        .iter()
        .zip(table)
        .map(|(&packed, lut)| lut.low[(packed & 0x0f) as usize] + lut.high[(packed >> 4) as usize])
        .sum()
}

#[inline]
fn lookup_combined_code_dot(codes: &[u8], table: &[RabitqCombinedChunkTable]) -> f32 {
    codes
        .iter()
        .zip(table)
        .map(|(&packed, lut)| lut.packed[packed as usize])
        .sum()
}

fn norm_sq(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum()
}

fn distance_estimate_from_dot(
    f_add: f32,
    f_rescale: f32,
    f_error: f32,
    estimate_offset: f32,
    error_norm_sq: f32,
    dot: f32,
) -> RabitqDistanceEstimate {
    let raw_estimate = f_add + estimate_offset + f_rescale * dot;
    let error = f_error * error_norm_sq.sqrt();
    RabitqDistanceEstimate {
        estimate: raw_estimate.max(0.0),
        lower_bound: (raw_estimate - error).max(0.0),
        upper_bound: (raw_estimate + error).max(0.0),
    }
}

/// Persist per-cell residual RaBitQ-2b codes in IVF posting order. Working
/// memory is one hydrated source vector, one residual, and the centroid table.
pub fn write_rabitq_artifact<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    path: &Path,
) -> Result<()> {
    write_rabitq_artifact_with_layout(source, ivf, RabitqLayout::CellMajorGlobal, path)
}

pub fn write_rabitq_artifact_for_metric<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
) -> Result<()> {
    let layout = if metric == crate::DistanceMetric::L2 {
        RabitqLayout::OrdinalResidual
    } else {
        RabitqLayout::CellMajorGlobal
    };
    write_rabitq_artifact_with_layout(source, ivf, layout, path)
}

fn write_rabitq_artifact_with_layout<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    layout: RabitqLayout,
    path: &Path,
) -> Result<()> {
    if source.len() != ivf.len() {
        return Err(GaussError::InvalidRequest(
            "RaBitQ source count disagrees with IVF".to_string(),
        ));
    }
    let vector_dim = ivf.vector_dim();
    let padded_dim = next_pow2(vector_dim);
    let code_bytes = padded_dim.div_ceil(4);
    let record_bytes = code_bytes + RABITQ_RECORD_META_BYTES;
    let centroids = ivf.centroids();

    let file_bytes =
        RABITQ_HEADER_BYTES
            .checked_add(source.len().checked_mul(record_bytes).ok_or_else(|| {
                GaussError::InvalidRequest("RaBitQ artifact overflow".to_string())
            })?)
            .ok_or_else(|| GaussError::InvalidRequest("RaBitQ artifact overflow".to_string()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)?;
    file.set_len(file_bytes as u64)?;
    let (magic, version) = match layout {
        RabitqLayout::OrdinalResidual => (RABITQ_V2_MAGIC, 2u32),
        RabitqLayout::CellMajorResidual => (RABITQ_V3_MAGIC, 3u32),
        RabitqLayout::CellMajorGlobal => (RABITQ_MAGIC, 4u32),
    };
    file.write_all(magic)?;
    file.write_all(&version.to_le_bytes())?;
    file.write_all(&(source.len() as u64).to_le_bytes())?;
    file.write_all(&(vector_dim as u64).to_le_bytes())?;
    file.write_all(&(padded_dim as u64).to_le_bytes())?;
    file.write_all(&(ivf.cells() as u64).to_le_bytes())?;
    file.write_all(&(code_bytes as u32).to_le_bytes())?;
    file.write_all(&(record_bytes as u32).to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;

    for (cell, centroid) in centroids.iter().enumerate() {
        let rotated_centroid = rotate_for_cascade(centroid);
        let centroid_norm_sq = norm_sq(&rotated_centroid);
        let centroid_dot_table = (matches!(layout, RabitqLayout::CellMajorGlobal))
            .then(|| prepare_dot_table(&rotated_centroid));
        for posting in ivf.posting_range(cell).expect("validated IVF cell") {
            let ordinal = ivf.posting_ordinal(posting).expect("validated IVF posting") as usize;
            let vector = source.vector(ordinal)?;
            if vector.len() != vector_dim {
                return Err(GaussError::DimensionMismatch {
                    expected: vector_dim,
                    actual: vector.len(),
                });
            }
            let residual = vector
                .iter()
                .zip(centroid)
                .map(|(value, center)| value - center)
                .collect::<Vec<_>>();
            let rotated = rotate_for_cascade(&residual);
            let mut codes = vec![0u8; code_bytes];
            let factors = quantize_residual_2bit(&rotated, &mut codes);
            let stored_add = centroid_dot_table.as_ref().map_or(factors.f_add, |table| {
                factors.f_add + centroid_norm_sq
                    - factors.f_rescale * lookup_split_code_dot(&codes, table)
            });
            let record = match layout {
                RabitqLayout::OrdinalResidual => ordinal,
                RabitqLayout::CellMajorResidual | RabitqLayout::CellMajorGlobal => posting,
            };
            file.seek(SeekFrom::Start(
                (RABITQ_HEADER_BYTES + record * record_bytes) as u64,
            ))?;
            file.write_all(&(cell as u32).to_le_bytes())?;
            file.write_all(&stored_add.to_le_bytes())?;
            file.write_all(&factors.f_rescale.to_le_bytes())?;
            file.write_all(&factors.f_error.to_le_bytes())?;
            file.write_all(&codes)?;
        }
    }
    file.seek(SeekFrom::Start(RABITQ_HEADER_BYTES as u64))?;
    let mut crc = crc32fast::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(52))?;
    file.write_all(&crc.finalize().to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct RabitqFactors {
    f_add: f32,
    f_rescale: f32,
    f_error: f32,
}

/// Reference RaBitQ multi-bit quantization for two bits per dimension.
///
/// The sign bit fixes the half-space. The second bit promotes the largest
/// magnitudes from `0.5` to `1.5`; the promotion count maximizes cosine
/// similarity between the residual and the discrete code. The three stored
/// factors then evaluate the reference asymmetric squared-L2 estimator and
/// its probabilistic lower confidence bound without reconstructing a vector.
fn quantize_residual_2bit(values: &[f32], codes: &mut [u8]) -> RabitqFactors {
    debug_assert_eq!(codes.len(), values.len().div_ceil(4));
    codes.fill(0);
    let norm_sq = values.iter().map(|value| value * value).sum::<f32>();
    if norm_sq == 0.0 {
        for dim in 0..values.len() {
            codes[dim / 4] |= 0b10 << ((dim % 4) * 2);
        }
        return RabitqFactors {
            f_add: 0.0,
            f_rescale: 0.0,
            f_error: 0.0,
        };
    }

    let mut order = (0..values.len()).collect::<Vec<_>>();
    order.sort_unstable_by(|&left, &right| {
        values[right]
            .abs()
            .total_cmp(&values[left].abs())
            .then_with(|| left.cmp(&right))
    });
    let sum_abs = values.iter().map(|value| value.abs()).sum::<f32>();
    let mut promoted = 0usize;
    let mut prefix = 0.0f32;
    let mut best_cosine_sq = (0.5 * sum_abs).powi(2) / (0.25 * values.len() as f32);
    for (rank, &dim) in order.iter().enumerate() {
        prefix += values[dim].abs();
        let high_count = rank + 1;
        let dot = 0.5 * sum_abs + prefix;
        let code_norm_sq = 0.25 * values.len() as f32 + 2.0 * high_count as f32;
        let cosine_sq = dot * dot / code_norm_sq;
        if cosine_sq > best_cosine_sq {
            best_cosine_sq = cosine_sq;
            promoted = high_count;
        }
    }
    let mut is_promoted = vec![false; values.len()];
    for &dim in order.iter().take(promoted) {
        is_promoted[dim] = true;
    }

    let mut dot = 0.0f32;
    let mut code_norm_sq = 0.0f32;
    for (dim, &value) in values.iter().enumerate() {
        let high = is_promoted[dim];
        let code = match (value.is_sign_negative(), high) {
            (true, true) => 0,
            (true, false) => 1,
            (false, false) => 2,
            (false, true) => 3,
        };
        codes[dim / 4] |= code << ((dim % 4) * 2);
        let level = code as f32 - 1.5;
        dot += value * level;
        code_norm_sq += level * level;
    }
    let f_rescale = -2.0 * norm_sq / dot;
    let relative_error_sq = (norm_sq * code_norm_sq / (dot * dot) - 1.0).max(0.0);
    let f_error = if values.len() > 1 {
        2.0 * norm_sq.sqrt()
            * RABITQ_ERROR_EPSILON
            * (relative_error_sq / (values.len() - 1) as f32).sqrt()
    } else {
        2.0 * norm_sq.sqrt() * relative_error_sq.sqrt()
    };
    RabitqFactors {
        f_add: norm_sq,
        f_rescale,
        f_error,
    }
}

pub(crate) fn migrate_legacy_v1_artifact<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
) -> Result<()> {
    let temporary = migration_path(path, "current-migrating");
    let backup = migration_path(path, "v1-backup");
    if !path.exists() && backup.exists() {
        fs::rename(&backup, path)?;
        sync_parent(path)?;
    }
    if !RabitqArtifact::is_legacy_v1(path)? {
        return Ok(());
    }
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    write_rabitq_artifact_for_metric(source, ivf, metric, &temporary)?;
    fs::rename(path, &backup)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::rename(&backup, path);
        return Err(error.into());
    }
    sync_parent(path)?;
    fs::remove_file(&backup)?;
    sync_parent(path)?;
    Ok(())
}

fn migration_path(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(RABITQ_FILE);
    path.with_file_name(format!("{file_name}.{suffix}"))
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn rq_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn rq_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn rq_usize(bytes: &[u8], offset: usize, path: &Path, field: &str) -> Result<usize> {
    let value =
        rq_u64(bytes, offset).ok_or_else(|| rabitq_corrupt(path, &format!("missing {field}")))?;
    usize::try_from(value).map_err(|_| rabitq_corrupt(path, &format!("{field} exceeds usize")))
}

fn rabitq_corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

/// Candidate over-sampling factor for the filter stage. Bigger = closer to
/// recall=1.0, but more f32 rerank work. 16 is the conservative starting point;
/// tune downward only with measured recall data.
const DEFAULT_OVERSAMPLE: usize = 16;

/// RaBitQ 1-bit code: sign bits over the rotated vector, plus the two
/// per-vector scalars the RaBitQ **unbiased estimator** needs (residual norm +
/// code fidelity). Sign bits are packed little-endian-within-word; positions
/// beyond the padded dim stay zero.
#[derive(Clone)]
struct BinaryCode {
    words: Vec<u64>,
    meta: super::rabitq_estimator::RabitqCodeMeta,
}

/// In-memory RaBitQ backend. Phase 4 will lay this out as a sealed
/// `rabitq.gdx` segment artifact; the wire-up reuses [`super::build`] semantics.
#[derive(Clone)]
pub struct RabitqBackend {
    vector_dim: usize,
    word_count: usize,
    codes: Vec<BinaryCode>,
    vectors: Vec<Vec<f32>>,
    ids: Vec<String>,
    id_to_idx: HashMap<String, usize>,
    over_sample: usize,
}

impl std::fmt::Debug for RabitqBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RabitqBackend")
            .field("vector_dim", &self.vector_dim)
            .field("word_count", &self.word_count)
            .field("points", &self.ids.len())
            .field("over_sample", &self.over_sample)
            .finish()
    }
}

impl RabitqBackend {
    pub fn build(points: &[Point], vector_dim: usize) -> Self {
        // B1.2: codes are packed over the *rotated* vector, which
        // `rotate_for_cascade` pads to `next_pow2(vector_dim)` — size the word
        // count for the padded length, not the raw dim.
        let word_count = sign_word_count(next_pow2(vector_dim));
        let mut backend = Self {
            vector_dim,
            word_count,
            codes: Vec::with_capacity(points.len()),
            vectors: Vec::with_capacity(points.len()),
            ids: Vec::with_capacity(points.len()),
            id_to_idx: HashMap::with_capacity(points.len()),
            over_sample: DEFAULT_OVERSAMPLE,
        };
        for point in points {
            backend.append_point(point);
        }
        backend
    }

    /// Override the per-collection over-sample factor. Only intended for the
    /// ann-benchmarks Pareto runner (row 133); production tuning belongs in
    /// `CollectionConfig`.
    pub fn with_oversample(mut self, factor: usize) -> Self {
        self.over_sample = factor.max(1);
        self
    }

    pub fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    fn append_point(&mut self, point: &Point) {
        if self.id_to_idx.contains_key(&point.id) {
            return;
        }
        let vec = pad_or_trim(&point.vector, self.vector_dim);
        // Rotate before sign-encoding so the RaBitQ estimator's decorrelation
        // assumption holds (see `rotate_for_cascade`, norm-preserving). The
        // exact f32 vectors stored below stay un-rotated for the stage-2 L2
        // rerank; the coarse filter uses the RaBitQ *unbiased distance
        // estimator* over the rotated sign code + per-vector norm/fidelity.
        let rotated = rotate_for_cascade(&vec);
        let code = BinaryCode {
            words: encode_sign_bits(&rotated, self.word_count),
            meta: super::rabitq_estimator::encode_meta(&rotated),
        };
        let idx = self.ids.len();
        self.ids.push(point.id.clone());
        self.id_to_idx.insert(point.id.clone(), idx);
        self.codes.push(code);
        self.vectors.push(vec);
    }
}

impl IndexBackend for RabitqBackend {
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        if self.ids.is_empty() || k == 0 {
            return Vec::new();
        }
        let query = pad_or_trim(query, self.vector_dim);
        // Same rotation on the query side; the RaBitQ estimator needs the
        // rotated query residual (centroid = 0 for the standalone backend).
        let rotated_query = rotate_for_cascade(&query);

        // Stage 1 — RaBitQ unbiased-estimator filter to top `candidate_pool`.
        let candidate_pool = ef_search
            .unwrap_or_else(|| k.saturating_mul(self.over_sample).max(k))
            .min(self.ids.len());

        let mut scored: Vec<(f32, usize)> = self
            .codes
            .iter()
            .enumerate()
            .map(|(idx, code)| {
                (
                    super::rabitq_estimator::estimate_squared_l2(
                        &code.words,
                        &code.meta,
                        &rotated_query,
                    ),
                    idx,
                )
            })
            .collect();
        // Partial sort: smaller estimated L2 = closer to query.
        let pivot = candidate_pool.min(scored.len().saturating_sub(1));
        scored.select_nth_unstable_by(pivot, |a, b| a.0.total_cmp(&b.0));
        let mut filtered: Vec<usize> = scored
            .into_iter()
            .take(candidate_pool)
            .map(|(_, idx)| idx)
            .collect();

        // Stage 2 — exact L2 rerank on the filtered candidates.
        filtered.sort_by(|&a, &b| {
            let da = squared_l2(&query, &self.vectors[a]);
            let db = squared_l2(&query, &self.vectors[b]);
            da.total_cmp(&db)
        });
        filtered.truncate(k);
        filtered
            .into_iter()
            .map(|idx| self.ids[idx].clone())
            .collect()
    }

    fn default_ef_search(&self, k: usize) -> usize {
        // Use a wider candidate pool than HNSW for binary quant — we pay one
        // popcount per point so the absolute cost is small.
        k.saturating_mul(self.over_sample).max(128)
    }

    fn ef_search_for_recall_target(&self, k: usize, recall_target: f32) -> usize {
        if !(0.5..=1.0).contains(&recall_target) || recall_target.is_nan() {
            return self.default_ef_search(k);
        }
        let factor = if recall_target >= 0.99 {
            32
        } else if recall_target >= 0.95 {
            self.over_sample
        } else if recall_target >= 0.90 {
            (self.over_sample * 3) / 4
        } else if recall_target >= 0.80 {
            self.over_sample / 2
        } else {
            self.over_sample / 4
        };
        k.saturating_mul(factor.max(1)).max(64)
    }

    fn insert_point(&mut self, point: &Point, vector_dim: usize) -> Result<()> {
        if vector_dim != self.vector_dim {
            return Err(crate::error::GaussError::DimensionMismatch {
                expected: self.vector_dim,
                actual: vector_dim,
            });
        }
        self.append_point(point);
        Ok(())
    }

    fn kind(&self) -> IndexKind {
        IndexKind::Rabitq
    }

    fn indexed_points(&self) -> usize {
        self.ids.len()
    }

    fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    fn contains(&self, id: &str) -> bool {
        self.id_to_idx.contains_key(id)
    }

    fn cells(&self) -> usize {
        // RaBitQ is flat over binary codes — surface point count as the cell
        // count so observability still has a non-zero signal.
        self.ids.len()
    }

    fn is_paged(&self) -> bool {
        false
    }
}

/// Build a [`RabitqBackend`] from raw points. Sibling to [`super::build`].
pub fn build(points: &[Point], params: &IndexParams) -> Box<dyn IndexBackend> {
    Box::new(RabitqBackend::build(points, params.vector_dim))
}

fn pad_or_trim(v: &[f32], dim: usize) -> Vec<f32> {
    let mut out = vec![0.0_f32; dim];
    let n = v.len().min(dim);
    out[..n].copy_from_slice(&v[..n]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, v: Vec<f32>) -> Point {
        Point {
            id: id.into(),
            vector: v,
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        }
    }

    fn lcg_vector(seed: u64, dim: usize) -> Vec<f32> {
        let mut state = seed ^ 0x517c_c1b7_2722_0a95;
        (0..dim)
            .map(|_| {
                state = state
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                let v = ((state >> 32) as u32) as f32 / u32::MAX as f32;
                v * 2.0 - 1.0
            })
            .collect()
    }

    #[test]
    fn v4_global_query_estimator_matches_v3_residual_estimator() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let v3_path = temp.path().join("rabitq-v3.gdx");
        let v4_path = temp.path().join(RABITQ_FILE);
        let vectors = (0..256).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 12, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_rabitq_artifact_with_layout(
            vectors.as_slice(),
            &ivf,
            RabitqLayout::CellMajorResidual,
            &v3_path,
        )
        .unwrap();
        write_rabitq_artifact(vectors.as_slice(), &ivf, &v4_path).unwrap();

        let v3 = RabitqArtifact::open(&v3_path, &ivf).unwrap();
        let v4 = RabitqArtifact::open(&v4_path, &ivf).unwrap();
        let bytes = std::fs::read(&v4_path).unwrap();
        assert_eq!(&bytes[..8], RABITQ_MAGIC);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 4);
        assert_eq!(v4.len(), vectors.len());
        assert_eq!(v4.cells(), ivf.cells());
        let centroids = ivf.centroids();
        for (cell, centroid) in centroids.iter().enumerate() {
            let first_posting = ivf.posting_range(cell).unwrap().next().unwrap();
            let first_ordinal = ivf.posting_ordinal(first_posting).unwrap() as usize;
            let query = &vectors[(first_ordinal + 37) % vectors.len()];
            let rotated_query = rotate_for_cascade(query);
            let rotated_centroid = rotate_for_cascade(centroid);
            let residual = query
                .iter()
                .zip(centroid)
                .map(|(value, center)| value - center)
                .collect::<Vec<_>>();
            let rotated = rotate_for_cascade(&residual);
            let v3_table = v3.prepare_distance_table(&rotated).unwrap();
            let global = v4.prepare_global_query_table(&rotated_query).unwrap();
            let v4_table = v4
                .prepare_global_cell_distance_table(&rotated_query, &rotated_centroid, &global)
                .unwrap();
            assert!(v3_table.combined_dot.is_empty());
            assert!(v4_table.split_dot.is_empty());
            assert!(Arc::ptr_eq(&global.dot, &v4_table.combined_dot));
            let records = ivf
                .posting_range(cell)
                .unwrap()
                .map(|posting| v4.record_at(posting).unwrap())
                .collect::<Vec<_>>();
            let mut batch_estimates = vec![0.0; records.len()];
            v4.estimate_squared_l2_for_records_with_table_for_basis::<true>(
                &records,
                &v4_table,
                &mut batch_estimates,
            )
            .unwrap();
            for (&record, &batch_estimate) in records.iter().zip(&batch_estimates) {
                let scalar = v4
                    .estimate_squared_l2_for_record_with_table_for_basis::<true>(record, &v4_table)
                    .unwrap();
                assert_eq!(batch_estimate, scalar);
            }
            for posting in ivf.posting_range(cell).unwrap() {
                let ordinal = ivf.posting_ordinal(posting).unwrap() as usize;
                let v3_estimate = v3.distance_estimate_with_table(ordinal, &v3_table).unwrap();
                let v4_estimate = v4.distance_estimate_with_table(ordinal, &v4_table).unwrap();
                let posting_estimate = v4
                    .distance_estimate_for_posting_with_table(posting, ordinal, &v4_table)
                    .unwrap();
                let navigation_estimate = v4
                    .estimate_squared_l2_with_table(ordinal, &v4_table)
                    .unwrap();
                let record = v4.record_for_ordinal_in_cell(ordinal, cell).unwrap();
                let direct_estimate = v4
                    .distance_estimate_for_record_with_table_for_basis::<true>(record, &v4_table)
                    .unwrap();
                let direct_navigation = v4
                    .estimate_squared_l2_for_record_with_table_for_basis::<true>(record, &v4_table)
                    .unwrap();
                assert_eq!(v4.cell(ordinal), Some(cell));
                assert!(
                    v4.record_for_ordinal_in_cell(ordinal, (cell + 1) % v4.cells())
                        .is_none()
                );
                for (name, actual, expected) in [
                    ("estimate", v4_estimate.estimate, v3_estimate.estimate),
                    (
                        "lower bound",
                        v4_estimate.lower_bound,
                        v3_estimate.lower_bound,
                    ),
                    (
                        "upper bound",
                        v4_estimate.upper_bound,
                        v3_estimate.upper_bound,
                    ),
                ] {
                    assert!(
                        (actual - expected).abs() <= 1e-4 * expected.abs().max(1.0),
                        "cell {cell} ordinal {ordinal}: v4 {name} {actual} disagrees with v3 {expected}"
                    );
                }
                assert_eq!(navigation_estimate, v4_estimate.estimate);
                assert_eq!(direct_navigation, v4_estimate.estimate);
                assert_eq!(direct_estimate.estimate, v4_estimate.estimate);
                assert_eq!(direct_estimate.lower_bound, v4_estimate.lower_bound);
                assert_eq!(direct_estimate.upper_bound, v4_estimate.upper_bound);
                assert_eq!(posting_estimate.estimate, v4_estimate.estimate);
                assert!(
                    v4_estimate.lower_bound <= v4_estimate.estimate
                        && v4_estimate.estimate <= v4_estimate.upper_bound,
                    "cell {cell}: invalid estimate bounds"
                );
            }
        }
        assert!(
            v4.distance_estimate_with_table(
                vectors.len(),
                &v4.prepare_global_cell_distance_table(
                    &rotate_for_cascade(&vectors[0]),
                    &rotate_for_cascade(&centroids[0]),
                    &v4.prepare_global_query_table(&rotate_for_cascade(&vectors[0]))
                        .unwrap(),
                )
                .unwrap(),
            )
            .is_none()
        );
        drop(v3);
        drop(v4);

        let mut bytes = std::fs::read(&v4_path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&v4_path, bytes).unwrap();
        let error = RabitqArtifact::open(&v4_path, &ivf).unwrap_err();
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
    }

    #[test]
    fn production_layout_matches_metric_query_order() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let l2_path = temp.path().join("l2.rabitq.gdx");
        let cosine_path = temp.path().join("cosine.rabitq.gdx");
        let dot_path = temp.path().join("dot.rabitq.gdx");
        let vectors = (0..64).map(|i| lcg_vector(i, 16)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 16, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();

        write_rabitq_artifact_for_metric(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &l2_path,
        )
        .unwrap();
        write_rabitq_artifact_for_metric(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::Cosine,
            &cosine_path,
        )
        .unwrap();
        write_rabitq_artifact_for_metric(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::Dot,
            &dot_path,
        )
        .unwrap();

        let l2_bytes = std::fs::read(&l2_path).unwrap();
        let cosine_bytes = std::fs::read(&cosine_path).unwrap();
        let dot_bytes = std::fs::read(&dot_path).unwrap();
        assert_eq!(&l2_bytes[..8], RABITQ_V2_MAGIC);
        assert_eq!(u32::from_le_bytes(l2_bytes[8..12].try_into().unwrap()), 2);
        assert_eq!(&cosine_bytes[..8], RABITQ_MAGIC);
        assert_eq!(
            u32::from_le_bytes(cosine_bytes[8..12].try_into().unwrap()),
            4
        );
        assert_eq!(&dot_bytes[..8], RABITQ_MAGIC);
        assert_eq!(u32::from_le_bytes(dot_bytes[8..12].try_into().unwrap()), 4);
        assert!(
            RabitqArtifact::open(&l2_path, &ivf)
                .unwrap()
                .ordinal_to_record
                .is_none()
        );
        assert!(
            RabitqArtifact::open(&cosine_path, &ivf)
                .unwrap()
                .ordinal_to_record
                .is_some()
        );
        assert!(
            RabitqArtifact::open(&cosine_path, &ivf)
                .unwrap()
                .uses_global_query_table()
        );
        assert!(
            RabitqArtifact::open(&dot_path, &ivf)
                .unwrap()
                .uses_global_query_table()
        );
    }

    #[test]
    fn multi_bit_estimator_is_nearly_unbiased_and_bound_has_reference_coverage() {
        let dim = 128;
        let samples = 4096;
        let mut signed_error = 0.0f64;
        let mut exact_total = 0.0f64;
        let mut covered = 0usize;
        for seed in 0..samples {
            let residual = lcg_vector(seed as u64, dim);
            let query = lcg_vector(seed as u64 + 50_000, dim);
            let mut codes = vec![0u8; dim.div_ceil(4)];
            let factors = quantize_residual_2bit(&residual, &mut codes);
            let dot = query
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    let code = (codes[index / 4] >> ((index % 4) * 2)) & 0b11;
                    value * (code as f32 - 1.5)
                })
                .sum::<f32>();
            let query_norm = query.iter().map(|value| value * value).sum::<f32>();
            let estimate = factors.f_add + query_norm + factors.f_rescale * dot;
            let lower_bound = (estimate - factors.f_error * query_norm.sqrt()).max(0.0);
            let exact = squared_l2(&residual, &query);
            signed_error += f64::from(estimate - exact);
            exact_total += f64::from(exact);
            let upper_bound = (estimate + factors.f_error * query_norm.sqrt()).max(0.0);
            covered += usize::from(lower_bound <= exact && exact <= upper_bound);
        }
        let relative_bias = signed_error.abs() / exact_total;
        let coverage = covered as f32 / samples as f32;
        assert!(
            relative_bias <= 0.01,
            "relative estimator bias {relative_bias:.6} exceeds 1%"
        );
        assert!(
            coverage >= 0.93,
            "lower-bound coverage {coverage:.4} is below the reference confidence floor"
        );
    }

    #[test]
    fn legacy_v1_artifact_is_rebuilt_as_v4_for_cosine() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let rabitq_path = temp.path().join(RABITQ_FILE);
        let vectors = (0..64).map(|i| lcg_vector(i, 16)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 16, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_legacy_v1_fixture(&ivf, &rabitq_path);

        assert!(RabitqArtifact::is_legacy_v1(&rabitq_path).unwrap());
        migrate_legacy_v1_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::Cosine,
            &rabitq_path,
        )
        .unwrap();
        assert!(!RabitqArtifact::is_legacy_v1(&rabitq_path).unwrap());
        let migrated = RabitqArtifact::open(&rabitq_path, &ivf).unwrap();
        assert_eq!(migrated.len(), vectors.len());
        assert!(migrated.uses_global_query_table());
        let migrated_bytes = std::fs::read(&rabitq_path).unwrap();
        assert_eq!(&migrated_bytes[..8], RABITQ_MAGIC);
        assert_eq!(
            u32::from_le_bytes(migrated_bytes[8..12].try_into().unwrap()),
            4
        );
        assert!(!migration_path(&rabitq_path, "v1-backup").exists());
        assert!(!migration_path(&rabitq_path, "current-migrating").exists());
    }

    #[test]
    fn legacy_v2_artifact_remains_readable_without_mutation() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let rabitq_path = temp.path().join(RABITQ_FILE);
        let vectors = (0..64).map(|i| lcg_vector(i, 16)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 16, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_rabitq_artifact_with_layout(
            vectors.as_slice(),
            &ivf,
            RabitqLayout::CellMajorResidual,
            &rabitq_path,
        )
        .unwrap();
        rewrite_current_as_v2(&ivf, &rabitq_path);

        let legacy = RabitqArtifact::open(&rabitq_path, &ivf).unwrap();
        let centroid = &ivf.centroids()[0];
        let posting = ivf.posting_range(0).unwrap().next().unwrap();
        let ordinal = ivf.posting_ordinal(posting).unwrap() as usize;
        let residual = vectors[ordinal]
            .iter()
            .zip(centroid)
            .map(|(value, center)| value - center)
            .collect::<Vec<_>>();
        let estimate = legacy.estimate_squared_l2(ordinal, &residual).unwrap();
        assert!(estimate.is_finite());
        let rotated = rotate_for_cascade(&residual);
        let table = legacy.prepare_distance_table(&rotated).unwrap();
        let by_ordinal = legacy
            .distance_estimate_with_table(ordinal, &table)
            .unwrap();
        let by_posting = legacy
            .distance_estimate_for_posting_with_table(posting, ordinal, &table)
            .unwrap();
        assert_eq!(by_posting.estimate, by_ordinal.estimate);
        let before = std::fs::read(&rabitq_path).unwrap();
        drop(legacy);
        migrate_legacy_v1_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &rabitq_path,
        )
        .unwrap();
        assert_eq!(std::fs::read(&rabitq_path).unwrap(), before);
        assert_eq!(&before[..8], RABITQ_V2_MAGIC);
        assert_eq!(u32::from_le_bytes(before[8..12].try_into().unwrap()), 2);
    }

    #[test]
    fn legacy_v3_artifact_remains_readable_without_mutation() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let rabitq_path = temp.path().join(RABITQ_FILE);
        let vectors = (0..64).map(|i| lcg_vector(i, 16)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 16, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_rabitq_artifact_with_layout(
            vectors.as_slice(),
            &ivf,
            RabitqLayout::CellMajorResidual,
            &rabitq_path,
        )
        .unwrap();

        let before = std::fs::read(&rabitq_path).unwrap();
        let legacy = RabitqArtifact::open(&rabitq_path, &ivf).unwrap();
        assert!(!legacy.uses_global_query_table());
        assert!(legacy.ordinal_to_record.is_some());
        drop(legacy);
        migrate_legacy_v1_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::Cosine,
            &rabitq_path,
        )
        .unwrap();
        assert_eq!(std::fs::read(&rabitq_path).unwrap(), before);
        assert_eq!(&before[..8], RABITQ_V3_MAGIC);
        assert_eq!(u32::from_le_bytes(before[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn v4_rejects_a_record_in_the_wrong_cell_even_with_a_valid_crc() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let rabitq_path = temp.path().join(RABITQ_FILE);
        let vectors = (0..64).map(|i| lcg_vector(i, 16)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 16, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_rabitq_artifact(vectors.as_slice(), &ivf, &rabitq_path).unwrap();

        let mut bytes = std::fs::read(&rabitq_path).unwrap();
        let first_cell = u32::from_le_bytes(
            bytes[RABITQ_HEADER_BYTES..RABITQ_HEADER_BYTES + 4]
                .try_into()
                .unwrap(),
        );
        bytes[RABITQ_HEADER_BYTES..RABITQ_HEADER_BYTES + 4]
            .copy_from_slice(&((first_cell + 1) % ivf.cells() as u32).to_le_bytes());
        let crc = crc32fast::hash(&bytes[RABITQ_HEADER_BYTES..]);
        bytes[52..56].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&rabitq_path, bytes).unwrap();

        let error = RabitqArtifact::open(&rabitq_path, &ivf).unwrap_err();
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
    }

    fn rewrite_current_as_v2(ivf: &IvfArtifact, path: &Path) {
        let current = std::fs::read(path).unwrap();
        let record_bytes = u32::from_le_bytes(current[48..52].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; ivf.len() * record_bytes];
        for posting in 0..ivf.len() {
            let ordinal = ivf.posting_ordinal(posting).unwrap() as usize;
            let source = RABITQ_HEADER_BYTES + posting * record_bytes;
            let target = ordinal * record_bytes;
            payload[target..target + record_bytes]
                .copy_from_slice(&current[source..source + record_bytes]);
        }
        let mut legacy = current[..RABITQ_HEADER_BYTES].to_vec();
        legacy[..8].copy_from_slice(RABITQ_V2_MAGIC);
        legacy[8..12].copy_from_slice(&2u32.to_le_bytes());
        legacy[52..56].copy_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        legacy.extend_from_slice(&payload);
        std::fs::write(path, legacy).unwrap();
    }

    fn write_legacy_v1_fixture(ivf: &IvfArtifact, path: &Path) {
        let padded_dim = next_pow2(ivf.vector_dim());
        let code_bytes = padded_dim.div_ceil(4);
        let record_bytes = code_bytes + 8;
        let mut payload = vec![0u8; ivf.len() * record_bytes];
        for cell in 0..ivf.cells() {
            for posting in ivf.posting_range(cell).unwrap() {
                let ordinal = ivf.posting_ordinal(posting).unwrap() as usize;
                let start = ordinal * record_bytes;
                payload[start..start + 4].copy_from_slice(&(cell as u32).to_le_bytes());
            }
        }
        let mut file = File::create(path).unwrap();
        file.write_all(RABITQ_V1_MAGIC).unwrap();
        file.write_all(&1u32.to_le_bytes()).unwrap();
        file.write_all(&(ivf.len() as u64).to_le_bytes()).unwrap();
        file.write_all(&(ivf.vector_dim() as u64).to_le_bytes())
            .unwrap();
        file.write_all(&(padded_dim as u64).to_le_bytes()).unwrap();
        file.write_all(&(ivf.cells() as u64).to_le_bytes()).unwrap();
        file.write_all(&(code_bytes as u32).to_le_bytes()).unwrap();
        file.write_all(&(record_bytes as u32).to_le_bytes())
            .unwrap();
        file.write_all(&crc32fast::hash(&payload).to_le_bytes())
            .unwrap();
        file.write_all(&payload).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn encode_sign_bits_packs_correctly() {
        let bits = encode_sign_bits(&[1.0, -1.0, 1.0, -1.0], 1);
        // pos, neg, pos, neg → 0b0101 = 5
        assert_eq!(bits, vec![0b0101]);
    }

    #[test]
    fn build_trait_object_with_correct_kind() {
        let points = vec![
            p("a", vec![1.0, 0.0, 0.0, 0.0]),
            p("b", vec![0.0, 1.0, 0.0, 0.0]),
        ];
        let idx: Box<dyn IndexBackend> = build(
            &points,
            &IndexParams {
                vector_dim: 4,
                ..Default::default()
            },
        );
        assert_eq!(idx.kind(), IndexKind::Rabitq);
        assert_eq!(idx.indexed_points(), 2);
        assert!(idx.contains("a"));
        assert!(!idx.contains("missing"));
    }

    #[test]
    fn searches_self_returns_self() {
        let points: Vec<Point> = (0..16)
            .map(|i| {
                let mut v = vec![0.0; 16];
                v[i] = 1.0;
                p(&format!("p{i}"), v)
            })
            .collect();
        let idx = RabitqBackend::build(&points, 16);
        for i in 0..16 {
            let mut q = vec![0.0; 16];
            q[i] = 1.0;
            let hits = idx.candidate_ids_with_ef(&q, 1, None);
            assert_eq!(hits, vec![format!("p{i}")]);
        }
    }

    #[test]
    fn recall_at_10_above_0_95_on_random_500() {
        // Synthetic recall_golden: 500 random 64-dim vectors, query each one
        // against itself. Cascade must return self in the top-10 every time
        // (≥ 0.95 recall). This is a lower bar than the sift-128 target but
        // proves the cascade wiring is sound.
        let dim = 64;
        let n = 500;
        let points: Vec<Point> = (0..n)
            .map(|i| p(&format!("p{i}"), lcg_vector(i as u64, dim)))
            .collect();
        let idx = RabitqBackend::build(&points, dim);
        let mut hits = 0usize;
        for i in 0..n {
            let q = lcg_vector(i as u64, dim);
            let result = idx.candidate_ids_with_ef(&q, 10, None);
            if result.iter().any(|id| id == &format!("p{i}")) {
                hits += 1;
            }
        }
        let recall = hits as f32 / n as f32;
        assert!(
            recall >= 0.95,
            "recall@10 = {recall:.4} below 0.95 (hits={hits}/{n})"
        );
    }

    #[test]
    fn rotated_codes_beat_plain_sign_on_correlated_data() {
        // B1.2 exit criterion: the rotation must not *lose* to plain sign-bit
        // codes at an equal candidate budget, and on correlated data (where
        // dimensions share a common signal, defeating the 1-bit estimator's
        // independence assumption) it should measurably win. We compute both
        // recalls inline over the same corpus so the only variable is the
        // rotation.
        use crate::index::rotate_for_cascade;
        use chirondb_types::distance::hamming_popcount;

        let dim = 64;
        let n = 800;
        let over_sample = 8;
        // Correlated corpus: every dim = shared base + small per-dim noise, so
        // sign bits are highly correlated across dimensions.
        let corpus: Vec<Vec<f32>> = (0..n)
            .map(|i| {
                let base = lcg_vector(i as u64, 1)[0];
                let noise = lcg_vector(i as u64 + 999_983, dim);
                (0..dim).map(|d| base + 0.3 * noise[d]).collect()
            })
            .collect();

        // Recall of a sign-bit cascade with `rotate` on/off, self-query.
        let recall_with = |rotate: bool| -> f32 {
            let wc = crate::index::sign_word_count(crate::index::next_pow2(dim));
            let encode = |v: &[f32]| {
                if rotate {
                    encode_sign_bits(&rotate_for_cascade(v), wc)
                } else {
                    encode_sign_bits(v, wc)
                }
            };
            let codes: Vec<Vec<u64>> = corpus.iter().map(|v| encode(v)).collect();
            let mut hits = 0usize;
            for (qi, q) in corpus.iter().enumerate() {
                let qb = encode(q);
                let mut scored: Vec<(u32, usize)> = codes
                    .iter()
                    .enumerate()
                    .map(|(idx, c)| (hamming_popcount(&qb, c), idx))
                    .collect();
                let pool = (10 * over_sample).min(n);
                scored.select_nth_unstable_by_key(pool - 1, |x| x.0);
                let mut filtered: Vec<usize> =
                    scored.into_iter().take(pool).map(|(_, i)| i).collect();
                filtered.sort_by(|&a, &b| {
                    squared_l2(q, &corpus[a]).total_cmp(&squared_l2(q, &corpus[b]))
                });
                filtered.truncate(10);
                if filtered.contains(&qi) {
                    hits += 1;
                }
            }
            hits as f32 / n as f32
        };

        let rotated = recall_with(true);
        let plain = recall_with(false);
        assert!(
            rotated >= plain,
            "rotated recall {rotated:.4} should be >= plain-sign recall {plain:.4}"
        );
    }

    #[test]
    fn ef_search_for_recall_target_is_monotonic() {
        let backend = RabitqBackend::build(&[p("x", vec![1.0; 16])], 16);
        let high = backend.ef_search_for_recall_target(10, 0.99);
        let mid = backend.ef_search_for_recall_target(10, 0.95);
        let low = backend.ef_search_for_recall_target(10, 0.80);
        assert!(high >= mid && mid >= low, "{high} {mid} {low}");
    }

    #[test]
    fn insert_point_appends() {
        let mut backend = RabitqBackend::build(&[p("a", vec![1.0; 16])], 16);
        backend.insert_point(&p("b", vec![-1.0; 16]), 16).unwrap();
        assert_eq!(backend.indexed_points(), 2);
        assert!(backend.contains("b"));
    }

    #[test]
    fn dim_mismatch_rejected() {
        let mut backend = RabitqBackend::build(&[p("a", vec![1.0; 16])], 16);
        let err = backend
            .insert_point(&p("b", vec![-1.0; 16]), 32)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::GaussError::DimensionMismatch { .. }
        ));
    }
}
