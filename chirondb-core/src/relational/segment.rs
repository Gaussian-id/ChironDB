//! Immutable sorted storage runs for native relational rows and indexes.
//!
//! The segment owns integrity and bounded point-lookup metadata inside the
//! existing application-level encryption envelope. Publication remains the
//! manifest's responsibility, so an interrupted writer can leave only an
//! unreachable immutable file.

mod admission;
mod generation;
mod record;
mod streaming;
use admission::AccountedMetadata;
pub(in crate::relational) use admission::EncodedBuffer;
pub(in crate::relational) use record::{OWNER_BYTES as RECORD_OWNER_BYTES, RecordBytes};

pub(super) use generation::Generation;
pub(super) use streaming::SegmentCursor;

use std::{fs, path::Path, sync::Arc};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};

use crate::{
    GaussError, Result,
    encryption::{FileType, PersistentFile},
};

const MAGIC: &[u8; 8] = b"CHRNRSG1";
const VERSION: u32 = 2;
const HEADER_LEN: usize = 56;
const RECORD_HEADER_LEN: usize = 12;
const SPARSE_STRIDE: usize = 128;
const BLOOM_HASHES: u8 = 3;
const MIN_BLOOM_BYTES: usize = 64;
const MAX_BLOOM_BYTES: usize = 8 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SegmentKind {
    Row,
    Index,
}

impl SegmentKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Row => 1,
            Self::Index => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Row),
            2 => Ok(Self::Index),
            _ => Err(corruption(format!("unknown relational segment kind {tag}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SegmentRecord {
    pub key: RecordBytes,
    pub value: RecordBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SparseEntry {
    pub key: Vec<u8>,
    /// Plaintext byte offset relative to the beginning of the record body.
    pub offset: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SegmentMetadata {
    pub kind: SegmentKind,
    pub sequence: u64,
    pub record_count: u64,
    pub min_key: Option<Vec<u8>>,
    pub max_key: Option<Vec<u8>>,
    pub bloom_hashes: u8,
    pub bloom: Vec<u8>,
    pub sparse_stride: u32,
    pub sparse: Vec<SparseEntry>,
}

impl SegmentMetadata {
    pub fn may_contain(&self, key: &[u8]) -> bool {
        if self.record_count == 0 || self.bloom.is_empty() {
            return false;
        }
        let bits = self.bloom.len() * 8;
        (0..self.bloom_hashes).all(|seed| {
            let bit = bloom_hash(key, seed) % bits;
            self.bloom[bit / 8] & (1 << (bit % 8)) != 0
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(super) struct ImmutableSegment {
    pub metadata: SegmentMetadata,
    pub records: Vec<SegmentRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(super) struct SegmentLookup {
    pub value: Vec<u8>,
    pub records_examined: usize,
    pub plaintext_bytes_read: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(super) struct SegmentScan {
    pub records: Vec<SegmentRecord>,
    pub records_examined: usize,
    pub plaintext_bytes_read: usize,
}

#[derive(Debug)]
struct SegmentLayout {
    file: Arc<PersistentFile>,
    metadata: AccountedMetadata,
    body_start: usize,
    body_end: usize,
    body_crc: u32,
    // Last field: close the mapping before deleting a private run directory.
    // Both full and prefix cursors share this layout and keep it alive.
    _scratch: Option<tempfile::TempDir>,
    _generation: Option<Arc<Generation>>,
    _scratch_parent: Option<Arc<tempfile::TempDir>>,
}

#[derive(Debug)]
pub(super) struct SegmentReader {
    layout: Arc<SegmentLayout>,
}

impl SegmentReader {
    pub(super) fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            layout: Arc::new(open_segment(path)?),
        })
    }

    pub(super) fn open_scratch(path: &Path, directory: tempfile::TempDir) -> Result<Self> {
        let mut layout = open_segment(path)?;
        layout._scratch = Some(directory);
        Ok(Self {
            layout: Arc::new(layout),
        })
    }

    pub(super) fn open_generation(path: &Path, generation: Arc<Generation>) -> Result<Self> {
        let mut layout = open_segment(path)?;
        layout._generation = Some(generation);
        Ok(Self {
            layout: Arc::new(layout),
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.layout.file.path()
    }

    /// Only fresh readers are adopted; full/prefix cursors subsequently share
    /// this owner so a dropped map cannot recursively remove a live run.
    pub(super) fn with_scratch_parent(mut self, parent: Arc<tempfile::TempDir>) -> Self {
        Arc::get_mut(&mut self.layout)
            .expect("fresh scratch reader")
            ._scratch_parent = Some(parent);
        self
    }
    pub(super) fn metadata(&self) -> &SegmentMetadata {
        &self.layout.metadata
    }
    #[cfg(test)]
    pub(super) fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<SegmentScan> {
        scan_layout_prefix(&self.layout, prefix, limit)
    }

    pub(super) fn prefix_cursor(&self, prefix: &[u8]) -> Result<SegmentPrefixCursor> {
        SegmentPrefixCursor::new(Arc::clone(&self.layout), prefix)
    }

    pub(super) fn prefix_cursor_from(
        &self,
        prefix: &[u8],
        lower_bound: &[u8],
    ) -> Result<SegmentPrefixCursor> {
        SegmentPrefixCursor::new_from(Arc::clone(&self.layout), prefix, lower_bound)
    }

    pub(super) fn range_cursor_from(&self, lower_bound: &[u8]) -> Result<SegmentPrefixCursor> {
        SegmentPrefixCursor::new_range_from(Arc::clone(&self.layout), lower_bound)
    }

    pub(super) fn cursor(&self) -> SegmentCursor {
        SegmentCursor::from_layout(Arc::clone(&self.layout))
    }

    #[cfg(test)]
    pub(super) fn scratch_directory(&self) -> Option<&Path> {
        self.layout
            ._scratch
            .as_ref()
            .map(|directory| directory.path())
    }

    pub(super) fn read_record(&self, offset: usize, length: usize) -> Result<SegmentRecord> {
        let (_, record, _) = read_frame(
            &self.layout,
            offset,
            Some(length),
            crate::resource_profile::current().sql_request_working_set_bytes as usize,
        )?;
        Ok(record)
    }
}

/// One framed record at a time, retaining the same immutable mapping as its
/// snapshot. Sparse routing never allocates an entire 128-record block.
pub(super) struct SegmentPrefixCursor {
    layout: Arc<SegmentLayout>,
    prefix: RecordBytes,
    lower_bound: RecordBytes,
    offset: usize,
    finished: bool,
}

impl SegmentPrefixCursor {
    fn new(layout: Arc<SegmentLayout>, prefix: &[u8]) -> Result<Self> {
        Self::new_from(layout, prefix, prefix)
    }

    fn new_from(layout: Arc<SegmentLayout>, prefix: &[u8], lower_bound: &[u8]) -> Result<Self> {
        if prefix.is_empty() {
            return Err(invalid("relational segment prefix must not be empty"));
        }
        Self::new_inner(layout, prefix, lower_bound)
    }

    fn new_range_from(layout: Arc<SegmentLayout>, lower_bound: &[u8]) -> Result<Self> {
        if lower_bound.is_empty() {
            return Err(invalid("relational segment range bound must not be empty"));
        }
        Self::new_inner(layout, b"", lower_bound)
    }

    fn new_inner(layout: Arc<SegmentLayout>, prefix: &[u8], lower_bound: &[u8]) -> Result<Self> {
        if !lower_bound.starts_with(prefix) {
            return Err(invalid("relational segment lower bound is outside prefix"));
        }
        // Exact-key probes often touch several disjoint immutable runs. Do
        // not decode a sparse block when this run cannot contain the prefix.
        let outside = match layout.metadata.min_key.as_deref() {
            None => true,
            Some(min_key) => {
                let max_key = layout
                    .metadata
                    .max_key
                    .as_deref()
                    .ok_or_else(|| corruption("non-empty segment is missing maximum key"))?;
                max_key < lower_bound
                    || (!prefix.is_empty() && min_key > prefix && !min_key.starts_with(prefix))
            }
        };
        if outside {
            return Ok(Self {
                offset: layout.body_end,
                layout,
                prefix: RecordBytes::copy(prefix)?,
                lower_bound: RecordBytes::copy(lower_bound)?,
                finished: true,
            });
        }
        let position = layout
            .metadata
            .sparse
            .partition_point(|entry| entry.key.as_slice() < lower_bound)
            .saturating_sub(1);
        let relative = layout
            .metadata
            .sparse
            .get(position)
            .map_or(0, |entry| entry.offset);
        let offset = usize::try_from(relative)
            .ok()
            .and_then(|offset| layout.body_start.checked_add(offset))
            .filter(|offset| *offset <= layout.body_end)
            .ok_or_else(|| corruption("prefix cursor offset overflow"))?;
        Ok(Self {
            layout,
            prefix: RecordBytes::copy(prefix)?,
            lower_bound: RecordBytes::copy(lower_bound)?,
            offset,
            finished: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<SegmentRecord>> {
        while self.offset < self.layout.body_end {
            super::check_sql_cancelled()?;
            let start = self.offset;
            let (_, record, end) = read_frame(
                &self.layout,
                start,
                None,
                crate::resource_profile::current().sql_request_working_set_bytes as usize,
            )?;
            self.offset = end;
            metrics::counter!("chirondb_relational_segment_lookup_records_total").increment(1);
            metrics::counter!("chirondb_relational_segment_lookup_plaintext_bytes_total")
                .increment((end - start) as u64);
            if record.key.as_slice() < self.lower_bound.as_slice() {
                continue;
            }
            return Ok(record.key.starts_with(&self.prefix).then_some(record));
        }
        Ok(None)
    }
}

impl Iterator for SegmentPrefixCursor {
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

pub(super) fn write_segment(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    records: &[SegmentRecord],
) -> Result<AccountedMetadata> {
    write_segment_iter(path, kind, sequence, records.iter(), records.len())
}

pub(super) fn write_segment_iter<'a>(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    records: impl Iterator<Item = &'a SegmentRecord> + Clone,
    count: usize,
) -> Result<AccountedMetadata> {
    streaming::write_records(path, kind, sequence, records, count)
}

pub(super) fn write_segment_stream<I: Iterator<Item = Result<SegmentRecord>>>(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    source: impl Fn() -> Result<I>,
) -> Result<AccountedMetadata> {
    streaming::write_stream(path, kind, sequence, source)
}

#[cfg(test)]
pub(super) fn read_segment(path: &Path) -> Result<ImmutableSegment> {
    let cursor = SegmentCursor::open(path)?;
    let metadata = cursor.metadata().clone();
    let records = cursor.collect::<Result<Vec<_>>>()?;
    Ok(ImmutableSegment { metadata, records })
}

/// Performs a bounded exact-key lookup using min/max, Bloom, and the sparse
/// directory. It authenticates/decrypts only the selected plaintext range and
/// verifies every examined record independently; full scans additionally check
/// the whole-body CRC.
#[cfg(test)]
pub(super) fn lookup_segment(path: &Path, key: &[u8]) -> Result<Option<SegmentLookup>> {
    let layout = open_segment(path)?;
    let Some(min_key) = layout.metadata.min_key.as_deref() else {
        return Ok(None);
    };
    let max_key = layout
        .metadata
        .max_key
        .as_deref()
        .ok_or_else(|| corruption("non-empty segment is missing maximum key"))?;
    if key < min_key || key > max_key || !layout.metadata.may_contain(key) {
        return Ok(None);
    }
    let position = layout
        .metadata
        .sparse
        .partition_point(|entry| entry.key.as_slice() <= key)
        .saturating_sub(1);
    let entry = layout
        .metadata
        .sparse
        .get(position)
        .ok_or_else(|| corruption("sparse directory cannot route an in-range key"))?;
    let start =
        usize::try_from(entry.offset).map_err(|_| corruption("sparse offset exceeds usize"))?;
    let body_len = layout.body_end - layout.body_start;
    let end = layout
        .metadata
        .sparse
        .get(position + 1)
        .map(|next| usize::try_from(next.offset))
        .transpose()
        .map_err(|_| corruption("sparse offset exceeds usize"))?
        .unwrap_or(body_len);
    let bytes = layout.file.read_range_admitted(
        layout
            .body_start
            .checked_add(start)
            .ok_or_else(|| corruption("lookup start overflow"))?
            ..layout
                .body_start
                .checked_add(end)
                .ok_or_else(|| corruption("lookup end overflow"))?,
    )?;
    let mut cursor = 0_usize;
    let mut examined = 0_usize;
    while cursor < bytes.len() {
        let (record, next) = decode_record(&bytes, cursor)?;
        examined += 1;
        match record.key.as_slice().cmp(key) {
            std::cmp::Ordering::Less => cursor = next,
            std::cmp::Ordering::Equal => {
                return Ok(Some(SegmentLookup {
                    value: record.value.to_vec(),
                    records_examined: examined,
                    plaintext_bytes_read: bytes.len(),
                }));
            }
            std::cmp::Ordering::Greater => return Ok(None),
        }
    }
    Ok(None)
}

/// Scans one contiguous key prefix from sparse-directory routed ranges.
/// Callers must provide a finite limit so a low-selectivity index cannot turn
/// an equality lookup into an unaccounted full-segment materialization.
#[cfg(test)]
pub(super) fn scan_segment_prefix(path: &Path, prefix: &[u8], limit: usize) -> Result<SegmentScan> {
    SegmentReader::open(path)?.scan_prefix(prefix, limit)
}

#[cfg(test)]
fn scan_layout_prefix(layout: &SegmentLayout, prefix: &[u8], limit: usize) -> Result<SegmentScan> {
    if prefix.is_empty() || limit == 0 {
        return Err(invalid(
            "relational segment prefix scans require a non-empty prefix and positive limit",
        ));
    }
    let Some(min_key) = layout.metadata.min_key.as_deref() else {
        return Ok(SegmentScan {
            records: Vec::new(),
            records_examined: 0,
            plaintext_bytes_read: 0,
        });
    };
    let max_key = layout
        .metadata
        .max_key
        .as_deref()
        .ok_or_else(|| corruption("non-empty segment is missing maximum key"))?;
    if max_key < prefix || (min_key > prefix && !min_key.starts_with(prefix)) {
        return Ok(SegmentScan {
            records: Vec::new(),
            records_examined: 0,
            plaintext_bytes_read: 0,
        });
    }
    let mut sparse_position = layout
        .metadata
        .sparse
        .partition_point(|entry| entry.key.as_slice() < prefix)
        .saturating_sub(1);
    let body_len = layout.body_end - layout.body_start;
    let mut scan = SegmentScan {
        records: Vec::new(),
        records_examined: 0,
        plaintext_bytes_read: 0,
    };
    while sparse_position < layout.metadata.sparse.len() {
        let start = usize::try_from(layout.metadata.sparse[sparse_position].offset)
            .map_err(|_| corruption("sparse offset exceeds usize"))?;
        let end = layout
            .metadata
            .sparse
            .get(sparse_position + 1)
            .map(|next| usize::try_from(next.offset))
            .transpose()
            .map_err(|_| corruption("sparse offset exceeds usize"))?
            .unwrap_or(body_len);
        let bytes = layout.file.read_range_admitted(
            layout
                .body_start
                .checked_add(start)
                .ok_or_else(|| corruption("prefix scan start overflow"))?
                ..layout
                    .body_start
                    .checked_add(end)
                    .ok_or_else(|| corruption("prefix scan end overflow"))?,
        )?;
        scan.plaintext_bytes_read = scan
            .plaintext_bytes_read
            .checked_add(bytes.len())
            .ok_or_else(|| {
                GaussError::ResourceExhausted("prefix scan byte count overflow".into())
            })?;
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            let (record, next) = decode_record(&bytes, cursor)?;
            scan.records_examined = scan.records_examined.checked_add(1).ok_or_else(|| {
                GaussError::ResourceExhausted("prefix scan record count overflow".into())
            })?;
            if record.key.as_slice() < prefix {
                cursor = next;
                continue;
            }
            if !record.key.starts_with(prefix) {
                return Ok(scan);
            }
            scan.records.push(record);
            if scan.records.len() == limit {
                return Ok(scan);
            }
            cursor = next;
        }
        sparse_position += 1;
    }
    Ok(scan)
}

pub(super) fn remove_segment_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn open_segment(path: &Path) -> Result<SegmentLayout> {
    let file = Arc::new(PersistentFile::open(path)?);
    if file.len() < HEADER_LEN {
        return Err(corruption("relational segment is shorter than its header"));
    }
    let header = file.read_range_admitted(0..HEADER_LEN)?;
    if &header[..8] != MAGIC {
        return Err(corruption("relational segment magic is unsupported"));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().expect("segment version"));
    if version != VERSION {
        return Err(corruption(format!(
            "unsupported relational segment version {version}; expected {VERSION}"
        )));
    }
    let kind = SegmentKind::from_tag(header[12])?;
    if header[13..16] != [0_u8; 3] {
        return Err(corruption("relational segment reserved bytes are non-zero"));
    }
    let sequence = u64::from_le_bytes(header[16..24].try_into().expect("segment sequence"));
    let record_count = u64::from_le_bytes(header[24..32].try_into().expect("record count"));
    let metadata_len = bounded_length(&header[32..40], MAX_METADATA_BYTES, "metadata")?;
    let body_len = bounded_length(&header[40..48], usize::MAX - HEADER_LEN, "body")?;
    let metadata_crc = u32::from_le_bytes(header[48..52].try_into().expect("metadata CRC"));
    let body_crc = u32::from_le_bytes(header[52..56].try_into().expect("body CRC"));
    let body_start = HEADER_LEN
        .checked_add(metadata_len)
        .ok_or_else(|| corruption("relational segment metadata offset overflow"))?;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or_else(|| corruption("relational segment body offset overflow"))?;
    if body_end != file.len() {
        return Err(corruption("relational segment length mismatch"));
    }
    let metadata = admission::read_metadata(&file, HEADER_LEN..body_start, metadata_crc)?;
    validate_metadata(&metadata, kind, sequence, record_count, body_len)?;
    Ok(SegmentLayout {
        file,
        metadata,
        body_start,
        body_end,
        body_crc,
        _scratch: None,
        _generation: None,
        _scratch_parent: None,
    })
}

fn validate_metadata(
    metadata: &SegmentMetadata,
    kind: SegmentKind,
    sequence: u64,
    record_count: u64,
    body_len: usize,
) -> Result<()> {
    let expected_sparse = usize::try_from(record_count)
        .map_err(|_| corruption("record count exceeds usize"))?
        .div_ceil(SPARSE_STRIDE);
    let empty_shape = record_count == 0
        && metadata.min_key.is_none()
        && metadata.max_key.is_none()
        && metadata.sparse.is_empty()
        && body_len == 0;
    let non_empty_shape = record_count > 0
        && metadata.min_key.is_some()
        && metadata.max_key.is_some()
        && metadata.sparse.len() == expected_sparse
        && metadata
            .sparse
            .first()
            .is_some_and(|entry| entry.offset == 0)
        && metadata
            .sparse
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key && pair[0].offset < pair[1].offset)
        && metadata
            .sparse
            .iter()
            .all(|entry| usize::try_from(entry.offset).is_ok_and(|offset| offset < body_len));
    if metadata.kind != kind
        || metadata.sequence != sequence
        || metadata.record_count != record_count
        || metadata.bloom_hashes != BLOOM_HASHES
        || metadata.bloom.is_empty()
        || metadata.sparse_stride != SPARSE_STRIDE as u32
        || (!empty_shape && !non_empty_shape)
    {
        return Err(corruption("relational segment metadata/header mismatch"));
    }
    Ok(())
}

/// Reserve each payload before copying/decrypting its range. Returned byte
/// owners keep their leases after the cursor advances, closes, or is moved.
fn read_frame(
    layout: &SegmentLayout,
    offset: usize,
    expected_length: Option<usize>,
    record_limit: usize,
) -> Result<([u8; RECORD_HEADER_LEN], SegmentRecord, usize)> {
    super::check_sql_cancelled()?;
    let header_end = offset
        .checked_add(RECORD_HEADER_LEN)
        .filter(|end| offset >= layout.body_start && *end <= layout.body_end)
        .ok_or_else(|| corruption("row locator points outside its source body"))?;
    let header: [u8; RECORD_HEADER_LEN] = layout
        .file
        .read_range_admitted(offset..header_end)?
        .as_ref()
        .try_into()
        .expect("bounded record header");
    let key_len = u32::from_le_bytes(header[..4].try_into().expect("key length")) as usize;
    let value_len = u32::from_le_bytes(header[4..8].try_into().expect("value length")) as usize;
    let key_end = header_end
        .checked_add(key_len)
        .ok_or_else(|| corruption("record key offset overflow"))?;
    let end = key_end
        .checked_add(value_len)
        .filter(|end| *end <= layout.body_end)
        .ok_or_else(|| corruption("truncated relational segment record"))?;
    if expected_length.is_some_and(|length| end - offset != length) {
        return Err(corruption("row locator frame length mismatch"));
    }
    if end - offset > record_limit {
        return Err(GaussError::ResourceExhausted(
            "relational segment record exceeds SQL working-set budget".into(),
        ));
    }
    let key = RecordBytes::read(&layout.file, header_end..key_end)?;
    let value = RecordBytes::read(&layout.file, key_end..end)?;
    if record_crc(&key, &value) != u32::from_le_bytes(header[8..].try_into().expect("record CRC")) {
        return Err(corruption("relational segment record CRC mismatch"));
    }
    Ok((header, SegmentRecord { key, value }, end))
}

#[cfg(test)]
fn decode_record(bytes: &[u8], cursor: usize) -> Result<(SegmentRecord, usize)> {
    let header_end = cursor
        .checked_add(RECORD_HEADER_LEN)
        .ok_or_else(|| corruption("record header offset overflow"))?;
    let header = bytes
        .get(cursor..header_end)
        .ok_or_else(|| corruption("truncated relational segment record header"))?;
    let key_len = u32::from_le_bytes(header[..4].try_into().expect("key length")) as usize;
    let value_len = u32::from_le_bytes(header[4..8].try_into().expect("value length")) as usize;
    let expected_crc = u32::from_le_bytes(header[8..12].try_into().expect("record CRC"));
    let key_end = header_end
        .checked_add(key_len)
        .ok_or_else(|| corruption("record key offset overflow"))?;
    let value_end = key_end
        .checked_add(value_len)
        .ok_or_else(|| corruption("record value offset overflow"))?;
    let key = bytes
        .get(header_end..key_end)
        .ok_or_else(|| corruption("truncated relational segment key"))?;
    let value = bytes
        .get(key_end..value_end)
        .ok_or_else(|| corruption("truncated relational segment value"))?;
    if record_crc(key, value) != expected_crc {
        return Err(corruption("relational segment record CRC mismatch"));
    }
    Ok((
        SegmentRecord {
            key: (key.to_vec()).into(),
            value: (value.to_vec()).into(),
        },
        value_end,
    ))
}

fn bounded_length(bytes: &[u8], maximum: usize, label: &str) -> Result<usize> {
    let value = u64::from_le_bytes(bytes.try_into().expect("segment length"));
    let value = usize::try_from(value)
        .map_err(|_| corruption(format!("relational segment {label} length exceeds usize")))?;
    if value > maximum {
        return Err(corruption(format!(
            "relational segment {label} length exceeds its bound"
        )));
    }
    Ok(value)
}

fn bloom_insert(bloom: &mut [u8], key: &[u8]) {
    let bits = bloom.len() * 8;
    for seed in 0..BLOOM_HASHES {
        let bit = bloom_hash(key, seed) % bits;
        bloom[bit / 8] |= 1 << (bit % 8);
    }
}

fn bloom_hash(key: &[u8], seed: u8) -> usize {
    let mut hasher = Hasher::new();
    hasher.update(&[seed]);
    hasher.update(key);
    hasher.finalize() as usize
}

fn record_crc(key: &[u8], value: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(key);
    hasher.update(value);
    hasher.finalize()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn corruption(message: impl Into<String>) -> GaussError {
    GaussError::SegmentCorruption {
        path: "relational-segment".into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn immutable_segment_round_trips_sorted_records_and_metadata() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("rows.rseg");
        let records = vec![
            SegmentRecord {
                key: (b"a".to_vec()).into(),
                value: (b"one".to_vec()).into(),
            },
            SegmentRecord {
                key: (b"b".to_vec()).into(),
                value: (b"two".to_vec()).into(),
            },
        ];
        let written = write_segment(&path, SegmentKind::Row, 7, &records).unwrap();
        assert_eq!(written.min_key.as_deref(), Some(b"a".as_slice()));
        assert_eq!(written.max_key.as_deref(), Some(b"b".as_slice()));
        assert_eq!(written.sparse.len(), 1);
        assert!(written.may_contain(b"a"));
        let recovered = read_segment(&path).unwrap();
        assert_eq!(recovered.metadata, *written);
        assert_eq!(recovered.records, records);
    }

    #[test]
    fn immutable_segment_rejects_unsorted_and_corrupt_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("index.rseg");
        let unsorted = vec![
            SegmentRecord {
                key: (b"b".to_vec()).into(),
                value: (Vec::new()).into(),
            },
            SegmentRecord {
                key: (b"a".to_vec()).into(),
                value: (Vec::new()).into(),
            },
        ];
        assert!(write_segment(&path, SegmentKind::Index, 1, &unsorted).is_err());
        let records = vec![SegmentRecord {
            key: (b"a".to_vec()).into(),
            value: (Vec::new()).into(),
        }];
        write_segment(&path, SegmentKind::Index, 1, &records).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        assert!(read_segment(&path).is_err());
        assert!(lookup_segment(&path, b"a").is_err());
    }

    #[test]
    fn sparse_directory_bounds_exact_point_lookup() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("lookup.rseg");
        let records = (0_u32..400)
            .map(|value| SegmentRecord {
                key: (format!("key-{value:04}").into_bytes()).into(),
                value: (value.to_le_bytes().to_vec()).into(),
            })
            .collect::<Vec<_>>();
        let metadata = write_segment(&path, SegmentKind::Index, 9, &records).unwrap();
        assert_eq!(metadata.sparse.len(), 4);
        for value in [0_u32, 127, 128, 255, 399] {
            let key = format!("key-{value:04}");
            let found = lookup_segment(&path, key.as_bytes()).unwrap().unwrap();
            assert_eq!(found.value, value.to_le_bytes());
            assert!(found.records_examined <= SPARSE_STRIDE);
            assert!(found.plaintext_bytes_read < fs::metadata(&path).unwrap().len() as usize);
        }
        assert!(lookup_segment(&path, b"aaa").unwrap().is_none());
        assert!(lookup_segment(&path, b"zzz").unwrap().is_none());
        assert!(lookup_segment(&path, b"key-0128x").unwrap().is_none());
    }

    #[test]
    fn sparse_directory_bounds_prefix_scan_and_limit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("prefix.rseg");
        let records = (0_u32..400)
            .map(|value| SegmentRecord {
                key: (format!("key-{value:04}").into_bytes()).into(),
                value: (value.to_le_bytes().to_vec()).into(),
            })
            .collect::<Vec<_>>();
        write_segment(&path, SegmentKind::Index, 11, &records).unwrap();

        let scan = scan_segment_prefix(&path, b"key-01", 10).unwrap();
        assert_eq!(scan.records.len(), 10);
        assert_eq!(scan.records[0].key.as_slice(), b"key-0100");
        assert_eq!(scan.records[9].key.as_slice(), b"key-0109");
        assert!(scan.records_examined <= SPARSE_STRIDE);
        assert!(scan.plaintext_bytes_read < fs::metadata(&path).unwrap().len() as usize);

        let all = scan_segment_prefix(&path, b"key-039", 32).unwrap();
        assert_eq!(all.records.len(), 10);
        assert_eq!(all.records[0].key.as_slice(), b"key-0390");
        assert_eq!(all.records[9].key.as_slice(), b"key-0399");
        assert!(
            scan_segment_prefix(&path, b"zzz", 1)
                .unwrap()
                .records
                .is_empty()
        );
        assert!(scan_segment_prefix(&path, b"", 1).is_err());
        assert!(scan_segment_prefix(&path, b"key", 0).is_err());
    }

    #[test]
    fn prefix_cursor_skips_disjoint_runs_without_reading_frames() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("prefix-range.rseg");
        let records = (100_u32..300)
            .map(|value| SegmentRecord {
                key: format!("key-{value:04}").into_bytes().into(),
                value: value.to_le_bytes().to_vec().into(),
            })
            .collect::<Vec<_>>();
        write_segment(&path, SegmentKind::Index, 12, &records).unwrap();
        let reader = SegmentReader::open(&path).unwrap();
        for prefix in [b"aaa".as_slice(), b"key-0300", b"zzz"] {
            let mut cursor = reader.prefix_cursor(prefix).unwrap();
            assert!(cursor.finished, "{prefix:?} must be outside the run");
            assert_eq!(cursor.offset, cursor.layout.body_end);
            assert!(cursor.next().is_none());
        }
        let mut matching = reader.prefix_cursor(b"key-01").unwrap();
        assert!(!matching.finished);
        assert_eq!(
            matching.next().unwrap().unwrap().key.as_slice(),
            b"key-0100"
        );
        let mut whole = reader.prefix_cursor(b"key").unwrap();
        assert!(!whole.finished);
        assert_eq!(whole.next().unwrap().unwrap().key.as_slice(), b"key-0100");
    }

    #[test]
    fn prefix_cursor_from_seeks_sparse_directory_and_keeps_prefix_bound() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("range.rseg");
        let records = (0_u32..1024)
            .map(|value| SegmentRecord {
                key: format!("key-{value:04}").into_bytes().into(),
                value: value.to_le_bytes().to_vec().into(),
            })
            .collect::<Vec<_>>();
        write_segment(&path, SegmentKind::Index, 1, &records).unwrap();
        let reader = SegmentReader::open(&path).unwrap();
        let mut cursor = reader.prefix_cursor_from(b"key-", b"key-0800").unwrap();
        assert_eq!(
            cursor.offset,
            cursor.layout.body_start + reader.metadata().sparse[6].offset as usize
        );
        assert_eq!(cursor.next().unwrap().unwrap(), records[800]);
        assert_eq!(cursor.collect::<Result<Vec<_>>>().unwrap(), records[801..]);

        let mut outside = reader.prefix_cursor_from(b"key-", b"key-1024").unwrap();
        assert!(outside.finished);
        assert!(outside.next().is_none());
        assert!(reader.prefix_cursor_from(b"key-", b"other").is_err());
    }

    #[test]
    fn prefix_cursor_streams_single_frames_and_retains_unlinked_generation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("cursor.rseg");
        let records = (0..400)
            .map(|id| SegmentRecord {
                key: (format!("key-{id:04}").into_bytes()).into(),
                value: (vec![37; 8192]).into(),
            })
            .collect::<Vec<_>>();
        write_segment(&path, SegmentKind::Index, 1, &records).unwrap();
        let reader = SegmentReader::open(&path).unwrap();
        assert!(reader.prefix_cursor(b"").is_err());
        let mut cursor = reader.prefix_cursor(b"key-01").unwrap();
        assert_eq!(cursor.next().unwrap().unwrap(), records[100]);
        let offset = cursor.offset;
        assert_eq!(cursor.next().unwrap().unwrap(), records[101]);
        assert_eq!(
            cursor.offset - offset,
            RECORD_HEADER_LEN + records[101].key.len() + 8192
        );
        drop(reader);
        fs::remove_file(&path).unwrap();
        assert_eq!(
            cursor.collect::<Result<Vec<_>>>().unwrap(),
            records[102..200]
        );
        assert!(SegmentReader::open(&path).is_err());

        write_segment(&path, SegmentKind::Index, 1, &records).unwrap();
        let reader = SegmentReader::open(&path).unwrap();
        let mut encoded = fs::read(&path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        // In-place overwrite, preserving the size of the active mapping.
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all(&encoded)
            .unwrap();
        let mut cursor = reader.prefix_cursor(b"key-0399").unwrap();
        assert!(cursor.next().unwrap().is_err());
        assert!(cursor.next().is_none());
    }
}
