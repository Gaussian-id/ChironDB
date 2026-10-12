//! Version-2 run I/O without whole-body plaintext or ciphertext buffers.

use std::{
    borrow::Cow,
    io::{self, Read},
};

use super::*;
use crate::encryption::atomic_write_persistent_stream;

pub(super) fn write_records<'a>(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    records: impl Iterator<Item = &'a SegmentRecord> + Clone,
    record_count: usize,
) -> Result<AccountedMetadata> {
    write_record_source(
        path,
        kind,
        sequence,
        || Ok(records.clone().map(|record| Ok(Cow::Borrowed(record)))),
        Some(record_count),
    )
}

pub(super) fn write_stream<I: Iterator<Item = Result<SegmentRecord>>>(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    source: impl Fn() -> Result<I>,
) -> Result<AccountedMetadata> {
    write_record_source(
        path,
        kind,
        sequence,
        || Ok(source()?.map(|record| record.map(Cow::Owned))),
        None,
    )
}

fn write_record_source<'a, I: Iterator<Item = Result<Cow<'a, SegmentRecord>>>>(
    path: &Path,
    kind: SegmentKind,
    sequence: u64,
    source: impl Fn() -> Result<I>,
    record_count: Option<usize>,
) -> Result<AccountedMetadata> {
    if sequence == 0 {
        return Err(invalid("relational segment sequence must be non-zero"));
    }
    // Compaction has no retained output array. Count a fresh bounded cursor
    // first so the frozen v2 Bloom sizing and exact byte contract stay intact.
    let record_count = match record_count {
        Some(count) => count,
        None => source()?.try_fold(0_usize, |count, record| {
            record?;
            count
                .checked_add(1)
                .ok_or_else(|| resource("segment count overflow"))
        })?,
    };
    let bloom_bytes = record_count
        .saturating_mul(10)
        .div_ceil(8)
        .clamp(MIN_BLOOM_BYTES, MAX_BLOOM_BYTES);
    let sparse_count = record_count.div_ceil(SPARSE_STRIDE);
    let mut charge = super::super::memory::Charge::storage();
    charge.prepare(admission::fixed_bytes(bloom_bytes, sparse_count)?)?;
    let mut sparse = Vec::new();
    sparse
        .try_reserve_exact(sparse_count)
        .map_err(|_| resource("segment metadata allocation failed"))?;
    let mut bloom = Vec::new();
    bloom
        .try_reserve_exact(bloom_bytes)
        .map_err(|_| resource("segment Bloom allocation failed"))?;
    bloom.resize(bloom_bytes, 0);
    let mut metadata = SegmentMetadata {
        kind,
        sequence,
        record_count: record_count as u64,
        min_key: None,
        max_key: None,
        bloom_hashes: BLOOM_HASHES,
        bloom,
        sparse_stride: SPARSE_STRIDE as u32,
        sparse,
    };
    charge.prepare(admission::metadata_bytes(&metadata)?)?;
    let mut body_len = 0_u64;
    let mut body_crc = Hasher::new();
    let mut count = 0;
    let mut sparse_bytes = 0_usize;
    for record in source()? {
        let record = record?;
        let record = record.as_ref();
        if metadata
            .max_key
            .as_ref()
            .is_some_and(|key| key.as_slice() >= record.key.as_slice())
        {
            return Err(invalid(
                "relational segment records must have unique ascending keys",
            ));
        }
        let record_bytes = RECORD_HEADER_LEN
            .checked_add(record.key.len())
            .and_then(|len| len.checked_add(record.value.len()))
            .ok_or_else(|| resource("relational segment record size overflow"))?;
        if record_bytes > crate::resource_profile::current().sql_request_working_set_bytes as usize
        {
            return Err(resource(
                "relational segment record exceeds SQL working-set budget",
            ));
        }
        if count >= record_count {
            return Err(invalid("relational segment input count mismatch"));
        }
        let old_max_bytes = metadata
            .max_key
            .as_ref()
            .map_or(0, |key| key.capacity() as u64);
        let key_copies =
            1 + usize::from(metadata.min_key.is_none()) + usize::from(count % SPARSE_STRIDE == 0);
        let extra = (record.key.len() as u64)
            .checked_mul(key_copies as u64)
            .ok_or_else(|| resource("segment key memory overflow"))?;
        charge.prepare(
            charge
                .bytes()
                .checked_add(extra)
                .ok_or_else(|| resource("segment key memory overflow"))?,
        )?;
        let header = record_header(record)?;
        bloom_insert(&mut metadata.bloom, &record.key);
        if count % SPARSE_STRIDE == 0 {
            sparse_bytes = sparse_bytes
                .checked_add(record.key.len())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SparseEntry>()))
                .ok_or_else(|| resource("segment sparse directory size overflow"))?;
            if sparse_bytes > MAX_METADATA_BYTES {
                return Err(resource("relational segment metadata is too large"));
            }
            metadata.sparse.push(SparseEntry {
                key: record.key.to_vec(),
                offset: body_len,
            });
        }
        for part in [header.as_slice(), &record.key, &record.value] {
            body_crc.update(part);
            body_len = body_len
                .checked_add(part.len() as u64)
                .ok_or_else(|| resource("relational segment body size overflow"))?;
        }
        metadata.min_key.get_or_insert_with(|| record.key.to_vec());
        metadata.max_key = Some(record.key.to_vec());
        charge.prepare(charge.bytes().saturating_sub(old_max_bytes))?;
        count += 1;
    }
    if count != record_count {
        return Err(invalid("relational segment input count mismatch"));
    }
    let encoded_metadata = admission::EncodedBuffer::encode(&metadata, MAX_METADATA_BYTES)?;
    let metadata_bytes = &encoded_metadata.bytes;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.push(kind.tag());
    header.extend_from_slice(&[0; 3]);
    header.extend_from_slice(&sequence.to_le_bytes());
    header.extend_from_slice(&(record_count as u64).to_le_bytes());
    header.extend_from_slice(&(metadata_bytes.len() as u64).to_le_bytes());
    header.extend_from_slice(&body_len.to_le_bytes());
    header.extend_from_slice(&crc32(metadata_bytes).to_le_bytes());
    let expected_crc = body_crc.finalize();
    header.extend_from_slice(&expected_crc.to_le_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);
    let plaintext_len = body_len
        .checked_add(HEADER_LEN as u64)
        .and_then(|len| len.checked_add(metadata_bytes.len() as u64))
        .ok_or_else(|| resource("relational segment length overflow"))?;
    let input = header
        .as_slice()
        .chain(metadata_bytes.as_slice())
        .chain(RecordReader {
            records: source()?,
            current: None,
            header: [0; RECORD_HEADER_LEN],
            offset: 0,
            crc: Hasher::new(),
            count: 0,
            expected_count: record_count,
            expected_crc,
        });
    atomic_write_persistent_stream(path, FileType::Segment, plaintext_len, input)?;
    Ok(AccountedMetadata {
        value: metadata,
        _charge: charge,
    })
}

fn record_header(record: &SegmentRecord) -> Result<[u8; RECORD_HEADER_LEN]> {
    let key_len =
        u32::try_from(record.key.len()).map_err(|_| resource("segment key is too large"))?;
    let value_len =
        u32::try_from(record.value.len()).map_err(|_| resource("segment value is too large"))?;
    let mut header = [0; RECORD_HEADER_LEN];
    header[..4].copy_from_slice(&key_len.to_le_bytes());
    header[4..8].copy_from_slice(&value_len.to_le_bytes());
    header[8..].copy_from_slice(&record_crc(&record.key, &record.value).to_le_bytes());
    Ok(header)
}

struct RecordReader<'a, I> {
    records: I,
    current: Option<Cow<'a, SegmentRecord>>,
    header: [u8; RECORD_HEADER_LEN],
    offset: usize,
    crc: Hasher,
    count: usize,
    expected_count: usize,
    expected_crc: u32,
}

impl<'a, I: Iterator<Item = Result<Cow<'a, SegmentRecord>>>> Read for RecordReader<'a, I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.is_none() {
                let Some(record) = self.records.next() else {
                    if self.count != self.expected_count
                        || self.crc.clone().finalize() != self.expected_crc
                    {
                        return Err(io::Error::other(
                            "relational segment source changed between passes",
                        ));
                    }
                    return Ok(0);
                };
                let record = record.map_err(io::Error::other)?;
                self.header = record_header(&record).map_err(io::Error::other)?;
                for part in [self.header.as_slice(), &record.key, &record.value] {
                    self.crc.update(part);
                }
                self.count += 1;
                self.current = Some(record);
                self.offset = 0;
            }
            let record = self.current.as_ref().expect("installed record");
            let mut offset = self.offset;
            for part in [self.header.as_slice(), &record.key, &record.value] {
                if offset < part.len() {
                    let count = output.len().min(part.len() - offset);
                    output[..count].copy_from_slice(&part[offset..offset + count]);
                    self.offset += count;
                    return Ok(count);
                }
                offset -= part.len();
            }
            self.current = None;
        }
    }
}

/// Retains the immutable mapping and reads one framed record at a time.
/// Full validation (including whole-body CRC) completes only at EOF. Callers
/// publishing a generation must exhaust this cursor; an error is terminal.
pub(in crate::relational) struct SegmentCursor {
    layout: Arc<SegmentLayout>,
    offset: usize,
    count: u64,
    previous: Option<RecordBytes>,
    crc: Hasher,
    finished: bool,
    record_limit: usize,
}

impl SegmentCursor {
    pub(in crate::relational) fn open(path: &Path) -> Result<Self> {
        Ok(Self::from_layout(Arc::new(open_segment(path)?)))
    }

    pub(super) fn from_layout(layout: Arc<SegmentLayout>) -> Self {
        Self {
            offset: layout.body_start,
            layout,
            count: 0,
            previous: None,
            crc: Hasher::new(),
            finished: false,
            record_limit: crate::resource_profile::current().sql_request_working_set_bytes as usize,
        }
    }

    pub(in crate::relational) fn metadata(&self) -> &SegmentMetadata {
        &self.layout.metadata
    }

    pub(in crate::relational) fn next_offset(&self) -> usize {
        self.offset
    }

    pub(in crate::relational) fn reader(&self) -> SegmentReader {
        SegmentReader {
            layout: Arc::clone(&self.layout),
        }
    }

    fn read_next(&mut self) -> Result<Option<SegmentRecord>> {
        let metadata = &self.layout.metadata;
        if self.offset == self.layout.body_end {
            if self.count != metadata.record_count
                || self.previous.as_deref().map(Vec::as_slice) != metadata.max_key.as_deref()
                || self.crc.clone().finalize() != self.layout.body_crc
            {
                return Err(corruption(
                    "relational segment record count, maximum or CRC mismatch",
                ));
            }
            return Ok(None);
        }
        let (header, record, value_end) =
            read_frame(&self.layout, self.offset, None, self.record_limit)?;
        let key = &record.key;
        let value = &record.value;
        let sparse = self.count.is_multiple_of(SPARSE_STRIDE as u64);
        if self.count >= metadata.record_count
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| previous >= key)
            || (self.count == 0 && metadata.min_key.as_deref() != Some(key.as_slice()))
            || !metadata.may_contain(key)
            || (sparse
                && !metadata
                    .sparse
                    .get(self.count as usize / SPARSE_STRIDE)
                    .is_some_and(|entry| {
                        entry.key.as_slice() == key.as_slice()
                            && entry.offset == (self.offset - self.layout.body_start) as u64
                    }))
        {
            return Err(corruption("relational segment record metadata mismatch"));
        }
        for part in [header.as_ref(), key.as_slice(), value.as_slice()] {
            self.crc.update(part);
        }
        self.previous = Some(key.clone());
        self.offset = value_end;
        self.count += 1;
        Ok(Some(record))
    }
}

impl Iterator for SegmentCursor {
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

fn resource(message: &str) -> GaussError {
    GaussError::ResourceExhausted(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn records(count: usize) -> Vec<SegmentRecord> {
        (0..count)
            .map(|index| SegmentRecord {
                key: (format!("row-{index:06}").into_bytes()).into(),
                value: (vec![(index % 251) as u8; 257]).into(),
            })
            .collect()
    }

    // Independent encoder for the pre-streaming v2 layout; never calls the
    // new writer or its frame/header encoder.
    fn legacy_bytes(records: &[SegmentRecord], metadata: &SegmentMetadata) -> Vec<u8> {
        let mut body = Vec::new();
        for record in records {
            body.extend_from_slice(&(record.key.len() as u32).to_le_bytes());
            body.extend_from_slice(&(record.value.len() as u32).to_le_bytes());
            let mut hash = Hasher::new();
            hash.update(&record.key);
            hash.update(&record.value);
            body.extend_from_slice(&hash.finalize().to_le_bytes());
            body.extend_from_slice(&record.key);
            body.extend_from_slice(&record.value);
        }
        let meta = serde_json::to_vec(metadata).unwrap();
        let mut output = b"CHRNRSG1".to_vec();
        output.extend_from_slice(&2_u32.to_le_bytes());
        output.extend_from_slice(&[1, 0, 0, 0]);
        output.extend_from_slice(&metadata.sequence.to_le_bytes());
        output.extend_from_slice(&metadata.record_count.to_le_bytes());
        output.extend_from_slice(&(meta.len() as u64).to_le_bytes());
        output.extend_from_slice(&(body.len() as u64).to_le_bytes());
        output.extend_from_slice(&crc32fast::hash(&meta).to_le_bytes());
        output.extend_from_slice(&crc32fast::hash(&body).to_le_bytes());
        output.extend_from_slice(&meta);
        output.extend_from_slice(&body);
        output
    }

    #[test]
    fn streamed_run_preserves_v2_bytes_and_reads_legacy_fixture() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run");
        let fixture = include_bytes!("../../../tests/fixtures/relational_segment_v2.rseg");
        let frozen = vec![
            SegmentRecord {
                key: (b"a".to_vec()).into(),
                value: (b"one".to_vec()).into(),
            },
            SegmentRecord {
                key: (b"b".to_vec()).into(),
                value: (b"two".to_vec()).into(),
            },
        ];
        fs::write(&path, fixture).unwrap();
        assert_eq!(
            SegmentCursor::open(&path)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            frozen
        );
        write_segment(&path, SegmentKind::Row, 7, &frozen).unwrap();
        assert_eq!(fs::read(&path).unwrap(), fixture);
        for count in [0, 1, 127, 128, 129, 1025] {
            let records = records(count);
            let metadata = write_segment(&path, SegmentKind::Row, 7, &records).unwrap();
            let expected = legacy_bytes(&records, &metadata);
            assert_eq!(fs::read(&path).unwrap(), expected);
            fs::write(&path, expected).unwrap();
            assert_eq!(
                SegmentCursor::open(&path)
                    .unwrap()
                    .collect::<Result<Vec<_>>>()
                    .unwrap(),
                records
            );
        }
    }

    #[test]
    fn cursor_validates_sparse_bloom_order_and_eof_integrity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run");
        let records = records(257);
        let metadata = write_segment(&path, SegmentKind::Row, 7, &records).unwrap();
        for case in 0..7 {
            let mut modified = metadata.clone();
            let mut rows = records.clone();
            match case {
                0 => modified.bloom.fill(0),
                1 => modified.sparse[1].offset += 1,
                2 => modified.min_key = Some(b"wrong-minimum".to_vec()),
                3 => modified.max_key = Some(b"wrong-maximum".to_vec()),
                4 => modified.record_count += 1,
                5 => rows.swap(1, 2),
                _ => {}
            }
            let mut bytes = legacy_bytes(&rows, &modified);
            if case == 6 {
                bytes[52] ^= 1;
            } // Only the whole-body CRC is bad.
            fs::write(&path, bytes).unwrap();
            let mut cursor = SegmentCursor::open(&path).unwrap();
            assert!(
                cursor.by_ref().collect::<Result<Vec<_>>>().is_err(),
                "case {case}"
            );
            assert!(cursor.next().is_none(), "errors must fuse the cursor");
        }
    }

    #[test]
    fn cursor_refuses_truncation_and_oversized_record_before_materializing_value() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run");
        let records = records(1);
        let metadata = write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
        let mut cursor = SegmentCursor::open(&path).unwrap();
        cursor.record_limit = 64;
        assert!(matches!(
            cursor.next().unwrap(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(cursor.count, 0);
        drop(cursor);
        let mut bytes = legacy_bytes(&records, &metadata);
        let meta_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
        bytes[HEADER_LEN + meta_len + 4..HEADER_LEN + meta_len + 8]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(SegmentCursor::open(&path).unwrap().next().unwrap().is_err());
    }

    #[test]
    fn streamed_writer_rejects_invalid_input_without_replacing_generation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run");
        let mut records = records(2);
        write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(write_records(&path, SegmentKind::Row, 2, records.iter(), 1).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        records.reverse();
        assert!(write_segment(&path, SegmentKind::Row, 2, &records).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn replayable_stream_matches_frozen_writer_and_refuses_changed_or_failed_passes() {
        use std::cell::Cell;
        let directory = tempdir().unwrap();
        let path = directory.path().join("run");
        let records = records(3);
        write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
        let original = fs::read(&path).unwrap();
        write_stream(&path, SegmentKind::Row, 1, || {
            Ok(records.iter().cloned().map(Ok))
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        for failed_pass in 1..=3 {
            let pass = Cell::new(0);
            assert!(
                write_stream(&path, SegmentKind::Row, 1, || {
                    pass.set(pass.get() + 1);
                    let fail = pass.get() == failed_pass;
                    Ok(records
                        .iter()
                        .cloned()
                        .enumerate()
                        .map(move |(position, record)| {
                            if fail && position == 1 {
                                Err(invalid("injected source error"))
                            } else {
                                Ok(record)
                            }
                        }))
                })
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), original, "pass {failed_pass}");
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
        let pass = Cell::new(0);
        assert!(
            write_stream(&path, SegmentKind::Row, 1, || {
                pass.set(pass.get() + 1);
                let changed = pass.get() == 3;
                Ok(records.iter().cloned().map(move |mut record| {
                    if changed {
                        let mut value = record.value.to_vec();
                        value[0] ^= 1;
                        record.value = value.into();
                    }
                    Ok(record)
                }))
            })
            .is_err(),
            "same-size body changes must fail before atomic replacement"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn encrypted_streamed_run_crosses_chunks_and_authenticates_corruption() {
        const CHILD: &str = "CHIRONDB_RELATIONAL_STREAM_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "relational::segment::streaming::tests::encrypted_streamed_run_crosses_chunks_and_authenticates_corruption", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        use base64::Engine as _;
        let directory = tempdir().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([7u8;32])}]})).unwrap();
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(key.path()).unwrap(),
            true,
        )
        .unwrap();
        let path = directory.path().join("run");
        let mut records = records(300);
        records[128].value = vec![42; 150_000].into();
        write_segment(&path, SegmentKind::Row, 7, &records).unwrap();
        let mut encoded = fs::read(&path).unwrap();
        assert!(encoded.starts_with(crate::encryption::MAGIC));
        assert_eq!(
            SegmentCursor::open(&path)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            records
        );
        let found = lookup_segment(&path, &records[128].key).unwrap().unwrap();
        assert_eq!(found.value, records[128].value);
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&path, encoded).unwrap();
        assert!(
            SegmentCursor::open(&path)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .is_err()
        );
    }
}
