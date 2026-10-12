//! Aggregate reservations follow metadata ownership, including writer results.

use super::*;
use crate::relational::memory::Charge;
use std::{
    io,
    io::Write,
    mem::size_of,
    ops::{Deref, Range},
};

const OWNER_BYTES: u64 = 4096;

#[derive(Debug)]
pub(in crate::relational) struct AccountedMetadata {
    // Drop allocations before releasing the reservation.
    pub(super) value: SegmentMetadata,
    pub(super) _charge: Charge,
}

impl Deref for AccountedMetadata {
    type Target = SegmentMetadata;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub(super) fn fixed_bytes(bloom: usize, sparse_capacity: usize) -> Result<u64> {
    (sparse_capacity as u64)
        .checked_mul(size_of::<SparseEntry>() as u64 + 32)
        .and_then(|n| n.checked_add(bloom as u64))
        .and_then(|n| n.checked_add(OWNER_BYTES))
        .ok_or_else(super::super::sql_overloaded)
}

pub(super) fn metadata_bytes(metadata: &SegmentMetadata) -> Result<u64> {
    let mut bytes = fixed_bytes(metadata.bloom.capacity(), metadata.sparse.capacity())?;
    for key in metadata
        .min_key
        .iter()
        .chain(&metadata.max_key)
        .chain(metadata.sparse.iter().map(|entry| &entry.key))
    {
        bytes = bytes
            .checked_add(key.capacity() as u64)
            .ok_or_else(super::super::sql_overloaded)?;
    }
    Ok(bytes)
}

pub(super) fn read_metadata(
    file: &PersistentFile,
    range: Range<usize>,
    expected_crc: u32,
) -> Result<AccountedMetadata> {
    let mut charge = Charge::storage();
    // The fixed schema contains byte vectors and SparseEntry {Vec<u8>, u64}.
    // Eight encoded bytes of reservation per input byte cover owned input,
    // serde's scratch and simultaneous old/new Vec capacities during growth.
    // On supported 64-bit targets SparseEntry is 32 bytes: >=21 JSON bytes
    // per entry cover <=3*32 bytes of overlapping Vec capacity during growth.
    // byte arrays need >=2 JSON bytes per element. The fixed owner allowance
    // covers empty/minimum vector capacities and parser/reader structures.
    let peak = (range.len() as u64)
        .checked_mul(8)
        .and_then(|n| n.checked_add(OWNER_BYTES))
        .ok_or_else(super::super::sql_overloaded)?;
    charge.prepare(peak)?;
    if file.crc32(range.clone())? != expected_crc {
        return Err(corruption("relational segment CRC mismatch"));
    }
    let metadata: SegmentMetadata = serde_json::from_slice(&file.read_range_admitted(range)?)?;
    let retained = metadata_bytes(&metadata)?;
    if retained > peak {
        return Err(super::super::sql_overloaded());
    }
    charge.prepare(retained)?;
    Ok(AccountedMetadata {
        value: metadata,
        _charge: charge,
    })
}

pub(in crate::relational) struct EncodedBuffer {
    pub(in crate::relational) bytes: Vec<u8>,
    pub(super) charge: Charge,
    exhausted: bool,
    limit: usize,
}

impl EncodedBuffer {
    pub(in crate::relational) fn into_parts(mut self) -> Result<(Vec<u8>, Charge)> {
        self.charge.prepare(self.bytes.capacity() as u64 + 256)?;
        Ok((self.bytes, self.charge))
    }

    pub(in crate::relational) fn encode(value: &impl Serialize, limit: usize) -> Result<Self> {
        Self::encode_with_formatter(value, limit, serde_json::ser::CompactFormatter)
    }

    pub(in crate::relational) fn encode_with_formatter(
        value: &impl Serialize,
        limit: usize,
        formatter: impl serde_json::ser::Formatter,
    ) -> Result<Self> {
        super::super::check_sql_cancelled()?;
        let mut output = Self {
            bytes: Vec::new(),
            charge: Charge::storage(),
            exhausted: false,
            limit,
        };
        let result = value.serialize(&mut serde_json::Serializer::with_formatter(
            &mut output,
            formatter,
        ));
        super::super::check_sql_cancelled()?;
        if output.exhausted {
            return Err(super::super::sql_overloaded());
        }
        result?;
        Ok(output)
    }

    fn reserve(&mut self, capacity: usize) -> Result<()> {
        if capacity <= self.bytes.capacity() {
            return Ok(());
        }
        // Reallocation may keep both old and new blocks live temporarily.
        let capacity = capacity
            .checked_next_power_of_two()
            .unwrap_or(self.limit)
            .min(self.limit);
        self.charge
            .prepare((self.bytes.capacity() as u64) + (capacity as u64))?;
        self.bytes
            .try_reserve_exact(capacity - self.bytes.len())
            .map_err(|_| super::super::sql_overloaded())?;
        self.charge.prepare(self.bytes.capacity() as u64)
    }
}

impl Write for EncodedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        super::super::check_sql_cancelled().map_err(io::Error::other)?;
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exhausted = true;
            return Err(io::Error::other(
                "relational encoded buffer exceeds its limit",
            ));
        }
        if let Err(error) = self.reserve(self.bytes.len() + bytes.len()) {
            self.exhausted = true;
            return Err(io::Error::other(error));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::memory::{self, with_storage_pool};

    #[test]
    fn cancellation_during_serialization_releases_partial_encoded_buffer() {
        use crate::relational::with_sql_cancellation;
        use serde::ser::SerializeSeq;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct CancelAfterValue {
            cancel: Arc<AtomicBool>,
            value: String,
        }
        impl Serialize for CancelAfterValue {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(2))?;
                sequence.serialize_element(&self.value)?;
                self.cancel.store(true, Ordering::Release);
                sequence.serialize_element(&self.value)?;
                sequence.end()
            }
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let value = CancelAfterValue {
            cancel: cancel.clone(),
            value: "x".repeat(8192),
        };
        with_storage_pool(64 * 1024, |pool| {
            let result =
                with_sql_cancellation(cancel, || EncodedBuffer::encode(&value, usize::MAX));
            assert!(result.is_err_and(|error| error.to_string().contains("query canceled")));
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn metadata_encoding_refusal_releases_partial_buffers_before_file_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rows.rseg");
        let records = [SegmentRecord {
            key: (vec![1]).into(),
            value: (vec![2]).into(),
        }];
        // Enough for decoded metadata; too little for its growing JSON buffer.
        with_storage_pool(4500, |pool| {
            assert!(matches!(
                write_segment(&path, SegmentKind::Row, 1, &records),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(pool.used(), 0);
            assert!(!path.exists());
        });
        with_storage_pool(8192, |pool| {
            let metadata = write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
            assert!(pool.used() > 0);
            drop(metadata);
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn metadata_decode_budget_covers_short_keys_and_vector_growth_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        for count in [0, 1, 4, 5, 257, 8193] {
            let metadata = SegmentMetadata {
                kind: SegmentKind::Row,
                sequence: 1,
                record_count: count as u64 * 128,
                min_key: Some(vec![]),
                max_key: Some(vec![]),
                bloom_hashes: BLOOM_HASHES,
                bloom: vec![0; 257],
                sparse_stride: SPARSE_STRIDE as u32,
                sparse: (0..count)
                    .map(|_| SparseEntry {
                        key: vec![],
                        offset: 0,
                    })
                    .collect(),
            };
            // Minimal per-entry JSON maximizes decoded structure overhead.
            // This tests admission before semantic sparse-order validation.
            let encoded = serde_json::to_vec(&metadata).unwrap();
            let peak = encoded.len() as u64 * 8 + OWNER_BYTES;
            let path = directory.path().join("metadata");
            fs::write(&path, &encoded).unwrap();
            let file = PersistentFile::open(&path).unwrap();
            with_storage_pool(peak + memory::LEASE_ROOT_BYTES - 1, |pool| {
                assert!(matches!(
                    read_metadata(&file, 0..encoded.len(), crc32(&encoded)),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(pool.used(), 0);
            });
            with_storage_pool(peak + memory::LEASE_ROOT_BYTES, |pool| {
                let decoded = read_metadata(&file, 0..encoded.len(), crc32(&encoded)).unwrap();
                assert_eq!(*decoded, metadata);
                assert_eq!(
                    pool.used(),
                    metadata_bytes(&decoded).unwrap() + memory::LEASE_ROOT_BYTES
                );
                assert!(pool.used() <= peak + memory::LEASE_ROOT_BYTES);
                drop(decoded);
                assert_eq!(pool.used(), 0);
            });
        }
    }
}
