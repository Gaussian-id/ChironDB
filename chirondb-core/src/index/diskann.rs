//! Page-aligned cold-segment records for explicit DiskANN-style I/O.
//!
//! Each immutable record contains the primary scaled-f16 rerank vector and
//! the fixed-width Vamana adjacency. Records never cross a 4 KiB payload page
//! when they fit; larger dimensions use a fixed whole-page span. Every page
//! carries its own CRC. Cold search reads pages with positional I/O through a
//! bounded process cache instead of faulting the full vector/graph mmaps.

use std::{
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    future::Future,
    io::{Read, Seek, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use futures_executor::block_on;
use object_store::{ObjectStore, path::Path as ObjectPath};

use crate::{
    GaussError, Result, encryption,
    index::vamana::VamanaArtifact,
    seal::{VectorInput, scaled_f16_row_bytes},
};

mod admission;
use crate::relational::wal_decode::MetadataCharge;

#[derive(Debug)]
struct CachedPage {
    payload: [u8; PAGE_PAYLOAD_BYTES],
    _memory: MetadataCharge,
}
impl std::ops::Deref for CachedPage {
    type Target = [u8; PAGE_PAYLOAD_BYTES];
    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

struct FetchedPages {
    pages: Vec<Arc<CachedPage>>,
    _memory: MetadataCharge,
}

struct RangeBytes {
    bytes: Vec<Vec<u8>>,
    _memory: MetadataCharge,
}

pub(crate) struct AdmittedVectors {
    vectors: Vec<Vec<f32>>,
    _memory: MetadataCharge,
}
impl std::ops::Deref for AdmittedVectors {
    type Target = [Vec<f32>];
    fn deref(&self) -> &Self::Target {
        &self.vectors
    }
}
impl std::ops::Deref for RangeBytes {
    type Target = [Vec<u8>];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

pub const DISKANN_FILE: &str = "diskann.gdx";
const MAGIC: &[u8; 8] = b"GAUSSDP1";
const VERSION: u32 = 1;
pub const PAGE_SIZE: usize = 4096;
const PAGE_CRC_BYTES: usize = 4;
const PAGE_PAYLOAD_BYTES: usize = PAGE_SIZE - PAGE_CRC_BYTES;
const HEADER_CRC_OFFSET: usize = PAGE_PAYLOAD_BYTES;
const CACHE_PAGES: usize = 256;
const GLOBAL_CACHE_BYTES: usize = 64 * 1024 * 1024;
const GLOBAL_CACHE_PAGES: usize = GLOBAL_CACHE_BYTES / PAGE_SIZE;
static GLOBAL_PAGE_CACHE: OnceLock<Mutex<PageCache>> = OnceLock::new();
static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct DiskAnnIoStats {
    pub active_segments: u64,
    pub remote_segments: u64,
    pub data_pages: u64,
    pub cache_capacity_bytes: u64,
    pub physical_page_reads: u64,
    pub remote_range_requests: u64,
    pub remote_range_pages: u64,
    pub cache_hits: u64,
    pub requested_records: u64,
    pub requested_pages: u64,
    pub bytes_read: u64,
    pub page_read_errors: u64,
}

impl std::ops::AddAssign for DiskAnnIoStats {
    fn add_assign(&mut self, rhs: Self) {
        self.active_segments += rhs.active_segments;
        self.remote_segments += rhs.remote_segments;
        self.data_pages += rhs.data_pages;
        self.cache_capacity_bytes += rhs.cache_capacity_bytes;
        self.physical_page_reads += rhs.physical_page_reads;
        self.remote_range_requests += rhs.remote_range_requests;
        self.remote_range_pages += rhs.remote_range_pages;
        self.cache_hits += rhs.cache_hits;
        self.requested_records += rhs.requested_records;
        self.requested_pages += rhs.requested_pages;
        self.bytes_read += rhs.bytes_read;
        self.page_read_errors += rhs.page_read_errors;
    }
}

#[derive(Debug)]
struct PageCache {
    pages: HashMap<(u64, u64), Arc<CachedPage>>,
    order: VecDeque<(u64, u64)>,
    hash_capacity: usize,
    _memory: MetadataCharge,
}

impl PageCache {
    fn new() -> Self {
        Self {
            pages: HashMap::new(),
            order: VecDeque::new(),
            hash_capacity: 0,
            _memory: MetadataCharge::default(),
        }
    }

    fn get(&mut self, key: (u64, u64)) -> Option<Arc<CachedPage>> {
        let value = self.pages.get(&key).cloned()?;
        self.order.retain(|entry| *entry != key);
        self.order.push_back(key);
        Some(value)
    }

    fn insert(&mut self, key: (u64, u64), payload: Arc<CachedPage>) -> Result<()> {
        // An empty cache binds its first allocation at use, not construction.
        if self.hash_capacity == 0 {
            self._memory = MetadataCharge::default();
        }
        let replacing = self.pages.contains_key(&key);
        let peak = admission::containers(self, !replacing)?;
        let retained = admission::containers(self, false)?;
        let root = if retained == 0 {
            crate::relational::wal_decode::lease_root_bytes()
        } else {
            0
        };
        if crate::relational::wal_decode::storage_available_bytes()
            < peak.saturating_sub(retained).saturating_add(root)
        {
            self.clear();
        }
        self._memory
            .prepare(admission::containers(self, !self.pages.contains_key(&key))?)?;
        if self.pages.contains_key(&key) {
            self.order.retain(|entry| *entry != key);
        } else if self.pages.len() == GLOBAL_CACHE_PAGES
            && let Some(evicted) = self.order.pop_front()
        {
            self.pages.remove(&evicted);
        }
        let result = (|| {
            if !self.pages.contains_key(&key) {
                self.pages
                    .try_reserve(1)
                    .map_err(|_| admission::exhausted())?;
            }
            self.hash_capacity = self.hash_capacity.max(self.pages.capacity());
            self.order
                .try_reserve(1)
                .map_err(|_| admission::exhausted())?;
            self.pages.insert(key, payload);
            self.order.push_back(key);
            Ok(())
        })();
        self._memory.reduce(admission::containers(self, false)?);
        result
    }

    fn remove_source(&mut self, source: u64) {
        self.pages.retain(|(candidate, _), _| *candidate != source);
        self.order.retain(|(candidate, _)| *candidate != source);
        if self.pages.is_empty() {
            self.clear();
        }
    }

    fn clear(&mut self) {
        self.pages = HashMap::new();
        self.order = VecDeque::new();
        self.hash_capacity = 0;
        self._memory.reduce(0);
    }
}

fn global_page_cache() -> &'static Mutex<PageCache> {
    GLOBAL_PAGE_CACHE.get_or_init(|| Mutex::new(PageCache::new()))
}

#[derive(Debug)]
enum PageSource {
    Local(File),
    EncryptedLocal {
        file: File,
        layout: encryption::EncryptedLayout,
    },
    ObjectStore {
        store: Arc<dyn ObjectStore>,
        location: ObjectPath,
    },
    EncryptedObjectStore {
        store: Arc<dyn ObjectStore>,
        location: ObjectPath,
        layout: encryption::EncryptedLayout,
    },
}

impl PageSource {
    fn is_remote(&self) -> bool {
        matches!(
            self,
            Self::ObjectStore { .. } | Self::EncryptedObjectStore { .. }
        )
    }

    fn read_ranges(&self, path: &Path, ranges: &[Range<u64>]) -> Result<RangeBytes> {
        let memory = admission::ranges(self, ranges)?;
        let bytes = match self {
            Self::Local(file) => ranges
                .iter()
                .map(|range| {
                    let len = usize::try_from(range.end.saturating_sub(range.start))
                        .map_err(|_| corrupt(path, "DiskANN read range exceeds usize"))?;
                    let mut bytes = vec![0_u8; len];
                    read_exact_at(file, &mut bytes, range.start)?;
                    Ok(bytes)
                })
                .collect(),
            Self::EncryptedLocal { file, layout } => {
                decrypt_ranges(layout, ranges, |encrypted_ranges| {
                    encrypted_ranges
                        .iter()
                        .map(|range| {
                            let len = usize::try_from(range.end.saturating_sub(range.start))
                                .map_err(|_| corrupt(path, "encrypted range exceeds usize"))?;
                            let mut bytes = vec![0_u8; len];
                            read_exact_at(file, &mut bytes, range.start)?;
                            Ok(bytes)
                        })
                        .collect()
                })
            }
            Self::ObjectStore { store, location } => {
                let bytes =
                    block_on_object_store(store.get_ranges(location, ranges)).map_err(|error| {
                        corrupt(
                            path,
                            &format!("DiskANN object-store range read failed: {error}"),
                        )
                    })?;
                Ok(bytes.into_iter().map(|bytes| bytes.to_vec()).collect())
            }
            Self::EncryptedObjectStore {
                store,
                location,
                layout,
            } => decrypt_ranges(layout, ranges, |encrypted_ranges| {
                let bytes = block_on_object_store(store.get_ranges(location, encrypted_ranges))
                    .map_err(|error| {
                        corrupt(
                            path,
                            &format!("encrypted DiskANN range read failed: {error}"),
                        )
                    })?;
                Ok(bytes.into_iter().map(|bytes| bytes.to_vec()).collect())
            }),
        }?;
        Ok(RangeBytes {
            bytes,
            _memory: memory,
        })
    }
}

fn decrypt_ranges(
    layout: &encryption::EncryptedLayout,
    ranges: &[Range<u64>],
    mut fetch: impl FnMut(&[Range<u64>]) -> Result<Vec<Vec<u8>>>,
) -> Result<Vec<Vec<u8>>> {
    let plaintext_len = layout.info().plaintext_len;
    let chunk_size = layout.info().chunk_size as u64;
    ranges
        .iter()
        .map(|range| {
            if range.start > range.end || range.end > plaintext_len {
                return Err(GaussError::InvalidRequest(
                    "encrypted DiskANN plaintext range is out of bounds".to_string(),
                ));
            }
            if range.start == range.end {
                return Ok(Vec::new());
            }
            let first = range.start / chunk_size;
            let last = (range.end - 1) / chunk_size;
            let encrypted_ranges = (first..=last)
                .map(|index| {
                    usize::try_from(index)
                        .map_err(|_| {
                            GaussError::InvalidRequest(
                                "encrypted DiskANN chunk index exceeds usize".to_string(),
                            )
                        })
                        .and_then(|index| layout.encrypted_chunk_range(index))
                })
                .collect::<Result<Vec<_>>>()?;
            let frames = fetch(&encrypted_ranges)?;
            if frames.len() != encrypted_ranges.len() {
                return Err(GaussError::InvalidRequest(
                    "encrypted DiskANN range response count mismatch".to_string(),
                ));
            }
            let requested_len = usize::try_from(range.end - range.start).map_err(|_| {
                GaussError::InvalidRequest(
                    "encrypted DiskANN requested range exceeds usize".to_string(),
                )
            })?;
            let mut output = Vec::with_capacity(requested_len);
            for (offset, frame) in frames.into_iter().enumerate() {
                let index = first as usize + offset;
                let plaintext = layout.decrypt_chunk_frame(index, &frame)?;
                let chunk_start = (index as u64).saturating_mul(chunk_size);
                let copy_start = range.start.saturating_sub(chunk_start) as usize;
                let copy_end = range.end.min(chunk_start + plaintext.len() as u64) - chunk_start;
                output.extend_from_slice(plaintext.get(copy_start..copy_end as usize).ok_or_else(
                    || {
                        GaussError::InvalidRequest(
                            "encrypted DiskANN chunk slice is out of bounds".to_string(),
                        )
                    },
                )?);
            }
            if output.len() != requested_len {
                return Err(GaussError::InvalidRequest(
                    "encrypted DiskANN plaintext range length mismatch".to_string(),
                ));
            }
            Ok(output)
        })
        .collect()
}

#[derive(Debug)]
pub struct DiskAnnArtifact {
    source: PageSource,
    path: PathBuf,
    object_len: u64,
    count: usize,
    vector_dim: usize,
    degree: usize,
    record_bytes: usize,
    records_per_page: usize,
    pages_per_record: usize,
    data_pages: usize,
    cache_id: u64,
    physical_page_reads: AtomicU64,
    remote_range_requests: AtomicU64,
    remote_range_pages: AtomicU64,
    cache_hits: AtomicU64,
    requested_records: AtomicU64,
    requested_pages: AtomicU64,
    page_read_errors: AtomicU64,
    _memory: MetadataCharge,
}

#[derive(Debug)]
pub struct DiskAnnRecord {
    pub vector: Vec<f32>,
    pub neighbors: Vec<u32>,
}

impl DiskAnnArtifact {
    pub fn open(path: &Path, expected_count: usize, expected_dim: usize) -> Result<Self> {
        let memory = admission::artifact(path.as_os_str().len())?;
        let mut file = File::open(path)?;
        let mut prefix = [0_u8; 8];
        file.read_exact(&mut prefix)?;
        if encryption::is_encrypted(&prefix) {
            let layout = encryption::EncryptedLayout::from_file_header(&mut file)?;
            let object_len = layout.info().plaintext_len;
            let source = PageSource::EncryptedLocal { file, layout };
            let header_bytes =
                source.read_ranges(path, std::slice::from_ref(&(0..PAGE_SIZE as u64)))?;
            let header: [u8; PAGE_SIZE] = header_bytes
                .first()
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .ok_or_else(|| corrupt(path, "short encrypted DiskANN header"))?;
            return Self::open_source(
                source,
                path.to_path_buf(),
                object_len,
                header,
                expected_count,
                expected_dim,
                memory,
            );
        }
        file.rewind()?;
        let mut header = [0_u8; PAGE_SIZE];
        file.read_exact(&mut header)?;
        let object_len = file.metadata()?.len();
        Self::open_source(
            PageSource::Local(file),
            path.to_path_buf(),
            object_len,
            header,
            expected_count,
            expected_dim,
            memory,
        )
    }

    pub(crate) fn open_object_store(
        store: Arc<dyn ObjectStore>,
        location: ObjectPath,
        object_len: u64,
        expected_count: usize,
        expected_dim: usize,
    ) -> Result<Self> {
        let memory = admission::artifact(
            location
                .as_ref()
                .len()
                .checked_add(9)
                .ok_or_else(admission::exhausted)?,
        )?;
        let path = PathBuf::from(format!("object://{location}"));
        let source = PageSource::ObjectStore {
            store: store.clone(),
            location: location.clone(),
        };
        let header_range = 0..PAGE_SIZE as u64;
        let header_bytes = source.read_ranges(&path, std::slice::from_ref(&header_range))?;
        let first_page = header_bytes
            .first()
            .ok_or_else(|| corrupt(&path, "missing DiskANN object-store header range"))?;
        if encryption::is_encrypted(first_page) {
            // The bounded CHIRENC1 header (at most 230 bytes) fits in this
            // already-read page; do not fetch ciphertext body for its metadata.
            let layout = encryption::EncryptedLayout::from_header(first_page)?;
            let plaintext_len = layout.info().plaintext_len;
            let source = PageSource::EncryptedObjectStore {
                store,
                location,
                layout,
            };
            let header_bytes =
                source.read_ranges(&path, std::slice::from_ref(&(0..PAGE_SIZE as u64)))?;
            let header: [u8; PAGE_SIZE] = header_bytes
                .first()
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .ok_or_else(|| corrupt(&path, "short encrypted DiskANN object header"))?;
            return Self::open_source(
                source,
                path,
                plaintext_len,
                header,
                expected_count,
                expected_dim,
                memory,
            );
        }
        let header: [u8; PAGE_SIZE] = first_page
            .as_slice()
            .try_into()
            .map_err(|_| corrupt(&path, "short DiskANN object-store header range"))?;
        Self::open_source(
            source,
            path,
            object_len,
            header,
            expected_count,
            expected_dim,
            memory,
        )
    }

    fn open_source(
        source: PageSource,
        path: PathBuf,
        object_len: u64,
        header: [u8; PAGE_SIZE],
        expected_count: usize,
        expected_dim: usize,
        memory: MetadataCharge,
    ) -> Result<Self> {
        let expected_header_crc =
            u32::from_le_bytes(header[HEADER_CRC_OFFSET..].try_into().expect("header crc"));
        if &header[..8] != MAGIC || crc(&header[..HEADER_CRC_OFFSET]) != expected_header_crc {
            return Err(corrupt(&path, "bad DiskANN page header or CRC"));
        }
        let version = u32_at(&header, 8);
        let flags = u32_at(&header, 12);
        let count = usize_from_u64(u64_at(&header, 16), &path, "point count")?;
        let vector_dim = u32_at(&header, 24) as usize;
        let degree = u32_at(&header, 28) as usize;
        let record_bytes = u32_at(&header, 32) as usize;
        let records_per_page = u32_at(&header, 36) as usize;
        let pages_per_record = u32_at(&header, 40) as usize;
        let page_size = u32_at(&header, 44) as usize;
        let page_payload = u32_at(&header, 48) as usize;
        let cache_pages = u32_at(&header, 52) as usize;
        let data_pages = usize_from_u64(u64_at(&header, 56), &path, "data page count")?;
        let expected_record_bytes = vector_dim
            .checked_mul(2)
            .and_then(|bytes| {
                degree
                    .checked_mul(4)
                    .and_then(|adjacency| adjacency.checked_add(8))
                    .and_then(|adjacency| bytes.checked_add(adjacency))
            })
            .ok_or_else(|| corrupt(&path, "DiskANN record width overflow"))?;
        let packed = record_bytes <= PAGE_PAYLOAD_BYTES;
        if version != VERSION
            || flags != 0
            || count != expected_count
            || vector_dim != expected_dim
            || count == 0
            || vector_dim == 0
            || degree == 0
            || degree > 1024
            || record_bytes != expected_record_bytes
            || page_size != PAGE_SIZE
            || page_payload != PAGE_PAYLOAD_BYTES
            || cache_pages != CACHE_PAGES
            || (packed
                && (records_per_page != PAGE_PAYLOAD_BYTES / record_bytes || pages_per_record != 1))
            || (!packed
                && (records_per_page != 0
                    || pages_per_record != record_bytes.div_ceil(PAGE_PAYLOAD_BYTES)))
        {
            return Err(corrupt(&path, "DiskANN metadata is inconsistent"));
        }
        let expected_data_pages = if packed {
            count.div_ceil(records_per_page)
        } else {
            count
                .checked_mul(pages_per_record)
                .ok_or_else(|| corrupt(&path, "DiskANN page count overflow"))?
        };
        let expected_len = (1usize)
            .checked_add(expected_data_pages)
            .and_then(|pages| pages.checked_mul(PAGE_SIZE))
            .ok_or_else(|| corrupt(&path, "DiskANN file length overflow"))?;
        if data_pages != expected_data_pages || object_len != expected_len as u64 {
            return Err(corrupt(&path, "DiskANN file length mismatch"));
        }
        Ok(Self {
            source,
            path,
            object_len,
            count,
            vector_dim,
            degree,
            record_bytes,
            records_per_page,
            pages_per_record,
            data_pages,
            cache_id: NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed),
            physical_page_reads: AtomicU64::new(0),
            remote_range_requests: AtomicU64::new(0),
            remote_range_pages: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            requested_records: AtomicU64::new(0),
            requested_pages: AtomicU64::new(0),
            page_read_errors: AtomicU64::new(0),
            _memory: memory,
        })
    }

    pub fn record(&self, ordinal: usize) -> Option<DiskAnnRecord> {
        self.try_record(ordinal).ok()
    }

    /// Read a record without turning a storage failure into an absent row.
    pub fn try_record(&self, ordinal: usize) -> Result<DiskAnnRecord> {
        self.read_record(
            ordinal,
            |bytes| decode_record(bytes, self.vector_dim, self.degree, self.count, ordinal),
            "invalid DiskANN record",
        )
    }

    pub fn vector(&self, ordinal: usize) -> Option<Vec<f32>> {
        self.try_vector(ordinal).ok()
    }

    pub fn try_vector(&self, ordinal: usize) -> Result<Vec<f32>> {
        self.read_record(
            ordinal,
            |bytes| decode_vector(bytes, self.vector_dim),
            "invalid DiskANN vector",
        )
    }

    pub(crate) fn try_vector_admitted(
        &self,
        ordinal: usize,
    ) -> Result<crate::index::VectorRead<'static>> {
        if ordinal >= self.count {
            return Err(GaussError::InvalidRequest(
                "DiskANN ordinal out of range".into(),
            ));
        }
        crate::index::VectorRead::owned_with(self.vector_dim, || self.try_vector(ordinal))
    }

    pub fn neighbors(&self, ordinal: usize) -> Option<Vec<u32>> {
        self.try_neighbors(ordinal).ok()
    }

    pub fn try_neighbors(&self, ordinal: usize) -> Result<Vec<u32>> {
        self.read_record(
            ordinal,
            |bytes| decode_neighbors(bytes, self.vector_dim, self.degree, self.count, ordinal),
            "invalid DiskANN adjacency",
        )
    }

    /// Return a complete rerank batch or the read error; never publish a subset.
    pub fn try_vectors(&self, ordinals: &[usize]) -> Result<Vec<Vec<f32>>> {
        // Public Vec compatibility cannot retain an engine lease. Native
        // rerank uses the private owner through the complete scoring scope.
        Ok(self.try_vectors_admitted(ordinals)?.vectors)
    }

    pub(crate) fn try_vectors_admitted(&self, ordinals: &[usize]) -> Result<AdmittedVectors> {
        if ordinals.is_empty() {
            return Ok(AdmittedVectors {
                vectors: Vec::new(),
                _memory: MetadataCharge::default(),
            });
        }
        if ordinals.iter().any(|ordinal| *ordinal >= self.count) {
            return Err(GaussError::InvalidRequest(
                "DiskANN ordinal out of range".into(),
            ));
        }
        let page_count = ordinals
            .len()
            .checked_mul(self.pages_per_record)
            .ok_or_else(admission::exhausted)?;
        let _memory = admission::batch(page_count)?;
        let vector_memory = admission::vectors(ordinals.len(), self.vector_dim)?;
        let mut pages = Vec::new();
        for &ordinal in ordinals {
            pages.extend(self.record_pages(ordinal).ok_or_else(|| {
                GaussError::InvalidRequest("DiskANN ordinal out of range".into())
            })?);
        }
        pages.sort_unstable();
        pages.dedup();
        self.prefetch_pages(&pages).inspect_err(|_| {
            self.page_read_errors.fetch_add(1, Ordering::Relaxed);
        })?;
        let vectors = ordinals
            .iter()
            .map(|&ordinal| self.try_vector(ordinal))
            .collect::<Result<Vec<_>>>()?;
        Ok(AdmittedVectors {
            vectors,
            _memory: vector_memory,
        })
    }

    /// Batch page acquisition for the final rerank set. Unique pages are
    /// issued once, then individual records resolve from the bounded cache.
    pub fn vectors(&self, ordinals: &[usize]) -> Vec<Option<Vec<f32>>> {
        let mut pages = ordinals
            .iter()
            .filter_map(|ordinal| self.record_pages(*ordinal))
            .flatten()
            .collect::<Vec<_>>();
        pages.sort_unstable();
        pages.dedup();
        let _ = self.prefetch_pages(&pages);
        ordinals
            .iter()
            .map(|ordinal| self.vector(*ordinal))
            .collect()
    }

    pub fn stats(&self) -> DiskAnnIoStats {
        DiskAnnIoStats {
            active_segments: 1,
            remote_segments: u64::from(self.source.is_remote()),
            data_pages: self.data_pages as u64,
            cache_capacity_bytes: self.cache_capacity_bytes() as u64,
            physical_page_reads: self.physical_page_reads.load(Ordering::Relaxed),
            remote_range_requests: self.remote_range_requests.load(Ordering::Relaxed),
            remote_range_pages: self.remote_range_pages.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            requested_records: self.requested_records.load(Ordering::Relaxed),
            requested_pages: self.requested_pages.load(Ordering::Relaxed),
            bytes_read: self
                .physical_page_reads
                .load(Ordering::Relaxed)
                .saturating_mul(PAGE_SIZE as u64),
            page_read_errors: self.page_read_errors.load(Ordering::Relaxed),
        }
    }

    pub fn reset_stats(&self) {
        self.physical_page_reads.store(0, Ordering::Relaxed);
        self.remote_range_requests.store(0, Ordering::Relaxed);
        self.remote_range_pages.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.requested_records.store(0, Ordering::Relaxed);
        self.requested_pages.store(0, Ordering::Relaxed);
        self.page_read_errors.store(0, Ordering::Relaxed);
        global_page_cache()
            .lock()
            .expect("DiskANN cache poisoned")
            .remove_source(self.cache_id);
    }

    pub fn cache_capacity_bytes(&self) -> usize {
        GLOBAL_CACHE_BYTES
    }

    pub fn data_pages(&self) -> usize {
        self.data_pages
    }

    pub(crate) fn object_len(&self) -> u64 {
        self.object_len
    }

    pub(crate) fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    /// Per-read page/range/controller/record overlap and decoded vector output.
    /// Shared page-cache retention requires its own owner, outside this scratch.
    pub(crate) fn vector_read_workspace_bytes(&self) -> Result<u64> {
        (self.record_bytes as u64)
            .checked_add(
                (self.vector_dim as u64)
                    .checked_mul(4)
                    .ok_or_else(|| corrupt(&self.path, "vector read width overflow"))?,
            )
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| n.checked_add((4 * PAGE_SIZE + 8192) as u64))
            .ok_or_else(|| corrupt(&self.path, "vector read workspace overflow"))
    }

    fn record_bytes(&self, ordinal: usize) -> Result<Vec<u8>> {
        let pages = self
            .record_pages(ordinal)
            .ok_or_else(|| corrupt(&self.path, "DiskANN ordinal out of range"))?;
        if self.records_per_page > 0 {
            let payload = self.read_page(pages.start)?;
            let slot = ordinal % self.records_per_page;
            let start = slot * self.record_bytes;
            return Ok(payload[start..start + self.record_bytes].to_vec());
        }
        let mut record = Vec::with_capacity(self.record_bytes);
        for page in pages {
            let payload = self.read_page(page)?;
            let remaining = self.record_bytes - record.len();
            record.extend_from_slice(&payload[..remaining.min(PAGE_PAYLOAD_BYTES)]);
        }
        Ok(record)
    }

    fn read_record<T>(
        &self,
        ordinal: usize,
        decode: impl FnOnce(&[u8]) -> Option<T>,
        invalid_record: &str,
    ) -> Result<T> {
        self.requested_records.fetch_add(1, Ordering::Relaxed);
        if ordinal >= self.count {
            return Err(GaussError::InvalidRequest(
                "DiskANN ordinal out of range".into(),
            ));
        }
        let _memory = admission::reserve(self.vector_read_workspace_bytes()?)?;
        self.record_bytes(ordinal)
            .and_then(|bytes| decode(&bytes).ok_or_else(|| corrupt(&self.path, invalid_record)))
            .inspect_err(|_| {
                self.page_read_errors.fetch_add(1, Ordering::Relaxed);
            })
    }

    fn record_pages(&self, ordinal: usize) -> Option<std::ops::Range<u64>> {
        if ordinal >= self.count {
            return None;
        }
        if self.records_per_page > 0 {
            let page = (ordinal / self.records_per_page) as u64;
            Some(page..page + 1)
        } else {
            let start = ordinal.checked_mul(self.pages_per_record)? as u64;
            Some(start..start + self.pages_per_record as u64)
        }
    }

    fn read_page(&self, data_page: u64) -> Result<Arc<CachedPage>> {
        self.requested_pages.fetch_add(1, Ordering::Relaxed);
        if let Some(payload) = global_page_cache()
            .lock()
            .expect("DiskANN cache poisoned")
            .get((self.cache_id, data_page))
        {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(payload);
        }
        if data_page >= self.data_pages as u64 {
            return Err(corrupt(&self.path, "DiskANN page out of range"));
        }
        // Keep the fetched pin instead of looking it up after releasing the
        // cache lock: another reader may evict it between those operations.
        self.fetch_pages(&[data_page])?
            .pages
            .pop()
            .ok_or_else(|| corrupt(&self.path, "missing fetched DiskANN page"))
    }

    fn prefetch_pages(&self, pages: &[u64]) -> Result<()> {
        if pages.is_empty() {
            return Ok(());
        }
        let _memory = admission::batch(pages.len())?;
        let missing = {
            let cache = global_page_cache().lock().expect("DiskANN cache poisoned");
            pages
                .iter()
                .copied()
                .filter(|page| !cache.pages.contains_key(&(self.cache_id, *page)))
                .collect::<Vec<_>>()
        };
        self.fetch_pages(&missing).map(|_| ())
    }

    fn fetch_pages(&self, pages: &[u64]) -> Result<FetchedPages> {
        if pages.is_empty() {
            return Ok(FetchedPages {
                pages: Vec::new(),
                _memory: MetadataCharge::default(),
            });
        }
        if pages.iter().any(|page| *page >= self.data_pages as u64) {
            return Err(corrupt(&self.path, "DiskANN page out of range"));
        }
        let memory = admission::batch(pages.len())?;
        let mut page_memory = Vec::new();
        page_memory
            .try_reserve_exact(pages.len())
            .map_err(|_| admission::exhausted())?;
        for _ in pages {
            page_memory.push(admission::reserve(admission::page_bytes())?);
        }
        let ranges = pages
            .iter()
            .map(|page| {
                let start = (page + 1).saturating_mul(PAGE_SIZE as u64);
                start..start + PAGE_SIZE as u64
            })
            .collect::<Vec<_>>();
        let fetched = self.source.read_ranges(&self.path, &ranges)?;
        if fetched.len() != pages.len() {
            return Err(corrupt(
                &self.path,
                "DiskANN range read returned the wrong page count",
            ));
        }
        if self.source.is_remote() {
            self.remote_range_requests.fetch_add(1, Ordering::Relaxed);
            self.remote_range_pages
                .fetch_add(pages.len() as u64, Ordering::Relaxed);
        }
        // Validate the whole response before publishing any derived pages.
        for page in fetched.iter() {
            if page.len() != PAGE_SIZE {
                return Err(corrupt(&self.path, "short DiskANN data-page range"));
            }
            let expected_crc =
                u32::from_le_bytes(page[PAGE_PAYLOAD_BYTES..].try_into().expect("page crc"));
            if crc(&page[..PAGE_PAYLOAD_BYTES]) != expected_crc {
                return Err(corrupt(&self.path, "DiskANN data page CRC mismatch"));
            }
        }
        let mut staged = FetchedPages {
            pages: Vec::new(),
            _memory: memory,
        };
        staged
            .pages
            .try_reserve_exact(pages.len())
            .map_err(|_| admission::exhausted())?;
        for (page, memory) in fetched.iter().zip(page_memory) {
            staged.pages.push(Arc::new(CachedPage {
                payload: page[..PAGE_PAYLOAD_BYTES]
                    .try_into()
                    .expect("checked page payload"),
                _memory: memory,
            }));
        }
        let mut cache = global_page_cache().lock().expect("DiskANN cache poisoned");
        for (data_page, payload) in pages.iter().copied().zip(&staged.pages) {
            cache.insert((self.cache_id, data_page), payload.clone())?;
            self.physical_page_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(staged)
    }
}

impl Drop for DiskAnnArtifact {
    fn drop(&mut self) {
        if let Some(cache) = GLOBAL_PAGE_CACHE.get()
            && let Ok(mut cache) = cache.lock()
        {
            cache.remove_source(self.cache_id);
        }
    }
}

fn block_on_object_store<F: Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        _ => block_on(future),
    }
}

pub fn write_diskann_artifact<I: VectorInput + ?Sized>(
    input: &I,
    vamana: &VamanaArtifact,
    ivf: &crate::index::ivf::IvfArtifact,
    vector_dim: usize,
    path: &Path,
) -> Result<()> {
    if input.len() == 0
        || input.len() != vamana.len()
        || input.len() != ivf.len()
        || vector_dim != vamana.vector_dim()
    {
        return Err(GaussError::InvalidRequest(
            "DiskANN source disagrees with Vamana".to_string(),
        ));
    }
    let degree = vamana.degree();
    let record_bytes = vector_dim
        .checked_mul(2)
        .and_then(|bytes| {
            degree
                .checked_mul(4)
                .and_then(|adjacency| adjacency.checked_add(8))
                .and_then(|adjacency| bytes.checked_add(adjacency))
        })
        .ok_or_else(|| GaussError::InvalidRequest("DiskANN record width overflow".to_string()))?;
    let records_per_page = if record_bytes <= PAGE_PAYLOAD_BYTES {
        PAGE_PAYLOAD_BYTES / record_bytes
    } else {
        0
    };
    let pages_per_record = if records_per_page > 0 {
        1
    } else {
        record_bytes.div_ceil(PAGE_PAYLOAD_BYTES)
    };
    let data_pages = if records_per_page > 0 {
        input.len().div_ceil(records_per_page)
    } else {
        input
            .len()
            .checked_mul(pages_per_record)
            .ok_or_else(|| GaussError::InvalidRequest("DiskANN page count overflow".to_string()))?
    };
    let ordinal_to_record = if vamana.uses_rabitq_record_keys() {
        let mut inverse = vec![u32::MAX; ivf.len()];
        for record in 0..ivf.len() {
            let ordinal = ivf.try_posting_ordinal(record)? as usize;
            inverse[ordinal] = record as u32;
        }
        Some(inverse)
    } else {
        None
    };
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    write_header(
        &mut file,
        input.len(),
        vector_dim,
        degree,
        (record_bytes, records_per_page, pages_per_record, data_pages),
    )?;
    if records_per_page > 0 {
        let mut page = [0_u8; PAGE_PAYLOAD_BYTES];
        for ordinal in 0..input.len() {
            let slot = ordinal % records_per_page;
            if slot == 0 {
                page.fill(0);
            }
            let record = encode_record(
                input,
                vamana,
                ivf,
                ordinal_to_record.as_deref(),
                ordinal,
                vector_dim,
                degree,
            )?;
            let start = slot * record_bytes;
            page[start..start + record_bytes].copy_from_slice(&record);
            if slot + 1 == records_per_page || ordinal + 1 == input.len() {
                write_page(&mut file, &page)?;
            }
        }
    } else {
        for ordinal in 0..input.len() {
            let record = encode_record(
                input,
                vamana,
                ivf,
                ordinal_to_record.as_deref(),
                ordinal,
                vector_dim,
                degree,
            )?;
            for chunk in record.chunks(PAGE_PAYLOAD_BYTES) {
                let mut page = [0_u8; PAGE_PAYLOAD_BYTES];
                page[..chunk.len()].copy_from_slice(chunk);
                write_page(&mut file, &page)?;
            }
        }
    }
    file.sync_all()?;
    Ok(())
}

fn encode_record<I: VectorInput + ?Sized>(
    input: &I,
    vamana: &VamanaArtifact,
    ivf: &crate::index::ivf::IvfArtifact,
    ordinal_to_record: Option<&[u32]>,
    ordinal: usize,
    vector_dim: usize,
    degree: usize,
) -> Result<Vec<u8>> {
    let point = input.point(ordinal)?;
    if point.vector.len() != vector_dim {
        return Err(GaussError::DimensionMismatch {
            expected: vector_dim,
            actual: point.vector.len(),
        });
    }
    let mut record = scaled_f16_row_bytes(&point.vector)?;
    let key = ordinal_to_record
        .map(|inverse| inverse[ordinal] as usize)
        .unwrap_or(ordinal);
    let mut neighbors = Vec::new();
    vamana.try_visit_neighbor_keys(key, |neighbor| {
        neighbors.push(if ordinal_to_record.is_some() {
            ivf.try_posting_ordinal(neighbor as usize)?
        } else {
            neighbor
        });
        Ok(())
    })?;
    record.extend_from_slice(&(neighbors.len() as u32).to_le_bytes());
    for neighbor in neighbors {
        record.extend_from_slice(&neighbor.to_le_bytes());
    }
    record.resize(4 + vector_dim * 2 + 4 + degree * 4, 0);
    Ok(record)
}

fn decode_record(
    bytes: &[u8],
    vector_dim: usize,
    degree: usize,
    count: usize,
    ordinal: usize,
) -> Option<DiskAnnRecord> {
    let vector = decode_vector(bytes, vector_dim)?;
    let neighbors = decode_neighbors(bytes, vector_dim, degree, count, ordinal)?;
    Some(DiskAnnRecord { vector, neighbors })
}

fn decode_vector(bytes: &[u8], vector_dim: usize) -> Option<Vec<f32>> {
    if bytes.len() < 4 + vector_dim * 2 {
        return None;
    }
    let scale = f32::from_le_bytes(bytes[..4].try_into().ok()?);
    if !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    Some(
        bytes[4..4 + vector_dim * 2]
            .chunks_exact(2)
            .map(|bits| {
                half::f16::from_bits(u16::from_le_bytes(bits.try_into().expect("f16 bits")))
                    .to_f32()
                    * scale
            })
            .collect(),
    )
}

fn decode_neighbors(
    bytes: &[u8],
    vector_dim: usize,
    degree: usize,
    count: usize,
    ordinal: usize,
) -> Option<Vec<u32>> {
    if bytes.len() != 4 + vector_dim * 2 + 4 + degree * 4 {
        return None;
    }
    let adjacency_start = 4 + vector_dim * 2;
    let len = u32::from_le_bytes(
        bytes[adjacency_start..adjacency_start + 4]
            .try_into()
            .ok()?,
    ) as usize;
    if len > degree {
        return None;
    }
    let neighbors = bytes[adjacency_start + 4..adjacency_start + 4 + len * 4]
        .chunks_exact(4)
        .map(|neighbor| u32::from_le_bytes(neighbor.try_into().expect("neighbor")))
        .collect::<Vec<_>>();
    let mut unique = std::collections::HashSet::with_capacity(neighbors.len());
    if neighbors
        .iter()
        .any(|neighbor| *neighbor as usize >= count || *neighbor as usize == ordinal)
        || !neighbors.iter().all(|neighbor| unique.insert(*neighbor))
    {
        return None;
    }
    Some(neighbors)
}

fn write_header(
    file: &mut File,
    count: usize,
    vector_dim: usize,
    degree: usize,
    layout: (usize, usize, usize, usize),
) -> Result<()> {
    let (record_bytes, records_per_page, pages_per_record, data_pages) = layout;
    let mut header = [0_u8; PAGE_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&0_u32.to_le_bytes());
    header[16..24].copy_from_slice(&(count as u64).to_le_bytes());
    header[24..28].copy_from_slice(&(vector_dim as u32).to_le_bytes());
    header[28..32].copy_from_slice(&(degree as u32).to_le_bytes());
    header[32..36].copy_from_slice(&(record_bytes as u32).to_le_bytes());
    header[36..40].copy_from_slice(&(records_per_page as u32).to_le_bytes());
    header[40..44].copy_from_slice(&(pages_per_record as u32).to_le_bytes());
    header[44..48].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
    header[48..52].copy_from_slice(&(PAGE_PAYLOAD_BYTES as u32).to_le_bytes());
    header[52..56].copy_from_slice(&(CACHE_PAGES as u32).to_le_bytes());
    header[56..64].copy_from_slice(&(data_pages as u64).to_le_bytes());
    let checksum = crc(&header[..HEADER_CRC_OFFSET]);
    header[HEADER_CRC_OFFSET..].copy_from_slice(&checksum.to_le_bytes());
    file.write_all(&header)?;
    Ok(())
}

fn write_page(file: &mut File, payload: &[u8; PAGE_PAYLOAD_BYTES]) -> Result<()> {
    file.write_all(payload)?;
    file.write_all(&crc(payload).to_le_bytes())?;
    Ok(())
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !output.is_empty() {
        let read = file.read_at(output, offset)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        offset += read as u64;
        output = &mut output[read..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut output: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !output.is_empty() {
        let read = file.seek_read(output, offset)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        offset += read as u64;
        output = &mut output[read..];
    }
    Ok(())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 header"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 header"))
}

fn usize_from_u64(value: u64, path: &Path, field: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(path, &format!("DiskANN {field} exceeds usize")))
}

fn crc(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::Arc;

    use object_store::{ObjectStore, local::LocalFileSystem, path::Path as ObjectPath};
    use tempfile::TempDir;

    use super::{DISKANN_FILE, DiskAnnArtifact, GLOBAL_CACHE_BYTES, PAGE_SIZE};
    use crate::DistanceMetric;
    use crate::index::ivf::{IVF_FILE, IvfArtifact};
    use crate::model::Point;
    use crate::seal::{SealConfig, SealIndexKind, build_segment};

    fn point(ordinal: usize, dim: usize) -> Point {
        Point {
            id: format!("p{ordinal:03}"),
            vector: (0..dim)
                .map(|dimension| ordinal as f32 + dimension as f32 / dim as f32)
                .collect(),
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        }
    }

    fn build(dim: usize, count: usize) -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().unwrap();
        let segment = temp.path().join("segment");
        let points = (0..count)
            .map(|ordinal| point(ordinal, dim))
            .collect::<Vec<_>>();
        build_segment(
            points.as_slice(),
            &segment,
            SealConfig {
                vector_dim: dim,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        (temp, segment)
    }

    #[test]
    fn cached_page_admission_survives_eviction_and_source_drop_until_last_pin() {
        let (_temp, segment) = build(8, 32);
        let artifact = DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 32, 8).unwrap();
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            let pin = artifact.read_page(0).unwrap();
            let bytes = used();
            assert!(bytes > super::PAGE_PAYLOAD_BYTES as u64);
            let clone = pin.clone();
            assert_eq!(used(), bytes);
            artifact.reset_stats();
            let pinned = used();
            assert!(pinned > super::PAGE_PAYLOAD_BYTES as u64 && pinned <= bytes);
            drop(artifact);
            assert_eq!(used(), pinned);
            assert_eq!(pin.payload, clone.payload);
            drop(pin);
            assert_eq!(used(), pinned);
            drop(clone);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn page_cache_container_growth_refuses_before_publication_and_churn_retains_buckets() {
        use super::{CachedPage, PageCache, admission};
        use crate::relational::wal_decode::with_test_storage_pool;
        let page = Arc::new(CachedPage {
            payload: [7; super::PAGE_PAYLOAD_BYTES],
            _memory: admission::reserve(admission::page_bytes()).unwrap(),
        });
        with_test_storage_pool(1, |used| {
            let mut cache = PageCache::new();
            assert_eq!(used(), 0);
            assert!(matches!(
                cache.insert((1, 0), page.clone()),
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert!(cache.pages.is_empty() && cache.order.is_empty());
            assert_eq!(cache.pages.capacity(), 0);
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            let mut cache = PageCache::new();
            for i in 0..200 {
                cache.insert((i, 0), page.clone()).unwrap();
                if i > 2 {
                    cache.remove_source(i - 2);
                }
                assert!(used() >= cache.hash_capacity as u64 * 128);
                assert_eq!(cache.pages.len(), cache.order.len());
            }
            let bucket_capacity = cache.hash_capacity;
            cache.remove_source(199);
            assert_eq!(cache.hash_capacity, bucket_capacity);
            assert!(used() >= bucket_capacity as u64 * 128);
            cache.clear();
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn duplicate_page_owners_remain_admitted_after_cache_replacement() {
        use super::{CachedPage, PageCache, admission};
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            let make = || {
                Arc::new(CachedPage {
                    payload: [7; super::PAGE_PAYLOAD_BYTES],
                    _memory: admission::reserve(admission::page_bytes()).unwrap(),
                })
            };
            let first = make();
            let bytes = used();
            let second = make();
            assert_eq!(used(), 2 * bytes);
            let mut cache = PageCache::new();
            cache.insert((1, 0), first.clone()).unwrap();
            cache.insert((1, 0), second.clone()).unwrap();
            assert_eq!(cache.pages.len(), 1);
            cache.clear();
            assert_eq!(used(), 2 * bytes);
            drop(first);
            assert_eq!(used(), bytes);
            drop(second);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn late_page_crc_failure_publishes_no_batch_and_releases_admission() {
        let (_temp, segment) = build(2200, 3);
        let path = segment.join(DISKANN_FILE);
        let artifact = DiskAnnArtifact::open(&path, 3, 2200).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut damaged = original.clone();
        damaged[super::PAGE_SIZE * 4 - 1] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            assert!(
                matches!(artifact.try_vectors(&[0,1]),Err(crate::GaussError::SegmentCorruption {message,..}) if message.contains("CRC mismatch"))
            );
            assert_eq!(used(), 0);
            assert!(
                !super::global_page_cache()
                    .lock()
                    .unwrap()
                    .pages
                    .keys()
                    .any(|(source, _)| *source == artifact.cache_id)
            );
        });
        std::fs::write(&path, original).unwrap();
        assert_eq!(artifact.try_vectors(&[0, 1]).unwrap().len(), 2);
        drop(artifact);
        assert_eq!(
            DiskAnnArtifact::open(&path, 3, 2200)
                .unwrap()
                .try_vectors(&[0, 1])
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn remote_page_budget_precedes_provider_failure_and_retry_preserves_order() {
        let (_temp, segment) = build(128, 32);
        let source = segment.join(DISKANN_FILE);
        let remote = TempDir::new().unwrap();
        let path = remote.path().join(DISKANN_FILE);
        std::fs::copy(&source, &path).unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(remote.path()).unwrap());
        let artifact = DiskAnnArtifact::open_object_store(
            store,
            ObjectPath::from(DISKANN_FILE),
            std::fs::metadata(&source).unwrap().len(),
            32,
            128,
        )
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(
                artifact.try_vectors(&[20, 0, 20]),
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        assert!(matches!(
            artifact.try_vector(0),
            Err(crate::GaussError::SegmentCorruption { .. })
        ));
        std::fs::copy(&source, &path).unwrap();
        let vectors = artifact.try_vectors(&[20, 0, 20]).unwrap();
        assert_eq!(vectors[0], vectors[2]);
        assert!(vectors[0][0] > vectors[1][0]);
    }

    #[test]
    fn page_pressure_evicts_residency_but_refuses_while_readers_pin_memory() {
        let (_temp, segment) = build(2200, 32);
        let artifact = DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 32, 2200).unwrap();
        crate::relational::wal_decode::with_test_storage_pool(96 * 1024, |used| {
            let mut pins = Vec::new();
            let mut refused = None;
            for page in 0..artifact.data_pages() {
                let before = artifact.stats().physical_page_reads;
                match artifact.read_page(page as u64) {
                    Ok(pin) => pins.push(pin),
                    Err(crate::GaussError::ResourceExhausted(_)) => {
                        assert_eq!(artifact.stats().physical_page_reads, before);
                        refused = Some(page as u64);
                        break;
                    }
                    Err(error) => panic!("unexpected refusal: {error}"),
                }
            }
            let refused = refused.expect("live page pins must exhaust the small pool");
            assert!(!pins.is_empty());
            assert!(used() >= pins.len() as u64 * super::PAGE_PAYLOAD_BYTES as u64);
            let first = pins.pop().unwrap();
            pins.clear();
            let retry = artifact.read_page(refused).unwrap();
            drop(retry);
            artifact.reset_stats();
            assert!(used() > super::PAGE_PAYLOAD_BYTES as u64);
            drop(first);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn rerank_vector_owner_retains_admission_and_large_batch_refuses_before_io() {
        let (_temp, segment) = build(2200, 3);
        let artifact = DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 3, 2200).unwrap();
        crate::relational::wal_decode::with_test_storage_pool(50 * 1024, |used| {
            assert!(matches!(
                artifact.try_vectors_admitted(&[0; 9]),
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
            assert_eq!(artifact.stats().physical_page_reads, 0);
        });
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert!(
            matches!(crate::relational::with_sql_cancellation(cancel,|| artifact.try_vectors_admitted(&[0])),Err(crate::GaussError::InvalidRequest(message)) if message=="query canceled")
        );
        crate::relational::wal_decode::with_test_storage_pool(2 * 1024 * 1024, |used| {
            let vectors = artifact.try_vectors_admitted(&[2, 0, 2]).unwrap();
            artifact.reset_stats();
            let bytes = used();
            let capacity = vectors.iter().map(|row| row.capacity() * 4).sum::<usize>();
            assert!(bytes > capacity as u64);
            drop(artifact);
            assert_eq!(used(), bytes);
            assert_eq!(vectors[0], vectors[2]);
            drop(vectors);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn cold_read_budget_refuses_before_physical_io_then_recovers() {
        let (_temp, segment) = build(8, 32);
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(
                DiskAnnArtifact::open(&segment.join("missing"), 32, 8),
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        let artifact = DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 32, 8).unwrap();
        let before = artifact.stats();
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            assert!(matches!(
                artifact.try_vector(0),
                Err(crate::GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
            assert_eq!(
                artifact.stats().physical_page_reads,
                before.physical_page_reads
            );
        });
        assert_eq!(artifact.try_vector(0).unwrap().len(), 8);
        assert_eq!(
            artifact.stats().physical_page_reads,
            before.physical_page_reads + 1
        );
    }

    #[test]
    fn fallible_rerank_batch_preserves_order_duplicates_and_checks_bounds_before_io() {
        let (_temp, segment) = build(128, 32);
        let artifact = DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 32, 128).unwrap();
        let vectors = artifact.try_vectors(&[20, 0, 20]).unwrap();
        assert_eq!(vectors[0], vectors[2]);
        for (actual, ordinal) in vectors.iter().zip([20, 0, 20]) {
            for (actual, expected) in actual.iter().zip(point(ordinal, 128).vector) {
                assert!((actual - expected).abs() < 0.01);
            }
        }
        let before = artifact.stats();
        assert_eq!(before.physical_page_reads, 2);
        assert_eq!(before.requested_records, 3);
        assert!(matches!(
            artifact.try_vectors(&[0, 32]),
            Err(crate::GaussError::InvalidRequest(_))
        ));
        assert!(matches!(
            artifact.try_vector(32),
            Err(crate::GaussError::InvalidRequest(_))
        ));
        assert!(artifact.vector(32).is_none());
        let after = artifact.stats();
        assert_eq!(after.physical_page_reads, before.physical_page_reads);
        assert_eq!(after.requested_pages, before.requested_pages);
        assert_eq!(
            after.page_read_errors, 0,
            "invalid ordinals are not physical IO failures"
        );
        assert!(artifact.try_vectors(&[]).unwrap().is_empty());
    }

    #[test]
    fn cached_pages_survive_shared_artifact_pins_and_release_on_last_drop() {
        let (_temp, segment) = build(8, 32);
        let artifact = Arc::new(DiskAnnArtifact::open(&segment.join(DISKANN_FILE), 32, 8).unwrap());
        artifact.try_vector(0).unwrap();
        let id = artifact.cache_id;
        let pin = artifact.clone();
        drop(artifact);
        assert!(
            super::global_page_cache()
                .lock()
                .unwrap()
                .pages
                .contains_key(&(id, 0))
        );
        pin.try_vector(0).unwrap();
        assert!(pin.stats().cache_hits > 0);
        drop(pin);
        let cache = super::global_page_cache().lock().unwrap();
        assert!(!cache.pages.keys().any(|(source, _)| *source == id));
        assert!(!cache.order.iter().any(|(source, _)| *source == id));
    }

    #[test]
    fn fallible_object_store_reads_reject_unavailable_or_corrupt_data_and_retry() {
        let (_temp, segment) = build(128, 32);
        let source = segment.join(DISKANN_FILE);
        let remote = TempDir::new().unwrap();
        let remote_path = remote.path().join(DISKANN_FILE);
        std::fs::copy(&source, &remote_path).unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(remote.path()).unwrap());
        let artifact = DiskAnnArtifact::open_object_store(
            store,
            ObjectPath::from(DISKANN_FILE),
            source.metadata().unwrap().len(),
            32,
            128,
        )
        .unwrap();
        std::fs::remove_file(&remote_path).unwrap();
        assert!(
            matches!(artifact.try_vector(0), Err(crate::GaussError::SegmentCorruption {message, ..}) if message.contains("range read failed"))
        );
        let mut corrupt = std::fs::read(&source).unwrap();
        corrupt[PAGE_SIZE + 11] ^= 0xff;
        std::fs::write(&remote_path, &corrupt).unwrap();
        assert!(
            matches!(artifact.try_vectors(&[0, 20]), Err(crate::GaussError::SegmentCorruption {message, ..}) if message.contains("CRC mismatch"))
        );
        assert_eq!(artifact.stats().page_read_errors, 2);
        std::fs::copy(source, &remote_path).unwrap();
        let values = artifact.try_vectors(&[0, 20]).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(artifact.stats().page_read_errors, 2);
    }

    #[test]
    fn fallible_reads_preserve_physical_io_failure_and_retry_after_repair() {
        let (_temp, segment) = build(8, 32);
        let path = segment.join(DISKANN_FILE);
        let original = std::fs::read(&path).unwrap();
        let artifact = DiskAnnArtifact::open(&path, 32, 8).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(PAGE_SIZE as u64)
            .unwrap();
        for error in [
            artifact.try_vector(0).unwrap_err(),
            artifact.try_record(0).unwrap_err(),
            artifact.try_neighbors(0).unwrap_err(),
        ] {
            assert!(
                matches!(error, crate::GaussError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        }
        assert_eq!(artifact.stats().page_read_errors, 3);
        std::fs::write(&path, &original).unwrap();
        let vectors = artifact.try_vectors(&[0, 7]).unwrap();
        assert_eq!(vectors.len(), 2);
        assert_eq!(artifact.try_record(7).unwrap().vector, vectors[1]);
        assert_eq!(artifact.stats().page_read_errors, 3);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn fallible_batch_returns_crc_failure_without_a_partial_result() {
        let (_temp, segment) = build(128, 32);
        let path = segment.join(DISKANN_FILE);
        let artifact = DiskAnnArtifact::open(&path, 32, 128).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let corrupt_offset = ((1 + 20 / artifact.records_per_page) * PAGE_SIZE + 11) as u64;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&[byte[0] ^ 0xff]).unwrap();
        file.sync_all().unwrap();
        assert!(
            matches!(artifact.try_vectors(&[0, 20]), Err(crate::GaussError::SegmentCorruption {message, ..}) if message.contains("CRC mismatch"))
        );
        assert_eq!(artifact.stats().page_read_errors, 1);
        assert!(
            artifact.try_vector(0).is_ok(),
            "the healthy first page remains readable"
        );
    }

    #[test]
    fn fallible_decode_rejects_invalid_rows_even_with_a_valid_page_crc() {
        let (_temp, segment) = build(8, 32);
        let path = segment.join(DISKANN_FILE);
        let original = std::fs::read(&path).unwrap();
        for (offset, replacement, message) in [
            (0, f32::NAN.to_bits(), "vector"),
            (4 + 8 * 2, u32::MAX, "adjacency"),
        ] {
            let mut bytes = original.clone();
            let page = &mut bytes[PAGE_SIZE..2 * PAGE_SIZE];
            page[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
            let crc = super::crc(&page[..super::PAGE_PAYLOAD_BYTES]);
            page[super::PAGE_PAYLOAD_BYTES..].copy_from_slice(&crc.to_le_bytes());
            std::fs::write(&path, bytes).unwrap();
            let artifact = DiskAnnArtifact::open(&path, 32, 8).unwrap();
            let error = if message == "vector" {
                artifact.try_vector(0).unwrap_err()
            } else {
                artifact.try_neighbors(0).unwrap_err()
            };
            assert!(
                matches!(error, crate::GaussError::SegmentCorruption {message: text, ..} if text.contains(message))
            );
            assert!(matches!(
                artifact.try_record(0),
                Err(crate::GaussError::SegmentCorruption { .. })
            ));
            assert_eq!(artifact.stats().page_read_errors, 2);
        }
    }

    #[test]
    fn packed_records_roundtrip_through_bounded_page_cache() {
        let (_temp, segment) = build(8, 32);
        let ivf = IvfArtifact::open(&segment.join(IVF_FILE)).unwrap();
        let artifact =
            DiskAnnArtifact::open(&segment.join(DISKANN_FILE), ivf.len(), ivf.vector_dim())
                .unwrap();

        artifact.reset_stats();
        let first = artifact.record(7).unwrap();
        let second = artifact.record(7).unwrap();
        assert_eq!(first.neighbors, second.neighbors);
        for (actual, expected) in first.vector.iter().zip(point(7, 8).vector) {
            assert!((actual - expected).abs() < 0.01);
        }
        let stats = artifact.stats();
        assert_eq!(stats.active_segments, 1);
        assert_eq!(stats.physical_page_reads, 1);
        assert!(stats.cache_hits >= 1);
        assert_eq!(stats.cache_capacity_bytes, GLOBAL_CACHE_BYTES as u64);
        assert_eq!(stats.page_read_errors, 0);
    }

    #[test]
    fn large_records_use_multiple_crc_checked_pages() {
        let (_temp, segment) = build(2_048, 4);
        let ivf = IvfArtifact::open(&segment.join(IVF_FILE)).unwrap();
        let artifact =
            DiskAnnArtifact::open(&segment.join(DISKANN_FILE), ivf.len(), ivf.vector_dim())
                .unwrap();

        artifact.reset_stats();
        assert_eq!(artifact.vector(2).unwrap().len(), 2_048);
        assert!(
            artifact.stats().physical_page_reads >= 2,
            "a record wider than one page must issue multiple reads"
        );
    }

    #[test]
    fn page_corruption_is_lazy_and_observable() {
        let (_temp, segment) = build(8, 32);
        let path = segment.join(DISKANN_FILE);
        let ivf = IvfArtifact::open(&segment.join(IVF_FILE)).unwrap();
        let artifact = DiskAnnArtifact::open(&path, ivf.len(), ivf.vector_dim()).unwrap();
        drop(artifact);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(PAGE_SIZE as u64 + 11)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(PAGE_SIZE as u64 + 11)).unwrap();
        file.write_all(&[byte[0] ^ 0xFF]).unwrap();
        file.sync_all().unwrap();

        // Open validates only the header and shape so a cold artifact is not
        // pulled into memory. The accessed page detects its own CRC failure.
        crate::seal::read_marker(&segment.join(crate::seal::SEAL_FILE)).unwrap();
        let artifact = DiskAnnArtifact::open(&path, ivf.len(), ivf.vector_dim()).unwrap();
        assert!(artifact.record(0).is_none());
        assert_eq!(artifact.stats().page_read_errors, 1);
    }

    #[test]
    fn object_store_source_batches_exact_page_ranges() {
        let (_temp, segment) = build(128, 32);
        let source = segment.join(DISKANN_FILE);
        let ivf = IvfArtifact::open(&segment.join(IVF_FILE)).unwrap();
        let remote = TempDir::new().unwrap();
        std::fs::copy(&source, remote.path().join(DISKANN_FILE)).unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(remote.path()).unwrap());
        let artifact = DiskAnnArtifact::open_object_store(
            store,
            ObjectPath::from(DISKANN_FILE),
            source.metadata().unwrap().len(),
            ivf.len(),
            ivf.vector_dim(),
        )
        .unwrap();

        artifact.reset_stats();
        let vectors = artifact.vectors(&[0, 20]);
        assert!(vectors.iter().all(Option::is_some));
        let stats = artifact.stats();
        assert_eq!(stats.remote_segments, 1);
        assert_eq!(stats.remote_range_requests, 1);
        assert_eq!(stats.remote_range_pages, 2);
        assert_eq!(stats.physical_page_reads, 2);
        assert_eq!(stats.bytes_read, (2 * PAGE_SIZE) as u64);
        assert_eq!(stats.page_read_errors, 0);
    }

    #[test]
    fn object_store_page_corruption_is_detected_lazily() {
        let (_temp, segment) = build(8, 32);
        let source = segment.join(DISKANN_FILE);
        let ivf = IvfArtifact::open(&segment.join(IVF_FILE)).unwrap();
        let remote = TempDir::new().unwrap();
        let remote_path = remote.path().join(DISKANN_FILE);
        std::fs::copy(&source, &remote_path).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&remote_path)
            .unwrap();
        file.seek(SeekFrom::Start(PAGE_SIZE as u64 + 11)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(PAGE_SIZE as u64 + 11)).unwrap();
        file.write_all(&[byte[0] ^ 0xFF]).unwrap();
        file.sync_all().unwrap();

        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(remote.path()).unwrap());
        let artifact = DiskAnnArtifact::open_object_store(
            store,
            ObjectPath::from(DISKANN_FILE),
            source.metadata().unwrap().len(),
            ivf.len(),
            ivf.vector_dim(),
        )
        .unwrap();
        assert!(artifact.record(0).is_none());
        let stats = artifact.stats();
        assert_eq!(stats.remote_range_requests, 1);
        assert_eq!(stats.page_read_errors, 1);
        assert_eq!(stats.physical_page_reads, 0);
    }
}
