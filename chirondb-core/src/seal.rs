//! Append-only LS-Vec sealed-segment writer.
//!
//! The writer consumes one point at a time, writes the immutable store before
//! building its paged HNSW, and publishes `seal.gdx` last. Directory install
//! is intentionally owned by `db.rs`; this module never removes siblings.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    fs::{self, File},
    io::{BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use crc32fast::Hasher;
use half::f16;
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

use crate::{
    DistanceMetric, GaussError, Point, Result,
    encryption::{self, FileType},
    h2qg,
};

pub(crate) mod graph;

pub const VECTOR_FILE: &str = "vec.gdx";
pub const IDS_FILE: &str = "ids.gdx";
pub const PAYLOAD_FILE: &str = "payload.gdx";
pub const TOMBSTONE_FILE: &str = "tomb.gdx";
pub const SEAL_FILE: &str = "seal.gdx";

const VECTOR_MAGIC_V4: &[u8; 8] = b"GAUSSV04";
const VECTOR_MAGIC_V5: &[u8; 8] = b"GAUSSV05";
const IDS_MAGIC: &[u8; 8] = b"GAUSSID4";
const PAYLOAD_MAGIC: &[u8; 8] = b"GAUSSPY4";
const TOMBSTONE_MAGIC: &[u8; 8] = b"GAUSSTM4";
const SEAL_MAGIC: &[u8; 8] = b"GAUSSSL4";
const MAX_MARKER_BYTES: usize = 1024 * 1024;
const HNSW_SEALED_FILES: [&str; 6] = [
    VECTOR_FILE,
    IDS_FILE,
    PAYLOAD_FILE,
    h2qg::HNSW_VECS_FILE,
    h2qg::INDEX_FILE,
    TOMBSTONE_FILE,
];
const ALGORITHM2_SEALED_FILES_V5: [&str; 7] = [
    VECTOR_FILE,
    IDS_FILE,
    PAYLOAD_FILE,
    crate::index::ivf::IVF_FILE,
    crate::index::rabitq::RABITQ_FILE,
    crate::index::vamana::VAMANA_SEGMENT_FILE,
    TOMBSTONE_FILE,
];
const ALGORITHM2_SEALED_FILES_V6: [&str; 8] = [
    VECTOR_FILE,
    IDS_FILE,
    PAYLOAD_FILE,
    crate::index::ivf::IVF_FILE,
    crate::index::rabitq::RABITQ_FILE,
    crate::index::vamana::VAMANA_SEGMENT_FILE,
    crate::index::diskann::DISKANN_FILE,
    TOMBSTONE_FILE,
];
const ALGORITHM2_SEALED_FILES_V7_COLD: [&str; 6] = [
    IDS_FILE,
    PAYLOAD_FILE,
    crate::index::ivf::IVF_FILE,
    crate::index::rabitq::RABITQ_FILE,
    crate::index::diskann::DISKANN_FILE,
    TOMBSTONE_FILE,
];

/// Repeatable point source used by both frozen streamers and future mmap
/// merge inputs. Implementations may borrow or hydrate one owned point.
pub trait VectorInput {
    fn len(&self) -> usize;
    fn point(&self, ordinal: usize) -> Result<Cow<'_, Point>>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl VectorInput for [Point] {
    fn len(&self) -> usize {
        <[Point]>::len(self)
    }

    fn point(&self, ordinal: usize) -> Result<Cow<'_, Point>> {
        self.get(ordinal).map(Cow::Borrowed).ok_or_else(|| {
            GaussError::InvalidRequest(format!("vector input ordinal {ordinal} is out of bounds"))
        })
    }
}

struct PagedVectorSource(crate::h2qg::PagedVectors);

impl crate::index::ivf::VectorSource for PagedVectorSource {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>> {
        if ordinal >= self.0.len() {
            return Err(GaussError::InvalidRequest(format!(
                "paged seal vector ordinal {ordinal} is out of bounds"
            )));
        }
        Ok(self.0.get(ordinal))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SealIndexKind {
    Hnsw,
    Algorithm2,
}

#[derive(Clone, Copy, Debug)]
pub struct SealConfig {
    pub vector_dim: usize,
    pub metric: DistanceMetric,
    pub hnsw_m: Option<u32>,
    pub hnsw_ef_construction: Option<u32>,
    pub index_kind: SealIndexKind,
    pub base_lsn: u64,
    pub end_lsn: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealMarker {
    pub version: u32,
    pub points: usize,
    pub vector_dim: usize,
    pub base_lsn: u64,
    pub end_lsn: u64,
    pub files: Vec<SealFile>,
}

impl SealMarker {
    pub(crate) fn has_graph(&self) -> bool {
        matches!(self.version, 10..=15)
    }

    // Only the marker reader may interpret this mapping before validation.
    // A graph version never licenses a vector-only recovery fallback.
    fn vector_version(&self) -> u32 {
        if self.has_graph() {
            self.version - 6
        } else {
            self.version
        }
    }

    fn require_vector_only_recovery(&self, dir: &Path) -> Result<()> {
        if self.has_graph() {
            return Err(corrupt(
                dir,
                "graph segment requires graph-aware collection manifest recovery",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealFile {
    pub name: String,
    pub bytes: u64,
    pub crc: u32,
}

#[derive(Debug)]
pub struct SealWrite {
    pub dir: PathBuf,
    pub marker: SealMarker,
}

#[derive(Clone, Debug)]
pub struct NamedVectorStorageStats {
    pub name: String,
    pub points: usize,
    pub dim: usize,
    pub search_vector_format_version: u32,
    pub search_vector_bytes_per_component: f64,
    pub search_vector_file_bytes: u64,
    pub search_vector_file_bytes_per_vector: f64,
    pub exact_original_preserved_in_payload: bool,
}

#[derive(Serialize)]
struct PointAux<'a> {
    vectors: &'a std::collections::HashMap<String, Vec<f32>>,
    sparse_vector: &'a Option<crate::SparseVector>,
    payload: &'a serde_json::Value,
}

#[derive(Deserialize)]
struct OwnedPointAux {
    vectors: HashMap<String, Vec<f32>>,
    sparse_vector: Option<crate::SparseVector>,
    payload: serde_json::Value,
}

struct NamedVectorWriter {
    vectors: BufWriter<File>,
    ids: Vec<String>,
    dim: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DenseVectorEncoding {
    F32,
    ScaledF16,
}

impl DenseVectorEncoding {
    fn marker_version(self) -> u32 {
        match self {
            Self::F32 => 4,
            Self::ScaledF16 => 5,
        }
    }

    fn row_bytes(self, dim: usize) -> Option<usize> {
        match self {
            Self::F32 => dim.checked_mul(std::mem::size_of::<f32>()),
            Self::ScaledF16 => dim
                .checked_mul(std::mem::size_of::<u16>())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<f32>())),
        }
    }
}

#[derive(Debug)]
pub(crate) struct NamedV4Store {
    vectors: encryption::PersistentFile,
    ids: Vec<String>,
    ordinals: HashMap<String, usize>,
    vector_dim: usize,
    vector_encoding: DenseVectorEncoding,
}

impl NamedV4Store {
    pub(crate) fn open(dir: &Path, name: &str) -> Result<Self> {
        Self::open_with_encoding(dir, name, None)
    }

    fn open_with_encoding(
        dir: &Path,
        name: &str,
        expected_encoding: Option<DenseVectorEncoding>,
    ) -> Result<Self> {
        validate_named_vector_name(name)?;
        let vectors_path = dir.join(named_vector_file(name));
        let ids_path = dir.join(named_ids_file(name));
        let vectors = encryption::PersistentFile::open(&vectors_path)?;
        if vectors.len() < 24 {
            return Err(corrupt(
                &vectors_path,
                "named-vector file is shorter than its header",
            ));
        }
        let header = vectors.read_range(0..24)?;
        let vector_encoding = match header.get(..8) {
            Some(magic) if magic == h2qg::HNSW_VECS_MAGIC => DenseVectorEncoding::F32,
            Some(magic) if magic == VECTOR_MAGIC_V5 => DenseVectorEncoding::ScaledF16,
            _ => return Err(corrupt(&vectors_path, "bad named-vector magic")),
        };
        if expected_encoding.is_some_and(|expected| vector_encoding != expected) {
            return Err(corrupt(
                &vectors_path,
                "named-vector encoding disagrees with seal marker version",
            ));
        }
        let count =
            u64::from_le_bytes(header[8..16].try_into().expect("named-vector count")) as usize;
        let vector_dim =
            u64::from_le_bytes(header[16..24].try_into().expect("named-vector dimension")) as usize;
        if vector_dim == 0 {
            return Err(corrupt(&vectors_path, "named-vector dimension is zero"));
        }
        let expected_bytes = 24_usize
            .checked_add(
                count
                    .checked_mul(
                        vector_encoding
                            .row_bytes(vector_dim)
                            .ok_or_else(|| corrupt(&vectors_path, "named-vector size overflows"))?,
                    )
                    .ok_or_else(|| corrupt(&vectors_path, "named-vector size overflows"))?,
            )
            .ok_or_else(|| corrupt(&vectors_path, "named-vector size overflows"))?;
        if vectors.len() != expected_bytes {
            return Err(corrupt(
                &vectors_path,
                "named-vector file length does not match its header",
            ));
        }
        let ids_file = encryption::PersistentFile::open(&ids_path)?;
        let ids = read_ids_file(&ids_file, &ids_path, count)?;
        let ordinals = ids
            .iter()
            .enumerate()
            .map(|(ordinal, id)| (id.clone(), ordinal))
            .collect::<HashMap<_, _>>();
        if ordinals.len() != ids.len() {
            return Err(corrupt(&ids_path, "named-vector ids contain duplicates"));
        }
        Ok(Self {
            vectors,
            ids,
            ordinals,
            vector_dim,
            vector_encoding,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.ids.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub(crate) fn id(&self, ordinal: usize) -> Option<&str> {
        self.ids.get(ordinal).map(String::as_str)
    }

    pub(crate) fn ordinal(&self, id: &str) -> Option<usize> {
        self.ordinals.get(id).copied()
    }

    pub(crate) fn vector_cow(&self, ordinal: usize) -> Option<Cow<'_, [f32]>> {
        match self.vector_encoding {
            DenseVectorEncoding::F32 => {
                let row_bytes = self.vector_dim.checked_mul(std::mem::size_of::<f32>())?;
                let start = 24_usize.checked_add(ordinal.checked_mul(row_bytes)?)?;
                let bytes = self
                    .vectors
                    .read_range(start..start.checked_add(row_bytes)?)
                    .ok()?;
                match bytes {
                    Cow::Borrowed(bytes) => Some(Cow::Borrowed(unsafe {
                        std::slice::from_raw_parts(bytes.as_ptr().cast::<f32>(), self.vector_dim)
                    })),
                    Cow::Owned(bytes) => Some(Cow::Owned(decode_f32_row(&bytes)?)),
                }
            }
            DenseVectorEncoding::ScaledF16 => self.scaled_f16_vector(ordinal).map(Cow::Owned),
        }
    }

    fn scaled_f16_vector(&self, ordinal: usize) -> Option<Vec<f32>> {
        if ordinal >= self.ids.len() || self.vector_encoding != DenseVectorEncoding::ScaledF16 {
            return None;
        }
        let row_bytes = self.vector_encoding.row_bytes(self.vector_dim)?;
        let start = 24_usize.checked_add(ordinal.checked_mul(row_bytes)?)?;
        let end = start.checked_add(row_bytes)?;
        let row = self.vectors.read_range(start..end).ok()?;
        let scale_end = std::mem::size_of::<f32>();
        let scale = f32::from_le_bytes(row.get(..scale_end)?.try_into().ok()?);
        Some(
            row.get(scale_end..)?
                .chunks_exact(2)
                .map(|bytes| {
                    f16::from_bits(u16::from_le_bytes(
                        bytes.try_into().expect("two-byte f16 component"),
                    ))
                    .to_f32()
                        * scale
                })
                .collect(),
        )
    }
}

pub fn inspect_named_vector_storage(dir: &Path) -> Result<Vec<NamedVectorStorageStats>> {
    let mut stats = named_algorithm2_names(dir)?
        .into_iter()
        .map(|name| {
            let store = NamedV4Store::open(dir, &name)?;
            let file_bytes = fs::metadata(dir.join(named_vector_file(&name)))?.len();
            Ok(NamedVectorStorageStats {
                name,
                points: store.len(),
                dim: store.vector_dim,
                search_vector_format_version: store.vector_encoding.marker_version(),
                search_vector_bytes_per_component: store
                    .vector_encoding
                    .row_bytes(store.vector_dim)
                    .unwrap_or_default() as f64
                    / store.vector_dim as f64,
                search_vector_file_bytes: file_bytes,
                search_vector_file_bytes_per_vector: file_bytes as f64 / store.len() as f64,
                // PointAux deliberately retains the inserted f32 values so
                // get/scroll/merge remain API-faithful across lossy search
                // row migrations.
                exact_original_preserved_in_payload: true,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    stats.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(stats)
}

impl crate::index::ivf::VectorSource for NamedV4Store {
    fn len(&self) -> usize {
        self.len()
    }

    fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>> {
        self.vector_cow(ordinal)
            .ok_or_else(|| GaussError::InvalidRequest("vector ordinal out of range".to_string()))
    }
}

/// Validated view of a committed v4+ segment store. Auxiliary records stay
/// mapped; primary vectors are mapped for hot segments and fetched through
/// bounded DiskANN pages for v7 cold segments.
///
/// The type name is retained for source compatibility. V4 rows are raw f32;
/// V5 rows are power-of-two-scaled f16 with one f32 decode scale per row.
#[derive(Debug)]
pub struct V4Store {
    vectors: PrimaryVectorStore,
    payloads: encryption::PersistentFile,
    ids: Vec<String>,
    ordinals: HashMap<String, usize>,
    payload_offsets: Vec<u64>,
    vector_dim: usize,
    vector_encoding: DenseVectorEncoding,
    segment_format_version: u32,
    payload_start: usize,
}

#[derive(Debug)]
enum PrimaryVectorStore {
    Persistent(encryption::PersistentFile),
    DiskAnn(Arc<crate::index::diskann::DiskAnnArtifact>),
}

impl V4Store {
    pub fn open(dir: &Path) -> Result<Self> {
        let marker = read_marker(&dir.join(SEAL_FILE))?;
        marker.require_vector_only_recovery(dir)?;
        Self::open_local_marker(dir, marker)
    }

    /// Only graph-generation admission may use this entry point. The public
    /// vector-only opener continues to reject graph markers.
    pub(crate) fn open_graph_base(dir: &Path) -> Result<Self> {
        let mut marker = read_marker(&dir.join(SEAL_FILE))?;
        if !marker.has_graph() {
            return Err(corrupt(dir, "graph base requires a graph seal marker"));
        }
        marker.version = marker.vector_version();
        Self::open_local_marker(dir, marker)
    }

    /// Open a graph-marked cold base whose DiskANN artifact remains in the
    /// object store. The marker and graph peers are still checked locally;
    /// only the independently paged DiskANN file may be remote.
    pub(crate) fn open_graph_base_with_diskann(
        dir: &Path,
        diskann: Arc<crate::index::diskann::DiskAnnArtifact>,
    ) -> Result<Self> {
        let mut marker = read_marker_with_diskann_len(&dir.join(SEAL_FILE), diskann.object_len())?;
        if !marker.has_graph() {
            return Err(corrupt(dir, "graph base requires a graph seal marker"));
        }
        marker.version = marker.vector_version();
        if !matches!(marker.version, 7 | 9)
            || marker.points != diskann.count()
            || marker.vector_dim != diskann.vector_dim()
        {
            return Err(corrupt(
                dir,
                "remote DiskANN metadata disagrees with cold graph seal marker",
            ));
        }
        Self::open_validated(dir, marker, Some(diskann))
    }

    fn open_local_marker(dir: &Path, marker: SealMarker) -> Result<Self> {
        let diskann = if matches!(marker.version, 7 | 9) {
            let diskann = crate::index::diskann::DiskAnnArtifact::open(
                &dir.join(crate::index::diskann::DISKANN_FILE),
                marker.points,
                marker.vector_dim,
            )?;
            Some(Arc::new(diskann))
        } else {
            None
        };
        Self::open_validated(dir, marker, diskann)
    }

    pub(crate) fn open_with_diskann(
        dir: &Path,
        diskann: Arc<crate::index::diskann::DiskAnnArtifact>,
    ) -> Result<Self> {
        let marker = read_marker_with_diskann_len(&dir.join(SEAL_FILE), diskann.object_len())?;
        marker.require_vector_only_recovery(dir)?;
        if !matches!(marker.version, 7 | 9)
            || marker.points != diskann.count()
            || marker.vector_dim != diskann.vector_dim()
        {
            return Err(corrupt(
                dir,
                "remote DiskANN metadata disagrees with cold seal marker",
            ));
        }
        Self::open_validated(dir, marker, Some(diskann))
    }

    fn open_validated(
        dir: &Path,
        marker: SealMarker,
        diskann: Option<Arc<crate::index::diskann::DiskAnnArtifact>>,
    ) -> Result<Self> {
        let vector_dim = marker.vector_dim;
        let (vectors, vector_encoding) = if let Some(diskann) = diskann {
            (
                PrimaryVectorStore::DiskAnn(diskann),
                DenseVectorEncoding::ScaledF16,
            )
        } else {
            let vectors = encryption::PersistentFile::open(&dir.join(VECTOR_FILE))?;
            let vector_header = vectors.read_range(0..24)?;
            let (vector_count, vector_dim, vector_encoding) =
                read_vector_header(&vector_header, &dir.join(VECTOR_FILE))?;
            if !matches!(
                (vector_encoding, marker.version),
                (DenseVectorEncoding::F32, 4) | (DenseVectorEncoding::ScaledF16, 5 | 6 | 8)
            ) {
                return Err(corrupt(
                    dir,
                    "sealed vector encoding disagrees with seal marker version",
                ));
            }
            if vector_count != marker.points || vector_dim != marker.vector_dim {
                return Err(corrupt(
                    dir,
                    "sealed vector header disagrees with seal marker",
                ));
            }
            let expected_vector_bytes = vector_count
                .checked_mul(
                    vector_encoding
                        .row_bytes(vector_dim)
                        .ok_or_else(|| corrupt(dir, "sealed vector row length overflow"))?,
                )
                .and_then(|bytes| bytes.checked_add(24))
                .ok_or_else(|| corrupt(dir, "sealed vector length overflow"))?;
            if vectors.len() != expected_vector_bytes {
                return Err(corrupt(dir, "sealed vector file length mismatch"));
            }
            (PrimaryVectorStore::Persistent(vectors), vector_encoding)
        };

        let ids_file = encryption::PersistentFile::open(&dir.join(IDS_FILE))?;
        let ids = read_ids_file(&ids_file, &dir.join(IDS_FILE), marker.points)?;
        let ordinals = ids
            .iter()
            .enumerate()
            .map(|(ordinal, id)| (id.clone(), ordinal))
            .collect::<HashMap<_, _>>();
        if ordinals.len() != ids.len() {
            return Err(corrupt(dir, "v4 ids contain duplicates"));
        }

        let payloads = encryption::PersistentFile::open(&dir.join(PAYLOAD_FILE))?;
        let (payload_offsets, payload_start) =
            read_payload_offsets_file(&payloads, &dir.join(PAYLOAD_FILE), marker.points)?;
        for ordinal in 0..marker.points {
            let range = payload_range(&payload_offsets, payload_start, ordinal)
                .ok_or_else(|| corrupt(dir, "v4 payload offset is out of bounds"))?;
            let payload = payloads.read_range(range)?;
            serde_json::from_slice::<OwnedPointAux>(&payload).map_err(|error| {
                corrupt(
                    dir,
                    &format!("v4 payload record {ordinal} is invalid: {error}"),
                )
            })?;
        }

        Ok(Self {
            vectors,
            payloads,
            ids,
            ordinals,
            payload_offsets,
            vector_dim,
            vector_encoding,
            segment_format_version: marker.version,
            payload_start,
        })
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    pub fn ordinal(&self, id: &str) -> Option<usize> {
        self.ordinals.get(id).copied()
    }

    pub fn id(&self, ordinal: usize) -> Option<&str> {
        self.ids.get(ordinal).map(String::as_str)
    }

    pub(crate) fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    /// Hydrate only the dense row. Algorithm 2 uses this for its final exact
    /// rescore without parsing payload JSON for candidates that do not win.
    pub fn vector(&self, ordinal: usize) -> Option<Vec<f32>> {
        Some(self.vector_cow(ordinal)?.into_owned())
    }

    pub fn exact_vector_bytes_per_component(&self) -> f64 {
        match self.vector_encoding {
            DenseVectorEncoding::F32 => std::mem::size_of::<f32>() as f64,
            DenseVectorEncoding::ScaledF16 => {
                (self
                    .vector_encoding
                    .row_bytes(self.vector_dim)
                    .unwrap_or_default() as f64)
                    / self.vector_dim as f64
            }
        }
    }

    pub fn exact_vector_format_version(&self) -> u32 {
        self.vector_encoding.marker_version()
    }

    pub fn segment_format_version(&self) -> u32 {
        self.segment_format_version
    }

    pub(crate) fn vector_cow(&self, ordinal: usize) -> Option<Cow<'_, [f32]>> {
        match &self.vectors {
            PrimaryVectorStore::Persistent(vectors) => match self.vector_encoding {
                DenseVectorEncoding::F32 => {
                    let row_bytes = self.vector_dim.checked_mul(std::mem::size_of::<f32>())?;
                    let start = 24_usize.checked_add(ordinal.checked_mul(row_bytes)?)?;
                    let bytes = vectors
                        .read_range(start..start.checked_add(row_bytes)?)
                        .ok()?;
                    match bytes {
                        Cow::Borrowed(bytes) => Some(Cow::Borrowed(unsafe {
                            std::slice::from_raw_parts(
                                bytes.as_ptr().cast::<f32>(),
                                self.vector_dim,
                            )
                        })),
                        Cow::Owned(bytes) => Some(Cow::Owned(decode_f32_row(&bytes)?)),
                    }
                }
                DenseVectorEncoding::ScaledF16 => self.scaled_f16_vector(ordinal).map(Cow::Owned),
            },
            PrimaryVectorStore::DiskAnn(diskann) => diskann.vector(ordinal).map(Cow::Owned),
        }
    }

    fn scaled_f16_vector(&self, ordinal: usize) -> Option<Vec<f32>> {
        if ordinal >= self.ids.len() || self.vector_encoding != DenseVectorEncoding::ScaledF16 {
            return None;
        }
        let row_bytes = self.vector_encoding.row_bytes(self.vector_dim)?;
        let start = 24_usize.checked_add(ordinal.checked_mul(row_bytes)?)?;
        let PrimaryVectorStore::Persistent(vectors) = &self.vectors else {
            return None;
        };
        let row = vectors
            .read_range(start..start.checked_add(row_bytes)?)
            .ok()?;
        let scale_end = std::mem::size_of::<f32>();
        let scale = f32::from_le_bytes(row.get(..scale_end)?.try_into().ok()?);
        let values = row.get(scale_end..)?;
        Some(
            values
                .chunks_exact(2)
                .map(|bytes| {
                    f16::from_bits(u16::from_le_bytes(
                        bytes.try_into().expect("two-byte f16 component"),
                    ))
                    .to_f32()
                        * scale
                })
                .collect(),
        )
    }

    pub fn get(&self, id: &str) -> Option<Point> {
        self.ordinals
            .get(id)
            .and_then(|ordinal| self.get_ordinal(*ordinal))
    }

    pub fn get_ordinal(&self, ordinal: usize) -> Option<Point> {
        let vector = self.vector(ordinal)?;
        self.get_ordinal_with_vector(ordinal, vector)
    }

    pub(crate) fn get_ordinal_for_aux_indexes(&self, ordinal: usize) -> Option<Point> {
        self.get_ordinal_with_vector(ordinal, Vec::new())
    }

    pub(crate) fn get_ordinal_with_vector(
        &self,
        ordinal: usize,
        vector: Vec<f32>,
    ) -> Option<Point> {
        if !vector.is_empty() && vector.len() != self.vector_dim {
            return None;
        }
        let id = self.ids.get(ordinal)?.clone();
        let range = payload_range(&self.payload_offsets, self.payload_start, ordinal)?;
        let payload = self.payloads.read_range(range).ok()?;
        let aux: OwnedPointAux = serde_json::from_slice(&payload).ok()?;
        Some(Point {
            id,
            vector,
            vectors: aux.vectors,
            sparse_vector: aux.sparse_vector,
            payload: aux.payload,
        })
    }

    pub(crate) fn diskann(&self) -> Option<Arc<crate::index::diskann::DiskAnnArtifact>> {
        match &self.vectors {
            PrimaryVectorStore::Persistent(_) => None,
            PrimaryVectorStore::DiskAnn(diskann) => Some(Arc::clone(diskann)),
        }
    }
}

pub fn build_segment<I: VectorInput + ?Sized>(
    input: &I,
    out_tmp: &Path,
    config: SealConfig,
) -> Result<SealWrite> {
    build_segment_with_encodings(
        input,
        out_tmp,
        config,
        DenseVectorEncoding::ScaledF16,
        DenseVectorEncoding::ScaledF16,
        None,
        None,
    )
}

/// Build an immutable segment into a stable workspace, reusing only stages
/// whose content-bound fingerprints and native artifact readers validate.
pub(crate) fn build_segment_resumable<I: VectorInput + ?Sized>(
    input: &I,
    workspace: &Path,
    segment_id: &str,
    config: SealConfig,
) -> Result<SealWrite> {
    build_segment_resumable_controlled(input, workspace, segment_id, config, None)
}

pub(crate) fn build_segment_resumable_with_prior_graph<I: VectorInput + ?Sized>(
    input: &I,
    workspace: &Path,
    segment_id: &str,
    config: SealConfig,
    prior_graph: &crate::index::vamana::StableGraphSeed,
) -> Result<SealWrite> {
    build_segment_resumable_controlled_inner(
        input,
        workspace,
        segment_id,
        config,
        Some(prior_graph),
        None,
    )
}

pub(crate) fn build_segment_resumable_controlled<I: VectorInput + ?Sized>(
    input: &I,
    workspace: &Path,
    segment_id: &str,
    config: SealConfig,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<SealWrite> {
    build_segment_resumable_controlled_inner(input, workspace, segment_id, config, None, cancelled)
}

fn build_segment_resumable_controlled_inner<I: VectorInput + ?Sized>(
    input: &I,
    workspace: &Path,
    segment_id: &str,
    config: SealConfig,
    prior_graph: Option<&crate::index::vamana::StableGraphSeed>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<SealWrite> {
    let identity = crate::build_progress::BuildIdentity::new_with_graph_seed(
        segment_id,
        input,
        config,
        prior_graph,
    )?;
    let mut progress = crate::build_progress::BuildProgress::open_or_reset(workspace, identity)?;
    let candidate = crate::build_progress::BuildProgress::candidate_dir(workspace);
    let mut resume = ResumableSeal {
        workspace,
        progress: &mut progress,
        cancelled,
    };
    build_segment_with_encodings(
        input,
        &candidate,
        config,
        DenseVectorEncoding::ScaledF16,
        DenseVectorEncoding::ScaledF16,
        prior_graph,
        Some(&mut resume),
    )
}

struct ResumableSeal<'a> {
    workspace: &'a Path,
    progress: &'a mut crate::build_progress::BuildProgress,
    cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

fn check_build_cancellation(resume: &Option<&mut ResumableSeal<'_>>) -> Result<()> {
    if resume.as_ref().is_some_and(|resume| {
        resume
            .cancelled
            .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
    }) {
        return Err(GaussError::ResourceExhausted(
            "background build cancelled during shutdown".to_string(),
        ));
    }
    Ok(())
}

fn resumable_artifact_valid(
    resume: &Option<&mut ResumableSeal<'_>>,
    root: &Path,
    relative: &str,
) -> bool {
    resume
        .as_ref()
        .is_some_and(|resume| resume.progress.artifact_is_valid(root, relative))
}

fn record_resumable_artifacts(
    resume: &mut Option<&mut ResumableSeal<'_>>,
    root: &Path,
    relatives: &[&str],
    stage: crate::build_progress::BuildStage,
) -> Result<()> {
    if let Some(resume) = resume.as_mut() {
        resume
            .progress
            .record_artifacts(resume.workspace, root, relatives, stage)?;
    }
    Ok(())
}

fn advance_resumable_stage(
    resume: &mut Option<&mut ResumableSeal<'_>>,
    stage: crate::build_progress::BuildStage,
) -> Result<()> {
    if let Some(resume) = resume.as_mut() {
        resume.progress.advance_stage(resume.workspace, stage)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn build_segment_with_encoding<I: VectorInput + ?Sized>(
    input: &I,
    out_tmp: &Path,
    config: SealConfig,
    vector_encoding: DenseVectorEncoding,
) -> Result<SealWrite> {
    build_segment_with_encodings(
        input,
        out_tmp,
        config,
        vector_encoding,
        vector_encoding,
        None,
        None,
    )
}

#[cfg(test)]
pub(crate) fn build_segment_with_legacy_named_rows<I: VectorInput + ?Sized>(
    input: &I,
    out_tmp: &Path,
    config: SealConfig,
) -> Result<SealWrite> {
    build_segment_with_encodings(
        input,
        out_tmp,
        config,
        DenseVectorEncoding::ScaledF16,
        DenseVectorEncoding::F32,
        None,
        None,
    )
}

fn build_segment_with_encodings<I: VectorInput + ?Sized>(
    input: &I,
    out_tmp: &Path,
    config: SealConfig,
    vector_encoding: DenseVectorEncoding,
    named_vector_encoding: DenseVectorEncoding,
    prior_graph: Option<&crate::index::vamana::StableGraphSeed>,
    mut resume: Option<&mut ResumableSeal<'_>>,
) -> Result<SealWrite> {
    check_build_cancellation(&resume)?;
    if config.vector_dim == 0 {
        return Err(GaussError::InvalidRequest(
            "cannot seal zero-dimensional vectors".to_string(),
        ));
    }
    if config.end_lsn < config.base_lsn {
        return Err(GaussError::InvalidRequest(format!(
            "seal end_lsn {} precedes base_lsn {}",
            config.end_lsn, config.base_lsn
        )));
    }
    if resume.is_none() && out_tmp.exists() && fs::read_dir(out_tmp)?.next().is_some() {
        return Err(GaussError::InvalidRequest(format!(
            "seal output directory is not empty: {}",
            out_tmp.display()
        )));
    }
    fs::create_dir_all(out_tmp)?;
    if resume.as_ref().is_some_and(|resume| {
        resume.progress.stage() == crate::build_progress::BuildStage::Complete
            && resume.progress.artifact_is_valid(out_tmp, SEAL_FILE)
    }) && let Ok(marker) = read_marker(&out_tmp.join(SEAL_FILE))
        && marker.points == input.len()
        && marker.vector_dim == config.vector_dim
        && marker.base_lsn == config.base_lsn
        && marker.end_lsn == config.end_lsn
    {
        return Ok(SealWrite {
            dir: out_tmp.to_path_buf(),
            marker,
        });
    }
    if let Some(resume) = resume.as_mut() {
        resume.progress.begin_resume(resume.workspace)?;
    }
    check_build_cancellation(&resume)?;

    let mut vectors = BufWriter::with_capacity(64 * 1024, File::create(out_tmp.join(VECTOR_FILE))?);
    let mut ids_file = BufWriter::with_capacity(64 * 1024, File::create(out_tmp.join(IDS_FILE))?);
    let mut payloads =
        BufWriter::with_capacity(64 * 1024, File::create(out_tmp.join(PAYLOAD_FILE))?);
    let mut normalized =
        BufWriter::with_capacity(64 * 1024, File::create(out_tmp.join(h2qg::HNSW_VECS_FILE))?);
    let vector_magic = match vector_encoding {
        DenseVectorEncoding::F32 => VECTOR_MAGIC_V4,
        DenseVectorEncoding::ScaledF16 => VECTOR_MAGIC_V5,
    };
    write_header(&mut vectors, vector_magic, input.len(), config.vector_dim)?;
    write_count_header(&mut ids_file, IDS_MAGIC, input.len())?;
    write_count_header(&mut payloads, PAYLOAD_MAGIC, input.len())?;
    payloads.write_all(&vec![0_u8; (input.len() + 1) * std::mem::size_of::<u64>()])?;
    write_header(
        &mut normalized,
        h2qg::HNSW_VECS_MAGIC,
        input.len(),
        config.vector_dim,
    )?;

    let mut ids = Vec::with_capacity(input.len());
    let mut unique = HashSet::with_capacity(input.len());
    let mut named_writers = HashMap::<String, NamedVectorWriter>::new();
    let mut payload_offsets = Vec::with_capacity(input.len() + 1);
    payload_offsets.push(0_u64);
    for ordinal in 0..input.len() {
        check_build_cancellation(&resume)?;
        let point = input.point(ordinal)?;
        if point.vector.len() != config.vector_dim {
            return Err(GaussError::DimensionMismatch {
                expected: config.vector_dim,
                actual: point.vector.len(),
            });
        }
        if !unique.insert(point.id.clone()) {
            return Err(GaussError::InvalidRequest(format!(
                "duplicate point id in seal input: {}",
                point.id
            )));
        }
        write_string(&mut ids_file, &point.id)?;
        match vector_encoding {
            DenseVectorEncoding::F32 => write_vector(&mut vectors, &point.vector)?,
            DenseVectorEncoding::ScaledF16 => write_scaled_f16_vector(&mut vectors, &point.vector)?,
        }
        if config.metric == DistanceMetric::Cosine {
            let mut vector = point.vector.clone();
            crate::search::normalize(&mut vector);
            write_vector(&mut normalized, &vector)?;
        } else {
            write_vector(&mut normalized, &point.vector)?;
        }
        if matches!(config.index_kind, SealIndexKind::Algorithm2) {
            for (name, vector) in &point.vectors {
                validate_named_vector_name(name)?;
                let writer = match named_writers.entry(name.clone()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let mut vectors = BufWriter::with_capacity(
                            64 * 1024,
                            File::create(out_tmp.join(named_vector_file(name)))?,
                        );
                        let magic = match named_vector_encoding {
                            DenseVectorEncoding::F32 => h2qg::HNSW_VECS_MAGIC,
                            DenseVectorEncoding::ScaledF16 => VECTOR_MAGIC_V5,
                        };
                        write_header(&mut vectors, magic, 0, vector.len())?;
                        entry.insert(NamedVectorWriter {
                            vectors,
                            ids: Vec::new(),
                            dim: vector.len(),
                        })
                    }
                };
                if vector.len() != writer.dim {
                    return Err(GaussError::DimensionMismatch {
                        expected: writer.dim,
                        actual: vector.len(),
                    });
                }
                if config.metric == DistanceMetric::Cosine {
                    let mut normalized = vector.clone();
                    crate::search::normalize(&mut normalized);
                    match named_vector_encoding {
                        DenseVectorEncoding::F32 => {
                            write_vector(&mut writer.vectors, &normalized)?;
                        }
                        DenseVectorEncoding::ScaledF16 => {
                            write_scaled_f16_vector(&mut writer.vectors, &normalized)?;
                        }
                    }
                } else {
                    match named_vector_encoding {
                        DenseVectorEncoding::F32 => write_vector(&mut writer.vectors, vector)?,
                        DenseVectorEncoding::ScaledF16 => {
                            write_scaled_f16_vector(&mut writer.vectors, vector)?;
                        }
                    }
                }
                writer.ids.push(point.id.clone());
            }
        }
        let aux = serde_json::to_vec(&PointAux {
            vectors: &point.vectors,
            sparse_vector: &point.sparse_vector,
            payload: &point.payload,
        })?;
        payloads.write_all(&aux)?;
        payload_offsets.push(
            payload_offsets
                .last()
                .copied()
                .unwrap_or(0)
                .checked_add(aux.len() as u64)
                .ok_or_else(|| {
                    GaussError::InvalidRequest("v4 payload offsets overflow u64".to_string())
                })?,
        );
        ids.push(point.id.clone());
    }
    sync_writer(vectors)?;
    sync_writer(ids_file)?;
    sync_payload_writer(payloads, &payload_offsets)?;
    sync_writer(normalized)?;
    encrypt_staged_file(&out_tmp.join(h2qg::HNSW_VECS_FILE))?;
    encrypt_staged_file(&out_tmp.join(VECTOR_FILE))?;
    encrypt_staged_file(&out_tmp.join(IDS_FILE))?;
    encrypt_staged_file(&out_tmp.join(PAYLOAD_FILE))?;
    record_resumable_artifacts(
        &mut resume,
        out_tmp,
        &[VECTOR_FILE, IDS_FILE, PAYLOAD_FILE, h2qg::HNSW_VECS_FILE],
        crate::build_progress::BuildStage::BaseStore,
    )?;
    check_build_cancellation(&resume)?;

    let has_named_vectors = !named_writers.is_empty();
    match config.index_kind {
        SealIndexKind::Hnsw => {
            check_build_cancellation(&resume)?;
            h2qg::write_index_paged_from_ids(
                out_tmp,
                &ids,
                config.vector_dim,
                config.hnsw_m,
                config.hnsw_ef_construction,
                config.metric,
            )?;
            check_build_cancellation(&resume)?;
            encrypt_staged_file(&out_tmp.join(h2qg::INDEX_FILE))?;
            record_resumable_artifacts(
                &mut resume,
                out_tmp,
                &[h2qg::INDEX_FILE],
                crate::build_progress::BuildStage::Vamana,
            )?;
        }
        SealIndexKind::Algorithm2 => {
            check_build_cancellation(&resume)?;
            let source =
                PagedVectorSource(h2qg::read_hnsw_vecs(&out_tmp.join(h2qg::HNSW_VECS_FILE))?);
            let ivf_path = out_tmp.join(crate::index::ivf::IVF_FILE);
            let mut ivf = resumable_artifact_valid(&resume, out_tmp, crate::index::ivf::IVF_FILE)
                .then(|| crate::index::ivf::IvfArtifact::open(&ivf_path).ok())
                .flatten()
                .filter(|ivf| ivf.len() == input.len() && ivf.vector_dim() == config.vector_dim);
            let ivf_reused = ivf.is_some();
            if ivf.is_none() {
                crate::index::ivf::write_ivf_artifact(
                    &source,
                    config.vector_dim,
                    ((input.len() as f64).sqrt().round() as usize).max(1),
                    &ivf_path,
                )?;
                encrypt_staged_file(&ivf_path)?;
                ivf = Some(crate::index::ivf::IvfArtifact::open(&ivf_path)?);
            }
            check_build_cancellation(&resume)?;
            let ivf = ivf.expect("IVF was opened or rebuilt");
            if ivf_reused {
                advance_resumable_stage(&mut resume, crate::build_progress::BuildStage::Ivf)?;
            } else {
                record_resumable_artifacts(
                    &mut resume,
                    out_tmp,
                    &[crate::index::ivf::IVF_FILE],
                    crate::build_progress::BuildStage::Ivf,
                )?;
            }

            let rabitq_path = out_tmp.join(crate::index::rabitq::RABITQ_FILE);
            let rabitq_valid =
                resumable_artifact_valid(&resume, out_tmp, crate::index::rabitq::RABITQ_FILE)
                    && crate::index::rabitq::RabitqArtifact::open(&rabitq_path, &ivf).is_ok();
            if !rabitq_valid {
                crate::index::rabitq::write_rabitq_artifact_for_metric(
                    &source,
                    &ivf,
                    config.metric,
                    &rabitq_path,
                )?;
                encrypt_staged_file(&rabitq_path)?;
                crate::index::rabitq::RabitqArtifact::open(&rabitq_path, &ivf)?;
            }
            check_build_cancellation(&resume)?;
            if rabitq_valid {
                advance_resumable_stage(&mut resume, crate::build_progress::BuildStage::Rabitq)?;
            } else {
                record_resumable_artifacts(
                    &mut resume,
                    out_tmp,
                    &[crate::index::rabitq::RABITQ_FILE],
                    crate::build_progress::BuildStage::Rabitq,
                )?;
            }

            let vamana_path = out_tmp.join(crate::index::vamana::VAMANA_SEGMENT_FILE);
            let vamana_valid = resumable_artifact_valid(
                &resume,
                out_tmp,
                crate::index::vamana::VAMANA_SEGMENT_FILE,
            ) && crate::index::vamana::VamanaArtifact::open(&vamana_path, &ivf)
                .is_ok();
            if !vamana_valid {
                if let Some(resume) = resume.as_mut() {
                    let cells_dir =
                        crate::build_progress::BuildProgress::cells_dir(resume.workspace);
                    let reusable_cells = (0..ivf.cells())
                        .filter_map(|cell| u32::try_from(cell).ok())
                        .filter(|cell| resume.progress.vamana_cell_is_valid(&cells_dir, *cell))
                        .collect::<std::collections::BTreeSet<_>>();
                    let workspace = resume.workspace.to_path_buf();
                    let control = crate::index::vamana::VamanaResumeInput {
                        cells_dir: &cells_dir,
                        reusable_cells: &reusable_cells,
                        cancelled: resume.cancelled,
                    };
                    if let Some(prior_graph) = prior_graph {
                        crate::index::vamana::write_vamana_artifact_resumable_seeded(
                            &source,
                            &ivf,
                            config.metric,
                            &vamana_path,
                            prior_graph,
                            control,
                            &mut |cell, path| {
                                resume.progress.record_vamana_cell(&workspace, cell, path)
                            },
                        )?;
                    } else {
                        crate::index::vamana::write_vamana_artifact_resumable(
                            &source,
                            &ivf,
                            config.metric,
                            &vamana_path,
                            control,
                            &mut |cell, path| {
                                resume.progress.record_vamana_cell(&workspace, cell, path)
                            },
                        )?;
                    }
                } else if let Some(prior_graph) = prior_graph {
                    crate::index::vamana::write_vamana_artifact_seeded(
                        &source,
                        &ivf,
                        config.metric,
                        &vamana_path,
                        prior_graph,
                    )?;
                } else {
                    crate::index::vamana::write_vamana_artifact(
                        &source,
                        &ivf,
                        config.metric,
                        &vamana_path,
                    )?;
                }
                check_build_cancellation(&resume)?;
                encrypt_staged_file(&vamana_path)?;
                crate::index::vamana::VamanaArtifact::open(&vamana_path, &ivf)?;
            }
            if vamana_valid {
                advance_resumable_stage(&mut resume, crate::build_progress::BuildStage::Vamana)?;
            } else {
                record_resumable_artifacts(
                    &mut resume,
                    out_tmp,
                    &[crate::index::vamana::VAMANA_SEGMENT_FILE],
                    crate::build_progress::BuildStage::Vamana,
                )?;
            }
            if vector_encoding == DenseVectorEncoding::ScaledF16 {
                let vamana = crate::index::vamana::VamanaArtifact::open(&vamana_path, &ivf)?;
                let diskann_path = out_tmp.join(crate::index::diskann::DISKANN_FILE);
                let diskann_valid =
                    resumable_artifact_valid(&resume, out_tmp, crate::index::diskann::DISKANN_FILE)
                        && crate::index::diskann::DiskAnnArtifact::open(
                            &diskann_path,
                            input.len(),
                            config.vector_dim,
                        )
                        .is_ok();
                if !diskann_valid {
                    check_build_cancellation(&resume)?;
                    crate::index::diskann::write_diskann_artifact(
                        input,
                        &vamana,
                        &ivf,
                        config.vector_dim,
                        &diskann_path,
                    )?;
                    check_build_cancellation(&resume)?;
                    encrypt_staged_file(&diskann_path)?;
                    crate::index::diskann::DiskAnnArtifact::open(
                        &diskann_path,
                        input.len(),
                        config.vector_dim,
                    )?;
                }
                if diskann_valid {
                    advance_resumable_stage(
                        &mut resume,
                        crate::build_progress::BuildStage::DiskAnn,
                    )?;
                } else {
                    record_resumable_artifacts(
                        &mut resume,
                        out_tmp,
                        &[crate::index::diskann::DISKANN_FILE],
                        crate::build_progress::BuildStage::DiskAnn,
                    )?;
                }
            }
            drop(source);
            fs::remove_file(out_tmp.join(h2qg::HNSW_VECS_FILE))?;

            for (name, writer) in named_writers {
                check_build_cancellation(&resume)?;
                finish_named_vectors(writer.vectors, writer.ids.len())?;
                write_ids(out_tmp, &named_ids_file(&name), &writer.ids)?;
                encrypt_staged_file(&out_tmp.join(named_vector_file(&name)))?;
                encrypt_staged_file(&out_tmp.join(named_ids_file(&name)))?;
                let source =
                    NamedV4Store::open_with_encoding(out_tmp, &name, Some(named_vector_encoding))?;
                let vector_file = named_vector_file(&name);
                let ids_file = named_ids_file(&name);
                let ivf_file = named_ivf_file(&name);
                let rabitq_file = named_rabitq_file(&name);
                let vamana_file = named_vamana_file(&name);
                let ivf_path = out_tmp.join(&ivf_file);
                let rabitq_path = out_tmp.join(&rabitq_file);
                let vamana_path = out_tmp.join(&vamana_file);
                let named_valid = resumable_artifact_valid(&resume, out_tmp, &ivf_file)
                    && resumable_artifact_valid(&resume, out_tmp, &rabitq_file)
                    && resumable_artifact_valid(&resume, out_tmp, &vamana_file)
                    && crate::index::ivf::IvfArtifact::open(&ivf_path).is_ok_and(|ivf| {
                        ivf.len() == source.len()
                            && ivf.vector_dim() == writer.dim
                            && crate::index::rabitq::RabitqArtifact::open(&rabitq_path, &ivf)
                                .is_ok()
                            && crate::index::vamana::VamanaArtifact::open(&vamana_path, &ivf)
                                .is_ok()
                    });
                if !named_valid {
                    write_algorithm2_artifacts(
                        &source,
                        writer.dim,
                        config.metric,
                        &ivf_path,
                        &rabitq_path,
                        &vamana_path,
                    )?;
                    encrypt_staged_file(&rabitq_path)?;
                    encrypt_staged_file(&vamana_path)?;
                    let ivf = crate::index::ivf::IvfArtifact::open(&ivf_path)?;
                    crate::index::rabitq::RabitqArtifact::open(&rabitq_path, &ivf)?;
                    crate::index::vamana::VamanaArtifact::open(&vamana_path, &ivf)?;
                }
                check_build_cancellation(&resume)?;
                if named_valid {
                    advance_resumable_stage(
                        &mut resume,
                        crate::build_progress::BuildStage::NamedIndexes,
                    )?;
                } else {
                    record_resumable_artifacts(
                        &mut resume,
                        out_tmp,
                        &[
                            &vector_file,
                            &ids_file,
                            &ivf_file,
                            &rabitq_file,
                            &vamana_file,
                        ],
                        crate::build_progress::BuildStage::NamedIndexes,
                    )?;
                }
            }
        }
    }
    check_build_cancellation(&resume)?;
    let mut tombstones = File::create(out_tmp.join(TOMBSTONE_FILE))?;
    tombstones.write_all(TOMBSTONE_MAGIC)?;
    tombstones.write_all(&0_u64.to_le_bytes())?;
    tombstones.sync_all()?;
    drop(tombstones);
    encrypt_staged_file(&out_tmp.join(TOMBSTONE_FILE))?;
    record_resumable_artifacts(
        &mut resume,
        out_tmp,
        &[TOMBSTONE_FILE],
        crate::build_progress::BuildStage::Tombstones,
    )?;
    check_build_cancellation(&resume)?;

    encrypt_sealed_artifacts(out_tmp)?;

    let sealed_files: &[&str] = match config.index_kind {
        SealIndexKind::Hnsw => &HNSW_SEALED_FILES,
        SealIndexKind::Algorithm2 if vector_encoding == DenseVectorEncoding::ScaledF16 => {
            &ALGORITHM2_SEALED_FILES_V6
        }
        SealIndexKind::Algorithm2 => &ALGORITHM2_SEALED_FILES_V5,
    };
    let mut files = sealed_files
        .iter()
        .copied()
        .map(|name| file_entry(out_tmp, name))
        .collect::<Result<Vec<_>>>()?;
    for name in named_algorithm2_names(out_tmp)? {
        for file in named_files(&name) {
            files.push(file_entry(out_tmp, &file)?);
        }
    }
    let marker = SealMarker {
        version: match config.index_kind {
            SealIndexKind::Hnsw => vector_encoding.marker_version(),
            SealIndexKind::Algorithm2
                if has_named_vectors && named_vector_encoding == DenseVectorEncoding::ScaledF16 =>
            {
                8
            }
            SealIndexKind::Algorithm2 if vector_encoding == DenseVectorEncoding::ScaledF16 => 6,
            SealIndexKind::Algorithm2 => vector_encoding.marker_version(),
        },
        points: input.len(),
        vector_dim: config.vector_dim,
        base_lsn: config.base_lsn,
        end_lsn: config.end_lsn,
        files,
    };
    write_marker(&out_tmp.join(SEAL_FILE), &marker)?;
    sync_directory(out_tmp)?;
    check_build_cancellation(&resume)?;
    record_resumable_artifacts(
        &mut resume,
        out_tmp,
        &[SEAL_FILE],
        crate::build_progress::BuildStage::Complete,
    )?;
    Ok(SealWrite {
        dir: out_tmp.to_path_buf(),
        marker,
    })
}

pub fn read_marker(path: &Path) -> Result<SealMarker> {
    read_marker_inner(path, None)
}

pub(crate) fn read_marker_with_diskann_len(path: &Path, diskann_len: u64) -> Result<SealMarker> {
    read_marker_inner(path, Some(diskann_len))
}

fn read_marker_inner(path: &Path, external_diskann_len: Option<u64>) -> Result<SealMarker> {
    let file = encryption::PersistentFile::open(path)?;
    if file.len() < 20 {
        return Err(corrupt(path, "truncated sealed-segment marker"));
    }
    if file.len() > 20 + MAX_MARKER_BYTES {
        return Err(corrupt(path, "sealed-segment marker exceeds size cap"));
    }
    let bytes = file.read_range(0..file.len())?;
    let header = &bytes[..20];
    if &header[..8] != SEAL_MAGIC {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "bad sealed-segment marker magic".to_string(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("marker length"),
    ))
    .map_err(|_| corrupt(path, "sealed-segment marker length exceeds usize"))?;
    if len > MAX_MARKER_BYTES {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("sealed-segment marker exceeds {MAX_MARKER_BYTES} bytes"),
        });
    }
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("marker crc"));
    let payload_end = 20_usize
        .checked_add(len)
        .ok_or_else(|| corrupt(path, "sealed-segment marker length overflow"))?;
    if payload_end != bytes.len() {
        return Err(corrupt(path, "sealed-segment marker length mismatch"));
    }
    let payload = &bytes[20..payload_end];
    if crc(payload) != expected_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "sealed-segment marker crc mismatch".to_string(),
        });
    }
    let marker: SealMarker = serde_json::from_slice(payload)?;
    let actual_names = marker
        .files
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<HashSet<_>>();
    let vector_version = marker.vector_version();
    let mut vector_names = actual_names.clone();
    let valid_graph_group = if marker.has_graph() {
        let complete = graph::FILES.iter().all(|name| actual_names.contains(name));
        for name in graph::FILES {
            vector_names.remove(name);
        }
        complete && marker.points <= u32::MAX as usize
    } else {
        true
    };
    let hnsw_names = HNSW_SEALED_FILES.into_iter().collect::<HashSet<_>>();
    let algorithm2_v5_names = ALGORITHM2_SEALED_FILES_V5
        .into_iter()
        .collect::<HashSet<_>>();
    let algorithm2_v6_names = ALGORITHM2_SEALED_FILES_V6
        .into_iter()
        .collect::<HashSet<_>>();
    let algorithm2_v7_cold_names = ALGORITHM2_SEALED_FILES_V7_COLD
        .into_iter()
        .collect::<HashSet<_>>();
    let unique_names = actual_names.len() == marker.files.len();
    let hnsw_file_set = matches!(vector_version, 4 | 5) && vector_names == hnsw_names;
    let algorithm2_v5_file_set = algorithm2_v5_names.is_subset(&vector_names)
        && validate_named_file_set(&vector_names, &algorithm2_v5_names);
    let algorithm2_v6_file_set = algorithm2_v6_names.is_subset(&vector_names)
        && validate_named_file_set(&vector_names, &algorithm2_v6_names);
    let algorithm2_v7_cold_file_set = algorithm2_v7_cold_names.is_subset(&vector_names)
        && validate_named_file_set(&vector_names, &algorithm2_v7_cold_names);
    let algorithm2_file_set = match vector_version {
        4 | 5 => algorithm2_v5_file_set,
        6 | 8 => algorithm2_v6_file_set,
        7 | 9 => algorithm2_v7_cold_file_set,
        _ => false,
    };
    let valid_file_set =
        unique_names && valid_graph_group && (hnsw_file_set || algorithm2_file_set);
    if !matches!(marker.version, 4..=15)
        || marker.vector_dim == 0
        || marker.end_lsn < marker.base_lsn
        || !valid_file_set
    {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "invalid sealed-segment marker metadata or file set".to_string(),
        });
    }
    for entry in &marker.files {
        if parse_named_file(&entry.name).is_some_and(|(_, kind)| kind == "vec") {
            let named_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&entry.name);
            let named_bytes = encryption::read_persistent(&named_path)?;
            let magic = named_bytes
                .get(..8)
                .ok_or_else(|| corrupt(&named_path, "truncated named-vector header"))?;
            let expected_magic = if matches!(vector_version, 8 | 9) {
                VECTOR_MAGIC_V5
            } else {
                h2qg::HNSW_VECS_MAGIC
            };
            if magic != expected_magic {
                return Err(GaussError::SegmentCorruption {
                    path: path.display().to_string(),
                    message: format!(
                        "named-vector encoding disagrees with marker version: {}",
                        entry.name
                    ),
                });
            }
        }
        // tomb.gdx is the one mutable v4 artifact. It carries its own CRC and
        // is atomically replaced before checkpoint watermark advancement.
        if entry.name == TOMBSTONE_FILE {
            continue;
        }
        // diskann.gdx is deliberately not streamed through the page cache at
        // open: doing so would pull the full cold artifact into the kernel
        // cache before the first query. Its header and every 4 KiB data page
        // carry independent CRCs that are checked by positional reads.
        if entry.name == crate::index::diskann::DISKANN_FILE {
            let actual_bytes = match external_diskann_len {
                Some(bytes) if matches!(vector_version, 7 | 9) => bytes,
                _ => encryption::persistent_plaintext_len(
                    &path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(&entry.name),
                )?,
            };
            if actual_bytes != entry.bytes {
                return Err(GaussError::SegmentCorruption {
                    path: path.display().to_string(),
                    message: format!("sealed file length mismatch: {}", entry.name),
                });
            }
            continue;
        }
        let actual = file_entry(path.parent().unwrap_or_else(|| Path::new(".")), &entry.name)?;
        if actual.bytes != entry.bytes || actual.crc != entry.crc {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("sealed file mismatch: {}", entry.name),
            });
        }
    }
    if marker.has_graph() {
        graph::validate_group(
            path.parent().unwrap_or_else(|| Path::new(".")),
            marker.points,
        )?;
    }
    Ok(marker)
}

/// Convert one validated hot Algorithm 2 segment copy into its cold-only
/// layout. V6 becomes v7; named-scaled-f16 v8 becomes v9. `diskann.gdx`
/// already contains the scaled-f16 primary vector rows and Vamana adjacency,
/// so retaining `vec.gdx` or `vamana.gdx` in cold storage duplicates
/// structures that the cold query path cannot use.
/// Named-vector and graph artifacts are preserved. Graph v12/v14 become
/// v13/v15 only after the complete graph group has passed checked loading.
///
/// Callers must operate on a private staging directory or otherwise exclude
/// concurrent readers while the marker is replaced.
pub fn thin_algorithm2_segment_for_cold(dir: &Path) -> Result<bool> {
    let marker_path = dir.join(SEAL_FILE);
    let marker = read_marker(&marker_path)?;
    if matches!(marker.vector_version(), 7 | 9) {
        return Ok(false);
    }
    if !matches!(marker.vector_version(), 6 | 8) {
        return Ok(false);
    }

    crate::index::diskann::DiskAnnArtifact::open(
        &dir.join(crate::index::diskann::DISKANN_FILE),
        marker.points,
        marker.vector_dim,
    )?;
    let mut cold_marker = marker;
    cold_marker.version = match cold_marker.version {
        6 => 7,
        8 => 9,
        12 => 13,
        14 => 15,
        _ => unreachable!("validated hot Algorithm 2 marker"),
    };
    cold_marker.files.retain(|entry| {
        entry.name != VECTOR_FILE && entry.name != crate::index::vamana::VAMANA_SEGMENT_FILE
    });

    let marker_tmp = dir.join(format!(".{SEAL_FILE}.cold.tmp"));
    if marker_tmp.exists() {
        fs::remove_file(&marker_tmp)?;
    }
    write_marker(&marker_tmp, &cold_marker)?;
    fs::remove_file(dir.join(VECTOR_FILE))?;
    fs::remove_file(dir.join(crate::index::vamana::VAMANA_SEGMENT_FILE))?;
    #[cfg(windows)]
    fs::remove_file(&marker_path)?;
    fs::rename(marker_tmp, marker_path)?;
    sync_directory(dir)?;
    Ok(true)
}

pub fn read_tombstone_ordinals(dir: &Path) -> Result<RoaringBitmap> {
    let path = dir.join(TOMBSTONE_FILE);
    let bytes = encryption::read_persistent(&path)?;
    if bytes.len() == 16 && &bytes[..8] == TOMBSTONE_MAGIC {
        let count = u64::from_le_bytes(bytes[8..16].try_into().expect("tombstone count"));
        if count == 0 {
            return Ok(RoaringBitmap::new());
        }
    }
    if bytes.len() < 20 || &bytes[..8] != TOMBSTONE_MAGIC {
        return Err(corrupt(&path, "bad v4 tombstone header"));
    }
    let count = u64::from_le_bytes(bytes[8..16].try_into().expect("tombstone count")) as usize;
    let expected_crc = u32::from_le_bytes(bytes[16..20].try_into().expect("tombstone crc"));
    let payload = &bytes[20..];
    if payload.len() != count.saturating_mul(std::mem::size_of::<u64>())
        || crc(payload) != expected_crc
    {
        return Err(corrupt(&path, "invalid v4 tombstone payload"));
    }
    let mut deleted = RoaringBitmap::new();
    for chunk in payload.chunks_exact(8) {
        let ordinal = u64::from_le_bytes(chunk.try_into().expect("tombstone ordinal"));
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| corrupt(&path, "v4 tombstone ordinal exceeds u32"))?;
        deleted.insert(ordinal);
    }
    Ok(deleted)
}

pub fn read_tombstones(dir: &Path, ids: &[String]) -> Result<HashSet<String>> {
    read_tombstone_ordinals(dir)?
        .into_iter()
        .map(|ordinal| {
            ids.get(ordinal as usize).cloned().ok_or_else(|| {
                corrupt(
                    &dir.join(TOMBSTONE_FILE),
                    "v4 tombstone ordinal out of bounds",
                )
            })
        })
        .collect()
}

pub fn write_tombstones(dir: &Path, store: &V4Store, deleted_ids: &HashSet<String>) -> Result<()> {
    let mut ordinals = deleted_ids
        .iter()
        .filter_map(|id| store.ordinal(id))
        .collect::<Vec<_>>();
    ordinals.sort_unstable();
    ordinals.dedup();
    let mut payload = Vec::with_capacity(ordinals.len() * std::mem::size_of::<u64>());
    for ordinal in ordinals {
        payload.extend_from_slice(&(ordinal as u64).to_le_bytes());
    }
    let path = dir.join(TOMBSTONE_FILE);
    let mut bytes = Vec::with_capacity(20 + payload.len());
    bytes.extend_from_slice(TOMBSTONE_MAGIC);
    bytes.extend_from_slice(&((payload.len() / 8) as u64).to_le_bytes());
    bytes.extend_from_slice(&crc(&payload).to_le_bytes());
    bytes.extend_from_slice(&payload);
    encryption::atomic_write_persistent(&path, FileType::Segment, &bytes)
}

fn write_header(writer: &mut impl Write, magic: &[u8; 8], count: usize, dim: usize) -> Result<()> {
    writer.write_all(magic)?;
    writer.write_all(&(count as u64).to_le_bytes())?;
    writer.write_all(&(dim as u64).to_le_bytes())?;
    Ok(())
}

fn finish_named_vectors(writer: BufWriter<File>, count: usize) -> Result<()> {
    let mut file = writer
        .into_inner()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&(count as u64).to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn write_ids(dir: &Path, name: &str, ids: &[String]) -> Result<()> {
    let mut writer = BufWriter::with_capacity(64 * 1024, File::create(dir.join(name))?);
    write_count_header(&mut writer, IDS_MAGIC, ids.len())?;
    for id in ids {
        write_string(&mut writer, id)?;
    }
    sync_writer(writer)
}

fn write_algorithm2_artifacts(
    source: &impl crate::index::ivf::VectorSource,
    vector_dim: usize,
    metric: crate::DistanceMetric,
    ivf_path: &Path,
    rabitq_path: &Path,
    vamana_path: &Path,
) -> Result<()> {
    crate::index::ivf::write_ivf_artifact(
        source,
        vector_dim,
        ((source.len() as f64).sqrt().round() as usize).max(1),
        ivf_path,
    )?;
    encrypt_staged_file(ivf_path)?;
    let ivf = crate::index::ivf::IvfArtifact::open(ivf_path)?;
    crate::index::rabitq::write_rabitq_artifact_for_metric(source, &ivf, metric, rabitq_path)?;
    crate::index::vamana::write_vamana_artifact(source, &ivf, metric, vamana_path)?;
    Ok(())
}

fn validate_named_vector_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(GaussError::InvalidRequest(format!(
            "invalid named-vector artifact field '{name}'"
        )));
    }
    Ok(())
}

pub(crate) fn named_vector_file(name: &str) -> String {
    format!("named-{name}.vec.gdx")
}

pub(crate) fn named_ids_file(name: &str) -> String {
    format!("named-{name}.ids.gdx")
}

pub(crate) fn named_ivf_file(name: &str) -> String {
    format!("named-{name}.ivf.gdx")
}

pub(crate) fn named_rabitq_file(name: &str) -> String {
    format!("named-{name}.rabitq.gdx")
}

pub(crate) fn named_vamana_file(name: &str) -> String {
    format!("named-{name}.vamana.gdx")
}

fn named_files(name: &str) -> [String; 5] {
    [
        named_vector_file(name),
        named_ids_file(name),
        named_ivf_file(name),
        named_rabitq_file(name),
        named_vamana_file(name),
    ]
}

pub(crate) fn named_algorithm2_names(dir: &Path) -> Result<Vec<String>> {
    let mut groups = BTreeMap::<String, HashSet<&'static str>>::new();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some((name, kind)) = parse_named_file(&file_name) {
            groups.entry(name).or_default().insert(kind);
        }
    }
    let expected = HashSet::from(["vec", "ids", "ivf", "rabitq", "vamana"]);
    for (name, kinds) in &groups {
        if kinds != &expected {
            return Err(corrupt(
                dir,
                &format!("incomplete named-vector artifacts for '{name}'"),
            ));
        }
    }
    Ok(groups.into_keys().collect())
}

fn parse_named_file(file: &str) -> Option<(String, &'static str)> {
    let value = file.strip_prefix("named-")?;
    for (suffix, kind) in [
        (".vec.gdx", "vec"),
        (".ids.gdx", "ids"),
        (".ivf.gdx", "ivf"),
        (".rabitq.gdx", "rabitq"),
        (".vamana.gdx", "vamana"),
    ] {
        if let Some(name) = value.strip_suffix(suffix)
            && validate_named_vector_name(name).is_ok()
        {
            return Some((name.to_string(), kind));
        }
    }
    None
}

fn validate_named_file_set(actual: &HashSet<&str>, base: &HashSet<&str>) -> bool {
    let mut groups = HashMap::<String, HashSet<&'static str>>::new();
    for file in actual.difference(base) {
        let Some((name, kind)) = parse_named_file(file) else {
            return false;
        };
        groups.entry(name).or_default().insert(kind);
    }
    let expected = HashSet::from(["vec", "ids", "ivf", "rabitq", "vamana"]);
    groups.values().all(|kinds| kinds == &expected)
}

fn write_count_header(writer: &mut impl Write, magic: &[u8; 8], count: usize) -> Result<()> {
    writer.write_all(magic)?;
    writer.write_all(&(count as u64).to_le_bytes())?;
    Ok(())
}

fn write_string(writer: &mut impl Write, value: &str) -> Result<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| GaussError::InvalidRequest("point id exceeds u32::MAX bytes".to_string()))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

fn write_vector(writer: &mut impl Write, vector: &[f32]) -> Result<()> {
    for value in vector {
        writer.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

fn write_scaled_f16_vector(writer: &mut impl Write, vector: &[f32]) -> Result<()> {
    writer.write_all(&scaled_f16_row_bytes(vector)?)?;
    Ok(())
}

pub(crate) fn scaled_f16_row_bytes(vector: &[f32]) -> Result<Vec<u8>> {
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(GaussError::InvalidRequest(
            "sealed vectors must contain only finite values".to_string(),
        ));
    }
    let max_abs = vector
        .iter()
        .map(|value| value.abs())
        .fold(0.0_f32, f32::max);
    let mut scale = scaled_f16_decode_scale(max_abs);
    let mut encoded = vector
        .iter()
        .map(|value| f16::from_f32(*value / scale))
        .collect::<Vec<_>>();
    if encoded.iter().any(|value| !value.is_finite()) {
        scale *= 2.0;
        encoded = vector
            .iter()
            .map(|value| f16::from_f32(*value / scale))
            .collect();
    }
    if !scale.is_finite() || scale <= 0.0 || encoded.iter().any(|value| !value.is_finite()) {
        return Err(GaussError::InvalidRequest(
            "vector cannot be represented by scaled f16 storage".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(4 + vector.len() * 2);
    bytes.extend_from_slice(&scale.to_le_bytes());
    for value in encoded {
        bytes.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    Ok(bytes)
}

fn scaled_f16_decode_scale(max_abs: f32) -> f32 {
    if max_abs == 0.0 {
        return 1.0;
    }
    let exponent = max_abs.log2().floor() as i32 - 15;
    let mut scale = 2.0_f32.powi(exponent);
    if scale == 0.0 {
        scale = f32::from_bits(1);
    }
    if max_abs / scale > f16::MAX.to_f32() {
        scale *= 2.0;
    }
    scale
}

fn sync_writer(writer: BufWriter<File>) -> Result<()> {
    let file = writer
        .into_inner()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    file.sync_all()?;
    Ok(())
}

fn sync_payload_writer(writer: BufWriter<File>, offsets: &[u64]) -> Result<()> {
    let mut file = writer
        .into_inner()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    file.seek(SeekFrom::Start(16))?;
    for offset in offsets {
        file.write_all(&offset.to_le_bytes())?;
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> Result<()> {
    // Windows does not allow opening directories through std::fs::File.
    Ok(())
}

fn file_entry(dir: &Path, name: &str) -> Result<SealFile> {
    let path = dir.join(name);
    let file = encryption::PersistentFile::open(&path)?;
    Ok(SealFile {
        name: name.to_string(),
        bytes: file.len() as u64,
        crc: file.crc32(0..file.len())?,
    })
}

fn write_marker(path: &Path, marker: &SealMarker) -> Result<()> {
    let payload = serde_json::to_vec(marker)?;
    if payload.len() > MAX_MARKER_BYTES {
        return Err(corrupt(path, "sealed-segment marker exceeds size cap"));
    }
    let mut bytes = Vec::with_capacity(20 + payload.len());
    bytes.extend_from_slice(SEAL_MAGIC);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&crc(&payload).to_le_bytes());
    bytes.extend_from_slice(&payload);
    encryption::atomic_write_persistent(path, FileType::Segment, &bytes)
}

fn crc(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn encrypt_sealed_artifacts(dir: &Path) -> Result<()> {
    if !encryption::encryption_enabled() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        encryption::encrypt_file_in_place(&path, FileType::Segment)?;
    }
    Ok(())
}

fn encrypt_staged_file(path: &Path) -> Result<()> {
    if !encryption::encryption_enabled() {
        return Ok(());
    }
    encryption::encrypt_file_in_place(path, FileType::Segment)
}

fn read_vector_header(bytes: &[u8], path: &Path) -> Result<(usize, usize, DenseVectorEncoding)> {
    let encoding = match bytes.get(..8) {
        Some(magic) if magic == VECTOR_MAGIC_V4 => DenseVectorEncoding::F32,
        Some(magic) if magic == VECTOR_MAGIC_V5 => DenseVectorEncoding::ScaledF16,
        _ => return Err(corrupt(path, "bad or truncated sealed vector header")),
    };
    if bytes.len() < 24 {
        return Err(corrupt(path, "bad or truncated sealed vector header"));
    }
    Ok((
        usize_from_u64(
            u64::from_le_bytes(bytes[8..16].try_into().expect("vector count")),
            path,
        )?,
        usize_from_u64(
            u64::from_le_bytes(bytes[16..24].try_into().expect("vector dim")),
            path,
        )?,
        encoding,
    ))
}

fn decode_f32_row(bytes: &[u8]) -> Option<Vec<f32>> {
    bytes
        .len()
        .is_multiple_of(std::mem::size_of::<f32>())
        .then(|| {
            bytes
                .chunks_exact(4)
                .map(|value| f32::from_le_bytes(value.try_into().expect("four-byte f32 component")))
                .collect()
        })
}

fn read_ids_file(
    file: &encryption::PersistentFile,
    path: &Path,
    expected_count: usize,
) -> Result<Vec<String>> {
    if file.len() < 16 {
        return Err(corrupt(path, "bad or truncated v4 ids header"));
    }
    let header = file.read_range(0..16)?;
    if &header[..8] != IDS_MAGIC {
        return Err(corrupt(path, "bad or truncated v4 ids header"));
    }
    let count = usize_from_u64(
        u64::from_le_bytes(header[8..16].try_into().expect("ids count")),
        path,
    )?;
    if count != expected_count {
        return Err(corrupt(path, "v4 ids count disagrees with seal marker"));
    }
    let mut ids = Vec::with_capacity(count);
    let mut pos = 16_usize;
    for ordinal in 0..count {
        let len_end = pos
            .checked_add(4)
            .ok_or_else(|| corrupt(path, "v4 ids offset overflow"))?;
        let len_bytes = file.read_range(pos..len_end)?;
        let len = u32::from_le_bytes(len_bytes.as_ref().try_into().expect("id length")) as usize;
        let id_end = len_end
            .checked_add(len)
            .ok_or_else(|| corrupt(path, "v4 id length overflow"))?;
        let id_bytes = file.read_range(len_end..id_end)?;
        let id = std::str::from_utf8(&id_bytes)
            .map_err(|error| corrupt(path, &format!("v4 id {ordinal} is not UTF-8: {error}")))?;
        ids.push(id.to_string());
        pos = id_end;
    }
    if pos != file.len() {
        return Err(corrupt(path, "v4 ids file has trailing bytes"));
    }
    Ok(ids)
}

fn read_payload_offsets_file(
    file: &encryption::PersistentFile,
    path: &Path,
    expected_count: usize,
) -> Result<(Vec<u64>, usize)> {
    if file.len() < 16 {
        return Err(corrupt(path, "bad or truncated v4 payload header"));
    }
    let header = file.read_range(0..16)?;
    if &header[..8] != PAYLOAD_MAGIC {
        return Err(corrupt(path, "bad or truncated v4 payload header"));
    }
    let count = usize_from_u64(
        u64::from_le_bytes(header[8..16].try_into().expect("payload count")),
        path,
    )?;
    if count != expected_count {
        return Err(corrupt(path, "v4 payload count disagrees with seal marker"));
    }
    let table_bytes = count
        .checked_add(1)
        .and_then(|entries| entries.checked_mul(std::mem::size_of::<u64>()))
        .ok_or_else(|| corrupt(path, "v4 payload table length overflow"))?;
    let payload_start = 16_usize
        .checked_add(table_bytes)
        .ok_or_else(|| corrupt(path, "v4 payload start overflow"))?;
    if payload_start > file.len() {
        return Err(corrupt(path, "truncated v4 payload offset table"));
    }
    let mut offsets = Vec::with_capacity(count + 1);
    let mut position = 16_usize;
    while position < payload_start {
        let end = position
            .checked_add(8)
            .ok_or_else(|| corrupt(path, "payload offset position overflow"))?;
        let offset = file.read_range(position..end)?;
        offsets.push(u64::from_le_bytes(
            offset.as_ref().try_into().expect("payload offset"),
        ));
        position = end;
    }
    if offsets.first().copied() != Some(0)
        || offsets.windows(2).any(|pair| pair[0] > pair[1])
        || offsets.last().copied() != Some((file.len() - payload_start) as u64)
    {
        return Err(corrupt(path, "invalid v4 payload offsets"));
    }
    Ok((offsets, payload_start))
}

fn payload_range(
    offsets: &[u64],
    payload_start: usize,
    ordinal: usize,
) -> Option<std::ops::Range<usize>> {
    let start = usize::try_from(*offsets.get(ordinal)?).ok()?;
    let end = usize::try_from(*offsets.get(ordinal + 1)?).ok()?;
    Some(payload_start.checked_add(start)?..payload_start.checked_add(end)?)
}

fn usize_from_u64(value: u64, path: &Path) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(path, "v4 integer exceeds platform usize"))
}

fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn point(id: &str, vector: Vec<f32>) -> Point {
        Point {
            id: id.to_string(),
            vector,
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"source": id}),
        }
    }

    fn lcg_vector(seed: u64, dim: usize) -> Vec<f32> {
        let mut state = seed ^ 0x517c_c1b7_2722_0a95;
        (0..dim)
            .map(|_| {
                state = state
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                (((state >> 32) as u32) as f32 / u32::MAX as f32) * 2.0 - 1.0
            })
            .collect()
    }

    #[test]
    fn algorithm2_segment_round_trip_search_and_filter() {
        use std::sync::Arc;

        use crate::index::IndexBackend;

        let temp = TempDir::new().unwrap();
        let out = temp.path().join("algorithm2.tmp");
        let points = (0..256)
            .map(|i| {
                let mut point = point(&format!("p{i:03}"), lcg_vector(i, 16));
                point
                    .vectors
                    .insert("image".to_string(), lcg_vector(i + 10_000, 16));
                point
            })
            .collect::<Vec<_>>();
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        assert!(out.join(crate::index::ivf::IVF_FILE).exists());
        assert!(out.join(crate::index::rabitq::RABITQ_FILE).exists());
        assert!(out.join(crate::index::vamana::VAMANA_SEGMENT_FILE).exists());
        for file in named_files("image") {
            assert!(out.join(file).exists());
        }
        assert_eq!(read_marker(&out.join(SEAL_FILE)).unwrap().version, 8);
        assert_eq!(
            fs::metadata(out.join(named_vector_file("image")))
                .unwrap()
                .len(),
            24 + 256 * (4 + 16 * 2)
        );
        assert!(!out.join(h2qg::INDEX_FILE).exists());
        assert!(!out.join(h2qg::HNSW_VECS_FILE).exists());
        assert!(read_marker(&out.join(SEAL_FILE)).is_ok());

        let store = Arc::new(V4Store::open(&out).unwrap());
        let index =
            crate::index::ivf_segment::IvfSegmentIndex::open(&out, store, DistanceMetric::L2)
                .unwrap();
        let mut self_hits = 0usize;
        for i in 0..64 {
            let hits = index.candidate_ids_with_ef(&lcg_vector(i, 16), 10, Some(128));
            if hits.iter().any(|id| id == &format!("p{i:03}")) {
                self_hits += 1;
            }
        }
        assert!(self_hits >= 61, "self recall@10 = {self_hits}/64");

        let named = crate::index::ivf_segment::IvfSegmentIndex::open_named(
            &out,
            "image",
            DistanceMetric::L2,
        )
        .unwrap();
        let named_hits = named.candidate_ids_with_ef(&lcg_vector(10_017, 16), 10, Some(128));
        assert!(named_hits.iter().any(|id| id == "p017"));
        assert_eq!(
            V4Store::open(&out).unwrap().get("p017").unwrap().vectors["image"],
            points[17].vectors["image"]
        );

        let even = |id: &str| {
            id.trim_start_matches('p')
                .parse::<usize>()
                .is_ok_and(|ordinal| ordinal % 2 == 0)
        };
        let filtered =
            index.candidate_ids_with_ef_filter(&lcg_vector(2, 16), 10, Some(128), Some(&even));
        assert!(!filtered.is_empty());
        assert!(filtered.iter().all(|id| even(id)));
    }

    #[test]
    fn resumable_build_recovers_partial_and_corrupt_vamana_cells() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("build");
        let config = SealConfig {
            vector_dim: 16,
            metric: DistanceMetric::Cosine,
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: SealIndexKind::Algorithm2,
            base_lsn: 0,
            end_lsn: 42,
        };
        let mut points = (0..144)
            .map(|i| point(&format!("p{i:03}"), lcg_vector(i, 16)))
            .collect::<Vec<_>>();

        let first =
            build_segment_resumable(points.as_slice(), &workspace, "sg-resume", config).unwrap();
        let candidate = first.dir;
        let baseline = temp.path().join("baseline");
        build_segment(points.as_slice(), &baseline, config).unwrap();
        for artifact in [
            crate::index::ivf::IVF_FILE,
            crate::index::rabitq::RABITQ_FILE,
            crate::index::vamana::VAMANA_SEGMENT_FILE,
            crate::index::diskann::DISKANN_FILE,
        ] {
            assert_eq!(
                fs::read(candidate.join(artifact)).unwrap(),
                fs::read(baseline.join(artifact)).unwrap(),
                "resumable build changed deterministic artifact {artifact}"
            );
        }
        let cells_dir = crate::build_progress::BuildProgress::cells_dir(&workspace);
        let mut cells = fs::read_dir(&cells_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        cells.sort();
        assert!(cells.len() > 1);

        fs::remove_file(candidate.join(SEAL_FILE)).unwrap();
        fs::remove_file(candidate.join(crate::index::vamana::VAMANA_SEGMENT_FILE)).unwrap();
        fs::remove_file(&cells[1]).unwrap();
        build_segment_resumable(points.as_slice(), &workspace, "sg-resume", config).unwrap();
        assert!(cells[1].exists(), "missing cell shard must be rebuilt");
        V4Store::open(&candidate).unwrap();

        fs::remove_file(candidate.join(SEAL_FILE)).unwrap();
        fs::remove_file(candidate.join(crate::index::vamana::VAMANA_SEGMENT_FILE)).unwrap();
        fs::write(&cells[0], b"corrupt-cell").unwrap();
        build_segment_resumable(points.as_slice(), &workspace, "sg-resume", config).unwrap();
        assert_ne!(fs::read(&cells[0]).unwrap(), b"corrupt-cell");
        V4Store::open(&candidate).unwrap();

        points[0].payload = json!({"generation": 2});
        build_segment_resumable(points.as_slice(), &workspace, "sg-resume", config).unwrap();
        assert_eq!(
            V4Store::open(&candidate)
                .unwrap()
                .get("p000")
                .unwrap()
                .payload,
            json!({"generation": 2})
        );
    }

    #[test]
    fn enospc_after_cell_checkpoint_resumes_without_rewriting_valid_cell() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("build-enospc");
        let config = SealConfig {
            vector_dim: 16,
            metric: DistanceMetric::Cosine,
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: SealIndexKind::Algorithm2,
            base_lsn: 0,
            end_lsn: 84,
        };
        let points = (0..144)
            .map(|i| point(&format!("p{i:03}"), lcg_vector(i, 16)))
            .collect::<Vec<_>>();

        crate::fs_util::fault_injection::inject_once(
            crate::fs_util::fault_injection::Fault::Enospc,
        );
        let error = build_segment_resumable(points.as_slice(), &workspace, "sg-enospc", config)
            .unwrap_err();
        assert!(matches!(
            error,
            GaussError::Io(ref io) if io.kind() == std::io::ErrorKind::StorageFull
        ));

        let cells_dir = crate::build_progress::BuildProgress::cells_dir(&workspace);
        let cells = fs::read_dir(&cells_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(cells.len(), 1, "fault must land after one durable cell");
        let first_cell = &cells[0];
        let bytes = fs::read(first_cell).unwrap();
        let modified = fs::metadata(first_cell).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        build_segment_resumable(points.as_slice(), &workspace, "sg-enospc", config).unwrap();
        assert_eq!(fs::read(first_cell).unwrap(), bytes);
        assert_eq!(
            fs::metadata(first_cell).unwrap().modified().unwrap(),
            modified
        );
        V4Store::open(&crate::build_progress::BuildProgress::candidate_dir(
            &workspace,
        ))
        .unwrap();
    }

    #[test]
    fn legacy_raw_f32_named_rows_remain_readable_and_cold_compatible() {
        use crate::index::IndexBackend;

        let temp = TempDir::new().unwrap();
        let out = temp.path().join("legacy-named-v6");
        let points = (0..64)
            .map(|i| {
                let mut point = point(&format!("p{i:03}"), lcg_vector(i, 16));
                point
                    .vectors
                    .insert("image".to_string(), lcg_vector(i + 10_000, 16));
                point
            })
            .collect::<Vec<_>>();
        build_segment_with_encodings(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
            DenseVectorEncoding::ScaledF16,
            DenseVectorEncoding::F32,
            None,
            None,
        )
        .unwrap();

        assert_eq!(read_marker(&out.join(SEAL_FILE)).unwrap().version, 6);
        assert_eq!(
            fs::metadata(out.join(named_vector_file("image")))
                .unwrap()
                .len(),
            24 + 64 * 16 * 4
        );
        let mut mismatched = read_marker(&out.join(SEAL_FILE)).unwrap();
        mismatched.version = 8;
        write_marker(&out.join(SEAL_FILE), &mismatched).unwrap();
        assert!(read_marker(&out.join(SEAL_FILE)).is_err());
        mismatched.version = 6;
        write_marker(&out.join(SEAL_FILE), &mismatched).unwrap();
        let named = crate::index::ivf_segment::IvfSegmentIndex::open_named(
            &out,
            "image",
            DistanceMetric::L2,
        )
        .unwrap();
        let hits = named.candidate_ids_with_ef(&points[17].vectors["image"], 10, Some(128));
        assert!(hits.iter().any(|id| id == "p017"));

        assert!(thin_algorithm2_segment_for_cold(&out).unwrap());
        assert_eq!(read_marker(&out.join(SEAL_FILE)).unwrap().version, 7);
        crate::index::ivf_segment::IvfSegmentIndex::open_named(&out, "image", DistanceMetric::L2)
            .unwrap();
    }

    #[test]
    fn builds_committed_v5_segment_without_touching_siblings() {
        let temp = TempDir::new().unwrap();
        let sibling = temp.path().join("sg-existing");
        fs::create_dir(&sibling).unwrap();
        fs::write(sibling.join("keep"), b"yes").unwrap();
        let out = temp.path().join("sg-next.tmp");
        let mut first = point("a", vec![3.0, 4.0]);
        first.vectors.insert("image".to_string(), vec![8.0, 9.0]);
        first.sparse_vector = Some(crate::SparseVector {
            indices: vec![7],
            values: vec![0.5],
        });
        let points = vec![first, point("b", vec![0.0, 2.0])];
        let write = build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::Cosine,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Hnsw,
                base_lsn: 10,
                end_lsn: 20,
            },
        )
        .unwrap();

        assert_eq!(write.marker.points, 2);
        assert_eq!(write.marker.version, 5);
        assert_eq!(read_marker(&out.join(SEAL_FILE)).unwrap().end_lsn, 20);
        assert_eq!(fs::read(sibling.join("keep")).unwrap(), b"yes");
        let index = h2qg::read_index_paged(&out).unwrap();
        assert_eq!(index.indexed_points(), 2);
        let store = V4Store::open(&out).unwrap();
        assert_eq!(store.ids(), ["a", "b"]);
        let hydrated = store.get("a").unwrap();
        assert_eq!(hydrated.vector, vec![3.0, 4.0]);
        assert_eq!(hydrated.vectors["image"], vec![8.0, 9.0]);
        assert_eq!(hydrated.sparse_vector.unwrap().indices, vec![7]);
        assert_eq!(hydrated.payload, json!({"source": "a"}));
    }

    #[test]
    fn scaled_f16_rows_reduce_bytes_and_preserve_f32_range() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("scaled-f16");
        let vectors = [vec![0.123_456_7; 16], vec![1.0e30; 16], vec![1.0e-30; 16]];
        let points = vectors
            .iter()
            .enumerate()
            .map(|(ordinal, vector)| point(&ordinal.to_string(), vector.clone()))
            .collect::<Vec<_>>();
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();

        let marker = read_marker(&out.join(SEAL_FILE)).unwrap();
        assert_eq!(marker.version, 6);
        assert!(out.join(crate::index::diskann::DISKANN_FILE).exists());
        assert_eq!(
            fs::metadata(out.join(VECTOR_FILE)).unwrap().len(),
            24 + 3 * (4 + 16 * 2)
        );
        let store = V4Store::open(&out).unwrap();
        assert_eq!(store.exact_vector_bytes_per_component(), 2.25);
        for (ordinal, expected) in vectors.iter().enumerate() {
            let actual = store.vector(ordinal).unwrap();
            for (actual, expected) in actual.iter().zip(expected) {
                let relative_error =
                    (actual - expected).abs() / expected.abs().max(f32::MIN_POSITIVE);
                assert!(
                    relative_error <= 0.001,
                    "scaled-f16 relative error {relative_error} for {expected:e}"
                );
            }
        }
    }

    #[test]
    fn cold_v9_preserves_scaled_named_rows_without_duplicate_primary_files() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("cold-v7");
        let mut points = (0..32)
            .map(|ordinal| point(&format!("p{ordinal:03}"), vec![ordinal as f32 + 0.125; 16]))
            .collect::<Vec<_>>();
        for (ordinal, point) in points.iter_mut().enumerate() {
            point.vectors.insert(
                "image".to_string(),
                vec![ordinal as f32, 31.0 - ordinal as f32],
            );
        }
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        assert_eq!(read_marker(&out.join(SEAL_FILE)).unwrap().version, 8);
        assert!(out.join(VECTOR_FILE).exists());
        assert!(out.join(crate::index::vamana::VAMANA_SEGMENT_FILE).exists());

        assert!(thin_algorithm2_segment_for_cold(&out).unwrap());
        assert!(!thin_algorithm2_segment_for_cold(&out).unwrap());
        let marker = read_marker(&out.join(SEAL_FILE)).unwrap();
        assert_eq!(marker.version, 9);
        assert!(!out.join(VECTOR_FILE).exists());
        assert!(!out.join(crate::index::vamana::VAMANA_SEGMENT_FILE).exists());
        assert!(marker.files.iter().all(|entry| entry.name != VECTOR_FILE
            && entry.name != crate::index::vamana::VAMANA_SEGMENT_FILE));
        assert!(out.join(named_vector_file("image")).exists());
        assert!(out.join(named_vamana_file("image")).exists());

        let store = Arc::new(V4Store::open(&out).unwrap());
        assert_eq!(store.segment_format_version(), 9);
        assert_eq!(store.exact_vector_bytes_per_component(), 2.25);
        let hydrated = store.get("p017").unwrap();
        assert_eq!(hydrated.id, "p017");
        assert_eq!(hydrated.vectors["image"], vec![17.0, 14.0]);
        for (actual, expected) in hydrated.vector.iter().zip(&points[17].vector) {
            assert!((actual - expected).abs() <= 0.001 * expected.abs().max(1.0));
        }
        crate::index::ivf_segment::IvfSegmentIndex::open_cold(
            &out,
            Arc::clone(&store),
            DistanceMetric::L2,
        )
        .unwrap();
        crate::index::ivf_segment::IvfSegmentIndex::open_named(&out, "image", DistanceMetric::L2)
            .unwrap();
    }

    #[test]
    fn legacy_v4_f32_rows_reopen_and_reseal_as_v6() {
        let temp = TempDir::new().unwrap();
        let legacy = temp.path().join("legacy-v4");
        let migrated = temp.path().join("migrated-v5");
        let points = vec![
            point("a", vec![0.123_456_7; 16]),
            point("b", vec![-9.876_543; 16]),
        ];
        build_segment_with_encoding(
            points.as_slice(),
            &legacy,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
            DenseVectorEncoding::F32,
        )
        .unwrap();
        assert_eq!(read_marker(&legacy.join(SEAL_FILE)).unwrap().version, 4);
        let legacy_store = V4Store::open(&legacy).unwrap();
        assert_eq!(legacy_store.exact_vector_bytes_per_component(), 4.0);
        assert_eq!(legacy_store.vector(0).unwrap(), points[0].vector);

        let hydrated = (0..legacy_store.len())
            .map(|ordinal| legacy_store.get_ordinal(ordinal).unwrap())
            .collect::<Vec<_>>();
        build_segment(
            hydrated.as_slice(),
            &migrated,
            SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 2,
            },
        )
        .unwrap();
        assert_eq!(read_marker(&migrated.join(SEAL_FILE)).unwrap().version, 6);
        assert!(
            fs::metadata(migrated.join(VECTOR_FILE)).unwrap().len()
                < fs::metadata(legacy.join(VECTOR_FILE)).unwrap().len()
        );
        let migrated_store = V4Store::open(&migrated).unwrap();
        assert_eq!(migrated_store.ids(), legacy_store.ids());
    }

    #[test]
    fn marker_detects_payload_corruption() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("segment.tmp");
        let points = vec![point("a", vec![1.0, 2.0])];
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let payload = out.join(PAYLOAD_FILE);
        let mut bytes = fs::read(&payload).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        fs::write(payload, bytes).unwrap();
        assert!(read_marker(&out.join(SEAL_FILE)).is_err());
    }

    #[test]
    fn mutable_tombstones_roundtrip_and_detect_corruption() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("segment.tmp");
        let points = vec![point("a", vec![1.0, 2.0]), point("b", vec![2.0, 3.0])];
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let store = V4Store::open(&out).unwrap();
        write_tombstones(&out, &store, &HashSet::from(["b".to_string()])).unwrap();
        assert_eq!(
            read_tombstones(&out, store.ids()).unwrap(),
            HashSet::from(["b".to_string()])
        );
        assert!(read_marker(&out.join(SEAL_FILE)).is_ok());

        let path = out.join(TOMBSTONE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        fs::write(path, bytes).unwrap();
        assert!(read_tombstones(&out, store.ids()).is_err());
    }

    #[test]
    fn failed_seal_never_publishes_marker() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("segment.tmp");
        let points = vec![point("bad", vec![1.0])];
        assert!(
            build_segment(
                points.as_slice(),
                &out,
                SealConfig {
                    vector_dim: 2,
                    metric: DistanceMetric::L2,
                    hnsw_m: None,
                    hnsw_ef_construction: None,
                    index_kind: SealIndexKind::Hnsw,
                    base_lsn: 0,
                    end_lsn: 1,
                },
            )
            .is_err()
        );
        assert!(!out.join(SEAL_FILE).exists());
    }

    #[test]
    fn threshold_segment_builds_paged_hnsw() {
        let temp = TempDir::new().unwrap();
        let out = temp.path().join("segment.tmp");
        let points = (0..h2qg::HNSW_THRESHOLD)
            .map(|i| point(&format!("p{i:05}"), vec![i as f32, (i % 97) as f32]))
            .collect::<Vec<_>>();
        build_segment(
            points.as_slice(),
            &out,
            SealConfig {
                vector_dim: 2,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();

        let index = h2qg::read_index_paged(&out).unwrap();
        assert!(index.is_hnsw());
        assert_eq!(index.indexed_points(), h2qg::HNSW_THRESHOLD);
        assert!(read_marker(&out.join(SEAL_FILE)).is_ok());
    }
}
