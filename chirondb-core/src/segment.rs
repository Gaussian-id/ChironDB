use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    future::Future,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use crc32fast::Hasher;
use futures_executor::block_on;
use object_store::{
    ObjectStore, ObjectStoreExt, PutPayload, local::LocalFileSystem, parse_url_opts,
    path::Path as ObjectPath,
};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    encryption::{self, FileType},
    error::{GaussError, Result},
    fs_util::copy_dir_all,
    h2qg::{self, H2qgIndex},
    model::{Point, SparseVector},
};

const MANIFEST_MAGIC: &[u8; 8] = b"GAUSSMF1";
const VECTOR_MAGIC: &[u8; 8] = b"GAUSSGD1";
const VECTOR_MAGIC_V2: &[u8; 8] = b"GAUSSGD2";
// P2E: GAUSSGD3 — Structure-of-Arrays (SoA) dim-strided vector storage.
// Inner magic distinguishes the V3 payload from anything that happens to
// start with `GAUSSGD3` while sharing the outer paged-framed envelope.
const VECTOR_MAGIC_V3: &[u8; 8] = b"GAUSSGD3";
const VECTOR_V3_INNER_MAGIC: &[u8; 8] = b"GD3INN01";
const V3_FLAG_HAS_NAMED: u32 = 1 << 0;
const V3_FLAG_HAS_SPARSE: u32 = 1 << 1;
const SPARSE_MAGIC: &[u8; 8] = b"GAUSSSP1";
const PAYLOAD_MAGIC: &[u8; 8] = b"GAUSSPY1";
const TOMBSTONE_MAGIC: &[u8; 8] = b"GAUSSTM1";
const COLD_INDEX_MAGIC: &[u8; 8] = b"GAUSSCL1";
const HEADER_LEN: usize = 20;
const SPARSE_BLOCK_SIZE: usize = 16;
const PAGE_SIZE: usize = 4096;
pub const MANIFEST_FILE: &str = "manifest.gdx";
pub const COLD_INDEX_FILE: &str = "cold_index.gdx";
const SEGMENT_FILE: &str = "vec.gdx";
pub const SPARSE_INDEX_FILE: &str = "sparse.gdx";
pub const PAYLOAD_INDEX_FILE: &str = "payload.gdx";
pub const TOMBSTONE_FILE: &str = "tomb.gdx";
pub const VAMANA_FILE: &str = "vamana.gdx";
pub const VAMANA_MAGIC: &[u8; 8] = b"GAUSSVN1";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SegmentPayload {
    points: Vec<Point>,
}

/// Borrowing twin of `SegmentPayload` used only to serialize without cloning
/// the (potentially huge) point set a second time.
#[derive(Serialize)]
struct SegmentPayloadRef<'a> {
    points: &'a [Point],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SparseIndexPayload {
    dimensions: Vec<SparseDimensionPayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SparseDimensionPayload {
    dimension: u32,
    postings: Vec<SparsePostingPayload>,
    #[serde(default)]
    blocks: Vec<SparseBlockPayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SparsePostingPayload {
    id: String,
    value: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SparseBlockPayload {
    start: usize,
    len: usize,
    max_value: f32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PayloadIndexPayload {
    fields: Vec<PayloadFieldPayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PayloadFieldPayload {
    field: String,
    values: Vec<PayloadValuePayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PayloadValuePayload {
    key: String,
    ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TombstonePayload {
    #[serde(default)]
    deleted_ids: Vec<String>,
    #[serde(default)]
    deleted_ordinals_roaring: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SegmentManifestPayload {
    id: String,
    points: usize,
    h2qg_cells: usize,
    #[serde(default)]
    named_h2qg_fields: usize,
    sparse_dimensions: usize,
    sparse_postings: usize,
    #[serde(default)]
    sparse_blocks: usize,
    payload_fields: usize,
    payload_values: usize,
    payload_postings: usize,
    #[serde(default)]
    tombstones: usize,
    files: Vec<SegmentManifestFilePayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SegmentManifestFilePayload {
    name: String,
    bytes: u64,
    crc: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ColdIndexPayload {
    segments: Vec<ColdIndexSegmentPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ColdIndexSegmentPayload {
    id: String,
    points: usize,
    files: usize,
    bytes: u64,
    manifest_crc: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    object_key_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    object_files: Vec<ColdIndexObjectFilePayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ColdIndexObjectFilePayload {
    name: String,
    key: String,
    bytes: u64,
    #[serde(default)]
    plaintext_bytes: u64,
    crc: u32,
}

impl ColdIndexObjectFilePayload {
    fn logical_bytes(&self) -> u64 {
        if self.plaintext_bytes == 0 {
            self.bytes
        } else {
            self.plaintext_bytes
        }
    }
}

pub type PayloadIndexSnapshot = BTreeMap<String, BTreeMap<String, Vec<String>>>;

// ── P2E: SoA (Structure-of-Arrays) vector storage — GAUSSGD3 ────────────────

/// Per-point auxiliary data carried alongside the SoA f32 grid.
/// `vector` is intentionally absent — the SoA grid is the source of truth for
/// the dense vector. Reconstruction joins `SoAVectorStorage::points` with the
/// SoA f32 slice by index.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PointAux {
    id: String,
    #[serde(default)]
    payload: serde_json::Value,
    #[serde(default)]
    sparse_vector: Option<SparseVector>,
    #[serde(default)]
    vectors: HashMap<String, Vec<f32>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SoAVectorStorage {
    /// Per-point aux (id, payload, sparse, named vectors) — same order as the
    /// SoA f32 grid (point 0..count).
    points: Vec<PointAux>,
    /// dim == length of each row. The grid has `count * dim` f32 values laid
    /// out dim-strided: `soa[d*count + i] = points[i].vector[d]`. The outer
    /// loop over `d` reads a single contiguous f32 column covering every
    /// point; SIMD distance kernels can load 8 contiguous f32 (8 points'
    /// `dim_d` value) in a single instruction, do a single subtract, square,
    /// and FMA into the 8-lane accumulator.
    dim: usize,
    soa: Vec<f32>,
}

impl SoAVectorStorage {
    pub fn dim(&self) -> usize {
        self.dim
    }
    pub fn count(&self) -> usize {
        self.points.len()
    }
    /// Materialize a [`Point`] at index `i` by gathering the SoA column for
    /// every dim. Used by `read_segment` to satisfy the legacy `Vec<Point>`
    /// contract.
    pub fn materialize(&self, i: usize) -> Option<Point> {
        let aux = self.points.get(i)?;
        let mut vector = Vec::with_capacity(self.dim);
        for d in 0..self.dim {
            vector.push(*self.soa.get(d * self.points.len() + i)?);
        }
        Some(Point {
            id: aux.id.clone(),
            vector,
            vectors: aux.vectors.clone(),
            sparse_vector: aux.sparse_vector.clone(),
            payload: aux.payload.clone(),
        })
    }
    /// Materialize every point (used by `read_segment` to satisfy the legacy
    /// `Vec<Point>` contract). For hot paths, prefer [`Self::materialize`] only
    /// for the indices actually needed.
    pub fn into_points(self) -> Vec<Point> {
        let count = self.points.len();
        (0..count)
            .map(|i| self.materialize(i).expect("in-bounds"))
            .collect()
    }
    /// Borrow the SoA f32 grid. Layout: `soa[d*count + i] = points[i].vector[d]`.
    pub fn soa(&self) -> &[f32] {
        &self.soa
    }
}

/// P2E: in-memory Structure-of-Arrays cache for a segment's dense vectors.
/// Owned by [`LoadedSearchers`] when the on-disk format is GAUSSGD3; `None`
/// when the segment was loaded from a legacy V1/V2 file and the cache has
/// not been (re-)built yet. The f32 grid is dim-strided — point `i`'s dense
/// vector lives at `soa[i*dim .. (i+1)*dim]`; the corresponding ID is at
/// `ids[i]`. Both slices are read-only and live for the segment's lifetime.
#[derive(Clone, Debug)]
pub struct SoASegmentCache {
    dim: usize,
    ids: Vec<String>,
    /// dim-strided: for d in 0..dim, for i in 0..count: soa[d*count + i]
    soa: Vec<f32>,
}

impl SoASegmentCache {
    pub fn dim(&self) -> usize {
        self.dim
    }
    pub fn count(&self) -> usize {
        self.ids.len()
    }
    pub fn ids(&self) -> &[String] {
        &self.ids
    }
    /// Borrow the dim-strided SoA f32 grid. Layout: `soa[d*count + i] =
    /// points[i].vector[d]`. The outer loop (over `d`) sees one contiguous
    /// f32 column covering every point — the read pattern the SIMD
    /// batch-distance kernel relies on.
    pub fn soa(&self) -> &[f32] {
        &self.soa
    }
    /// Build a SoA cache from a GAUSSGD3 storage. The on-disk layout is
    /// already dim-strided, so this is a clone of the SoA f32 grid plus a
    /// copy of the ID list. Zero copy *work* — only the same Vec<f32> we
    /// mmap-read gets cloned into the cache.
    pub fn from_storage(storage: &SoAVectorStorage) -> Self {
        Self {
            dim: storage.dim(),
            ids: storage.points.iter().map(|p| p.id.clone()).collect(),
            soa: storage.soa.clone(),
        }
    }
    /// Build a SoA cache from an AoS `Vec<Point>` (used when loading V1/V2
    /// legacy segments). One sequential transpose pass.
    pub fn from_points(points: &[Point]) -> Result<Self> {
        if points.is_empty() {
            return Ok(Self {
                dim: 0,
                ids: Vec::new(),
                soa: Vec::new(),
            });
        }
        let dim = points[0].vector.len();
        if dim == 0 {
            return Err(GaussError::InvalidRequest(
                "cannot build SoA cache: first point has zero-dim vector".to_string(),
            ));
        }
        for point in points {
            if point.vector.len() != dim {
                return Err(GaussError::InvalidRequest(format!(
                    "cannot build SoA cache: dim mismatch ({} vs {}) for point {}",
                    point.vector.len(),
                    dim,
                    point.id
                )));
            }
        }
        let count = points.len();
        let mut soa = vec![0.0_f32; count * dim];
        for d in 0..dim {
            let column_offset = d * count;
            for (i, point) in points.iter().enumerate() {
                soa[column_offset + i] = point.vector[d];
            }
        }
        Ok(Self {
            dim,
            ids: points.iter().map(|p| p.id.clone()).collect(),
            soa,
        })
    }

    /// Migrate a legacy (V1 or V2) `vec.gdx` on disk to the V3 SoA format
    /// in place, with a `.v1bak` / `.v2bak` backup. Returns the storage
    /// that was written. Idempotent: re-running on a V3 file is a no-op.
    /// Atomicity: the new file is written to `<path>.v3tmp` and then renamed
    /// over the original; on any error the original is restored from the
    /// backup.
    pub fn migrate_legacy_file(path: &Path) -> Result<SoAVectorStorage> {
        let raw_bytes = encryption::read_persistent(path)?;
        if raw_bytes.len() >= 8 && &raw_bytes[0..8] == VECTOR_MAGIC_V3 {
            return read_segment_soa(path);
        }
        let backup_label = if raw_bytes.len() >= 8 && &raw_bytes[0..8] == VECTOR_MAGIC_V2 {
            "v2bak"
        } else if raw_bytes.len() >= 8 && &raw_bytes[0..8] == VECTOR_MAGIC {
            "v1bak"
        } else {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: "unrecognised segment magic — not V1, V2, or V3".to_string(),
            });
        };
        let points = read_segment(path)?;
        let storage = build_soa_storage(&points)?;
        let backup_path = path.with_extension(backup_label);
        if backup_path.exists() {
            std::fs::remove_file(&backup_path)?;
        }
        std::fs::rename(path, &backup_path)?;
        let tmp_path = path.with_extension("v3tmp");
        if tmp_path.exists() {
            std::fs::remove_file(&tmp_path)?;
        }
        match write_segment_soa(&tmp_path, &storage) {
            Ok(()) => {
                std::fs::rename(&tmp_path, path)?;
                Ok(storage)
            }
            Err(error) => {
                let _ = std::fs::remove_file(&tmp_path);
                let _ = std::fs::rename(&backup_path, path);
                Err(error)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoadedSearchers {
    pub points: HashMap<String, Point>,
    pub h2qg: Option<H2qgIndex>,
    pub named_h2qg: HashMap<String, H2qgIndex>,
    pub payload_index: Option<PayloadIndexSnapshot>,
    /// P2E: optional dim-strided dense-vector cache. Populated when the
    /// segment was loaded from a GAUSSGD3 file (zero-copy-ish) and rebuilt
    /// from the AoS `points` map when the segment was loaded from a legacy
    /// V1/V2 file. Consumers that only need dense distance (exact brute
    /// force, recall-SLA ground truth, ACORN-lite prefilter) should
    /// prefer this over the `points` map to skip the per-call
    /// `point_vector` lookups.
    pub soa: Option<SoASegmentCache>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdTierWrite {
    pub segments: usize,
    pub files: usize,
    pub bytes: u64,
    pub points: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ColdObjectStoreConfig {
    LocalDir(PathBuf),
    Url(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreFileWrite {
    pub name: String,
    pub key: String,
    pub bytes: u64,
    pub plaintext_bytes: u64,
    pub crc: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreDirectoryWrite {
    pub object_key_prefix: String,
    pub files: usize,
    pub bytes: u64,
    pub object_files: Vec<ObjectStoreFileWrite>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreDirectoryRead {
    pub files: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentWrite {
    pub id: String,
    pub manifest_path: PathBuf,
    pub path: PathBuf,
    pub h2qg_path: PathBuf,
    pub named_h2qg_paths: BTreeMap<String, PathBuf>,
    pub sparse_path: PathBuf,
    pub payload_path: PathBuf,
    pub tombstone_path: PathBuf,
    pub points: usize,
    pub h2qg_cells: usize,
    pub named_h2qg_fields: usize,
    pub sparse_dimensions: usize,
    pub sparse_postings: usize,
    pub sparse_blocks: usize,
    pub payload_fields: usize,
    pub payload_values: usize,
    pub payload_postings: usize,
    pub tombstones: usize,
}

/// One segment dir loaded as an independent unit (LS-Vec rework D3):
/// its own points, index, and named indexes — nothing merged across
/// segments, unlike the legacy `LoadedSearchers` aggregate. On-disk
/// tombstones are already applied (removed from `points`) — permanent
/// deletes need no query-time mask; the searcher's live tombstone set
/// starts empty and fills from WAL replay / later deletes.
#[derive(Debug)]
pub struct LoadedSegment {
    pub id: String,
    pub dir: PathBuf,
    pub points: HashMap<String, Point>,
    pub h2qg: Option<H2qgIndex>,
    pub named_h2qg: HashMap<String, H2qgIndex>,
    pub payload_index: Option<PayloadIndexSnapshot>,
    pub v4_store: Option<crate::seal::V4Store>,
    pub tombstones: HashSet<String>,
    pub tombstone_ordinals: RoaringBitmap,
}

/// Per-segment loader: every `sg-*` dir under `dirs` becomes one
/// `LoadedSegment`, sorted by path (hot before cold within each dir list
/// entry, oldest-id first). Replaces the merged-map behavior of
/// `load_searchers_from_dirs` for the multi-segment serving path.
pub fn load_segments_with_cold_object_store(
    searchers_dir: &Path,
    cold_dir: &Path,
    object_store_config: Option<&ColdObjectStoreConfig>,
    installed_segments: Option<&HashSet<String>>,
) -> Result<Vec<LoadedSegment>> {
    if let Some(object_store_config) = object_store_config
        && cold_dir.exists()
    {
        validate_cold_index_with_object_store(cold_dir, Some(object_store_config))?;
        let remote_diskann =
            remote_diskann_artifacts(cold_dir, object_store_config, installed_segments)?;
        return load_segments_from_dirs_with_remote_diskann(
            &[searchers_dir, cold_dir],
            false,
            installed_segments,
            &remote_diskann,
        );
    }
    load_segments_from_dirs(&[searchers_dir, cold_dir], true, installed_segments)
}

fn load_segments_from_dirs(
    dirs: &[&Path],
    validate_indexes: bool,
    installed_segments: Option<&HashSet<String>>,
) -> Result<Vec<LoadedSegment>> {
    load_segments_from_dirs_with_remote_diskann(
        dirs,
        validate_indexes,
        installed_segments,
        &HashMap::new(),
    )
}

fn load_segments_from_dirs_with_remote_diskann(
    dirs: &[&Path],
    validate_indexes: bool,
    installed_segments: Option<&HashSet<String>>,
    remote_diskann: &HashMap<String, Arc<crate::index::diskann::DiskAnnArtifact>>,
) -> Result<Vec<LoadedSegment>> {
    let mut segment_dirs = Vec::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        if validate_indexes {
            validate_cold_index(dir)?;
        }
        segment_dirs.extend(
            fs::read_dir(dir)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?,
        );
    }
    segment_dirs.sort();

    let mut segments = Vec::new();
    for segment_dir in segment_dirs {
        if !segment_dir.is_dir() {
            continue;
        }
        let segment_id = segment_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if installed_segments.is_some_and(|segments| !segments.contains(&segment_id)) {
            continue;
        }
        if segment_dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if segment_dir.join(crate::seal::SEAL_FILE).exists() {
            let store = remote_diskann.get(&segment_id).map_or_else(
                || crate::seal::V4Store::open(&segment_dir),
                |diskann| {
                    crate::seal::V4Store::open_with_diskann(&segment_dir, Arc::clone(diskann))
                },
            )?;
            let tombstone_ordinals = crate::seal::read_tombstone_ordinals(&segment_dir)?;
            if tombstone_ordinals
                .iter()
                .any(|ordinal| ordinal as usize >= store.len())
            {
                return Err(GaussError::SegmentCorruption {
                    path: segment_dir.join(TOMBSTONE_FILE).display().to_string(),
                    message: "v4 tombstone ordinal out of bounds".to_string(),
                });
            }
            let tombstones = tombstone_ordinals
                .iter()
                .filter_map(|ordinal| store.id(ordinal as usize).map(str::to_string))
                .collect();
            let h2qg = if segment_dir.join(crate::index::ivf::IVF_FILE).exists() {
                None
            } else {
                Some(h2qg::read_index_paged(&segment_dir)?)
            };
            segments.push(LoadedSegment {
                id: segment_id,
                dir: segment_dir,
                points: HashMap::new(),
                h2qg,
                named_h2qg: HashMap::new(),
                payload_index: None,
                v4_store: Some(store),
                tombstones,
                tombstone_ordinals,
            });
            continue;
        }
        let manifest_path = segment_dir.join(MANIFEST_FILE);
        if manifest_path.exists() {
            read_manifest(&manifest_path, &segment_dir)?;
        }
        let segment_points = read_segment(&segment_dir.join(SEGMENT_FILE))?;
        let segment_ids = segment_points
            .iter()
            .map(|point| point.id.clone())
            .collect::<Vec<_>>();
        let mut points: HashMap<String, Point> = segment_points
            .into_iter()
            .map(|point| (point.id.clone(), point))
            .collect();
        let tombstone_path = segment_dir.join(TOMBSTONE_FILE);
        if tombstone_path.exists() {
            for id in read_tombstones(&tombstone_path, &segment_ids)? {
                points.remove(&id);
            }
        }
        let h2qg_path = segment_dir.join(h2qg::INDEX_FILE);
        let h2qg = if h2qg_path.exists() {
            Some(h2qg::read_index_paged(&segment_dir)?)
        } else {
            None
        };
        let mut named_h2qg = HashMap::new();
        for (name, path) in named_h2qg_paths(&segment_dir)? {
            named_h2qg.insert(name, h2qg::read_index(&path)?);
        }
        let payload_path = segment_dir.join(PAYLOAD_INDEX_FILE);
        let payload_index = if payload_path.exists() {
            Some(read_payload_index(&payload_path)?)
        } else {
            None
        };
        segments.push(LoadedSegment {
            id: segment_id,
            dir: segment_dir,
            points,
            h2qg,
            named_h2qg,
            payload_index,
            v4_store: None,
            tombstones: HashSet::new(),
            tombstone_ordinals: RoaringBitmap::new(),
        });
    }
    Ok(segments)
}

pub(crate) fn remote_diskann_artifacts(
    cold_dir: &Path,
    object_store_config: &ColdObjectStoreConfig,
    installed_segments: Option<&HashSet<String>>,
) -> Result<HashMap<String, Arc<crate::index::diskann::DiskAnnArtifact>>> {
    let index_path = cold_dir.join(COLD_INDEX_FILE);
    if !index_path.exists() {
        return Ok(HashMap::new());
    }
    let payload = read_framed(&index_path, COLD_INDEX_MAGIC, "cold index")?;
    let index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
    let object_store = cold_object_store(object_store_config)?;
    let mut artifacts = HashMap::new();
    for segment in index.segments {
        if installed_segments.is_some_and(|installed| !installed.contains(&segment.id)) {
            continue;
        }
        let segment_dir = cold_dir.join(&segment.id);
        if !segment_dir.join(crate::seal::SEAL_FILE).exists()
            || segment.object_files.iter().any(|file| {
                file.name == crate::index::diskann::DISKANN_FILE
                    && segment_dir.join(&file.name).exists()
            })
        {
            continue;
        }
        let diskann_file = segment
            .object_files
            .iter()
            .find(|file| file.name == crate::index::diskann::DISKANN_FILE)
            .ok_or_else(|| GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold segment '{}' has no remote DiskANN object", segment.id),
            })?;
        let marker = crate::seal::read_marker_with_diskann_len(
            &segment_dir.join(crate::seal::SEAL_FILE),
            diskann_file.logical_bytes(),
        )?;
        let location = cold_object_path(
            &diskann_file.key,
            &index_path,
            ObjectStoreErrorContext::Corruption,
        )?;
        let artifact = crate::index::diskann::DiskAnnArtifact::open_object_store(
            Arc::clone(&object_store.store),
            location,
            diskann_file.bytes,
            marker.points,
            marker.vector_dim,
        )?;
        artifacts.insert(segment.id, Arc::new(artifact));
    }
    Ok(artifacts)
}

pub fn load_searchers(searchers_dir: &Path) -> Result<LoadedSearchers> {
    load_searchers_from_dirs(&[searchers_dir], true)
}

pub fn load_searchers_with_cold(searchers_dir: &Path, cold_dir: &Path) -> Result<LoadedSearchers> {
    load_searchers_from_dirs(&[searchers_dir, cold_dir], true)
}

pub fn load_searchers_with_cold_object_store(
    searchers_dir: &Path,
    cold_dir: &Path,
    object_store_config: Option<&ColdObjectStoreConfig>,
) -> Result<LoadedSearchers> {
    if let Some(object_store_config) = object_store_config
        && cold_dir.exists()
    {
        validate_cold_index_with_object_store(cold_dir, Some(object_store_config))?;
        return load_searchers_from_dirs(&[searchers_dir, cold_dir], false);
    }
    load_searchers_from_dirs(&[searchers_dir, cold_dir], true)
}

fn load_searchers_from_dirs(dirs: &[&Path], validate_indexes: bool) -> Result<LoadedSearchers> {
    if !dirs.iter().any(|dir| dir.exists()) {
        return Ok(LoadedSearchers {
            points: HashMap::new(),
            h2qg: None,
            named_h2qg: HashMap::new(),
            payload_index: None,
            soa: None,
        });
    }

    let mut segment_dirs = Vec::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        if validate_indexes {
            validate_cold_index(dir)?;
        }
        segment_dirs.extend(
            fs::read_dir(dir)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?,
        );
    }
    segment_dirs.sort();

    let mut points = HashMap::new();
    let mut h2qg = None;
    let mut named_h2qg = HashMap::new();
    let mut payload_index = None;
    for segment_dir in segment_dirs {
        if !segment_dir.is_dir() {
            continue;
        }
        let manifest_path = segment_dir.join(MANIFEST_FILE);
        if manifest_path.exists() {
            read_manifest(&manifest_path, &segment_dir)?;
        }
        let segment_points = read_segment(&segment_dir.join(SEGMENT_FILE))?;
        let segment_ids = segment_points
            .iter()
            .map(|point| point.id.clone())
            .collect::<Vec<_>>();
        for point in segment_points {
            points.insert(point.id.clone(), point);
        }
        let tombstone_path = segment_dir.join(TOMBSTONE_FILE);
        if tombstone_path.exists() {
            for id in read_tombstones(&tombstone_path, &segment_ids)? {
                points.remove(&id);
            }
        }
        let h2qg_path = segment_dir.join(h2qg::INDEX_FILE);
        if h2qg_path.exists() {
            // Attaches the h2qg_vecs.gdx mmap sidecar when present, so paged
            // segments load with their vectors on disk instead of in heap.
            h2qg = Some(h2qg::read_index_paged(&segment_dir)?);
        }
        for (name, path) in named_h2qg_paths(&segment_dir)? {
            named_h2qg.insert(name, h2qg::read_index(&path)?);
        }
        let sparse_path = segment_dir.join(SPARSE_INDEX_FILE);
        if sparse_path.exists() {
            read_sparse_index(&sparse_path)?;
        }
        let payload_path = segment_dir.join(PAYLOAD_INDEX_FILE);
        if payload_path.exists() {
            payload_index = Some(read_payload_index(&payload_path)?);
        }
    }
    Ok(LoadedSearchers {
        points,
        h2qg,
        named_h2qg,
        payload_index,
        soa: None,
    })
}

pub fn tier_searchers_to_cold(
    searchers_dir: &Path,
    cold_dir: &Path,
    collection: &str,
    points: usize,
    object_store_config: Option<&ColdObjectStoreConfig>,
) -> Result<ColdTierWrite> {
    let mut segment_dirs = Vec::new();
    if searchers_dir.exists() {
        for entry in fs::read_dir(searchers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir()
                && (path.join(MANIFEST_FILE).exists() || path.join(crate::seal::SEAL_FILE).exists())
            {
                segment_dirs.push(path);
            }
        }
    }
    segment_dirs.sort();
    if segment_dirs.is_empty() {
        return Ok(ColdTierWrite {
            segments: 0,
            files: 0,
            bytes: 0,
            points,
        });
    }

    fs::create_dir_all(cold_dir)?;
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for segment_dir in segment_dirs {
        let segment_name = segment_dir.file_name().ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "searcher segment path has no final component: {}",
                segment_dir.display()
            ))
        })?;
        let target = cold_dir.join(segment_name);
        if target.exists() {
            cold_segment_metadata(&target)?;
            fs::remove_dir_all(&segment_dir)?;
            continue;
        }
        let tmp_parent = cold_dir.join(format!("{}.tmp", segment_name.to_string_lossy()));
        let tmp = tmp_parent.join(segment_name);
        if tmp_parent.exists() {
            fs::remove_dir_all(&tmp_parent)?;
        }
        fs::create_dir_all(&tmp_parent)?;
        copy_dir_all(&segment_dir, &tmp)?;
        if tmp.join(crate::seal::SEAL_FILE).exists() {
            crate::seal::thin_algorithm2_segment_for_cold(&tmp)?;
        }
        cold_segment_metadata(&tmp)?;
        let (segment_files, segment_bytes) = directory_stats(&tmp)?;
        files += segment_files;
        bytes += segment_bytes;
        fs::rename(&tmp, &target)?;
        fs::remove_dir_all(&tmp_parent)?;
        fs::remove_dir_all(&segment_dir)?;
    }
    let cold_segments = count_segment_dirs(cold_dir)?;
    write_cold_index(cold_dir, collection, object_store_config)?;
    Ok(ColdTierWrite {
        segments: cold_segments,
        files,
        bytes,
        points,
    })
}

fn count_segment_dirs(dir: &Path) -> Result<usize> {
    let mut segments = 0;
    if !dir.exists() {
        return Ok(segments);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && (entry.path().join(MANIFEST_FILE).exists()
                || entry.path().join(crate::seal::SEAL_FILE).exists())
        {
            segments += 1;
        }
    }
    Ok(segments)
}

fn write_cold_index(
    cold_dir: &Path,
    collection: &str,
    object_store_config: Option<&ColdObjectStoreConfig>,
) -> Result<()> {
    let mut segments = Vec::new();
    if cold_dir.exists() {
        let mut entries = fs::read_dir(cold_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        for segment_dir in entries {
            if !segment_dir.is_dir() {
                continue;
            }
            if !segment_dir.join(MANIFEST_FILE).exists()
                && !segment_dir.join(crate::seal::SEAL_FILE).exists()
            {
                continue;
            }
            let (id, points, marker_path) = cold_segment_metadata(&segment_dir)?;
            let (files, bytes) = directory_stats(&segment_dir)?;
            let marker_bytes = encryption::read_persistent(&marker_path)?;
            let (object_key_prefix, object_files) = object_store_config
                .map(|object_store_config| {
                    mirror_segment_to_object_store(
                        object_store_config,
                        collection,
                        &id,
                        &segment_dir,
                    )
                })
                .transpose()?
                .map(|write| (Some(write.object_key_prefix), write.object_files))
                .unwrap_or((None, Vec::new()));
            segments.push(ColdIndexSegmentPayload {
                id,
                points,
                files,
                bytes,
                manifest_crc: checksum(&marker_bytes),
                object_key_prefix,
                object_files,
            });
        }
    }
    let payload = serde_json::to_vec(&ColdIndexPayload { segments })?;
    let crc = checksum(&payload);
    write_framed(
        &cold_dir.join(COLD_INDEX_FILE),
        COLD_INDEX_MAGIC,
        &payload,
        crc,
    )
}

/// Rebuild local cold-index byte accounting after encryption migration or
/// KEK rewrap. Remote object descriptors remain byte-for-byte authority for
/// the external copies and are never rewritten by this local-tree operation.
pub(crate) fn refresh_cold_indexes_for_encryption(
    root: &Path,
    keyring: &encryption::Keyring,
) -> Result<usize> {
    let mut indexes = Vec::new();
    collect_cold_indexes(root, &mut indexes)?;
    indexes.sort();
    indexes.dedup();
    for index_path in &indexes {
        let cold_dir = index_path.parent().ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "cold index has no parent directory: {}",
                index_path.display()
            ))
        })?;
        let payload = read_encrypted_framed(index_path, COLD_INDEX_MAGIC, "cold index", keyring)?;
        let mut index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
        let mut indexed = HashSet::new();
        for segment in &mut index.segments {
            if !indexed.insert(segment.id.clone()) {
                return Err(GaussError::SegmentCorruption {
                    path: index_path.display().to_string(),
                    message: format!("duplicate cold index segment '{}'", segment.id),
                });
            }
            let segment_dir = cold_dir.join(&segment.id);
            if !segment_dir.is_dir() {
                // A remote-only object-store segment intentionally has no
                // local directory. Its external metadata remains unchanged.
                if segment.object_files.is_empty() {
                    return Err(GaussError::SegmentCorruption {
                        path: index_path.display().to_string(),
                        message: format!("cold segment '{}' is missing locally", segment.id),
                    });
                }
                continue;
            }
            let marker_path = if segment_dir.join(crate::seal::SEAL_FILE).exists() {
                segment_dir.join(crate::seal::SEAL_FILE)
            } else if segment_dir.join(MANIFEST_FILE).exists() {
                segment_dir.join(MANIFEST_FILE)
            } else {
                return Err(GaussError::SegmentCorruption {
                    path: segment_dir.display().to_string(),
                    message: "cold segment has no checked marker".to_string(),
                });
            };
            let (mut files, mut bytes) = directory_stats(&segment_dir)?;
            if let Some(remote_diskann) = segment.object_files.iter().find(|object_file| {
                object_file.name == crate::index::diskann::DISKANN_FILE
                    && !segment_dir.join(&object_file.name).exists()
            }) {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(remote_diskann.bytes);
            }
            let marker = decrypt_persisted_file(&marker_path, keyring)?;
            segment.files = files;
            segment.bytes = bytes;
            segment.manifest_crc = checksum(&marker);
            if !segment.object_files.is_empty() && segment.object_files.len() != files {
                return Err(GaussError::SegmentCorruption {
                    path: index_path.display().to_string(),
                    message: format!(
                        "cold object file count disagrees with local segment '{}' after rewrite",
                        segment.id
                    ),
                });
            }
        }
        for entry in fs::read_dir(cold_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            if !path.join(crate::seal::SEAL_FILE).exists() && !path.join(MANIFEST_FILE).exists() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if !indexed.contains(&id) {
                return Err(GaussError::SegmentCorruption {
                    path: index_path.display().to_string(),
                    message: format!("cold index missing local segment '{id}'"),
                });
            }
        }
        let payload = serde_json::to_vec(&index)?;
        write_encrypted_framed(
            index_path,
            COLD_INDEX_MAGIC,
            &payload,
            FileType::Segment,
            keyring,
        )?;
        let checked = read_encrypted_framed(index_path, COLD_INDEX_MAGIC, "cold index", keyring)?;
        let checked = serde_json::from_slice::<ColdIndexPayload>(&checked)?;
        if checked != index {
            return Err(GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: "rebuilt cold index changed during authenticated write".to_string(),
            });
        }
    }
    Ok(indexes.len())
}

pub fn external_cold_object_file_count(
    root: &Path,
    keyring: &encryption::Keyring,
) -> Result<usize> {
    let mut indexes = Vec::new();
    collect_cold_indexes(root, &mut indexes)?;
    indexes.into_iter().try_fold(0_usize, |total, path| {
        let payload = read_encrypted_framed(&path, COLD_INDEX_MAGIC, "cold index", keyring)?;
        let index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
        Ok(total.saturating_add(
            index
                .segments
                .iter()
                .map(|segment| segment.object_files.len())
                .sum::<usize>(),
        ))
    })
}

fn collect_cold_indexes(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(GaussError::InvalidRequest(format!(
                "refusing symbolic link while refreshing cold indexes: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            collect_cold_indexes(&entry.path(), output)?;
        } else if file_type.is_file() && entry.file_name().to_str() == Some(COLD_INDEX_FILE) {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn decrypt_persisted_file(path: &Path, keyring: &encryption::Keyring) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if !encryption::is_encrypted(&bytes) {
        return Err(GaussError::InvalidRequest(format!(
            "expected encrypted persisted file {}",
            path.display()
        )));
    }
    encryption::decrypt_bytes(keyring, &bytes).map(|(_, plaintext)| plaintext)
}

fn read_encrypted_framed(
    path: &Path,
    magic: &[u8; 8],
    label: &str,
    keyring: &encryption::Keyring,
) -> Result<Vec<u8>> {
    let bytes = decrypt_persisted_file(path, keyring)?;
    if bytes.len() < HEADER_LEN || &bytes[..8] != magic {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("invalid {label} header"),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(bytes[8..16].try_into().expect("length")))
        .map_err(|_| GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} length exceeds usize"),
        })?;
    let expected_crc = u32::from_le_bytes(bytes[16..20].try_into().expect("crc"));
    if len != bytes.len() - HEADER_LEN || checksum(&bytes[HEADER_LEN..]) != expected_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} length or crc mismatch"),
        });
    }
    Ok(bytes[HEADER_LEN..].to_vec())
}

fn write_encrypted_framed(
    path: &Path,
    magic: &[u8; 8],
    payload: &[u8],
    file_type: FileType,
    keyring: &encryption::Keyring,
) -> Result<()> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&checksum(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    let envelope = encryption::encrypt_bytes(keyring, file_type, &bytes)?;
    crate::fs_util::atomic_write(path, &envelope)
}

fn cold_segment_metadata(segment_dir: &Path) -> Result<(String, usize, PathBuf)> {
    cold_segment_metadata_with_diskann_len(segment_dir, None)
}

fn cold_segment_metadata_with_diskann_len(
    segment_dir: &Path,
    external_diskann_len: Option<u64>,
) -> Result<(String, usize, PathBuf)> {
    let seal_path = segment_dir.join(crate::seal::SEAL_FILE);
    if seal_path.exists() {
        let marker = match external_diskann_len {
            Some(bytes) => crate::seal::read_marker_with_diskann_len(&seal_path, bytes)?,
            None => crate::seal::read_marker(&seal_path)?,
        };
        if external_diskann_len.is_none() {
            if marker.has_graph() {
                crate::seal::V4Store::open_graph_base(segment_dir)?;
            } else {
                crate::seal::V4Store::open(segment_dir)?;
            }
        }
        let id = segment_dir
            .file_name()
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "cold segment path has no final component: {}",
                    segment_dir.display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        return Ok((id, marker.points, seal_path));
    }
    let manifest_path = segment_dir.join(MANIFEST_FILE);
    let manifest = read_manifest(&manifest_path, segment_dir)?;
    Ok((manifest.id, manifest.points, manifest_path))
}

fn validate_cold_index(dir: &Path) -> Result<()> {
    validate_cold_index_with_object_store(dir, None)
}

fn validate_cold_index_with_object_store(
    dir: &Path,
    object_store_config: Option<&ColdObjectStoreConfig>,
) -> Result<()> {
    let index_path = dir.join(COLD_INDEX_FILE);
    if !index_path.exists() {
        return Ok(());
    }
    let payload = read_framed(&index_path, COLD_INDEX_MAGIC, "cold index")?;
    let index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
    let object_store = object_store_config.map(cold_object_store).transpose()?;
    let mut indexed_segments = BTreeMap::new();
    for segment in index.segments {
        validate_cold_object_files(&index_path, object_store.as_ref(), &segment)?;
        indexed_segments.insert(segment.id.clone(), segment);
    }
    let mut actual_segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let segment_dir = entry.path();
        if !entry.file_type()?.is_dir()
            || (!segment_dir.join(MANIFEST_FILE).exists()
                && !segment_dir.join(crate::seal::SEAL_FILE).exists())
        {
            continue;
        }
        let id = segment_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let indexed = indexed_segments
            .get(&id)
            .ok_or_else(|| GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold index missing segment '{id}'"),
            })?;
        let remote_diskann = indexed.object_files.iter().find(|object_file| {
            object_file.name == crate::index::diskann::DISKANN_FILE
                && !segment_dir.join(&object_file.name).exists()
        });
        let external_diskann_len = if object_store.is_some() {
            remote_diskann.map(ColdIndexObjectFilePayload::logical_bytes)
        } else {
            None
        };
        let (validated_id, points, marker_path) =
            cold_segment_metadata_with_diskann_len(&segment_dir, external_diskann_len)?;
        if validated_id != id {
            return Err(GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold segment id mismatch for '{id}'"),
            });
        }
        actual_segments.push(id.clone());
        let (mut files, mut bytes) = directory_stats(&segment_dir)?;
        if let Some(remote_diskann) = remote_diskann {
            files += 1;
            bytes = bytes.saturating_add(remote_diskann.bytes);
        }
        let marker_bytes = encryption::read_persistent(&marker_path)?;
        if indexed.points != points
            || indexed.files != files
            || indexed.bytes != bytes
            || indexed.manifest_crc != checksum(&marker_bytes)
        {
            return Err(GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold index metadata mismatch for segment '{id}'"),
            });
        }
    }
    let missing_indexed_segments = indexed_segments
        .values()
        .filter(|segment| !actual_segments.iter().any(|actual| actual == &segment.id))
        .collect::<Vec<_>>();
    if !missing_indexed_segments.is_empty()
        && (object_store.is_none()
            || missing_indexed_segments
                .iter()
                .any(|segment| segment.object_files.is_empty()))
    {
        return Err(GaussError::SegmentCorruption {
            path: index_path.display().to_string(),
            message: "cold index segment count mismatch".to_string(),
        });
    }
    Ok(())
}

/// Validate the cold index and return segment IDs whose durable authority is
/// the configured object store. These IDs may intentionally have no local
/// directory until a query materializes the required files.
pub(crate) fn validated_remote_cold_segment_ids(
    dir: &Path,
    object_store_config: &ColdObjectStoreConfig,
) -> Result<HashSet<String>> {
    validate_cold_index_with_object_store(dir, Some(object_store_config))?;
    let index_path = dir.join(COLD_INDEX_FILE);
    if !index_path.exists() {
        return Ok(HashSet::new());
    }
    let payload = read_framed(&index_path, COLD_INDEX_MAGIC, "cold index")?;
    let index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
    Ok(index
        .segments
        .into_iter()
        .filter(|segment| !segment.object_files.is_empty())
        .map(|segment| segment.id)
        .collect())
}

/// Controls which files are fetched when partially materializing a cold segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColdMaterializeScope {
    /// Materialize all files (used for compaction, full restores).
    Full,
    /// Materialize only files needed for ANN search.
    Search,
    /// Materialize files needed for hybrid (dense + sparse) search.
    HybridSearch,
    /// Materialize files needed for scroll/count operations.
    Scroll,
}

impl ColdMaterializeScope {
    pub fn required_files(self) -> &'static [&'static str] {
        match self {
            Self::Full => &[
                "vec.gdx",
                "ids.gdx",
                "seal.gdx",
                "h2qg.gdx",
                "h2qg_vecs.gdx",
                "ivf.gdx",
                "rabitq.gdx",
                "vamana.gdx",
                "diskann.gdx",
                "sparse.gdx",
                "payload.gdx",
                "tomb.gdx",
                "manifest.gdx",
                "checkpoint.gdx",
            ],
            Self::Search => &[
                "vec.gdx",
                "ids.gdx",
                "payload.gdx",
                "seal.gdx",
                "h2qg.gdx",
                "h2qg_vecs.gdx",
                "ivf.gdx",
                "rabitq.gdx",
                "vamana.gdx",
                "diskann.gdx",
                "tomb.gdx",
            ],
            Self::HybridSearch => &[
                "vec.gdx",
                "ids.gdx",
                "payload.gdx",
                "seal.gdx",
                "h2qg.gdx",
                "h2qg_vecs.gdx",
                "ivf.gdx",
                "rabitq.gdx",
                "vamana.gdx",
                "diskann.gdx",
                "sparse.gdx",
                "tomb.gdx",
            ],
            Self::Scroll => &["vec.gdx", "ids.gdx", "seal.gdx", "tomb.gdx", "payload.gdx"],
        }
    }
}

/// Copy only the files required by `scope` from `cold_segment_dir` into `segment_dir`.
/// Files that already exist in `segment_dir` are skipped.
/// Returns the count of files actually copied.
pub fn materialize_cold_segment_files(
    segment_dir: &Path,
    cold_segment_dir: &Path,
    scope: ColdMaterializeScope,
) -> Result<usize> {
    let mut copied = 0_usize;
    for &filename in scope.required_files() {
        let dest = segment_dir.join(filename);
        if dest.exists() {
            continue;
        }
        let src = cold_segment_dir.join(filename);
        if src.exists() {
            fs::copy(&src, &dest)?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// Fetch only the files required by `scope` from an object store into `segment_dir`.
/// Files that already exist locally are skipped.
/// Returns the count of files actually fetched.
pub fn materialize_cold_segment_files_from_object_store(
    segment_dir: &Path,
    object_store_config: &ColdObjectStoreConfig,
    cold_prefix: &str,
    scope: ColdMaterializeScope,
) -> Result<usize> {
    let object_store = cold_object_store(object_store_config)?;
    let object_key_prefix = object_store.key(cold_prefix);
    let mut fetched = 0_usize;
    for &filename in scope.required_files() {
        if filename == crate::index::diskann::DISKANN_FILE && scope != ColdMaterializeScope::Full {
            continue;
        }
        let dest = segment_dir.join(filename);
        if dest.exists() {
            continue;
        }
        let key = format!("{object_key_prefix}/{filename}");
        // Use head to check existence without erroring on missing files.
        let path_ref = Path::new(filename);
        let object_path = match ObjectPath::parse(&key) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let exists = block_on_object_store(object_store.store.head(&object_path)).is_ok();
        if !exists {
            continue;
        }
        let bytes = object_store_get_bytes(
            &object_store,
            &key,
            path_ref,
            ObjectStoreErrorContext::Request,
        )?;
        fs::write(&dest, bytes)?;
        fetched += 1;
    }
    Ok(fetched)
}

pub fn materialize_missing_cold_segments_from_object_store(
    cold_dir: &Path,
    object_store_config: &ColdObjectStoreConfig,
) -> Result<usize> {
    let index_path = cold_dir.join(COLD_INDEX_FILE);
    if !index_path.exists() {
        return Ok(0);
    }
    let payload = read_framed(&index_path, COLD_INDEX_MAGIC, "cold index")?;
    let index = serde_json::from_slice::<ColdIndexPayload>(&payload)?;
    if index
        .segments
        .iter()
        .all(|segment| segment.object_files.is_empty() || cold_dir.join(&segment.id).exists())
    {
        return Ok(0);
    }
    let object_store = cold_object_store(object_store_config)?;
    let mut materialized = 0_usize;
    for segment in index.segments {
        if segment.object_files.is_empty() {
            continue;
        }
        let target = cold_dir.join(&segment.id);
        if target.exists() {
            continue;
        }
        let tmp_parent = cold_dir.join(format!("{}.fetching", segment.id));
        let tmp = tmp_parent.join(&segment.id);
        if tmp_parent.exists() {
            fs::remove_dir_all(&tmp_parent)?;
        }
        fs::create_dir_all(&tmp)?;
        let mut remote_diskann_len = None;
        for object_file in &segment.object_files {
            let file_name = cold_object_file_name(&index_path, &object_file.name)?;
            if file_name == crate::index::diskann::DISKANN_FILE {
                let meta = object_store_head(
                    &object_store,
                    &object_file.key,
                    &index_path,
                    ObjectStoreErrorContext::Corruption,
                )?;
                if meta.size != object_file.bytes {
                    return Err(GaussError::SegmentCorruption {
                        path: index_path.display().to_string(),
                        message: format!(
                            "remote DiskANN length mismatch for segment '{}'",
                            segment.id
                        ),
                    });
                }
                remote_diskann_len = Some(object_file.logical_bytes());
                continue;
            }
            let bytes = object_store_get_bytes(
                &object_store,
                &object_file.key,
                &index_path,
                ObjectStoreErrorContext::Corruption,
            )?;
            fs::write(tmp.join(file_name), bytes)?;
        }
        cold_segment_metadata_with_diskann_len(&tmp, remote_diskann_len)?;
        fs::rename(&tmp, &target)?;
        fs::remove_dir_all(&tmp_parent)?;
        materialized += 1;
    }
    Ok(materialized)
}

struct ColdObjectStoreWrite {
    object_key_prefix: String,
    object_files: Vec<ColdIndexObjectFilePayload>,
}

fn mirror_segment_to_object_store(
    object_store_config: &ColdObjectStoreConfig,
    collection: &str,
    segment_id: &str,
    segment_dir: &Path,
) -> Result<ColdObjectStoreWrite> {
    let logical_key_prefix = format!("collections/{collection}/segments/{segment_id}");
    let write =
        mirror_directory_to_object_store(object_store_config, &logical_key_prefix, segment_dir)?;
    Ok(ColdObjectStoreWrite {
        object_key_prefix: write.object_key_prefix,
        object_files: write
            .object_files
            .into_iter()
            .map(|object_file| ColdIndexObjectFilePayload {
                name: object_file.name,
                key: object_file.key,
                bytes: object_file.bytes,
                plaintext_bytes: object_file.plaintext_bytes,
                crc: object_file.crc,
            })
            .collect(),
    })
}

pub fn mirror_directory_to_object_store(
    object_store_config: &ColdObjectStoreConfig,
    logical_key_prefix: &str,
    dir: &Path,
) -> Result<ObjectStoreDirectoryWrite> {
    let object_store = cold_object_store(object_store_config)?;
    let object_key_prefix = object_store.key(logical_key_prefix);
    let mut files = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    let mut total_bytes = 0_u64;
    let mut object_files = Vec::new();
    for file in files {
        if !file.is_file() {
            continue;
        }
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "object-store file name is not valid UTF-8: {}",
                    file.display()
                ))
            })?
            .to_string();
        let key = format!("{object_key_prefix}/{name}");
        let bytes = fs::read(&file)?;
        let crc = checksum(&bytes);
        let plaintext_bytes = encryption::persistent_plaintext_len(&file)?;
        object_store_put_bytes(&object_store, &key, bytes)?;
        let stored =
            object_store_head(&object_store, &key, &file, ObjectStoreErrorContext::Request)?;
        total_bytes += stored.size;
        object_files.push(ObjectStoreFileWrite {
            name,
            key,
            bytes: stored.size,
            plaintext_bytes,
            crc,
        });
    }
    Ok(ObjectStoreDirectoryWrite {
        object_key_prefix,
        files: object_files.len(),
        bytes: total_bytes,
        object_files,
    })
}

pub fn object_store_child_prefix_names(
    object_store_config: &ColdObjectStoreConfig,
    logical_key_prefix: &str,
) -> Result<Vec<String>> {
    let object_store = cold_object_store(object_store_config)?;
    let object_key_prefix = object_store.key(logical_key_prefix);
    let object_path = cold_object_path(
        &object_key_prefix,
        Path::new(&object_key_prefix),
        ObjectStoreErrorContext::Request,
    )?;
    let listed = block_on_object_store(object_store.store.list_with_delimiter(Some(&object_path)))
        .map_err(|error| {
            GaussError::InvalidRequest(format!(
                "failed to list object store prefix '{object_key_prefix}': {error}"
            ))
        })?;
    let prefix = format!("{object_key_prefix}/");
    let mut names = listed
        .common_prefixes
        .into_iter()
        .filter_map(|path| {
            let path = path.to_string();
            path.strip_prefix(&prefix)
                .and_then(|name| name.trim_end_matches('/').split('/').next())
                .filter(|name| !name.is_empty())
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    Ok(names)
}

pub fn restore_object_store_directory_to_local(
    object_store_config: &ColdObjectStoreConfig,
    logical_key_prefix: &str,
    target: &Path,
) -> Result<ObjectStoreDirectoryRead> {
    let object_store = cold_object_store(object_store_config)?;
    let object_key_prefix = object_store.key(logical_key_prefix);
    let mut object_keys = Vec::new();
    collect_object_store_keys(&object_store, &object_key_prefix, &mut object_keys)?;
    object_keys.sort();
    let prefix = format!("{object_key_prefix}/");
    let tmp = target.with_extension("tmp");
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    fs::create_dir_all(&tmp)?;
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for key in object_keys {
        let relative = key.strip_prefix(&prefix).ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "object key '{key}' is outside expected prefix '{object_key_prefix}'"
            ))
        })?;
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(GaussError::InvalidRequest(format!(
                "invalid object key relative path '{relative}'"
            )));
        }
        let data = object_store_get_bytes(
            &object_store,
            &key,
            Path::new(&key),
            ObjectStoreErrorContext::Request,
        )?;
        let target_file = tmp.join(relative_path);
        if let Some(parent) = target_file.parent() {
            fs::create_dir_all(parent)?;
        }
        bytes += data.len() as u64;
        fs::write(target_file, data)?;
        files += 1;
    }
    if target.exists() {
        fs::remove_dir_all(target)?;
    }
    fs::rename(&tmp, target)?;
    Ok(ObjectStoreDirectoryRead { files, bytes })
}

fn collect_object_store_keys(
    object_store: &ColdObjectStore,
    object_key_prefix: &str,
    object_keys: &mut Vec<String>,
) -> Result<()> {
    let object_path = cold_object_path(
        object_key_prefix,
        Path::new(object_key_prefix),
        ObjectStoreErrorContext::Request,
    )?;
    let listed = block_on_object_store(object_store.store.list_with_delimiter(Some(&object_path)))
        .map_err(|error| {
            GaussError::InvalidRequest(format!(
                "failed to list object store prefix '{object_key_prefix}': {error}"
            ))
        })?;
    for object in listed.objects {
        object_keys.push(object.location.to_string());
    }
    for prefix in listed.common_prefixes {
        collect_object_store_keys(object_store, prefix.as_ref(), object_keys)?;
    }
    Ok(())
}

fn validate_cold_object_files(
    index_path: &Path,
    object_store: Option<&ColdObjectStore>,
    segment: &ColdIndexSegmentPayload,
) -> Result<()> {
    if segment.object_files.is_empty() {
        return Ok(());
    }
    if segment.object_files.len() != segment.files {
        return Err(GaussError::SegmentCorruption {
            path: index_path.display().to_string(),
            message: format!(
                "cold object file count mismatch for segment '{}'",
                segment.id
            ),
        });
    }
    let Some(object_store) = object_store else {
        return Ok(());
    };
    for object_file in &segment.object_files {
        cold_object_file_name(index_path, &object_file.name)?;
        let meta = object_store_head(
            object_store,
            &object_file.key,
            index_path,
            ObjectStoreErrorContext::Corruption,
        )?;
        if object_file.bytes != meta.size {
            return Err(GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold object metadata mismatch for segment '{}'", segment.id),
            });
        }
        if object_file.name == crate::index::diskann::DISKANN_FILE {
            continue;
        }
        let bytes = object_store_get_bytes(
            object_store,
            &object_file.key,
            index_path,
            ObjectStoreErrorContext::Corruption,
        )?;
        if object_file.crc != checksum(&bytes) {
            return Err(GaussError::SegmentCorruption {
                path: index_path.display().to_string(),
                message: format!("cold object metadata mismatch for segment '{}'", segment.id),
            });
        }
    }
    Ok(())
}

fn cold_object_file_name<'a>(index_path: &Path, name: &'a str) -> Result<&'a str> {
    let path = Path::new(name);
    if path.components().count() != 1
        || path.file_name().and_then(|part| part.to_str()) != Some(name)
    {
        return Err(GaussError::SegmentCorruption {
            path: index_path.display().to_string(),
            message: format!("invalid cold object file name '{name}'"),
        });
    }
    Ok(name)
}

#[derive(Clone, Copy, Debug)]
enum ObjectStoreErrorContext {
    Corruption,
    Request,
}

struct ColdObjectStore {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl ColdObjectStore {
    fn key(&self, logical_key: &str) -> String {
        if self.prefix.is_empty() {
            logical_key.to_string()
        } else {
            format!("{}/{}", self.prefix, logical_key)
        }
    }
}

fn cold_object_store(config: &ColdObjectStoreConfig) -> Result<ColdObjectStore> {
    match config {
        ColdObjectStoreConfig::LocalDir(root) => {
            fs::create_dir_all(root)?;
            let store = LocalFileSystem::new_with_prefix(root).map_err(|error| {
                GaussError::InvalidRequest(format!(
                    "failed to open cold object store {}: {error}",
                    root.display()
                ))
            })?;
            Ok(ColdObjectStore {
                store: Arc::new(store),
                prefix: String::new(),
            })
        }
        ColdObjectStoreConfig::Url(raw_url) => {
            let url = Url::parse(raw_url).map_err(|error| {
                GaussError::InvalidRequest(format!(
                    "invalid cold object store URL '{raw_url}': {error}"
                ))
            })?;
            let mut options = std::env::vars().collect::<Vec<_>>();
            if url.scheme() == "http"
                && !options
                    .iter()
                    .any(|(key, _)| key.eq_ignore_ascii_case("allow_http"))
            {
                // An explicitly configured http:// object-store URL is itself
                // the operator's opt-in to plaintext transport.
                options.push(("allow_http".to_string(), "true".to_string()));
            }
            let (store, prefix) = parse_url_opts(&url, options).map_err(|error| {
                GaussError::InvalidRequest(format!(
                    "failed to open cold object store URL '{raw_url}': {error}"
                ))
            })?;
            Ok(ColdObjectStore {
                store: Arc::from(store),
                prefix: prefix.to_string(),
            })
        }
    }
}

fn cold_object_path(
    key: &str,
    path: &Path,
    context: ObjectStoreErrorContext,
) -> Result<ObjectPath> {
    ObjectPath::parse(key).map_err(|error| {
        object_store_error(
            context,
            path,
            format!("invalid cold object key '{key}': {error}"),
        )
    })
}

fn object_store_put_bytes(store: &ColdObjectStore, key: &str, bytes: Vec<u8>) -> Result<()> {
    let path = cold_object_path(key, Path::new(key), ObjectStoreErrorContext::Request)?;
    block_on_object_store(store.store.put(&path, PutPayload::from(bytes))).map_err(|error| {
        GaussError::InvalidRequest(format!("failed to write cold object '{key}': {error}"))
    })?;
    Ok(())
}

fn object_store_head(
    store: &ColdObjectStore,
    key: &str,
    path: &Path,
    context: ObjectStoreErrorContext,
) -> Result<object_store::ObjectMeta> {
    let object_path = cold_object_path(key, path, context)?;
    block_on_object_store(store.store.head(&object_path)).map_err(|error| {
        object_store_error(
            context,
            path,
            format!("failed to stat cold object '{key}': {error}"),
        )
    })
}

fn object_store_get_bytes(
    store: &ColdObjectStore,
    key: &str,
    path: &Path,
    context: ObjectStoreErrorContext,
) -> Result<Vec<u8>> {
    let object_path = cold_object_path(key, path, context)?;
    let bytes = block_on_object_store(async {
        let result = store.store.get(&object_path).await?;
        result.bytes().await
    })
    .map_err(|error| {
        object_store_error(
            context,
            path,
            format!("failed to read cold object '{key}': {error}"),
        )
    })?;
    Ok(bytes.to_vec())
}

fn block_on_object_store<F: Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            // Network-backed object_store clients rely on Tokio's reactor; a plain
            // futures executor can stall S3-compatible requests inside the server.
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        _ => block_on(future),
    }
}

fn object_store_error(
    context: ObjectStoreErrorContext,
    path: &Path,
    message: String,
) -> GaussError {
    match context {
        ObjectStoreErrorContext::Corruption => GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message,
        },
        ObjectStoreErrorContext::Request => GaussError::InvalidRequest(message),
    }
}

pub fn compact_searchers(
    searchers_dir: &Path,
    points: &mut HashMap<String, Point>,
    vector_dim: usize,
    named_vector_dims: &std::collections::HashMap<String, usize>,
    metric: crate::DistanceMetric,
) -> Result<SegmentWrite> {
    compact_searchers_with_params(
        searchers_dir,
        points,
        vector_dim,
        named_vector_dims,
        None,
        None,
        metric,
    )
}

pub fn compact_searchers_with_params(
    searchers_dir: &Path,
    points: &mut HashMap<String, Point>,
    vector_dim: usize,
    named_vector_dims: &std::collections::HashMap<String, usize>,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: crate::DistanceMetric,
) -> Result<SegmentWrite> {
    fs::create_dir_all(searchers_dir)?;
    // Move the points out instead of cloning the whole collection — at 1M
    // high-dim vectors that clone alone is several GB of transient peak.
    // The map is rebuilt from the same moved points before returning, on
    // both the success and error paths, so the caller's map is never left
    // empty. Callers hold the collection write lock across this call, so
    // no reader can observe the temporarily-empty map.
    let mut sorted_points = std::mem::take(points).into_values().collect::<Vec<_>>();
    sorted_points.sort_by(|left, right| left.id.cmp(&right.id));
    let result = compact_sorted_points(
        searchers_dir,
        &sorted_points,
        vector_dim,
        named_vector_dims,
        hnsw_m,
        hnsw_ef_construction,
        metric,
    );
    points.extend(
        sorted_points
            .into_iter()
            .map(|point| (point.id.clone(), point)),
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn compact_sorted_points(
    searchers_dir: &Path,
    sorted_points: &[Point],
    vector_dim: usize,
    named_vector_dims: &std::collections::HashMap<String, usize>,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: crate::DistanceMetric,
) -> Result<SegmentWrite> {
    // Stream the segment payload straight to disk: the segment id depends on
    // the payload CRC, which the streaming writer computes on the fly, so we
    // write into a neutral pending dir first and rename once the id is known.
    // This keeps peak memory at ~1x the point set instead of point set +
    // serialized JSON + paged copy.
    let pending_dir = searchers_dir.join("sg-pending.tmp");
    if pending_dir.exists() {
        fs::remove_dir_all(&pending_dir)?;
    }
    fs::create_dir_all(&pending_dir)?;
    let writer = PagedFramedWriter::create(&pending_dir.join(SEGMENT_FILE), VECTOR_MAGIC_V2)?;
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, writer);
    serde_json::to_writer(
        &mut writer,
        &SegmentPayloadRef {
            points: sorted_points,
        },
    )?;
    let writer = writer
        .into_inner()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let (_payload_len, crc) = writer.finish()?;
    let segment_id = format!("sg-{crc:08x}");
    let tmp_dir = searchers_dir.join(format!("{segment_id}.tmp"));
    let final_dir = searchers_dir.join(&segment_id);

    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::rename(&pending_dir, &tmp_dir)?;
    // Paged index write: graph vectors go to a flat h2qg_vecs.gdx sidecar so
    // the reloaded index reads them through an OS-paged mmap instead of
    // keeping a second full in-heap copy of every vector resident.
    // ponytail: named indexes stay non-paged — page them too if named-vector
    // collections ever hit the same memory wall.
    let h2qg_write = h2qg::write_index_paged_with_params(
        &tmp_dir,
        sorted_points,
        vector_dim,
        hnsw_m,
        hnsw_ef_construction,
        metric,
    )?;
    let named_h2qg_writes = write_named_h2qg_indexes(
        &tmp_dir,
        sorted_points,
        vector_dim,
        named_vector_dims,
        hnsw_m,
        hnsw_ef_construction,
        metric,
    )?;
    let sparse_write = write_sparse_index(&tmp_dir.join(SPARSE_INDEX_FILE), sorted_points)?;
    let payload_write = write_payload_index(&tmp_dir.join(PAYLOAD_INDEX_FILE), sorted_points)?;
    let segment_ids = sorted_points
        .iter()
        .map(|point| point.id.clone())
        .collect::<Vec<_>>();
    let tombstone_write = write_tombstones(&tmp_dir.join(TOMBSTONE_FILE), &segment_ids, &[])?;
    encrypt_segment_artifacts(&tmp_dir)?;
    write_manifest(
        &tmp_dir.join(MANIFEST_FILE),
        &tmp_dir,
        SegmentManifestStats {
            id: segment_id.clone(),
            points: sorted_points.len(),
            h2qg_cells: h2qg_write.cells,
            named_h2qg_fields: named_h2qg_writes.len(),
            sparse_dimensions: sparse_write.dimensions,
            sparse_postings: sparse_write.postings,
            sparse_blocks: sparse_write.blocks,
            payload_fields: payload_write.fields,
            payload_values: payload_write.values,
            payload_postings: payload_write.postings,
            tombstones: tombstone_write.deleted_ids,
        },
    )?;

    let backup_dir = searchers_dir.join(format!("{segment_id}.old"));
    if backup_dir.exists() {
        fs::remove_dir_all(&backup_dir)?;
    }
    if final_dir.exists() {
        fs::rename(&final_dir, &backup_dir)?;
    }
    fs::rename(&tmp_dir, &final_dir)?;

    for entry in fs::read_dir(searchers_dir)? {
        let path = entry?.path();
        if path.is_dir() && path != final_dir {
            fs::remove_dir_all(path)?;
        }
    }

    Ok(SegmentWrite {
        id: segment_id,
        manifest_path: final_dir.join(MANIFEST_FILE),
        path: final_dir.join(SEGMENT_FILE),
        h2qg_path: final_dir.join(h2qg::INDEX_FILE),
        named_h2qg_paths: named_h2qg_writes
            .keys()
            .map(|name| (name.clone(), final_dir.join(named_h2qg_file_name(name))))
            .collect(),
        sparse_path: final_dir.join(SPARSE_INDEX_FILE),
        payload_path: final_dir.join(PAYLOAD_INDEX_FILE),
        tombstone_path: final_dir.join(TOMBSTONE_FILE),
        points: sorted_points.len(),
        h2qg_cells: h2qg_write.cells,
        named_h2qg_fields: named_h2qg_writes.len(),
        sparse_dimensions: sparse_write.dimensions,
        sparse_postings: sparse_write.postings,
        sparse_blocks: sparse_write.blocks,
        payload_fields: payload_write.fields,
        payload_values: payload_write.values,
        payload_postings: payload_write.postings,
        tombstones: tombstone_write.deleted_ids,
    })
}

/// Write payload with per-page CRC checksums (V2 format).
/// Format: magic (8) + total_payload_len u64 le (8) + outer_crc32 u32 le (4) + paged data.
/// Paged data = for each PAGE_SIZE chunk: 4-byte CRC32 of chunk + chunk bytes.
fn write_paged_framed(path: &Path, magic: &[u8; 8], payload: &[u8]) -> Result<()> {
    let mut paged_data: Vec<u8> =
        Vec::with_capacity(payload.len() + (payload.len() / PAGE_SIZE + 1) * 4);
    for chunk in payload.chunks(PAGE_SIZE) {
        let page_crc = checksum(chunk);
        paged_data.extend_from_slice(&page_crc.to_le_bytes());
        paged_data.extend_from_slice(chunk);
    }
    let outer_crc = checksum(&paged_data);
    let mut bytes = Vec::with_capacity(HEADER_LEN + paged_data.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&outer_crc.to_le_bytes());
    bytes.extend_from_slice(&paged_data);
    encryption::atomic_write_persistent(path, FileType::Segment, &bytes)
}

/// Read a paged-framed file, verifying outer and per-page CRCs, then call `f` on the
/// reassembled payload.
fn with_paged_framed_slice<T>(
    path: &Path,
    magic: &[u8; 8],
    label: &str,
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let file = encryption::PersistentFile::open(path)?;
    if file.len() < HEADER_LEN {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} shorter than header"),
        });
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != magic {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("bad {label} magic"),
        });
    }
    let payload_len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("payload len"),
    ))
    .map_err(|_| GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: format!("{label} payload length exceeds usize"),
    })?;
    let outer_crc = u32::from_le_bytes(header[16..20].try_into().expect("outer crc"));
    if file.crc32(HEADER_LEN..file.len())? != outer_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} outer crc mismatch"),
        });
    }
    let mut payload = Vec::with_capacity(payload_len);
    let mut pos = HEADER_LEN;
    let mut page_index = 0_usize;
    while pos < file.len() {
        if pos + 4 > file.len() {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("{label} truncated page crc at page {page_index}"),
            });
        }
        let page_crc_bytes = file.read_range(pos..pos + 4)?;
        let page_crc = u32::from_le_bytes(page_crc_bytes.as_ref().try_into().expect("page crc"));
        pos += 4;
        let chunk_len = PAGE_SIZE.min(payload_len - payload.len());
        if pos + chunk_len > file.len() {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("{label} truncated page data at page {page_index}"),
            });
        }
        let chunk = file.read_range(pos..pos + chunk_len)?;
        if checksum(&chunk) != page_crc {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("{label} page {page_index} crc mismatch"),
            });
        }
        payload.extend_from_slice(&chunk);
        pos += chunk_len;
        page_index += 1;
    }
    f(&payload)
}

/// Streaming counterpart of [`write_paged_framed`]: an [`std::io::Write`] sink
/// that pages, CRCs, and writes payload bytes as they arrive, so serializing a
/// large segment never materialises the whole payload (or its paged copy) in
/// memory. The 20-byte header is back-patched in `finish()`, which returns
/// `(payload_len, payload_crc)` — `payload_crc` matches `checksum(payload)`
/// and is what segment ids are derived from.
struct PagedFramedWriter {
    file: File,
    page: Vec<u8>,
    outer: Hasher,
    payload_crc: Hasher,
    payload_len: u64,
}

impl PagedFramedWriter {
    fn create(path: &Path, magic: &[u8; 8]) -> Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(magic)?;
        file.write_all(&[0u8; 12])?; // placeholder: payload_len + outer_crc
        Ok(Self {
            file,
            page: Vec::with_capacity(PAGE_SIZE),
            outer: Hasher::new(),
            payload_crc: Hasher::new(),
            payload_len: 0,
        })
    }

    fn flush_page(&mut self) -> std::io::Result<()> {
        if self.page.is_empty() {
            return Ok(());
        }
        let page_crc = checksum(&self.page).to_le_bytes();
        self.outer.update(&page_crc);
        self.outer.update(&self.page);
        self.file.write_all(&page_crc)?;
        self.file.write_all(&self.page)?;
        self.page.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<(u64, u32)> {
        use std::io::{Seek, SeekFrom};
        self.flush_page()?;
        let outer_crc = self.outer.clone().finalize();
        self.file.seek(SeekFrom::Start(8))?;
        self.file.write_all(&self.payload_len.to_le_bytes())?;
        self.file.write_all(&outer_crc.to_le_bytes())?;
        self.file.sync_all()?;
        Ok((self.payload_len, self.payload_crc.clone().finalize()))
    }
}

impl Write for PagedFramedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.payload_crc.update(buf);
        self.payload_len += buf.len() as u64;
        let mut rest = buf;
        while !rest.is_empty() {
            let take = (PAGE_SIZE - self.page.len()).min(rest.len());
            self.page.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.page.len() == PAGE_SIZE {
                self.flush_page()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Partial pages must stay buffered until finish() — page framing is
        // fixed-size, so an early flush would corrupt the page layout.
        Ok(())
    }
}

fn write_sparse_index(path: &Path, points: &[Point]) -> Result<SparseIndexStats> {
    let payload = build_sparse_index_payload(points);
    let stats = payload.stats();
    let payload = serde_json::to_vec(&payload)?;
    let crc = checksum(&payload);
    write_framed(path, SPARSE_MAGIC, &payload, crc)?;
    Ok(stats)
}

fn write_named_h2qg_indexes(
    segment_dir: &Path,
    points: &[Point],
    vector_dim: usize,
    named_vector_dims: &std::collections::HashMap<String, usize>,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    metric: crate::DistanceMetric,
) -> Result<BTreeMap<String, h2qg::H2qgWrite>> {
    let mut names = BTreeMap::<String, ()>::new();
    for point in points {
        for name in point.vectors.keys() {
            names.insert(name.clone(), ());
        }
    }

    let mut writes = BTreeMap::new();
    for name in names.keys() {
        let dim = named_vector_dims.get(name).copied().unwrap_or(vector_dim);
        let path = segment_dir.join(named_h2qg_file_name(name));
        let write = h2qg::write_named_index_with_params(
            &path,
            points,
            dim,
            name,
            hnsw_m,
            hnsw_ef_construction,
            metric,
        )?;
        if write.indexed_points > 0 {
            writes.insert(name.clone(), write);
        } else if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(writes)
}

fn write_payload_index(path: &Path, points: &[Point]) -> Result<PayloadIndexStats> {
    let payload = build_payload_index_payload(points);
    let stats = payload.stats();
    let payload = serde_json::to_vec(&payload)?;
    let crc = checksum(&payload);
    write_framed(path, PAYLOAD_MAGIC, &payload, crc)?;
    Ok(stats)
}

/// Update a sealed segment's tombstone file in-place by adding `additional_deleted_ids`.
/// Reads the current tombstone (if any), merges with the new IDs, rewrites the
/// tombstone artifact, and refreshes the manifest file-entry so validation still
/// passes — allowing incremental delete propagation without a full recompaction.
/// Returns the total tombstone count after the update.
pub fn apply_incremental_tombstone(
    segment_dir: &Path,
    additional_deleted_ids: &[String],
) -> Result<usize> {
    let segment_ids: Vec<String> = read_segment(&segment_dir.join(SEGMENT_FILE))?
        .into_iter()
        .map(|p| p.id)
        .collect();
    let tomb_path = segment_dir.join(TOMBSTONE_FILE);
    let mut all_deleted = if tomb_path.exists() {
        read_tombstones(&tomb_path, &segment_ids)?
    } else {
        Vec::new()
    };
    all_deleted.extend_from_slice(additional_deleted_ids);
    let stats = write_tombstones(&tomb_path, &segment_ids, &all_deleted)?;

    // Refresh the manifest's tombstone file-entry and count so manifest
    // validation continues to pass after the in-place tombstone update.
    let manifest_path = segment_dir.join(MANIFEST_FILE);
    if manifest_path.exists() {
        let mut manifest: SegmentManifestPayload =
            with_framed_slice(&manifest_path, MANIFEST_MAGIC, "manifest", |payload| {
                Ok(serde_json::from_slice(payload)?)
            })?;
        manifest.tombstones = stats.deleted_ids;
        let new_entry = manifest_file_entry(segment_dir, TOMBSTONE_FILE)?;
        if let Some(entry) = manifest.files.iter_mut().find(|f| f.name == TOMBSTONE_FILE) {
            *entry = new_entry;
        } else {
            manifest.files.push(new_entry);
        }
        let payload = serde_json::to_vec(&manifest)?;
        let crc = checksum(&payload);
        write_framed(&manifest_path, MANIFEST_MAGIC, &payload, crc)?;
    }

    Ok(stats.deleted_ids)
}

fn write_tombstones(
    path: &Path,
    segment_ids: &[String],
    deleted_ids: &[String],
) -> Result<TombstoneStats> {
    let mut deleted_ids = deleted_ids.to_vec();
    deleted_ids.sort();
    deleted_ids.dedup();
    let segment_ordinals = segment_ids
        .iter()
        .enumerate()
        .map(|(ordinal, id)| {
            let ordinal = u32::try_from(ordinal).map_err(|_| {
                GaussError::InvalidRequest(
                    "segment has more than u32::MAX tombstone ordinals".to_string(),
                )
            })?;
            Ok((id.as_str(), ordinal))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    let mut deleted_ordinals = RoaringBitmap::new();
    for id in &deleted_ids {
        if let Some(ordinal) = segment_ordinals.get(id.as_str()) {
            deleted_ordinals.insert(*ordinal);
        }
    }
    let mut deleted_ordinals_roaring = Vec::with_capacity(deleted_ordinals.serialized_size());
    deleted_ordinals.serialize_into(&mut deleted_ordinals_roaring)?;
    let stats = TombstoneStats {
        deleted_ids: deleted_ids.len(),
    };
    let payload = serde_json::to_vec(&TombstonePayload {
        deleted_ids,
        deleted_ordinals_roaring,
    })?;
    let crc = checksum(&payload);
    write_framed(path, TOMBSTONE_MAGIC, &payload, crc)?;
    Ok(stats)
}

fn write_manifest(path: &Path, segment_dir: &Path, stats: SegmentManifestStats) -> Result<()> {
    let payload = SegmentManifestPayload {
        id: stats.id,
        points: stats.points,
        h2qg_cells: stats.h2qg_cells,
        named_h2qg_fields: stats.named_h2qg_fields,
        sparse_dimensions: stats.sparse_dimensions,
        sparse_postings: stats.sparse_postings,
        sparse_blocks: stats.sparse_blocks,
        payload_fields: stats.payload_fields,
        payload_values: stats.payload_values,
        payload_postings: stats.payload_postings,
        tombstones: stats.tombstones,
        files: manifest_file_names(segment_dir)?
            .into_iter()
            .map(|name| manifest_file_entry(segment_dir, &name))
            .collect::<Result<Vec<_>>>()?,
    };
    let payload = serde_json::to_vec(&payload)?;
    let crc = checksum(&payload);
    write_framed(path, MANIFEST_MAGIC, &payload, crc)
}

fn encrypt_segment_artifacts(segment_dir: &Path) -> Result<()> {
    if !encryption::encryption_enabled() {
        return Ok(());
    }
    for entry in fs::read_dir(segment_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.file_name() == MANIFEST_FILE {
            continue;
        }
        let path = entry.path();
        let plaintext = fs::read(&path)?;
        if encryption::is_encrypted(&plaintext) {
            continue;
        }
        encryption::atomic_write_persistent(&path, FileType::Segment, &plaintext)?;
    }
    Ok(())
}

fn manifest_file_names(segment_dir: &Path) -> Result<Vec<String>> {
    let mut names = [
        SEGMENT_FILE.to_string(),
        h2qg::INDEX_FILE.to_string(),
        SPARSE_INDEX_FILE.to_string(),
        PAYLOAD_INDEX_FILE.to_string(),
        TOMBSTONE_FILE.to_string(),
    ]
    .into_iter()
    .collect::<Vec<_>>();
    // Paged-vector sidecar only exists for HNSW segments written by the paged
    // writer — include it in the manifest (and its validation) when present.
    if segment_dir.join(h2qg::HNSW_VECS_FILE).exists() {
        names.push(h2qg::HNSW_VECS_FILE.to_string());
    }
    for (_, path) in named_h2qg_paths(segment_dir)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "named H2QG file name is not valid UTF-8: {}",
                    path.display()
                ))
            })?
            .to_string();
        names.push(name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn write_framed(path: &Path, magic: &[u8; 8], payload: &[u8], crc: u32) -> Result<()> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    encryption::atomic_write_persistent(path, FileType::Segment, &bytes)
}

/// Streaming page-verified reader over a persisted paged-framed file. Verifies
/// each page CRC as it is consumed and hands payload bytes to the caller
/// without reassembling the whole payload in memory (the outer CRC is
/// checked up front over the mmap, which the page cache keeps bounded).
struct PagedPayloadReader<'a> {
    file: &'a encryption::PersistentFile,
    pos: usize,
    remaining: usize,
    chunk: Vec<u8>,
    chunk_pos: usize,
}

impl std::io::Read for PagedPayloadReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Error, ErrorKind};
        if self.chunk_pos == self.chunk.len() {
            if self.remaining == 0 {
                return Ok(0);
            }
            let chunk_len = PAGE_SIZE.min(self.remaining);
            if self.pos + 4 + chunk_len > self.file.len() {
                return Err(Error::new(ErrorKind::InvalidData, "truncated segment page"));
            }
            let page_crc_bytes = self
                .file
                .read_range(self.pos..self.pos + 4)
                .map_err(|error| Error::other(error.to_string()))?;
            let page_crc = u32::from_le_bytes(page_crc_bytes.as_ref().try_into().unwrap());
            self.pos += 4;
            let chunk = self
                .file
                .read_range(self.pos..self.pos + chunk_len)
                .map_err(|error| Error::other(error.to_string()))?;
            if checksum(&chunk) != page_crc {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "segment page crc mismatch",
                ));
            }
            self.pos += chunk_len;
            self.remaining -= chunk_len;
            self.chunk = chunk.into_owned();
            self.chunk_pos = 0;
        }
        let available = self.chunk.len() - self.chunk_pos;
        let take = buf.len().min(available);
        buf[..take].copy_from_slice(&self.chunk[self.chunk_pos..self.chunk_pos + take]);
        self.chunk_pos += take;
        Ok(take)
    }
}

/// Streaming V2 segment read: header + outer-CRC checks match
/// [`with_paged_framed_slice`], but the JSON payload is parsed through
/// [`PagedPayloadReader`] so the reassembled payload never lives in memory.
fn read_segment_v2_streaming(path: &Path) -> Result<Vec<Point>> {
    let file = encryption::PersistentFile::open(path)?;
    let corrupt = |message: String| GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message,
    };
    if file.len() < HEADER_LEN {
        return Err(corrupt("segment shorter than header".into()));
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != VECTOR_MAGIC_V2 {
        return Err(corrupt("bad segment magic".into()));
    }
    let payload_len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("payload len"),
    ))
    .map_err(|_| corrupt("segment payload length exceeds usize".into()))?;
    let outer_crc = u32::from_le_bytes(header[16..20].try_into().expect("outer crc"));
    let expected_len = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|bytes| bytes.checked_add(payload_len.div_ceil(PAGE_SIZE) * 4))
        .ok_or_else(|| corrupt("segment paged length overflow".into()))?;
    if file.len() != expected_len {
        return Err(corrupt("segment paged length mismatch".into()));
    }
    if file.crc32(HEADER_LEN..file.len())? != outer_crc {
        return Err(corrupt("segment outer crc mismatch".into()));
    }
    let reader = PagedPayloadReader {
        file: &file,
        pos: HEADER_LEN,
        remaining: payload_len,
        chunk: Vec::new(),
        chunk_pos: 0,
    };
    let reader = std::io::BufReader::with_capacity(64 * 1024, reader);
    Ok(serde_json::from_reader::<_, SegmentPayload>(reader)?.points)
}

fn read_segment(path: &Path) -> Result<Vec<Point>> {
    // Try V2 format first.
    if let Ok(result) = read_segment_v2_streaming(path) {
        return Ok(result);
    }
    // Fall back to V1.
    with_framed_slice(path, VECTOR_MAGIC, "segment", |payload| {
        Ok(serde_json::from_slice::<SegmentPayload>(payload)?.points)
    })
}

fn read_sparse_index(path: &Path) -> Result<SparseIndexStats> {
    with_framed_slice(path, SPARSE_MAGIC, "sparse index", |payload| {
        Ok(serde_json::from_slice::<SparseIndexPayload>(payload)?.stats())
    })
}

fn read_payload_index(path: &Path) -> Result<PayloadIndexSnapshot> {
    with_framed_slice(path, PAYLOAD_MAGIC, "payload index", |payload| {
        Ok(serde_json::from_slice::<PayloadIndexPayload>(payload)?.into_snapshot())
    })
}

fn read_tombstones(path: &Path, segment_ids: &[String]) -> Result<Vec<String>> {
    with_framed_slice(path, TOMBSTONE_MAGIC, "tombstone index", |payload| {
        let payload = serde_json::from_slice::<TombstonePayload>(payload)?;
        let mut deleted_ids = payload.deleted_ids;
        if !payload.deleted_ordinals_roaring.is_empty() {
            let deleted_ordinals =
                RoaringBitmap::deserialize_from(Cursor::new(payload.deleted_ordinals_roaring))?;
            for ordinal in deleted_ordinals {
                let id = segment_ids.get(ordinal as usize).ok_or_else(|| {
                    GaussError::SegmentCorruption {
                        path: path.display().to_string(),
                        message: format!("tombstone ordinal {ordinal} out of bounds"),
                    }
                })?;
                deleted_ids.push(id.clone());
            }
        }
        deleted_ids.sort();
        deleted_ids.dedup();
        Ok(deleted_ids)
    })
}

fn read_manifest(path: &Path, segment_dir: &Path) -> Result<SegmentManifestPayload> {
    with_framed_slice(path, MANIFEST_MAGIC, "manifest", |payload| {
        let manifest = serde_json::from_slice::<SegmentManifestPayload>(payload)?;
        validate_manifest_files(path, segment_dir, &manifest)?;
        Ok(manifest)
    })
}

/// Zero-copy framed-file reader.  Maps `path` with mmap, validates the header
/// and CRC, then calls `f` with a slice into the mapped payload — no heap copy.
/// The Mmap lives for the duration of the call; the slice must not escape `f`.
fn with_framed_slice<T>(
    path: &Path,
    magic: &[u8; 8],
    label: &str,
    f: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let file = encryption::PersistentFile::open(path)?;
    if file.len() < HEADER_LEN {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} shorter than header"),
        });
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != magic {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("bad {label} magic"),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("segment length"),
    ))
    .map_err(|_| GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: format!("{label} length exceeds usize"),
    })?;
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("segment crc"));
    if file.len() != HEADER_LEN + len {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} length mismatch"),
        });
    }
    let actual_crc = file.crc32(HEADER_LEN..file.len())?;
    if actual_crc != expected_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: format!("{label} crc mismatch"),
        });
    }
    let payload = file.read_range(HEADER_LEN..file.len())?;
    f(&payload)
}

/// Compatibility wrapper: reads framed file and returns an owned Vec<u8>.
/// Prefer `with_framed_slice` for hot paths to avoid the heap copy.
fn read_framed(path: &Path, magic: &[u8; 8], label: &str) -> Result<Vec<u8>> {
    with_framed_slice(path, magic, label, |payload| Ok(payload.to_vec()))
}

fn build_sparse_index_payload(points: &[Point]) -> SparseIndexPayload {
    let mut dimensions: BTreeMap<u32, Vec<SparsePostingPayload>> = BTreeMap::new();
    for point in points {
        let Some(sparse_vector) = &point.sparse_vector else {
            continue;
        };
        for (&dimension, &value) in sparse_vector.indices.iter().zip(&sparse_vector.values) {
            dimensions
                .entry(dimension)
                .or_default()
                .push(SparsePostingPayload {
                    id: point.id.clone(),
                    value,
                });
        }
    }

    SparseIndexPayload {
        dimensions: dimensions
            .into_iter()
            .map(|(dimension, mut postings)| {
                postings.sort_by(|left, right| {
                    right
                        .value
                        .total_cmp(&left.value)
                        .then_with(|| left.id.cmp(&right.id))
                });
                let blocks = sparse_blocks(&postings);
                SparseDimensionPayload {
                    dimension,
                    postings,
                    blocks,
                }
            })
            .collect(),
    }
}

fn sparse_blocks(postings: &[SparsePostingPayload]) -> Vec<SparseBlockPayload> {
    (0..postings.len())
        .step_by(SPARSE_BLOCK_SIZE)
        .map(|start| {
            let end = (start + SPARSE_BLOCK_SIZE).min(postings.len());
            let max_value = postings[start..end]
                .iter()
                .map(|posting| posting.value)
                .fold(f32::NEG_INFINITY, f32::max);
            SparseBlockPayload {
                start,
                len: end - start,
                max_value,
            }
        })
        .collect()
}

fn build_payload_index_payload(points: &[Point]) -> PayloadIndexPayload {
    let mut fields: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for point in points {
        let Some(payload) = point.payload.as_object() else {
            continue;
        };
        for (field, value) in payload {
            build_payload_index_value(&mut fields, field, value, &point.id);
        }
    }

    PayloadIndexPayload {
        fields: fields
            .into_iter()
            .map(|(field, values)| PayloadFieldPayload {
                field,
                values: values
                    .into_iter()
                    .map(|(key, mut ids)| {
                        ids.sort();
                        PayloadValuePayload { key, ids }
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn build_payload_index_value(
    fields: &mut BTreeMap<String, BTreeMap<String, Vec<String>>>,
    field: &str,
    value: &serde_json::Value,
    point_id: &str,
) {
    if let Some(key) = payload_index_key(value) {
        fields
            .entry(field.to_string())
            .or_default()
            .entry(key)
            .or_default()
            .push(point_id.to_string());
        return;
    }

    let Some(object) = value.as_object() else {
        if let Some(array) = value.as_array() {
            for item in array {
                build_payload_index_value(fields, field, item, point_id);
            }
        }
        return;
    };
    for (child, child_value) in object {
        build_payload_index_value(fields, &format!("{field}.{child}"), child_value, point_id);
    }
}

fn payload_index_key(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => Some("null".to_string()),
        serde_json::Value::Bool(value) => Some(format!("bool:{value}")),
        serde_json::Value::Number(value) => Some(format!("number:{value}")),
        serde_json::Value::String(value) => Some(format!("string:{value}")),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SegmentManifestStats {
    id: String,
    points: usize,
    h2qg_cells: usize,
    named_h2qg_fields: usize,
    sparse_dimensions: usize,
    sparse_postings: usize,
    sparse_blocks: usize,
    payload_fields: usize,
    payload_values: usize,
    payload_postings: usize,
    tombstones: usize,
}

fn named_h2qg_file_name(name: &str) -> String {
    format!("h2qg-{name}.gdx")
}

pub(crate) fn named_h2qg_paths(segment_dir: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut paths = BTreeMap::new();
    if !segment_dir.exists() {
        return Ok(paths);
    }
    for entry in fs::read_dir(segment_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name) = file_name
            .strip_prefix("h2qg-")
            .and_then(|value| value.strip_suffix(".gdx"))
        else {
            continue;
        };
        paths.insert(name.to_string(), entry.path());
    }
    Ok(paths)
}

fn manifest_file_entry(segment_dir: &Path, name: &str) -> Result<SegmentManifestFilePayload> {
    let path = segment_dir.join(name);
    let bytes = encryption::read_persistent(&path)?;
    Ok(SegmentManifestFilePayload {
        name: name.to_string(),
        bytes: bytes.len() as u64,
        crc: checksum(&bytes),
    })
}

fn directory_stats(path: &Path) -> Result<(usize, u64)> {
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let (nested_files, nested_bytes) = directory_stats(&entry.path())?;
            files += nested_files;
            bytes += nested_bytes;
        } else if file_type.is_file() {
            files += 1;
            bytes += entry.metadata()?.len();
        }
    }
    Ok((files, bytes))
}

fn validate_manifest_files(
    manifest_path: &Path,
    segment_dir: &Path,
    manifest: &SegmentManifestPayload,
) -> Result<()> {
    if segment_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|segment_id| segment_id != manifest.id)
    {
        return Err(GaussError::SegmentCorruption {
            path: manifest_path.display().to_string(),
            message: "manifest segment id mismatch".to_string(),
        });
    }
    for expected_name in [
        SEGMENT_FILE,
        h2qg::INDEX_FILE,
        SPARSE_INDEX_FILE,
        PAYLOAD_INDEX_FILE,
    ] {
        if !manifest.files.iter().any(|file| file.name == expected_name) {
            return Err(GaussError::SegmentCorruption {
                path: manifest_path.display().to_string(),
                message: format!("manifest missing {expected_name}"),
            });
        }
    }
    for file in &manifest.files {
        if file.name.contains('/') || file.name.contains('\\') {
            return Err(GaussError::SegmentCorruption {
                path: manifest_path.display().to_string(),
                message: format!("manifest contains invalid file name {}", file.name),
            });
        }
        let path = segment_dir.join(&file.name);
        let bytes =
            encryption::read_persistent(&path).map_err(|error| GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("manifest-listed file is unreadable: {error}"),
            })?;
        if bytes.len() as u64 != file.bytes {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: "manifest file length mismatch".to_string(),
            });
        }
        let actual_crc = checksum(&bytes);
        if actual_crc != file.crc {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: "manifest file crc mismatch".to_string(),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TombstoneStats {
    deleted_ids: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SparseIndexStats {
    dimensions: usize,
    postings: usize,
    blocks: usize,
}

impl SparseIndexPayload {
    fn stats(&self) -> SparseIndexStats {
        SparseIndexStats {
            dimensions: self.dimensions.len(),
            postings: self
                .dimensions
                .iter()
                .map(|dimension| dimension.postings.len())
                .sum(),
            blocks: self
                .dimensions
                .iter()
                .map(|dimension| dimension.blocks.len())
                .sum(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadIndexStats {
    fields: usize,
    values: usize,
    postings: usize,
}

impl PayloadIndexPayload {
    fn stats(&self) -> PayloadIndexStats {
        PayloadIndexStats {
            fields: self.fields.len(),
            values: self.fields.iter().map(|field| field.values.len()).sum(),
            postings: self
                .fields
                .iter()
                .flat_map(|field| &field.values)
                .map(|value| value.ids.len())
                .sum(),
        }
    }

    fn into_snapshot(self) -> PayloadIndexSnapshot {
        self.fields
            .into_iter()
            .map(|field| {
                (
                    field.field,
                    field
                        .values
                        .into_iter()
                        .map(|value| (value.key, value.ids))
                        .collect(),
                )
            })
            .collect()
    }
}

fn checksum(payload: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(payload);
    hasher.finalize()
}

// ── P2E: GAUSSGD3 (SoA) writer + reader ─────────────────────────────────────

/// Build an [`SoAVectorStorage`] from a sorted slice of points.
/// All points must share the same `vector.len()`; mixed dims are rejected.
fn build_soa_storage(points: &[Point]) -> Result<SoAVectorStorage> {
    if points.is_empty() {
        return Ok(SoAVectorStorage {
            points: Vec::new(),
            dim: 0,
            soa: Vec::new(),
        });
    }
    let dim = points[0].vector.len();
    if dim == 0 {
        return Err(GaussError::InvalidRequest(
            "cannot build SoA storage: first point has zero-dim vector".to_string(),
        ));
    }
    for point in points {
        if point.vector.len() != dim {
            return Err(GaussError::InvalidRequest(format!(
                "cannot build SoA storage: dim mismatch ({} vs {}) for point {}",
                point.vector.len(),
                dim,
                point.id
            )));
        }
    }
    let count = points.len();
    // P2E: dim-strided SoA layout. `soa[d*count + i] = points[i].vector[d]`.
    // The transpose is a single sequential pass: for each dim d, sweep
    // through every point and write its dim-d value contiguously. This is
    // the read pattern the SIMD batch-distance kernel relies on (load 8
    // contiguous f32 = 8 points' dim-d value in one AVX2/NEON instruction).
    let mut soa = vec![0.0_f32; count * dim];
    for d in 0..dim {
        let column_offset = d * count;
        for (i, point) in points.iter().enumerate() {
            soa[column_offset + i] = point.vector[d];
        }
    }
    let aux = points
        .iter()
        .map(|point| PointAux {
            id: point.id.clone(),
            payload: point.payload.clone(),
            sparse_vector: point.sparse_vector.clone(),
            vectors: point.vectors.clone(),
        })
        .collect();
    Ok(SoAVectorStorage {
        points: aux,
        dim,
        soa,
    })
}

fn encode_v3_payload(storage: &SoAVectorStorage) -> Result<Vec<u8>> {
    let dim = storage.dim;
    let count = storage.count();
    let soa_bytes = count
        .checked_mul(dim)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| {
            GaussError::InvalidRequest(format!("soa payload overflow: count={count} dim={dim}"))
        })?;
    let aux = serde_json::to_vec(&storage.points)?;
    let aux_len = aux.len();
    let total = 8_usize
        .checked_add(4)
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(soa_bytes))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(aux_len))
        .ok_or_else(|| GaussError::InvalidRequest("soa v3 payload length overflow".to_string()))?;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(VECTOR_V3_INNER_MAGIC);
    let mut flags = 0_u32;
    if storage.points.iter().any(|p| !p.vectors.is_empty()) {
        flags |= V3_FLAG_HAS_NAMED;
    }
    if storage.points.iter().any(|p| p.sparse_vector.is_some()) {
        flags |= V3_FLAG_HAS_SPARSE;
    }
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&(dim as u32).to_le_bytes());
    buf.extend_from_slice(&(count as u64).to_le_bytes());
    buf.extend_from_slice(&(soa_bytes as u64).to_le_bytes());
    for value in &storage.soa {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    buf.extend_from_slice(&(aux_len as u64).to_le_bytes());
    buf.extend_from_slice(&aux);
    debug_assert_eq!(buf.len(), total);
    Ok(buf)
}

/// P2E: write a legacy V2 (GAUSSGD2) segment from a `Vec<Point>`. Used by
/// the integration test for `gaussctl migrate-segment` and by any
/// downstream tool that needs to materialise V2 data on disk.
pub fn write_segment_v2_legacy(path: &Path, points: &[Point]) -> Result<()> {
    let payload = serde_json::to_vec(&SegmentPayload {
        points: points.to_vec(),
    })?;
    write_paged_framed(path, VECTOR_MAGIC_V2, &payload)
}

// ── P2C / PC-2 v3: Vamana/DiskANN single-layer graph persistence ────────────

/// Stats returned by [`write_vamana_index`]. Mirrors the `SegmentWrite`
/// shape so the manifest writer can treat both uniformly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VamanaWrite {
    pub path: PathBuf,
    pub bytes: u64,
    pub crc: u32,
    pub points: usize,
}

/// PC-2 v3: serialize a `VamanaBackend` to `vamana.gdx` next to the
/// `h2qg.gdx` index. The on-disk layout is the existing framed envelope
/// (8-byte magic + 4-byte payload_len + 4-byte outer_crc + paged payload
/// with per-page CRC chunks) wrapping the JSON-serialized backend, so
/// legacy loaders that read the file as `serde_json::from_slice` see a
/// single contiguous blob and the on-disk format is forward-compatible
/// (add new fields at the JSON layer, no format bump).
pub fn write_vamana_index(
    path: &Path,
    backend: &crate::index::vamana::VamanaBackend,
) -> Result<VamanaWrite> {
    let payload = serde_json::to_vec(backend)?;
    let crc = checksum(&payload);
    write_framed(path, VAMANA_MAGIC, &payload, crc)?;
    let bytes = std::fs::metadata(path)?.len();
    // P2C v3: VamanaBackend::point_count is the public accessor for
    // the trait's `indexed_points` (same expression, no trait import).
    let points = backend.point_count();
    Ok(VamanaWrite {
        path: path.to_path_buf(),
        bytes,
        crc,
        points,
    })
}

/// PC-2 v3: deserialize a `VamanaBackend` from `vamana.gdx`. Returns
/// `Ok(None)` when the file is absent (legacy V1/V2 segment without a
/// vamana index, or a non-DiskANN collection). The framed envelope's
/// magic check protects against wrong-file reads.
pub fn read_vamana_index(path: &Path) -> Result<Option<crate::index::vamana::VamanaBackend>> {
    if !path.exists() {
        return Ok(None);
    }
    let backend = with_framed_slice(path, VAMANA_MAGIC, "vamana", |payload| {
        serde_json::from_slice::<crate::index::vamana::VamanaBackend>(payload).map_err(|error| {
            GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("vamana index JSON decode failed: {error}"),
            }
        })
    })?;
    Ok(Some(backend))
}

fn write_segment_soa(path: &Path, storage: &SoAVectorStorage) -> Result<()> {
    let payload = encode_v3_payload(storage)?;
    write_paged_framed(path, VECTOR_MAGIC_V3, &payload)
}

fn decode_v3_payload(payload: &[u8]) -> Result<SoAVectorStorage> {
    if payload.len() < 8 + 4 + 4 + 8 + 8 {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: "v3 inner payload shorter than fixed header".to_string(),
        });
    }
    if &payload[0..8] != VECTOR_V3_INNER_MAGIC {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: "v3 inner magic mismatch".to_string(),
        });
    }
    let flags = u32::from_le_bytes(payload[8..12].try_into().expect("flags"));
    let dim = u32::from_le_bytes(payload[12..16].try_into().expect("dim")) as usize;
    let count = u64::from_le_bytes(payload[16..24].try_into().expect("count")) as usize;
    let soa_bytes = u64::from_le_bytes(payload[24..32].try_into().expect("soa bytes")) as usize;
    let expected_soa_bytes = count
        .checked_mul(dim)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: format!("v3 soa byte count overflow (count={count} dim={dim})"),
        })?;
    if soa_bytes != expected_soa_bytes {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: format!("v3 soa bytes header {soa_bytes} != count*dim*4 {expected_soa_bytes}"),
        });
    }
    let soa_start = 32_usize;
    let soa_end = soa_start + soa_bytes;
    let aux_len_start = soa_end;
    let aux_len_end = aux_len_start + 8;
    if aux_len_end > payload.len() {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: "v3 aux length header truncated".to_string(),
        });
    }
    let aux_len = u64::from_le_bytes(
        payload[aux_len_start..aux_len_end]
            .try_into()
            .expect("aux len"),
    ) as usize;
    let aux_start = aux_len_end;
    let aux_end = aux_start + aux_len;
    if aux_end > payload.len() {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: format!(
                "v3 aux blob truncated (want {aux_len} bytes, have {})",
                payload.len() - aux_start
            ),
        });
    }
    let soa_src = &payload[soa_start..soa_end];
    let mut soa = Vec::with_capacity(count * dim);
    for chunk in soa_src.chunks_exact(4) {
        let bytes: [u8; 4] = chunk.try_into().expect("f32 chunk");
        soa.push(f32::from_le_bytes(bytes));
    }
    let aux_bytes = &payload[aux_start..aux_end];
    let points: Vec<PointAux> = serde_json::from_slice(aux_bytes)?;
    if points.len() != count {
        return Err(GaussError::SegmentCorruption {
            path: "<v3>".to_string(),
            message: format!(
                "v3 aux point count {} != header count {}",
                points.len(),
                count
            ),
        });
    }
    let _ = (flags, V3_FLAG_HAS_NAMED, V3_FLAG_HAS_SPARSE);
    Ok(SoAVectorStorage { points, dim, soa })
}

fn read_segment_soa(path: &Path) -> Result<SoAVectorStorage> {
    with_paged_framed_slice(path, VECTOR_MAGIC_V3, "segment v3", |payload| {
        decode_v3_payload(payload)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::{
        collections::{HashMap, HashSet},
        fs::{self, OpenOptions},
        io::{Seek, Write},
    };
    use tempfile::TempDir;

    use crate::{model::Point, segment};
    use roaring::RoaringBitmap;

    #[test]
    fn loads_v4_segment_as_mmap_store() {
        let temp = TempDir::new().unwrap();
        let segment_dir = temp.path().join("sg-v4");
        let points = vec![Point {
            id: "a".to_string(),
            vector: vec![1.0, 0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"kind": "doc"}),
        }];
        crate::seal::build_segment(
            points.as_slice(),
            &segment_dir,
            crate::seal::SealConfig {
                vector_dim: 2,
                metric: crate::DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: crate::seal::SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        fs::create_dir(temp.path().join(".sg-v4-uncommitted.tmp-1")).unwrap();

        let loaded = super::load_segments_from_dirs(&[temp.path()], true, None).unwrap();
        assert_eq!(loaded.len(), 1);
        let searcher = crate::searcher::SegmentSearcher::from_loaded(
            loaded.into_iter().next().unwrap(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        assert!(matches!(
            &searcher.store,
            crate::searcher::SegmentStore::V4(_)
        ));
        assert_eq!(
            searcher.get_live("a").unwrap().payload,
            json!({"kind": "doc"})
        );
        assert_eq!(
            searcher
                .backend_for(None)
                .unwrap()
                .candidate_ids_with_ef(&[1.0, 0.0], 1, None),
            vec!["a".to_string()]
        );
        assert!(
            super::load_segments_from_dirs(&[temp.path()], true, Some(&HashSet::new()))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            super::load_segments_from_dirs(
                &[temp.path()],
                true,
                Some(&HashSet::from(["sg-v4".to_string()])),
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn writes_and_reads_compacted_searcher_segment() {
        let temp = TempDir::new().unwrap();
        let mut points = std::collections::HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::from([("image".to_string(), vec![0.0, 1.0])]),
                sparse_vector: Some(crate::model::SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({"kind": "doc"}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        assert!(write.manifest_path.exists());
        assert!(write.path.exists());
        assert!(write.h2qg_path.exists());
        assert!(write.named_h2qg_paths["image"].exists());
        assert!(write.sparse_path.exists());
        assert!(write.payload_path.exists());
        assert!(write.tombstone_path.exists());
        assert_eq!(write.named_h2qg_fields, 1);
        assert_eq!(write.sparse_dimensions, 1);
        assert_eq!(write.sparse_postings, 1);
        assert_eq!(write.sparse_blocks, 1);
        assert_eq!(write.payload_fields, 1);
        assert_eq!(write.payload_values, 1);
        assert_eq!(write.payload_postings, 1);
        assert_eq!(write.tombstones, 0);
        let sparse_stats = super::read_sparse_index(&write.sparse_path).unwrap();
        assert_eq!(sparse_stats.blocks, 1);

        let loaded = segment::load_searchers(temp.path()).unwrap();
        assert_eq!(loaded.points["a"].vector, vec![1.0, 0.0]);
        assert_eq!(loaded.h2qg.unwrap().indexed_points(), 1);
        assert_eq!(loaded.named_h2qg["image"].indexed_points(), 1);
        let payload_index = loaded.payload_index.unwrap();
        assert_eq!(payload_index["kind"]["string:doc"], vec!["a".to_string()]);
    }

    #[test]
    fn rejects_corrupt_sparse_segment_index() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: Some(crate::model::SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                payload: json!({}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        fs::remove_file(&write.manifest_path).unwrap();
        let mut sparse = OpenOptions::new()
            .write(true)
            .open(&write.sparse_path)
            .unwrap();
        sparse.seek(std::io::SeekFrom::Start(20)).unwrap();
        sparse.write_all(b"x").unwrap();

        let error = segment::load_searchers(temp.path()).unwrap_err();
        assert!(error.to_string().contains("sparse index crc mismatch"));
    }

    #[test]
    fn rejects_corrupt_segment_manifest() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        let mut manifest = OpenOptions::new()
            .write(true)
            .open(&write.manifest_path)
            .unwrap();
        manifest.seek(std::io::SeekFrom::Start(20)).unwrap();
        manifest.write_all(b"x").unwrap();

        let error = segment::load_searchers(temp.path()).unwrap_err();
        assert!(error.to_string().contains("manifest crc mismatch"));
    }

    #[test]
    fn rejects_manifest_file_mismatch() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        let mut segment_file = OpenOptions::new().write(true).open(&write.path).unwrap();
        segment_file.seek(std::io::SeekFrom::Start(20)).unwrap();
        segment_file.write_all(b"x").unwrap();

        let error = segment::load_searchers(temp.path()).unwrap_err();
        assert!(error.to_string().contains("manifest file crc mismatch"));
    }

    #[test]
    fn rejects_corrupt_payload_segment_index() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({"kind": "doc"}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        fs::remove_file(&write.manifest_path).unwrap();
        let mut payload = OpenOptions::new()
            .write(true)
            .open(&write.payload_path)
            .unwrap();
        payload.seek(std::io::SeekFrom::Start(20)).unwrap();
        payload.write_all(b"x").unwrap();

        let error = segment::load_searchers(temp.path()).unwrap_err();
        assert!(error.to_string().contains("payload index crc mismatch"));
    }

    #[test]
    fn tombstone_segment_index_removes_deleted_points() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        fs::remove_file(&write.manifest_path).unwrap();
        let mut deleted_ordinals = RoaringBitmap::new();
        deleted_ordinals.insert(0);
        let mut deleted_ordinals_roaring = Vec::with_capacity(deleted_ordinals.serialized_size());
        deleted_ordinals
            .serialize_into(&mut deleted_ordinals_roaring)
            .unwrap();
        let payload = serde_json::to_vec(&super::TombstonePayload {
            deleted_ids: Vec::new(),
            deleted_ordinals_roaring,
        })
        .unwrap();
        super::write_framed(
            &write.tombstone_path,
            super::TOMBSTONE_MAGIC,
            &payload,
            super::checksum(&payload),
        )
        .unwrap();

        let loaded = segment::load_searchers(temp.path()).unwrap();
        assert!(loaded.points.is_empty());
    }

    #[test]
    fn writes_tombstone_segment_index_as_roaring_ordinals() {
        let temp = TempDir::new().unwrap();
        let ids = vec!["a".to_string(), "b".to_string()];
        let path = temp.path().join(segment::TOMBSTONE_FILE);

        let stats = super::write_tombstones(&path, &ids, &["b".to_string()]).unwrap();
        let payload = super::read_framed(&path, super::TOMBSTONE_MAGIC, "tombstone index").unwrap();
        let payload = serde_json::from_slice::<super::TombstonePayload>(&payload).unwrap();
        let deleted_ordinals =
            RoaringBitmap::deserialize_from(std::io::Cursor::new(payload.deleted_ordinals_roaring))
                .unwrap();

        assert_eq!(stats.deleted_ids, 1);
        assert!(deleted_ordinals.contains(1));
        assert_eq!(deleted_ordinals.len(), 1);
    }

    #[test]
    fn rejects_corrupt_tombstone_segment_index() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        points.insert(
            "a".to_string(),
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: json!({}),
            },
        );

        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();
        fs::remove_file(&write.manifest_path).unwrap();
        let mut tombstone = OpenOptions::new()
            .write(true)
            .open(&write.tombstone_path)
            .unwrap();
        tombstone.seek(std::io::SeekFrom::Start(20)).unwrap();
        tombstone.write_all(b"x").unwrap();

        let error = segment::load_searchers(temp.path()).unwrap_err();
        assert!(error.to_string().contains("tombstone index crc mismatch"));
    }

    #[test]
    fn incremental_tombstone_merges_without_recompaction() {
        let temp = TempDir::new().unwrap();
        let mut points = HashMap::new();
        for id in &["a", "b", "c", "d"] {
            points.insert(
                id.to_string(),
                Point {
                    id: id.to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: json!({}),
                },
            );
        }
        let write = segment::compact_searchers(
            temp.path(),
            &mut points,
            2,
            &std::collections::HashMap::new(),
            crate::DistanceMetric::L2,
        )
        .unwrap();

        // First incremental tombstone: delete "a"
        let count = segment::apply_incremental_tombstone(
            write.tombstone_path.parent().unwrap(),
            &["a".to_string()],
        )
        .unwrap();
        assert_eq!(count, 1);

        // Second incremental tombstone: also delete "c" — merges with previous
        let count = segment::apply_incremental_tombstone(
            write.tombstone_path.parent().unwrap(),
            &["c".to_string()],
        )
        .unwrap();
        assert_eq!(count, 2);

        // Reloading should respect both tombstones
        let loaded = segment::load_searchers(temp.path()).unwrap();
        assert!(!loaded.points.contains_key("a"));
        assert!(loaded.points.contains_key("b"));
        assert!(!loaded.points.contains_key("c"));
        assert!(loaded.points.contains_key("d"));
    }

    #[test]
    fn selective_cold_materialization_only_copies_needed_files() {
        use segment::ColdMaterializeScope;
        let temp = TempDir::new().unwrap();
        let cold_dir = temp.path().join("cold_seg");
        fs::create_dir_all(&cold_dir).unwrap();

        // Write a minimal set of fake files representing a cold segment directory.
        let all_files = [
            "vec.gdx",
            "ids.gdx",
            "seal.gdx",
            "h2qg.gdx",
            "h2qg_vecs.gdx",
            "ivf.gdx",
            "rabitq.gdx",
            "vamana.gdx",
            "sparse.gdx",
            "payload.gdx",
            "tomb.gdx",
        ];
        for name in &all_files {
            fs::write(cold_dir.join(name), b"fake").unwrap();
        }

        let dest_dir = temp.path().join("dest_seg");
        fs::create_dir_all(&dest_dir).unwrap();

        // Search scope is the union of HNSW and Algorithm 2 artifacts plus
        // the v4 metadata needed to resolve ids/payloads.
        let copied = segment::materialize_cold_segment_files(
            &dest_dir,
            &cold_dir,
            ColdMaterializeScope::Search,
        )
        .unwrap();
        assert_eq!(copied, 10);
        assert!(dest_dir.join("vec.gdx").exists());
        assert!(dest_dir.join("ids.gdx").exists());
        assert!(dest_dir.join("seal.gdx").exists());
        assert!(dest_dir.join("h2qg.gdx").exists());
        assert!(dest_dir.join("h2qg_vecs.gdx").exists());
        assert!(dest_dir.join("ivf.gdx").exists());
        assert!(dest_dir.join("rabitq.gdx").exists());
        assert!(dest_dir.join("vamana.gdx").exists());
        assert!(dest_dir.join("tomb.gdx").exists());
        // Sparse stays out of pure dense search; payload is required because
        // the v4 store resolves candidate points after the ANN leg.
        assert!(!dest_dir.join("sparse.gdx").exists());
        assert!(dest_dir.join("payload.gdx").exists());

        // Running again should copy 0 (already present).
        let copied2 = segment::materialize_cold_segment_files(
            &dest_dir,
            &cold_dir,
            ColdMaterializeScope::Search,
        )
        .unwrap();
        assert_eq!(copied2, 0);
    }

    #[test]
    fn paged_framed_roundtrip() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test_paged.gdx");
        // Build a payload larger than one page (> 4096 bytes).
        let payload: Vec<u8> = (0..6000_u16).map(|i| (i % 256) as u8).collect();
        super::write_paged_framed(&path, super::VECTOR_MAGIC_V2, &payload).unwrap();
        let result =
            super::with_paged_framed_slice(&path, super::VECTOR_MAGIC_V2, "test", |data| {
                Ok(data.to_vec())
            })
            .unwrap();
        assert_eq!(result, payload, "roundtrip payload must match exactly");
    }

    #[test]
    fn paged_framed_detects_per_page_corruption() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("corrupted_paged.gdx");
        // Write a payload spanning two pages.
        let payload: Vec<u8> = (0..6000_u16).map(|i| (i % 256) as u8).collect();
        super::write_paged_framed(&path, super::VECTOR_MAGIC_V2, &payload).unwrap();

        // Corrupt a byte inside the second page's data region.
        // Layout: 20 (header) + 4 (page0 crc) + 4096 (page0 data) + 4 (page1 crc) + offset
        let corrupt_offset = 20 + 4 + 4096 + 4 + 100;
        {
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(std::io::SeekFrom::Start(corrupt_offset as u64))
                .unwrap();
            file.write_all(b"\xff").unwrap();
        }

        let err =
            super::with_paged_framed_slice(&path, super::VECTOR_MAGIC_V2, "segment", |_| Ok(()))
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("crc mismatch"),
            "expected crc mismatch error, got: {msg}"
        );
    }
}
