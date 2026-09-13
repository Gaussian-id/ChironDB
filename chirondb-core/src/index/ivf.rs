//! IVF (inverted file) coarse-partition backend — B1.1 / L0 of the paper's
//! H²QG 4-layer fusion (`.SPEC/gaussdb-vector_cleaned.md` §VI). This is the
//! *real* multi-cell k-means layer that replaces the single-zero-centroid IVF
//! stub in [`crate::h2qg`] (`build_flat`, kept only for backward-compatible
//! reads). A3's `entry_candidates`/`NPROBE` inside HNSW was the cheap
//! stand-in for exactly this — one coarse partition so a query near a cluster
//! boundary probes multiple cells instead of committing to one greedy basin.
//!
//! Search is the classic IVF-Flat cascade (paper's L0 + L3, no graph yet;
//! B1.3 fuses this cell restriction into the HNSW/Vamana beam):
//!
//! 1. **Coarse probe** — score the `nlist` centroids by squared-L2, probe the
//!    nearest cells until the accumulated candidate pool reaches `ef_search`
//!    (so `ef_search` is the single recall/QPS knob, same as every other
//!    backend here).
//! 2. **Exact rerank** — full-f32 L2 over the probed cells' members, truncate
//!    to `k`.
//!
//! Training is mini-batch k-means (Sculley 2010): bounded iterations over
//! sampled batches keep build cost sub-linear in the iterate count, and the
//! one full assignment pass at the end is `rayon`-parallel. `nlist ≈ √n`
//! mirrors the same sizing heuristic `entry_candidates` and `vamana::medoid`
//! already use.
//!
//! Memory-only, like [`super::rabitq`]: built on the background
//! `spawn_index_build` when a collection crosses `HNSW_THRESHOLD`, held in
//! `Collection::ivf`, routed through `Collection::primary_backend`. A
//! per-segment `ivf.gdx` artifact (disk persistence across restart) is the
//! same follow-up RaBitQ still has open — deliberately out of B1.1 scope.

use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{BufWriter, Seek, SeekFrom, Write},
    path::Path,
};

use chirondb_types::distance::{hamming_popcount, squared_l2};

use crate::index::{IndexBackend, IndexKind, IndexParams, encode_sign_bits, sign_word_count};
use crate::model::Point;
use crate::{DistanceMetric, GaussError, Result};

/// Mini-batch k-means iteration cap. Bounded so training cost never scales
/// with corpus size the way full Lloyd would — 12 mirrors the `dim`-sweep
/// anchor count discipline elsewhere; raise only with measured recall data.
const KMEANS_ITERS: usize = 12;

/// Points sampled per mini-batch k-means step. Sized so a batch is a
/// meaningful sample of even a 1M corpus while each step stays cheap.
const MINIBATCH_SIZE: usize = 4096;

/// Deterministic seed for k-means init + batch sampling. Fixed so a rebuild
/// of the same corpus yields the same partition (reproducible artifacts).
const KMEANS_SEED: u64 = 0x1F3D_5B7F_9EA1_C3E5;

/// Capacity-constrained IVF assignment bounds pathological cells without a
/// customer-facing tuning knob. A 2x ideal-load ceiling leaves natural cluster
/// shape intact while preventing one cell from dominating mini-Vamana build
/// time and query posting scans.
const MAX_CELL_IMBALANCE: usize = 2;

/// One balanced Lloyd step realigns the coarse centers with the
/// capacity-constrained partition. A final mean pass then makes every
/// persisted centroid describe its actual posting list exactly. Keeping this
/// fixed avoids a customer-facing build knob and one iteration is enough to
/// correct the mini-batch centers without multiplying large-corpus build time.
const BALANCED_REFINEMENT_ITERS: usize = 1;

/// Phase 3 / Algorithm 2 coarse-partition artifact.
pub const IVF_FILE: &str = "ivf.gdx";
const IVF_MAGIC: &[u8; 8] = b"GAUSIVF1";
const IVF_HEADER_BYTES: usize = 44;

/// Random-access vector source for bounded IVF training. Implementations may
/// borrow in-memory rows or hydrate one owned mmap row at a time.
pub trait VectorSource {
    fn len(&self) -> usize;
    fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bounded, bounds-checked view of the Algorithm 2 coarse partition.
/// Centroids are small enough to hydrate once; postings remain on disk and
/// are decoded only for the cells selected by a query.
#[derive(Debug)]
pub struct IvfArtifact {
    file: crate::encryption::PersistentFile,
    count: usize,
    vector_dim: usize,
    nlist: usize,
    centroid_start: usize,
    radii_start: Option<usize>,
    offsets_start: usize,
    postings_start: usize,
}

impl IvfArtifact {
    pub fn open(path: &Path) -> Result<Self> {
        let file = crate::encryption::PersistentFile::open(path)?;
        if file.len() < IVF_HEADER_BYTES {
            return Err(ivf_corrupt(path, "bad or truncated IVF header"));
        }
        let header = file.read_range(0..IVF_HEADER_BYTES)?;
        if &header[..8] != IVF_MAGIC {
            return Err(ivf_corrupt(path, "bad or truncated IVF header"));
        }
        let version = read_u32(&file, 8).ok_or_else(|| ivf_corrupt(path, "missing version"))?;
        if !matches!(version, 1 | 2) {
            return Err(ivf_corrupt(path, "unsupported IVF version"));
        }
        let count = read_usize(&file, 12, path, "point count")?;
        let vector_dim = read_usize(&file, 20, path, "vector dimension")?;
        let nlist = read_usize(&file, 28, path, "cell count")?;
        if count == 0 || vector_dim == 0 || nlist == 0 || nlist > count {
            return Err(ivf_corrupt(
                path,
                "invalid IVF count, dimension, or cell count",
            ));
        }
        let expected_crc = read_u32(&file, 36).ok_or_else(|| ivf_corrupt(path, "missing CRC"))?;
        let reserved = read_u32(&file, 40).ok_or_else(|| ivf_corrupt(path, "missing flags"))?;
        if reserved != 0 {
            return Err(ivf_corrupt(path, "unsupported IVF flags"));
        }

        let centroid_bytes = nlist
            .checked_mul(vector_dim)
            .and_then(|values| values.checked_mul(4))
            .ok_or_else(|| ivf_corrupt(path, "centroid length overflow"))?;
        let offsets_bytes = nlist
            .checked_add(1)
            .and_then(|values| values.checked_mul(8))
            .ok_or_else(|| ivf_corrupt(path, "offset length overflow"))?;
        let postings_bytes = count
            .checked_mul(4)
            .ok_or_else(|| ivf_corrupt(path, "postings length overflow"))?;
        let radii_bytes = if version >= 2 {
            nlist
                .checked_mul(4)
                .ok_or_else(|| ivf_corrupt(path, "cell radius length overflow"))?
        } else {
            0
        };
        let radii_start = (version >= 2).then_some(
            IVF_HEADER_BYTES
                .checked_add(centroid_bytes)
                .ok_or_else(|| ivf_corrupt(path, "artifact length overflow"))?,
        );
        let offsets_start = IVF_HEADER_BYTES
            .checked_add(centroid_bytes)
            .and_then(|offset| offset.checked_add(radii_bytes))
            .ok_or_else(|| ivf_corrupt(path, "artifact length overflow"))?;
        let postings_start = offsets_start
            .checked_add(offsets_bytes)
            .ok_or_else(|| ivf_corrupt(path, "artifact length overflow"))?;
        let expected_len = postings_start
            .checked_add(postings_bytes)
            .ok_or_else(|| ivf_corrupt(path, "artifact length overflow"))?;
        if file.len() != expected_len {
            return Err(ivf_corrupt(path, "IVF artifact length mismatch"));
        }
        if file.crc32(IVF_HEADER_BYTES..file.len())? != expected_crc {
            return Err(ivf_corrupt(path, "IVF payload CRC mismatch"));
        }
        if let Some(start) = radii_start {
            for cell in 0..nlist {
                let offset = start + cell * 4;
                let bytes = file.read_range(offset..offset + 4)?;
                let radius = f32::from_le_bytes(bytes.as_ref().try_into().unwrap());
                if !radius.is_finite() || radius < 0.0 {
                    return Err(ivf_corrupt(path, "invalid IVF cell radius"));
                }
            }
        }

        let mut previous = 0usize;
        let mut seen = vec![false; count];
        for cell in 0..=nlist {
            let offset = read_usize(&file, offsets_start + cell * 8, path, "posting offset")?;
            if offset < previous || offset > count || (cell == nlist && offset != count) {
                return Err(ivf_corrupt(path, "invalid IVF posting offsets"));
            }
            for posting in previous..offset {
                let ordinal = read_u32(&file, postings_start + posting * 4)
                    .ok_or_else(|| ivf_corrupt(path, "truncated posting"))?
                    as usize;
                if ordinal >= count || std::mem::replace(&mut seen[ordinal], true) {
                    return Err(ivf_corrupt(
                        path,
                        "postings are not a unique ordinal partition",
                    ));
                }
            }
            previous = offset;
        }

        Ok(Self {
            file,
            count,
            vector_dim,
            nlist,
            centroid_start: IVF_HEADER_BYTES,
            radii_start,
            offsets_start,
            postings_start,
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    pub fn cells(&self) -> usize {
        self.nlist
    }

    pub fn centroids(&self) -> Vec<Vec<f32>> {
        (0..self.nlist)
            .map(|cell| {
                (0..self.vector_dim)
                    .map(|dim| {
                        let offset = self.centroid_start + (cell * self.vector_dim + dim) * 4;
                        let bytes = self.file.read_range(offset..offset + 4).unwrap();
                        f32::from_le_bytes(bytes.as_ref().try_into().unwrap())
                    })
                    .collect()
            })
            .collect()
    }

    pub fn cell_radius(&self, cell: usize) -> Option<f32> {
        let start = self.radii_start?;
        let offset = start.checked_add(cell.checked_mul(4)?)?;
        let bytes = self.file.read_range(offset..offset + 4).ok()?;
        let radius = f32::from_le_bytes(bytes.as_ref().try_into().ok()?);
        (radius.is_finite() && radius >= 0.0).then_some(radius)
    }

    pub fn postings(&self, cell: usize) -> Option<Vec<u32>> {
        let range = self.posting_range(cell)?;
        Some(
            range
                .map(|posting| self.posting_ordinal(posting).unwrap())
                .collect(),
        )
    }

    /// Global posting-index range for one cell. Keeping this separate from
    /// ordinals lets companion artifacts use the same cell-major row order.
    pub fn posting_range(&self, cell: usize) -> Option<std::ops::Range<usize>> {
        if cell >= self.nlist {
            return None;
        }
        let start = usize::try_from(read_u64(&self.file, self.offsets_start + cell * 8)?).ok()?;
        let end =
            usize::try_from(read_u64(&self.file, self.offsets_start + (cell + 1) * 8)?).ok()?;
        Some(start..end)
    }

    pub fn posting_ordinal(&self, posting: usize) -> Option<u32> {
        if posting >= self.count {
            return None;
        }
        read_u32(&self.file, self.postings_start + posting * 4)
    }
}

/// Train and persist the L0 IVF partition without retaining source vectors.
pub fn write_ivf_artifact<S: VectorSource + ?Sized>(
    source: &S,
    vector_dim: usize,
    nlist: usize,
    path: &Path,
) -> Result<()> {
    let mut centroids = train_centroids(source, vector_dim, nlist)?;
    let mut postings = assign_postings_streaming(source, vector_dim, &centroids)?;
    for _ in 0..BALANCED_REFINEMENT_ITERS {
        centroids = recompute_posting_centroids(source, vector_dim, &centroids, &postings)?;
        postings = assign_postings_streaming(source, vector_dim, &centroids)?;
    }
    centroids = recompute_posting_centroids(source, vector_dim, &centroids, &postings)?;
    let (centroids, postings): (Vec<_>, Vec<_>) = centroids
        .into_iter()
        .zip(postings)
        .filter(|(_, cell)| !cell.is_empty())
        .unzip();
    let mut radii = Vec::with_capacity(centroids.len());
    for (centroid, cell) in centroids.iter().zip(&postings) {
        let mut radius = 0.0f32;
        for &ordinal in cell {
            let vector = source.vector(ordinal as usize)?;
            validate_training_dim(&vector, vector_dim)?;
            radius = radius.max(squared_l2(&vector, centroid).sqrt());
        }
        radii.push(radius * (1.0 + 8.0 * f32::EPSILON) + f32::EPSILON);
    }
    let mut file = File::create(path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, &mut file);
    writer.write_all(IVF_MAGIC)?;
    writer.write_all(&2u32.to_le_bytes())?;
    writer.write_all(&(source.len() as u64).to_le_bytes())?;
    writer.write_all(&(vector_dim as u64).to_le_bytes())?;
    writer.write_all(&(centroids.len() as u64).to_le_bytes())?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&0u32.to_le_bytes())?;

    let mut crc = crc32fast::Hasher::new();
    for centroid in &centroids {
        for value in centroid {
            write_crc(&mut writer, &mut crc, &value.to_le_bytes())?;
        }
    }
    for radius in &radii {
        write_crc(&mut writer, &mut crc, &radius.to_le_bytes())?;
    }
    let mut offset = 0u64;
    write_crc(&mut writer, &mut crc, &offset.to_le_bytes())?;
    for cell in &postings {
        offset = offset.checked_add(cell.len() as u64).ok_or_else(|| {
            GaussError::InvalidRequest("IVF posting offsets overflow".to_string())
        })?;
        write_crc(&mut writer, &mut crc, &offset.to_le_bytes())?;
    }
    for cell in &postings {
        for ordinal in cell {
            write_crc(&mut writer, &mut crc, &ordinal.to_le_bytes())?;
        }
    }
    writer.flush()?;
    drop(writer);
    file.seek(SeekFrom::Start(36))?;
    file.write_all(&crc.finalize().to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn write_crc(writer: &mut impl Write, crc: &mut crc32fast::Hasher, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes)?;
    crc.update(bytes);
    Ok(())
}

fn read_u32(file: &crate::encryption::PersistentFile, offset: usize) -> Option<u32> {
    let bytes = file.read_range(offset..offset.checked_add(4)?).ok()?;
    Some(u32::from_le_bytes(bytes.as_ref().try_into().ok()?))
}

fn read_u64(file: &crate::encryption::PersistentFile, offset: usize) -> Option<u64> {
    let bytes = file.read_range(offset..offset.checked_add(8)?).ok()?;
    Some(u64::from_le_bytes(bytes.as_ref().try_into().ok()?))
}

fn read_usize(
    file: &crate::encryption::PersistentFile,
    offset: usize,
    path: &Path,
    field: &str,
) -> Result<usize> {
    let value =
        read_u64(file, offset).ok_or_else(|| ivf_corrupt(path, &format!("missing {field}")))?;
    usize::try_from(value).map_err(|_| ivf_corrupt(path, &format!("{field} exceeds usize")))
}

fn ivf_corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

impl VectorSource for [Vec<f32>] {
    fn len(&self) -> usize {
        <[Vec<f32>]>::len(self)
    }

    fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>> {
        self.get(ordinal)
            .map(|vector| Cow::Borrowed(vector.as_slice()))
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!(
                    "IVF training ordinal {ordinal} is out of bounds"
                ))
            })
    }
}

/// One centroid + the indices of its assigned points (into `vectors`/`ids`).
#[derive(Clone)]
struct Cell {
    centroid: Vec<f32>,
    postings: Vec<usize>,
}

/// B1.3 — L1 binary-filter is skipped unless a probed cell union is at least
/// this multiple of the exact-rerank pool. Below it, ranking the whole union
/// exactly is already cheap and the Hamming pre-pass would only add lossy
/// work; above it, the popcount filter cuts the exact-distance count on a big
/// probed cell. `4` keeps the filter on the path only when it pays.
const L1_FILTER_TRIGGER: usize = 4;

/// B1.3 — L1 keeps this multiple of the exact pool after the Hamming filter,
/// so the lossy binary stage over-samples before the exact rerank narrows to
/// `k` (same oversample discipline as `rabitq::DEFAULT_OVERSAMPLE`).
const L1_OVERSAMPLE: usize = 4;

/// In-memory IVF backend. See module docs.
#[derive(Clone)]
pub struct IvfBackend {
    vector_dim: usize,
    metric: DistanceMetric,
    cells: Vec<Cell>,
    /// Full-precision vectors, cosine-normalized at build time when the
    /// collection metric is Cosine (so the always-squared-L2 ranking below
    /// matches the collection's real notion of "near", exactly as
    /// `h2qg::build_hnsw_index_inner` does).
    vectors: Vec<Vec<f32>>,
    /// B1.3 / L1 — packed sign-bit codes, one per vector, parallel to
    /// `vectors`. The RaBitQ binary filter layer: a Hamming pre-pass over a
    /// large probed-cell union before the exact-L2 rerank. Reuses the shared
    /// [`encode_sign_bits`]; B1.2 sharpens the code via the proper rotation.
    codes: Vec<Vec<u64>>,
    word_count: usize,
    ids: Vec<String>,
    id_to_idx: HashMap<String, usize>,
}

impl std::fmt::Debug for IvfBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IvfBackend")
            .field("vector_dim", &self.vector_dim)
            .field("metric", &self.metric)
            .field("nlist", &self.cells.len())
            .field("points", &self.ids.len())
            .finish()
    }
}

impl IvfBackend {
    pub fn build(points: &[Point], vector_dim: usize) -> Self {
        Self::build_with_metric(points, vector_dim, DistanceMetric::L2)
    }

    pub fn build_with_metric(points: &[Point], vector_dim: usize, metric: DistanceMetric) -> Self {
        let word_count = sign_word_count(vector_dim);
        let mut ids = Vec::with_capacity(points.len());
        let mut id_to_idx = HashMap::with_capacity(points.len());
        let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(points.len());
        let mut codes: Vec<Vec<u64>> = Vec::with_capacity(points.len());
        for point in points {
            if point.vector.len() != vector_dim || id_to_idx.contains_key(&point.id) {
                continue;
            }
            let vec = prepare_vector(&point.vector, metric);
            codes.push(encode_sign_bits(&vec, word_count));
            id_to_idx.insert(point.id.clone(), ids.len());
            ids.push(point.id.clone());
            vectors.push(vec);
        }

        let cells = if vectors.is_empty() {
            Vec::new()
        } else {
            let nlist = nlist_for(vectors.len());
            train_cells(&vectors, vector_dim, nlist)
        };

        Self {
            vector_dim,
            metric,
            cells,
            vectors,
            codes,
            word_count,
            ids,
            id_to_idx,
        }
    }

    pub fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    /// Default cells to probe when no `ef_search` is supplied: `√nlist`,
    /// the standard IVF operating point (probing a sqrt-fraction of cells
    /// recovers the bulk of recall at a fraction of the exhaustive cost).
    fn default_nprobe(&self) -> usize {
        ((self.cells.len() as f64).sqrt().round() as usize).clamp(1, self.cells.len().max(1))
    }

    fn append_point(&mut self, point: &Point) {
        if self.id_to_idx.contains_key(&point.id) {
            return;
        }
        let vec = prepare_vector(&point.vector, self.metric);
        let idx = self.ids.len();
        self.codes.push(encode_sign_bits(&vec, self.word_count));
        // Assign to the nearest existing centroid (no re-clustering — this is
        // the build-window backfill path, mirroring rabitq's append). If no
        // cells exist yet (empty build), open a singleton cell around it.
        if self.cells.is_empty() {
            self.cells.push(Cell {
                centroid: vec.clone(),
                postings: vec![idx],
            });
        } else {
            let nearest = self
                .cells
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| {
                    squared_l2(&vec, &a.centroid).total_cmp(&squared_l2(&vec, &b.centroid))
                })
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.cells[nearest].postings.push(idx);
        }
        self.id_to_idx.insert(point.id.clone(), idx);
        self.ids.push(point.id.clone());
        self.vectors.push(vec);
    }

    /// Shared coarse-probe: return the point indices in the `probe` nearest
    /// cells to `query`, enough to fill a candidate pool of at least `pool`.
    /// Exposed to the crate so B1.3 can feed this restricted set into the
    /// graph beam instead of re-deriving it.
    pub(crate) fn probe_candidate_indices(&self, query: &[f32], pool: usize) -> Vec<usize> {
        if self.cells.is_empty() {
            return Vec::new();
        }
        let q = prepare_vector(query, self.metric);
        let mut ranked: Vec<(f32, usize)> = self
            .cells
            .iter()
            .enumerate()
            .map(|(i, cell)| (squared_l2(&q, &cell.centroid), i))
            .collect();
        ranked.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let min_cells = self.default_nprobe();
        let mut out = Vec::new();
        for (rank, (_, cell_idx)) in ranked.into_iter().enumerate() {
            if rank >= min_cells && out.len() >= pool {
                break;
            }
            out.extend_from_slice(&self.cells[cell_idx].postings);
        }
        out
    }
}

impl IndexBackend for IvfBackend {
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        if self.ids.is_empty() || k == 0 || query.len() != self.vector_dim {
            return Vec::new();
        }
        let pool = ef_search
            .unwrap_or_else(|| self.default_ef_search(k))
            .max(k);
        let q = prepare_vector(query, self.metric);

        // L0 — coarse probe: point indices in the nearest cells.
        let mut candidates = self.probe_candidate_indices(query, pool);

        // L1 — RaBitQ binary filter: when the probed union is much larger than
        // the exact pool, a Hamming popcount pre-pass (32x cheaper than an f32
        // distance) narrows it to `pool * L1_OVERSAMPLE` before the exact
        // rerank pays for full distances. Skipped on small unions where exact
        // ranking is already cheap.
        let exact_pool = pool.saturating_mul(L1_OVERSAMPLE).max(k);
        if candidates.len() > exact_pool.saturating_mul(L1_FILTER_TRIGGER) {
            let query_code = encode_sign_bits(&q, self.word_count);
            candidates.sort_by_key(|&idx| hamming_popcount(&query_code, &self.codes[idx]));
            candidates.truncate(exact_pool);
        }

        // L3 — exact-L2 rerank over the surviving candidates.
        candidates.sort_by(|&a, &b| {
            squared_l2(&q, &self.vectors[a]).total_cmp(&squared_l2(&q, &self.vectors[b]))
        });
        candidates.truncate(k);
        candidates
            .into_iter()
            .map(|idx| self.ids[idx].clone())
            .collect()
    }

    fn default_ef_search(&self, k: usize) -> usize {
        // Wider than HNSW's default: IVF recall is set by how many cell
        // members reach the exact rerank, so err toward a fuller pool.
        k.saturating_mul(4).max(128)
    }

    fn ef_search_for_recall_target(&self, k: usize, recall_target: f32) -> usize {
        if !(0.5..=1.0).contains(&recall_target) || recall_target.is_nan() {
            return self.default_ef_search(k);
        }
        let factor = if recall_target >= 0.99 {
            16
        } else if recall_target >= 0.95 {
            8
        } else if recall_target >= 0.90 {
            4
        } else if recall_target >= 0.80 {
            2
        } else {
            1
        };
        k.saturating_mul(factor).max(64)
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
        IndexKind::Ivf
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
        self.cells.len()
    }

    fn is_paged(&self) -> bool {
        false
    }
}

/// Build an [`IvfBackend`] from raw points. Sibling to [`super::build`].
pub fn build(points: &[Point], params: &IndexParams) -> Box<dyn IndexBackend> {
    Box::new(IvfBackend::build_with_metric(
        points,
        params.vector_dim,
        params.metric,
    ))
}

/// `nlist ≈ √n`, clamped to `[1, n]`. Same heuristic `entry_candidates` and
/// `vamana::medoid` use for the same reason (one representative per implicit
/// cluster as the corpus grows).
fn nlist_for(n: usize) -> usize {
    ((n as f64).sqrt().round() as usize).clamp(1, n.max(1))
}

/// Cosine collections normalize before ranking so the always-squared-L2
/// distance below matches the real metric (`||a-b||² = 2 - 2cos(a,b)` for
/// unit vectors). L2 passes through. Dot/MIPS is a known, documented gap,
/// same as the HNSW path.
fn prepare_vector(v: &[f32], metric: DistanceMetric) -> Vec<f32> {
    let mut out = v.to_vec();
    if metric == DistanceMetric::Cosine {
        crate::search::normalize(&mut out);
    }
    out
}

/// Mini-batch k-means (Sculley 2010) → `nlist` cells with full point
/// assignment. Deterministic under [`KMEANS_SEED`].
fn train_cells(vectors: &[Vec<f32>], vector_dim: usize, nlist: usize) -> Vec<Cell> {
    let centroids = train_centroids(vectors, vector_dim, nlist)
        .expect("in-memory IVF vectors were validated before training");

    // Final full assignment (parallel over points for the in-memory backend).
    use rayon::prelude::*;
    let assignments: Vec<usize> = vectors
        .par_iter()
        .map(|x| nearest_centroid(x, &centroids))
        .collect();

    let mut cells: Vec<Cell> = centroids
        .into_iter()
        .map(|centroid| Cell {
            centroid,
            postings: Vec::new(),
        })
        .collect();
    for (idx, &c) in assignments.iter().enumerate() {
        cells[c].postings.push(idx);
    }
    // Drop empty cells so `nprobe` never wastes a probe on a dead centroid.
    cells.retain(|c| !c.postings.is_empty());
    cells
}

/// Train deterministic mini-batch centroids without retaining source vectors.
/// Peak working memory is the centroid table plus one hydrated vector.
pub(crate) fn train_centroids<S: VectorSource + ?Sized>(
    source: &S,
    vector_dim: usize,
    nlist: usize,
) -> Result<Vec<Vec<f32>>> {
    if source.is_empty() || vector_dim == 0 {
        return Err(GaussError::InvalidRequest(
            "cannot train IVF centroids from an empty or zero-dimensional source".to_string(),
        ));
    }
    let n = source.len();
    let nlist = nlist.clamp(1, n);
    // Init: pick `nlist` distinct points as seed centroids via a seeded
    // stride walk (cheap, deterministic, spreads picks across the corpus).
    let mut centroids: Vec<Vec<f32>> = Vec::with_capacity(nlist);
    let mut seen = std::collections::HashSet::with_capacity(nlist);
    let mut state = KMEANS_SEED;
    while centroids.len() < nlist {
        state = crate::h2qg::splitmix64(state);
        let pick = (state as usize) % n;
        if seen.insert(pick) {
            let vector = source.vector(pick)?;
            validate_training_dim(&vector, vector_dim)?;
            centroids.push(vector.into_owned());
        }
        // Fallback if the corpus has fewer distinct picks than nlist rounds
        // can find quickly (tiny n): fill sequentially.
        if seen.len() == n {
            for i in 0..n {
                if centroids.len() >= nlist {
                    break;
                }
                if seen.insert(i) {
                    let vector = source.vector(i)?;
                    validate_training_dim(&vector, vector_dim)?;
                    centroids.push(vector.into_owned());
                }
            }
            break;
        }
    }

    // Mini-batch refinement: per-centroid running mean with a 1/count step.
    let mut counts = vec![0u64; centroids.len()];
    for iter in 0..KMEANS_ITERS {
        state = crate::h2qg::splitmix64(state ^ (iter as u64).wrapping_mul(0x9E37_79B9));
        let batch = MINIBATCH_SIZE.min(n);
        for _ in 0..batch {
            state = crate::h2qg::splitmix64(state);
            let xi = (state as usize) % n;
            let x = source.vector(xi)?;
            validate_training_dim(&x, vector_dim)?;
            let c = nearest_centroid(&x, &centroids);
            counts[c] += 1;
            let eta = 1.0 / counts[c] as f32;
            let centroid = &mut centroids[c];
            for d in 0..vector_dim {
                centroid[d] += eta * (x[d] - centroid[d]);
            }
        }
    }

    Ok(centroids)
}

/// Assign every source row to its nearest centroid in one streaming pass.
/// Postings use persisted `u32` ordinals, matching the paper's 4N-byte L0
/// layout and rejecting segments too large for that on-disk contract.
pub(crate) fn assign_postings_streaming<S: VectorSource + ?Sized>(
    source: &S,
    vector_dim: usize,
    centroids: &[Vec<f32>],
) -> Result<Vec<Vec<u32>>> {
    if source.is_empty() || centroids.is_empty() {
        return Err(GaussError::InvalidRequest(
            "cannot assign IVF postings without source rows and centroids".to_string(),
        ));
    }
    for centroid in centroids {
        validate_training_dim(centroid, vector_dim)?;
    }
    let n = source.len();
    let ideal_load = n.div_ceil(centroids.len());
    let max_cell_load = ideal_load.saturating_mul(MAX_CELL_IMBALANCE).min(n);
    let mut postings = vec![Vec::new(); centroids.len()];
    let mut loads = vec![0usize; centroids.len()];

    // Traverse ordinals through a deterministic full-cycle stride so a source
    // ordered by label/time cannot fill nearby cells before the rest of the
    // corpus is seen. This retains O(nlist + postings) working memory.
    let mut ordinal = (KMEANS_SEED as usize) % n;
    let stride = coprime_stride(n, (KMEANS_SEED >> 32) as usize);
    for _ in 0..n {
        let persisted_ordinal = u32::try_from(ordinal).map_err(|_| {
            GaussError::InvalidRequest(
                "IVF segment exceeds the u32 persisted ordinal limit".to_string(),
            )
        })?;
        let vector = source.vector(ordinal)?;
        validate_training_dim(&vector, vector_dim)?;
        let cell = nearest_centroid_with_capacity(&vector, centroids, &loads, max_cell_load)
            .expect("2x ideal IVF capacity always covers the source");
        postings[cell].push(persisted_ordinal);
        loads[cell] += 1;
        ordinal = (ordinal + stride) % n;
    }
    Ok(postings)
}

/// Recompute exact posting means in one streaming pass. Empty cells retain
/// their previous center until the subsequent assignment either fills them or
/// the artifact writer removes them.
fn recompute_posting_centroids<S: VectorSource + ?Sized>(
    source: &S,
    vector_dim: usize,
    previous: &[Vec<f32>],
    postings: &[Vec<u32>],
) -> Result<Vec<Vec<f32>>> {
    if previous.len() != postings.len() {
        return Err(GaussError::InvalidRequest(
            "IVF centroid and posting counts disagree".to_string(),
        ));
    }
    let mut centroids = vec![vec![0.0f32; vector_dim]; previous.len()];
    for (cell, ordinals) in postings.iter().enumerate() {
        if ordinals.is_empty() {
            validate_training_dim(&previous[cell], vector_dim)?;
            centroids[cell].copy_from_slice(&previous[cell]);
            continue;
        }
        for &ordinal in ordinals {
            let vector = source.vector(ordinal as usize)?;
            validate_training_dim(&vector, vector_dim)?;
            for (sum, value) in centroids[cell].iter_mut().zip(vector.iter()) {
                *sum += value;
            }
        }
        let reciprocal = 1.0 / ordinals.len() as f32;
        for value in &mut centroids[cell] {
            *value *= reciprocal;
        }
    }
    Ok(centroids)
}

fn nearest_centroid_with_capacity(
    vector: &[f32],
    centroids: &[Vec<f32>],
    loads: &[usize],
    max_cell_load: usize,
) -> Option<usize> {
    let mut best = None;
    let mut best_distance = f32::INFINITY;
    for (cell, centroid) in centroids.iter().enumerate() {
        if loads[cell] >= max_cell_load {
            continue;
        }
        let distance = squared_l2(vector, centroid);
        if distance < best_distance {
            best = Some(cell);
            best_distance = distance;
        }
    }
    best
}

fn coprime_stride(n: usize, seed: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut stride = seed % n;
    if stride == 0 {
        stride = 1;
    }
    while gcd(stride, n) != 1 {
        stride += 1;
        if stride == n {
            stride = 1;
        }
    }
    stride
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

fn validate_training_dim(vector: &[f32], expected: usize) -> Result<()> {
    if vector.len() != expected {
        return Err(GaussError::DimensionMismatch {
            expected,
            actual: vector.len(),
        });
    }
    Ok(())
}

pub(crate) fn nearest_centroid(x: &[f32], centroids: &[Vec<f32>]) -> usize {
    let mut best = 0usize;
    let mut best_d = f32::INFINITY;
    for (i, c) in centroids.iter().enumerate() {
        let d = squared_l2(x, c);
        if d < best_d {
            best_d = d;
            best = i;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HydratingSource(Vec<Vec<f32>>);

    impl VectorSource for HydratingSource {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>> {
            self.0
                .get(ordinal)
                .cloned()
                .map(Cow::Owned)
                .ok_or_else(|| GaussError::PointNotFound(ordinal.to_string()))
        }
    }

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

    /// Planted-cluster corpus: `clusters` well-separated Gaussians. A query at
    /// a cluster center must land in that cluster's members.
    fn planted(clusters: usize, per: usize, dim: usize) -> (Vec<Point>, Vec<Vec<f32>>) {
        let mut points = Vec::new();
        let mut centers = Vec::new();
        for c in 0..clusters {
            let mut center = vec![0.0f32; dim];
            // Separate centers far apart along distinct axes.
            center[c % dim] = 100.0 * (c + 1) as f32;
            centers.push(center.clone());
            for j in 0..per {
                let jitter = lcg_vector((c * 1000 + j) as u64, dim);
                let v: Vec<f32> = center.iter().zip(&jitter).map(|(a, b)| a + b).collect();
                points.push(p(&format!("c{c}_p{j}"), v));
            }
        }
        (points, centers)
    }

    #[test]
    fn centroid_training_is_deterministic_across_borrowed_and_hydrated_sources() {
        let vectors = (0..128).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        let borrowed = train_centroids(vectors.as_slice(), 12, 11).unwrap();
        let hydrated = train_centroids(&HydratingSource(vectors), 12, 11).unwrap();
        assert_eq!(borrowed, hydrated);
    }

    #[test]
    fn streaming_postings_partition_every_ordinal_once() {
        let vectors = (0..97).map(|i| lcg_vector(i, 8)).collect::<Vec<_>>();
        let centroids = train_centroids(vectors.as_slice(), 8, 9).unwrap();
        let postings = assign_postings_streaming(vectors.as_slice(), 8, &centroids).unwrap();
        let mut ordinals = postings.into_iter().flatten().collect::<Vec<_>>();
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..97u32).collect::<Vec<_>>());
    }

    #[test]
    fn capacity_constrained_assignment_bounds_degenerate_cells() {
        let vectors = vec![vec![0.0_f32; 4]; 101];
        let centroids = vec![vec![0.0_f32; 4]; 10];
        let postings = assign_postings_streaming(vectors.as_slice(), 4, &centroids).unwrap();
        let max_cell_load = 101usize.div_ceil(10) * MAX_CELL_IMBALANCE;
        assert!(postings.iter().all(|cell| cell.len() <= max_cell_load));
        let mut ordinals = postings.into_iter().flatten().collect::<Vec<_>>();
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..101u32).collect::<Vec<_>>());
    }

    #[test]
    fn posting_centroids_are_exact_assigned_means() {
        let vectors = vec![
            vec![0.0, 0.0],
            vec![2.0, 2.0],
            vec![10.0, 10.0],
            vec![14.0, 14.0],
        ];
        let previous = vec![vec![-5.0, -5.0], vec![50.0, 50.0], vec![7.0, 7.0]];
        let postings = vec![vec![0, 1], vec![2, 3], Vec::new()];
        let centroids =
            recompute_posting_centroids(vectors.as_slice(), 2, &previous, &postings).unwrap();
        assert_eq!(
            centroids,
            vec![vec![1.0, 1.0], vec![12.0, 12.0], vec![7.0, 7.0]]
        );
    }

    #[test]
    fn training_rejects_dimension_mismatch() {
        let vectors = vec![vec![1.0, 2.0], vec![3.0]];
        let error = train_centroids(vectors.as_slice(), 2, 2).unwrap_err();
        assert!(matches!(error, GaussError::DimensionMismatch { .. }));
    }

    #[test]
    fn ivf_artifact_round_trip_and_crc_validation() {
        use std::io::{Read, Seek};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(IVF_FILE);
        let vectors = (0..128).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 12, 11, &path).unwrap();

        let artifact = IvfArtifact::open(&path).unwrap();
        assert_eq!(artifact.len(), 128);
        assert_eq!(artifact.vector_dim(), 12);
        assert_eq!(artifact.cells(), 11);
        let centroids = artifact.centroids();
        assert_eq!(centroids.len(), 11);
        for (cell, centroid) in centroids.iter().enumerate() {
            let radius = artifact.cell_radius(cell).unwrap();
            assert!(artifact.postings(cell).unwrap().into_iter().all(|ordinal| {
                squared_l2(&vectors[ordinal as usize], centroid).sqrt() <= radius
            }));
        }
        let mut ordinals = (0..artifact.cells())
            .flat_map(|cell| artifact.postings(cell).unwrap())
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..128u32).collect::<Vec<_>>());
        assert!(artifact.postings(artifact.cells()).is_none());
        drop(artifact);

        let mut legacy = std::fs::read(&path).unwrap();
        let radii_start = IVF_HEADER_BYTES + 11 * 12 * 4;
        legacy.drain(radii_start..radii_start + 11 * 4);
        legacy[8..12].copy_from_slice(&1u32.to_le_bytes());
        let crc = crc32fast::hash(&legacy[IVF_HEADER_BYTES..]);
        legacy[36..40].copy_from_slice(&crc.to_le_bytes());
        let legacy_path = temp.path().join("ivf-v1.gdx");
        std::fs::write(&legacy_path, legacy).unwrap();
        let legacy_artifact = IvfArtifact::open(&legacy_path).unwrap();
        assert_eq!(legacy_artifact.len(), 128);
        assert!(legacy_artifact.cell_radius(0).is_none());

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[byte[0] ^ 0xff]).unwrap();
        file.sync_all().unwrap();
        let error = IvfArtifact::open(&path).unwrap_err();
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
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
        assert_eq!(idx.kind(), IndexKind::Ivf);
        assert_eq!(idx.indexed_points(), 2);
        assert!(idx.contains("a"));
        assert!(!idx.contains("missing"));
        assert!(idx.cells() >= 1);
    }

    #[test]
    fn nlist_is_sqrt_n() {
        assert_eq!(nlist_for(100), 10);
        assert_eq!(nlist_for(0), 1);
        assert_eq!(nlist_for(1), 1);
    }

    #[test]
    fn multi_cell_partition_on_planted_clusters() {
        // 8 well-separated clusters, 50 points each → a real multi-cell
        // partition, not the single-cell stub. Query at each cluster center
        // must return that cluster's own members.
        let (points, centers) = planted(8, 50, 16);
        let idx = IvfBackend::build_with_metric(&points, 16, DistanceMetric::L2);
        assert!(idx.cells() > 1, "expected multi-cell, got {}", idx.cells());
        for (c, center) in centers.iter().enumerate() {
            let hits = idx.candidate_ids_with_ef(center, 10, None);
            let own = hits
                .iter()
                .filter(|id| id.starts_with(&format!("c{c}_")))
                .count();
            assert!(
                own >= 9,
                "cluster {c}: only {own}/10 hits from own cluster ({hits:?})",
            );
        }
    }

    #[test]
    fn recall_at_10_above_0_95_on_random_500() {
        // Same synthetic recall_golden as the rabitq backend: query each point
        // against itself, self must land in top-10.
        let dim = 64;
        let n = 500;
        let points: Vec<Point> = (0..n)
            .map(|i| p(&format!("p{i}"), lcg_vector(i as u64, dim)))
            .collect();
        let idx = IvfBackend::build_with_metric(&points, dim, DistanceMetric::L2);
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
    fn l1_binary_filter_holds_recall_at_scale() {
        // n large enough that a probed-cell union exceeds L1_FILTER_TRIGGER *
        // exact_pool, so the Hamming pre-pass is actually on the path. Recall
        // must stay off the floor — the binary filter narrows, it must not
        // drop the true neighbors.
        let dim = 16;
        let n = 30_000;
        let points: Vec<Point> = (0..n)
            .map(|i| p(&format!("p{i}"), lcg_vector(i as u64, dim)))
            .collect();
        let idx = IvfBackend::build_with_metric(&points, dim, DistanceMetric::L2);
        let queries = 200;
        let mut hits = 0usize;
        for i in 0..queries {
            let q = lcg_vector(i as u64, dim);
            let result = idx.candidate_ids_with_ef(&q, 10, None);
            if result.iter().any(|id| id == &format!("p{i}")) {
                hits += 1;
            }
        }
        let recall = hits as f32 / queries as f32;
        assert!(
            recall >= 0.90,
            "recall@10 with L1 filter active = {recall:.4} below 0.90 (hits={hits}/{queries})"
        );
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
        let idx = IvfBackend::build_with_metric(&points, 16, DistanceMetric::L2);
        for i in 0..16 {
            let mut q = vec![0.0; 16];
            q[i] = 1.0;
            let hits = idx.candidate_ids_with_ef(&q, 1, None);
            assert_eq!(hits, vec![format!("p{i}")]);
        }
    }

    /// B1.5 — cost-model split (paper Eq. 7): the binary-filter cost `cb(d)`
    /// (Hamming popcount over packed sign codes) must be far below the exact
    /// full-distance cost `cδ(d)` (squared-L2 over f32), or the L1 cascade
    /// stage does not pay. Measured locally on this codebase's kernels rather
    /// than assumed from the paper's hardware. Ignored by default (timing is
    /// environment-dependent); run with:
    ///   cargo test -p chirondb-core cost_model_binary_filter -- --ignored --nocapture
    #[test]
    #[ignore]
    fn cost_model_binary_filter_far_cheaper_than_exact() {
        use chirondb_types::distance::hamming_popcount;
        use std::time::Instant;

        for dim in [128usize, 768, 1536] {
            let n = 50_000;
            let vecs: Vec<Vec<f32>> = (0..n).map(|i| lcg_vector(i as u64, dim)).collect();
            let wc = sign_word_count(dim);
            let codes: Vec<Vec<u64>> = vecs.iter().map(|v| encode_sign_bits(v, wc)).collect();
            let q = lcg_vector(7, dim);
            let qc = encode_sign_bits(&q, wc);

            let t0 = Instant::now();
            let mut acc_l2 = 0.0f32;
            for v in &vecs {
                acc_l2 += squared_l2(&q, v);
            }
            let c_delta = t0.elapsed().as_nanos() as f64 / n as f64;

            let t1 = Instant::now();
            let mut acc_h = 0u64;
            for c in &codes {
                acc_h += hamming_popcount(&qc, c) as u64;
            }
            let c_b = t1.elapsed().as_nanos() as f64 / n as f64;

            std::hint::black_box((acc_l2, acc_h));
            println!(
                "dim={dim:>4}  c_delta={c_delta:>7.2}ns  c_b={c_b:>6.2}ns  ratio(c_delta/c_b)={:>5.1}x",
                c_delta / c_b
            );
            assert!(
                c_b < c_delta,
                "dim={dim}: binary filter cost {c_b:.2}ns not below exact {c_delta:.2}ns"
            );
        }
    }

    #[test]
    fn ef_search_for_recall_target_is_monotonic() {
        let backend =
            IvfBackend::build_with_metric(&[p("x", vec![1.0; 16])], 16, DistanceMetric::L2);
        let high = backend.ef_search_for_recall_target(10, 0.99);
        let mid = backend.ef_search_for_recall_target(10, 0.95);
        let low = backend.ef_search_for_recall_target(10, 0.80);
        assert!(high >= mid && mid >= low, "{high} {mid} {low}");
    }

    #[test]
    fn insert_point_appends_and_dim_mismatch_rejected() {
        let mut backend =
            IvfBackend::build_with_metric(&[p("a", vec![1.0; 16])], 16, DistanceMetric::L2);
        backend.insert_point(&p("b", vec![-1.0; 16]), 16).unwrap();
        assert_eq!(backend.indexed_points(), 2);
        assert!(backend.contains("b"));
        let err = backend.insert_point(&p("c", vec![1.0; 8]), 8).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GaussError::DimensionMismatch { .. }
        ));
    }
}
