//! Vamana / DiskANN single-layer graph backend — P4 of the 6-pillar UVP
//! roadmap (`AGENTS.md` § Mission & Posture).
//!
//! Implements the simplified single-pass Vamana index from
//! "DiskANN: Fast Accurate Billion-point Nearest Neighbor Search on a
//! Single Node" (Subramanya et al., 2019). The graph is **flat** — every
//! point sits on a single layer with up to `R` out-edges — in contrast to
//! HNSW's multi-layer hierarchy. That makes Vamana/DiskANN cheaper to
//! build and naturally mmap-friendly, at the cost of slightly slower
//! build-time pruning.
//!
//! Build pipeline (called once per `Collection` once it crosses
//! `HNSW_THRESHOLD`, just like HNSW):
//!
//! 1. Pick a medoid (point with smallest sum-of-distances to all others)
//!    as the start node `s`. Fall back to point 0 when `n == 1`.
//! 2. For each point `p` in a random permutation of the dataset:
//!    1. Greedy beam search from `s` to get the `L` closest visited points
//!       — this is the **candidate set** for `p`.
//!    2. Add reverse edges: union `p`'s neighbours into every candidate's
//!       neighbour list (capped at `R`).
//!    3. **Robust prune** `p`'s neighbours: greedily pick the closest
//!       un-pruned candidate, then drop any other candidate `c` whose
//!       distance to `p` is `>= alpha * dist(p, picked)` AND
//!       `dist(c, picked) < dist(p, c)` — i.e. `picked` "occludes" `c`.
//!       The `alpha > 1` slack is what makes this "angular pruning":
//!       candidates that are a bit further than the best are still kept
//!       when they sit in a different direction, preserving graph
//!       navigability at the cost of one extra edge per node.
//!    4. Re-prune any candidate that now exceeds `R` out-edges.
//!
//! Search is a textbook beam search with the same `L` width used at
//! build time; the `ef_search` parameter from the trait maps directly to
//! that beam width (Vamana has no separate top-`k` and beam-width knobs
//! — they're the same thing).
//!
//! Target operating point: recall@10 ≥ 0.95 on a synthetic 500×64
//! random-uniform dataset (the row-141 golden test below). The
//! `ann-benchmarks` Pareto sweep on `Performance1536D50K` ships in
//! `chirondb-server/src/bench/ann_benchmarks.rs` via the
//! `--index-kind vamana` bench flag.
//!
//! Cross-platform: pure Rust + `chirondb_types::distance::squared_l2`
//! (SIMD via the `wide` crate), no platform intrinsics of our own.

use std::{
    collections::{BTreeSet, BinaryHeap, HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use chirondb_types::distance::squared_l2;
use serde::{Deserialize, Serialize};

use crate::index::ivf::{IvfArtifact, VectorSource};
use crate::index::{IndexBackend, IndexKind, IndexParams};
use crate::model::Point;
use crate::{GaussError, Result};

pub const VAMANA_SEGMENT_FILE: &str = "vamana.gdx";
const VAMANA_SEGMENT_V2_MAGIC: &[u8; 8] = b"GAUSVN02";
const VAMANA_SEGMENT_V3_MAGIC: &[u8; 8] = b"GAUSVN03";
const VAMANA_SEGMENT_HEADER_BYTES: usize = 64;
const STITCH_ADJACENT_CELLS: usize = 4;
const STITCH_REPRESENTATIVES: usize = 8;
const VAMANA_CELL_MAGIC: &[u8; 8] = b"CHIRVC01";
const VAMANA_CELL_VERSION: u32 = 1;
const VAMANA_CELL_HEADER_BYTES: usize = 40;
const PRIOR_EDGE_BUDGET: usize = DEFAULT_R - 1;

/// Snapshot-ordinal adjacency inherited from immutable input generations.
///
/// This is an internal build hint, not a persisted/public index knob. A
/// generation builder may discard the whole seed when any source artifact is
/// invalid. The generation builder resolves every old ordinal through stable
/// point IDs before inserting a row, then stores only compact `u32` ordinals.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct StableGraphSeed {
    rows: Vec<Vec<u32>>,
}

impl StableGraphSeed {
    pub(crate) fn new(points: usize) -> Self {
        Self {
            rows: vec![Vec::new(); points],
        }
    }

    pub(crate) fn insert(&mut self, ordinal: usize, neighbors: Vec<u32>) -> Result<()> {
        let row = self.rows.get_mut(ordinal).ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "prior Vamana seed ordinal {ordinal} is out of bounds"
            ))
        })?;
        *row = neighbors;
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.iter().all(Vec::is_empty)
    }

    pub(crate) fn rows(&self) -> &[Vec<u32>] {
        &self.rows
    }

    fn graph_keys(&self, ivf: &IvfArtifact, metric: crate::DistanceMetric) -> Result<Vec<u32>> {
        if self.rows.len() != ivf.len() {
            return Err(GaussError::InvalidRequest(
                "prior Vamana seed count disagrees with IVF".to_string(),
            ));
        }
        let mut ordinal_to_key = (0..self.rows.len())
            .map(|ordinal| u32::try_from(ordinal).ok())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| GaussError::InvalidRequest("Vamana seed exceeds u32".to_string()))?;
        if metric == crate::DistanceMetric::Cosine {
            for posting in 0..ivf.len() {
                let ordinal = ivf
                    .posting_ordinal(posting)
                    .ok_or_else(|| GaussError::InvalidRequest("IVF posting is missing".into()))?
                    as usize;
                ordinal_to_key[ordinal] = u32::try_from(posting).map_err(|_| {
                    GaussError::InvalidRequest("Vamana record key exceeds u32".to_string())
                })?;
            }
        }
        Ok(ordinal_to_key)
    }
}

#[derive(Clone, Copy)]
struct PriorGraphOverlay<'a> {
    seed: &'a StableGraphSeed,
    graph_keys: &'a [u32],
}

/// Persistent Algorithm 2 graph. Legacy v2 rows use vector ordinals; v3
/// cosine rows use cell-major RaBitQ record IDs so graph hops address the
/// compressed code directly.
#[derive(Debug)]
pub struct VamanaArtifact {
    file: crate::encryption::PersistentFile,
    count: usize,
    vector_dim: usize,
    nlist: usize,
    degree: usize,
    entries_start: usize,
    records_start: usize,
    record_bytes: usize,
    key_space: VamanaKeySpace,
    legacy_ordinal_to_record: Option<Vec<u32>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VamanaKeySpace {
    Ordinal,
    LegacyRecordRows,
    RabitqRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VamanaConnectivityProfile {
    pub nodes: usize,
    pub original_nodes: usize,
    pub weak_components: usize,
    pub original_nodes_without_original_neighbors: usize,
}

impl VamanaArtifact {
    pub fn open(path: &Path, ivf: &IvfArtifact) -> Result<Self> {
        let file = crate::encryption::PersistentFile::open(path)?;
        if file.len() < VAMANA_SEGMENT_HEADER_BYTES {
            return Err(vamana_corrupt(path, "bad or truncated Vamana header"));
        }
        let header = file.read_range(0..VAMANA_SEGMENT_HEADER_BYTES)?;
        let version =
            vn_u32_bytes(&header, 8).ok_or_else(|| vamana_corrupt(path, "missing version"))?;
        let key_space = match (&header[..8], version) {
            (magic, 2) if magic == VAMANA_SEGMENT_V2_MAGIC => VamanaKeySpace::Ordinal,
            // Historical v3 used record-key rows, but kept cell entries and
            // adjacency values as vector ordinals under the GAUSVN02 magic.
            (magic, 3) if magic == VAMANA_SEGMENT_V2_MAGIC => VamanaKeySpace::LegacyRecordRows,
            (magic, 3) if magic == VAMANA_SEGMENT_V3_MAGIC => VamanaKeySpace::RabitqRecord,
            _ => return Err(vamana_corrupt(path, "unsupported Vamana version")),
        };
        let count = vn_usize(&file, 12, path, "point count")?;
        let vector_dim = vn_usize(&file, 20, path, "vector dimension")?;
        let nlist = vn_usize(&file, 28, path, "cell count")?;
        let degree =
            vn_u32(&file, 36).ok_or_else(|| vamana_corrupt(path, "missing degree"))? as usize;
        let local_degree =
            vn_u32(&file, 40).ok_or_else(|| vamana_corrupt(path, "missing local degree"))? as usize;
        let adjacent = vn_u32(&file, 44)
            .ok_or_else(|| vamana_corrupt(path, "missing stitch adjacency"))?
            as usize;
        let representatives = vn_u32(&file, 48)
            .ok_or_else(|| vamana_corrupt(path, "missing representative count"))?
            as usize;
        let record_bytes =
            vn_u32(&file, 52).ok_or_else(|| vamana_corrupt(path, "missing record width"))? as usize;
        let expected_crc = vn_u32(&file, 56).ok_or_else(|| vamana_corrupt(path, "missing CRC"))?;
        let flags = vn_u32(&file, 60).ok_or_else(|| vamana_corrupt(path, "missing flags"))?;
        if flags != 0
            || count != ivf.len()
            || vector_dim != ivf.vector_dim()
            || nlist != ivf.cells()
            || degree != DEFAULT_R
            || local_degree != degree.saturating_sub(STITCH_ADJACENT_CELLS)
            || adjacent != STITCH_ADJACENT_CELLS
            || representatives != STITCH_REPRESENTATIVES
            || record_bytes != 4 + degree * 4
        {
            return Err(vamana_corrupt(path, "Vamana metadata disagrees with IVF"));
        }
        let entries_start = VAMANA_SEGMENT_HEADER_BYTES;
        let records_start = entries_start
            .checked_add(
                nlist
                    .checked_mul(4)
                    .ok_or_else(|| vamana_corrupt(path, "entry length overflow"))?,
            )
            .ok_or_else(|| vamana_corrupt(path, "entry length overflow"))?;
        let expected_len = records_start
            .checked_add(
                count
                    .checked_mul(record_bytes)
                    .ok_or_else(|| vamana_corrupt(path, "graph length overflow"))?,
            )
            .ok_or_else(|| vamana_corrupt(path, "graph length overflow"))?;
        if file.len() != expected_len {
            return Err(vamana_corrupt(path, "Vamana artifact length mismatch"));
        }
        if file.crc32(entries_start..file.len())? != expected_crc {
            return Err(vamana_corrupt(path, "Vamana payload CRC mismatch"));
        }
        let legacy_ordinal_to_record = if key_space == VamanaKeySpace::LegacyRecordRows {
            let mut inverse = vec![u32::MAX; count];
            for record in 0..count {
                let ordinal = ivf
                    .posting_ordinal(record)
                    .ok_or_else(|| vamana_corrupt(path, "missing IVF posting ordinal"))?
                    as usize;
                let slot = inverse
                    .get_mut(ordinal)
                    .ok_or_else(|| vamana_corrupt(path, "posting ordinal out of bounds"))?;
                if *slot != u32::MAX {
                    return Err(vamana_corrupt(path, "duplicate IVF posting ordinal"));
                }
                *slot = u32::try_from(record)
                    .map_err(|_| vamana_corrupt(path, "Vamana record key exceeds u32"))?;
            }
            if inverse.contains(&u32::MAX) {
                return Err(vamana_corrupt(path, "incomplete IVF posting permutation"));
            }
            Some(inverse)
        } else {
            None
        };
        for cell in 0..nlist {
            let entry = vn_u32(&file, entries_start + cell * 4)
                .ok_or_else(|| vamana_corrupt(path, "truncated cell entry"))?
                as usize;
            let entry_key = match key_space {
                VamanaKeySpace::Ordinal => Some(entry),
                VamanaKeySpace::LegacyRecordRows => legacy_ordinal_to_record
                    .as_ref()
                    .and_then(|inverse| inverse.get(entry))
                    .map(|record| *record as usize),
                VamanaKeySpace::RabitqRecord => Some(entry),
            };
            if entry >= count
                || entry_key.is_none()
                || (key_space != VamanaKeySpace::Ordinal
                    && !ivf
                        .posting_range(cell)
                        .expect("validated IVF cell")
                        .contains(&entry_key.expect("checked entry key")))
            {
                return Err(vamana_corrupt(path, "cell entry key is invalid"));
            }
        }
        for record in 0..count {
            let start = records_start + record * record_bytes;
            let row = file
                .read_range(start..start + record_bytes)
                .map_err(|_| vamana_corrupt(path, "truncated adjacency row"))?;
            let len = vn_u32_bytes(&row, 0)
                .ok_or_else(|| vamana_corrupt(path, "truncated adjacency row"))?
                as usize;
            if len > degree {
                return Err(vamana_corrupt(path, "adjacency degree exceeds fixed width"));
            }
            let mut unique = [u32::MAX; DEFAULT_R];
            let self_key = if key_space == VamanaKeySpace::LegacyRecordRows {
                ivf.posting_ordinal(record)
                    .ok_or_else(|| vamana_corrupt(path, "missing IVF posting ordinal"))?
                    as usize
            } else {
                record
            };
            for slot in 0..len {
                let neighbor = vn_u32_bytes(&row, 4 + slot * 4)
                    .ok_or_else(|| vamana_corrupt(path, "truncated neighbor"))?;
                if neighbor as usize >= count
                    || neighbor as usize == self_key
                    || unique[..slot].contains(&neighbor)
                {
                    return Err(vamana_corrupt(path, "invalid Vamana neighbor key"));
                }
                unique[slot] = neighbor;
            }
        }
        Ok(Self {
            file,
            count,
            vector_dim,
            nlist,
            degree,
            entries_start,
            records_start,
            record_bytes,
            key_space,
            legacy_ordinal_to_record,
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

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn entry(&self, cell: usize) -> Option<u32> {
        if cell >= self.nlist {
            return None;
        }
        let entry = vn_u32(&self.file, self.entries_start + cell * 4)?;
        Some(entry)
    }

    pub(crate) fn uses_rabitq_record_keys(&self) -> bool {
        self.key_space == VamanaKeySpace::RabitqRecord
    }

    /// Translate persisted graph keys back to vector ordinals. Callers map
    /// those ordinals to stable point IDs before carrying adjacency into a new
    /// generation.
    #[cfg(test)]
    pub(crate) fn ordinal_adjacency(&self, ivf: &IvfArtifact) -> Result<Vec<Vec<u32>>> {
        if self.count != ivf.len() || self.nlist != ivf.cells() {
            return Err(GaussError::InvalidRequest(
                "Vamana adjacency source disagrees with IVF".to_string(),
            ));
        }
        let ordinal_to_key = self.ordinal_to_key(ivf)?;
        let mut rows = vec![Vec::new(); self.count];
        for (ordinal, row) in rows.iter_mut().enumerate() {
            *row = self.ordinal_neighbors(ivf, &ordinal_to_key, ordinal)?;
        }
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn ordinal_to_key(&self, ivf: &IvfArtifact) -> Result<Vec<usize>> {
        if self.count != ivf.len() || self.nlist != ivf.cells() {
            return Err(GaussError::InvalidRequest(
                "Vamana key map disagrees with IVF".to_string(),
            ));
        }
        let mut ordinal_to_key = (0..self.count).collect::<Vec<_>>();
        if self.key_space != VamanaKeySpace::Ordinal {
            for key in 0..self.count {
                let ordinal = ivf.posting_ordinal(key).ok_or_else(|| {
                    GaussError::InvalidRequest("Vamana record has no IVF posting".to_string())
                })? as usize;
                ordinal_to_key[ordinal] = key;
            }
        }
        Ok(ordinal_to_key)
    }

    #[doc(hidden)]
    pub fn ordinal_neighbors(
        &self,
        ivf: &IvfArtifact,
        ordinal_to_key: &[usize],
        ordinal: usize,
    ) -> Result<Vec<u32>> {
        let &key = ordinal_to_key.get(ordinal).ok_or_else(|| {
            GaussError::InvalidRequest(format!("Vamana ordinal {ordinal} is out of bounds"))
        })?;
        let mut neighbors = Vec::new();
        self.visit_raw_neighbors(key, |neighbor| neighbors.push(neighbor))
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!("Vamana adjacency is missing graph key {key}"))
            })?;
        neighbors
            .into_iter()
            .map(|neighbor| match self.key_space {
                VamanaKeySpace::Ordinal | VamanaKeySpace::LegacyRecordRows => Ok(neighbor),
                VamanaKeySpace::RabitqRecord => {
                    ivf.posting_ordinal(neighbor as usize).ok_or_else(|| {
                        GaussError::InvalidRequest("Vamana neighbor has no IVF posting".to_string())
                    })
                }
            })
            .collect()
    }

    pub fn neighbors(&self, ordinal: usize) -> Option<Vec<u32>> {
        if self.key_space == VamanaKeySpace::RabitqRecord {
            return None;
        }
        let mut neighbors = Vec::new();
        self.visit_neighbors(ordinal, |neighbor| neighbors.push(neighbor))?;
        Some(neighbors)
    }

    /// Exact weak-connectivity and original-neighbor safety profile used by
    /// C19 after a structural-node rebuild. `original_nodes` is the semantic
    /// prefix installed before structural points. Edges are treated as
    /// undirected for component counting, matching weak connectivity.
    pub fn connectivity_profile(&self, original_nodes: usize) -> Result<VamanaConnectivityProfile> {
        if original_nodes > self.count {
            return Err(GaussError::InvalidRequest(format!(
                "original node count {original_nodes} exceeds Vamana node count {}",
                self.count
            )));
        }
        if u32::try_from(self.count).is_err() {
            return Err(GaussError::InvalidRequest(
                "Vamana connectivity profile exceeds u32 ordinal space".to_string(),
            ));
        }
        let mut union = UnionFind::new(self.count);
        let mut original_nodes_without_original_neighbors = 0usize;
        for ordinal in 0..self.count {
            let mut has_original_neighbor = false;
            self.visit_neighbors(ordinal, |neighbor| {
                let neighbor = neighbor as usize;
                union.join(ordinal, neighbor);
                if neighbor < original_nodes {
                    has_original_neighbor = true;
                }
            })
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!("Vamana adjacency is missing ordinal {ordinal}"))
            })?;
            if ordinal < original_nodes && !has_original_neighbor {
                original_nodes_without_original_neighbors += 1;
            }
        }
        let weak_components = (0..self.count)
            .filter(|ordinal| union.find(*ordinal) == *ordinal)
            .count();
        Ok(VamanaConnectivityProfile {
            nodes: self.count,
            original_nodes,
            weak_components,
            original_nodes_without_original_neighbors,
        })
    }

    /// Exact connectivity profile with checked IVF translation for persisted
    /// record-key graphs such as cosine GAUSVN03 artifacts.
    #[doc(hidden)]
    pub fn connectivity_profile_with_ivf(
        &self,
        ivf: &IvfArtifact,
        original_nodes: usize,
    ) -> Result<VamanaConnectivityProfile> {
        if original_nodes > self.count {
            return Err(GaussError::InvalidRequest(format!(
                "original node count {original_nodes} exceeds Vamana node count {}",
                self.count
            )));
        }
        if u32::try_from(self.count).is_err() {
            return Err(GaussError::InvalidRequest(
                "Vamana connectivity profile exceeds u32 ordinal space".to_string(),
            ));
        }
        let ordinal_to_key = self.ordinal_to_key(ivf)?;
        let mut union = UnionFind::new(self.count);
        let mut original_nodes_without_original_neighbors = 0usize;
        for ordinal in 0..self.count {
            let neighbors = self.ordinal_neighbors(ivf, &ordinal_to_key, ordinal)?;
            let mut has_original_neighbor = false;
            for neighbor in neighbors {
                let neighbor = neighbor as usize;
                union.join(ordinal, neighbor);
                if neighbor < original_nodes {
                    has_original_neighbor = true;
                }
            }
            if ordinal < original_nodes && !has_original_neighbor {
                original_nodes_without_original_neighbors += 1;
            }
        }
        let weak_components = (0..self.count)
            .filter(|ordinal| union.find(*ordinal) == *ordinal)
            .count();
        Ok(VamanaConnectivityProfile {
            nodes: self.count,
            original_nodes,
            weak_components,
            original_nodes_without_original_neighbors,
        })
    }

    #[inline]
    pub(crate) fn visit_neighbors(&self, ordinal: usize, visit: impl FnMut(u32)) -> Option<()> {
        let key = match self.key_space {
            VamanaKeySpace::Ordinal => ordinal,
            VamanaKeySpace::LegacyRecordRows => self
                .legacy_ordinal_to_record
                .as_ref()?
                .get(ordinal)
                .copied()? as usize,
            VamanaKeySpace::RabitqRecord => return None,
        };
        self.visit_raw_neighbors(key, visit)
    }

    #[inline]
    pub(crate) fn visit_neighbor_keys(&self, key: usize, mut visit: impl FnMut(u32)) -> Option<()> {
        if self.key_space == VamanaKeySpace::LegacyRecordRows {
            let inverse = self.legacy_ordinal_to_record.as_ref()?;
            return self.visit_raw_neighbors(key, |ordinal| {
                if let Some(record) = inverse.get(ordinal as usize) {
                    visit(*record);
                }
            });
        }
        self.visit_raw_neighbors(key, visit)
    }

    #[inline]
    fn visit_raw_neighbors(&self, key: usize, mut visit: impl FnMut(u32)) -> Option<()> {
        if key >= self.count {
            return None;
        }
        let start = self.records_start + key * self.record_bytes;
        let row = self
            .file
            .read_range(start..start.checked_add(self.record_bytes)?)
            .ok()?;
        let len = vn_u32_bytes(&row, 0)? as usize;
        for slot in 0..len {
            visit(vn_u32_bytes(&row, 4 + slot * 4)?);
        }
        Some(())
    }
}

struct UnionFind {
    parent: Vec<u32>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(nodes: usize) -> Self {
        Self {
            parent: (0..nodes as u32).collect(),
            rank: vec![0; nodes],
        }
    }

    fn find(&mut self, node: usize) -> usize {
        let parent = self.parent[node] as usize;
        if parent != node {
            let root = self.find(parent);
            self.parent[node] = root as u32;
        }
        self.parent[node] as usize
    }

    fn join(&mut self, left: usize, right: usize) {
        let mut left_root = self.find(left);
        let mut right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        if self.rank[left_root] < self.rank[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root as u32;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
    }
}

/// Default maximum out-degree per node. DiskANN's R — the knn max degree.
/// 32 is a conservative starting point that hits the recall@10 ≥ 0.95
/// floor on the 500×64 golden test without burning graph memory.
pub const DEFAULT_R: usize = 32;

/// Default beam width for both build and search. Matches the
/// `L` parameter in the Vamana paper. Bumping this widens the candidate
/// pool at the cost of O(L) extra distance work per visited node.
pub const DEFAULT_L: usize = 100;

/// Default prune slack factor. `alpha = 1.0` keeps only the absolute
/// nearest neighbours; values in `[1.0, 1.4]` retain more long-range
/// edges (the "angular" part of angular pruning), which improves recall
/// on well-distributed data. 1.2 is the value the original DiskANN
/// repository ships as default and is what we land on.
pub const DEFAULT_ALPHA: f32 = 1.2;

/// In-memory Vamana single-layer graph. Phase 4 will lay this out as a
/// sealed `vamana.gdx` segment artifact; the wire-up reuses
/// [`super::build`] semantics and the existing `Collection::primary_backend`
/// dispatch (PC-2).
#[derive(Clone, Serialize, Deserialize)]
pub struct VamanaBackend {
    vector_dim: usize,
    r: usize,
    l: usize,
    alpha: f32,
    start: usize,
    ids: Vec<String>,
    vectors: Vec<Vec<f32>>,
    id_to_idx: HashMap<String, usize>,
    neighbors: Vec<Vec<usize>>,
}

impl std::fmt::Debug for VamanaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VamanaBackend")
            .field("vector_dim", &self.vector_dim)
            .field("points", &self.ids.len())
            .field("r", &self.r)
            .field("l", &self.l)
            .field("alpha", &self.alpha)
            .field("start", &self.start)
            .finish()
    }
}

impl VamanaBackend {
    pub fn build(points: &[Point], vector_dim: usize) -> Self {
        Self::build_with_params(points, vector_dim, DEFAULT_R, DEFAULT_L, DEFAULT_ALPHA)
    }

    /// PC-2 v3: total point count for the persistence path.
    /// Mirrors `IndexBackend::indexed_points` (same expression) but is
    /// callable without the trait in scope. Used by `write_vamana_index`.
    pub fn point_count(&self) -> usize {
        self.ids.len()
    }

    pub fn build_with_params(
        points: &[Point],
        vector_dim: usize,
        r: usize,
        l: usize,
        alpha: f32,
    ) -> Self {
        let r = r.max(1);
        let l = l.max(r).max(8);
        let alpha = if alpha.is_finite() && alpha >= 1.0 {
            alpha
        } else {
            DEFAULT_ALPHA
        };

        let mut ids = Vec::with_capacity(points.len());
        let mut vectors = Vec::with_capacity(points.len());
        let mut id_to_idx = HashMap::with_capacity(points.len());
        for point in points {
            if id_to_idx.contains_key(&point.id) {
                continue;
            }
            let v = pad_or_trim(&point.vector, vector_dim);
            let idx = ids.len();
            ids.push(point.id.clone());
            id_to_idx.insert(point.id.clone(), idx);
            vectors.push(v);
        }

        let (start, neighbors) = build_local_graph(&vectors, r, l, alpha);

        Self {
            vector_dim,
            r,
            l,
            alpha,
            start,
            ids,
            vectors,
            id_to_idx,
            neighbors,
        }
    }

    pub fn with_params(mut self, r: usize, l: usize, alpha: f32) -> Self {
        if r > 0 {
            self.r = r;
        }
        if l > 0 {
            self.l = l;
        }
        if alpha.is_finite() && alpha >= 1.0 {
            self.alpha = alpha;
        }
        self
    }

    pub fn r(&self) -> usize {
        self.r
    }
    pub fn l(&self) -> usize {
        self.l
    }
    pub fn alpha(&self) -> f32 {
        self.alpha
    }
    pub fn vector_dim(&self) -> usize {
        self.vector_dim
    }

    fn beam_search(&self, query: &[f32], l: usize) -> Vec<usize> {
        if self.ids.is_empty() {
            return Vec::new();
        }
        let q = pad_or_trim(query, self.vector_dim);
        greedy_search_by_vec(&q, self.start, l, &self.vectors, &self.neighbors)
    }
}

/// Build one Vamana graph over an already-hydrated IVF cell. Algorithm 2
/// callers discard `vectors` after persisting that cell, bounding peak build
/// memory to the largest cell rather than the full sealed segment.
pub(crate) fn build_local_graph(
    vectors: &[Vec<f32>],
    r: usize,
    l: usize,
    alpha: f32,
) -> (usize, Vec<Vec<usize>>) {
    let n = vectors.len();
    let start = if n == 0 {
        0
    } else {
        medoid(vectors).unwrap_or(0)
    };
    let mut neighbors: Vec<Vec<usize>> = vec![Vec::new(); n];
    let perm = deterministic_permutation(n, start as u64);

    for &p in &perm {
        let candidates = greedy_search(p, start, l, vectors, &neighbors);
        for &c in &candidates {
            if c == p {
                continue;
            }
            if !neighbors[c].contains(&p) {
                neighbors[c].push(p);
            }
            if neighbors[c].len() > r {
                let c_vec = vectors[c].clone();
                neighbors[c] = robust_prune(&c_vec, &neighbors[c], vectors, r, alpha);
                if !neighbors[c].contains(&p) {
                    neighbors[c].push(p);
                    if neighbors[c].len() > r {
                        let p_vec = vectors[p].clone();
                        let c_vec = vectors[c].clone();
                        let p_dist = squared_l2(&c_vec, &p_vec);
                        let mut worst: (usize, f32) = (usize::MAX, -1.0);
                        for (slot, &n_idx) in neighbors[c].iter().enumerate() {
                            let d = squared_l2(&c_vec, &vectors[n_idx]);
                            if d > worst.1 {
                                worst = (slot, d);
                            }
                        }
                        if worst.0 != usize::MAX && p_dist < worst.1 {
                            neighbors[c].swap_remove(worst.0);
                        } else {
                            // `p` was appended last. If it cannot displace an
                            // existing neighbour, remove it again so reverse
                            // edges never violate the caller's degree budget.
                            neighbors[c].pop();
                        }
                    }
                }
            }
        }
        let p_vec = vectors[p].clone();
        let mut pool: Vec<usize> = candidates.into_iter().filter(|&c| c != p).collect();
        for &c in &neighbors[p] {
            if c != p && !pool.contains(&c) {
                pool.push(c);
            }
        }
        neighbors[p] = robust_prune(&p_vec, &pool, vectors, r, alpha);
        if neighbors[p].len() > r {
            neighbors[p].truncate(r);
        }
    }
    debug_assert!(neighbors.iter().all(|row| row.len() <= r));
    (start, neighbors)
}

/// Build per-cell mini-Vamana graphs and stitch each cell to its four nearest
/// centroid neighbors through eight representatives. Fixed-width random
/// writes keep the full graph off heap during construction.
pub fn write_vamana_artifact<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
) -> Result<()> {
    write_vamana_artifact_inner(source, ivf, metric, path, None, None)
}

pub(crate) fn write_vamana_artifact_seeded<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
    seed: &StableGraphSeed,
) -> Result<()> {
    let graph_keys = seed.graph_keys(ivf, metric)?;
    write_vamana_artifact_inner(
        source,
        ivf,
        metric,
        path,
        Some(PriorGraphOverlay {
            seed,
            graph_keys: &graph_keys,
        }),
        None,
    )
}

struct VamanaBuildResume<'a> {
    cells_dir: &'a Path,
    reusable_cells: &'a BTreeSet<u32>,
    cancelled: Option<&'a std::sync::atomic::AtomicBool>,
    on_cell_completed: &'a mut dyn FnMut(u32, &Path) -> Result<()>,
}

pub(crate) struct VamanaResumeInput<'a> {
    pub(crate) cells_dir: &'a Path,
    pub(crate) reusable_cells: &'a BTreeSet<u32>,
    pub(crate) cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

/// Resume per-cell graph construction from immutable, checksummed shards.
/// The final Vamana file is always deterministically stitched from validated
/// shards in IVF cell order; workers never share a random-write graph file.
pub(crate) fn write_vamana_artifact_resumable<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
    control: VamanaResumeInput<'_>,
    on_cell_completed: &mut dyn FnMut(u32, &Path) -> Result<()>,
) -> Result<()> {
    crate::fs_util::durable_create_dir(control.cells_dir)?;
    write_vamana_artifact_inner(
        source,
        ivf,
        metric,
        path,
        None,
        Some(VamanaBuildResume {
            cells_dir: control.cells_dir,
            reusable_cells: control.reusable_cells,
            cancelled: control.cancelled,
            on_cell_completed,
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_vamana_artifact_resumable_seeded<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
    seed: &StableGraphSeed,
    control: VamanaResumeInput<'_>,
    on_cell_completed: &mut dyn FnMut(u32, &Path) -> Result<()>,
) -> Result<()> {
    crate::fs_util::durable_create_dir(control.cells_dir)?;
    let graph_keys = seed.graph_keys(ivf, metric)?;
    write_vamana_artifact_inner(
        source,
        ivf,
        metric,
        path,
        Some(PriorGraphOverlay {
            seed,
            graph_keys: &graph_keys,
        }),
        Some(VamanaBuildResume {
            cells_dir: control.cells_dir,
            reusable_cells: control.reusable_cells,
            cancelled: control.cancelled,
            on_cell_completed,
        }),
    )
}

fn write_vamana_artifact_inner<S: VectorSource + ?Sized>(
    source: &S,
    ivf: &IvfArtifact,
    metric: crate::DistanceMetric,
    path: &Path,
    prior: Option<PriorGraphOverlay<'_>>,
    mut resume: Option<VamanaBuildResume<'_>>,
) -> Result<()> {
    if source.len() != ivf.len() {
        return Err(GaussError::InvalidRequest(
            "Vamana source count disagrees with IVF".to_string(),
        ));
    }
    let record_bytes = 4 + DEFAULT_R * 4;
    let entries_bytes = ivf
        .cells()
        .checked_mul(4)
        .ok_or_else(|| GaussError::InvalidRequest("Vamana entries overflow".to_string()))?;
    let records_start = VAMANA_SEGMENT_HEADER_BYTES
        .checked_add(entries_bytes)
        .ok_or_else(|| GaussError::InvalidRequest("Vamana offset overflow".to_string()))?;
    let file_bytes = records_start
        .checked_add(
            source
                .len()
                .checked_mul(record_bytes)
                .ok_or_else(|| GaussError::InvalidRequest("Vamana graph overflow".to_string()))?,
        )
        .ok_or_else(|| GaussError::InvalidRequest("Vamana graph overflow".to_string()))?;
    let local_degree = DEFAULT_R.saturating_sub(STITCH_ADJACENT_CELLS).max(1);
    let centroids = ivf.centroids();
    let mut entries = vec![0u32; ivf.cells()];
    let mut representatives = vec![Vec::<u32>::new(); ivf.cells()];
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)?;
    file.set_len(file_bytes as u64)?;
    let key_space = if metric == crate::DistanceMetric::Cosine {
        VamanaKeySpace::RabitqRecord
    } else {
        VamanaKeySpace::Ordinal
    };
    let (magic, version) = match key_space {
        VamanaKeySpace::Ordinal => (VAMANA_SEGMENT_V2_MAGIC, 2u32),
        VamanaKeySpace::LegacyRecordRows | VamanaKeySpace::RabitqRecord => {
            (VAMANA_SEGMENT_V3_MAGIC, 3u32)
        }
    };
    file.write_all(magic)?;
    file.write_all(&version.to_le_bytes())?;
    file.write_all(&(source.len() as u64).to_le_bytes())?;
    file.write_all(&(ivf.vector_dim() as u64).to_le_bytes())?;
    file.write_all(&(ivf.cells() as u64).to_le_bytes())?;
    file.write_all(&(DEFAULT_R as u32).to_le_bytes())?;
    file.write_all(&(local_degree as u32).to_le_bytes())?;
    file.write_all(&(STITCH_ADJACENT_CELLS as u32).to_le_bytes())?;
    file.write_all(&(STITCH_REPRESENTATIVES as u32).to_le_bytes())?;
    file.write_all(&(record_bytes as u32).to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;
    file.write_all(&0u32.to_le_bytes())?;

    for (cell, centroid) in centroids.iter().enumerate() {
        if resume.as_ref().is_some_and(|resume| {
            resume
                .cancelled
                .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
        }) {
            return Err(GaussError::ResourceExhausted(
                "background build cancelled during shutdown".to_string(),
            ));
        }
        let range = ivf.posting_range(cell).expect("validated IVF cell");
        let mut keys = Vec::with_capacity(range.len());
        for posting in range.clone() {
            let ordinal = ivf.posting_ordinal(posting).expect("validated IVF posting");
            keys.push(match key_space {
                VamanaKeySpace::Ordinal => ordinal,
                VamanaKeySpace::LegacyRecordRows | VamanaKeySpace::RabitqRecord => posting as u32,
            });
        }
        if keys.is_empty() {
            return Err(GaussError::InvalidRequest(format!(
                "Vamana IVF cell {cell} has no postings"
            )));
        }
        let cell_u32 = u32::try_from(cell)
            .map_err(|_| GaussError::InvalidRequest("Vamana cell exceeds u32".to_string()))?;
        let shard_path = resume.as_ref().map(|resume| {
            resume
                .cells_dir
                .join(crate::build_progress::cell_file_name(cell_u32))
        });
        let shard = shard_path
            .as_deref()
            .filter(|_| {
                resume
                    .as_ref()
                    .is_some_and(|resume| resume.reusable_cells.contains(&cell_u32))
            })
            .and_then(|path| read_vamana_cell(path, cell_u32, key_space, &keys).ok())
            .unwrap_or_else(|| VamanaCell {
                entry: 0,
                representatives: Vec::new(),
                neighbors: Vec::new(),
            });
        let shard = if shard.neighbors.is_empty() {
            let mut vectors = Vec::with_capacity(range.len());
            for posting in range {
                let ordinal = ivf.posting_ordinal(posting).expect("validated IVF posting");
                let vector = source.vector(ordinal as usize)?;
                if vector.len() != ivf.vector_dim() {
                    return Err(GaussError::DimensionMismatch {
                        expected: ivf.vector_dim(),
                        actual: vector.len(),
                    });
                }
                vectors.push(vector.into_owned());
            }
            let (start, local_neighbors) =
                build_local_graph(&vectors, local_degree, DEFAULT_L, DEFAULT_ALPHA);
            let mut ranked = (0..vectors.len())
                .map(|local| (squared_l2(&vectors[local], centroid), local))
                .collect::<Vec<_>>();
            ranked.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            let built = VamanaCell {
                entry: keys[start],
                representatives: ranked
                    .into_iter()
                    .take(STITCH_REPRESENTATIVES)
                    .map(|(_, local)| keys[local])
                    .collect(),
                neighbors: local_neighbors
                    .iter()
                    .map(|neighbors| neighbors.iter().map(|neighbor| keys[*neighbor]).collect())
                    .collect(),
            };
            if let (Some(path), Some(resume)) = (shard_path.as_deref(), resume.as_mut()) {
                write_vamana_cell(path, cell_u32, key_space, &built)?;
                (resume.on_cell_completed)(cell_u32, path)?;
            }
            built
        } else {
            shard
        };
        entries[cell] = shard.entry;
        representatives[cell] = shard.representatives;
        for (local, global_neighbors) in shard.neighbors.iter().enumerate() {
            write_vamana_row(
                &mut file,
                records_start,
                record_bytes,
                keys[local] as usize,
                global_neighbors,
            )?;
        }
        crate::failpoint::check("seal.after_vamana_cell")?;
    }

    if resume.as_ref().is_some_and(|resume| {
        resume
            .cancelled
            .is_some_and(|cancelled| cancelled.load(std::sync::atomic::Ordering::Acquire))
    }) {
        return Err(GaussError::ResourceExhausted(
            "background build cancelled during shutdown".to_string(),
        ));
    }

    file.seek(SeekFrom::Start(VAMANA_SEGMENT_HEADER_BYTES as u64))?;
    for entry in &entries {
        file.write_all(&entry.to_le_bytes())?;
    }

    for cell in 0..ivf.cells() {
        let mut adjacent = (0..ivf.cells())
            .filter(|other| *other != cell)
            .map(|other| (squared_l2(&centroids[cell], &centroids[other]), other))
            .collect::<Vec<_>>();
        adjacent.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        for (_, other) in adjacent.into_iter().take(STITCH_ADJACENT_CELLS) {
            for (&source, &target) in representatives[cell].iter().zip(&representatives[other]) {
                append_vamana_neighbor(
                    &mut file,
                    records_start,
                    record_bytes,
                    DEFAULT_R,
                    source,
                    target,
                )?;
            }
        }
    }

    if let Some(prior) = prior {
        if prior.seed.rows.len() != source.len() || prior.graph_keys.len() != source.len() {
            return Err(GaussError::InvalidRequest(
                "Vamana seed count disagrees with source".to_string(),
            ));
        }
        for (ordinal, inherited) in prior.seed.rows.iter().enumerate() {
            if inherited.is_empty() {
                continue;
            }
            let record = prior.graph_keys[ordinal] as usize;
            let current = read_vamana_row(&mut file, records_start, record_bytes, record)?;
            let mut merged = Vec::with_capacity(DEFAULT_R);
            for &neighbor_ordinal in inherited.iter().take(PRIOR_EDGE_BUDGET) {
                let Some(&neighbor_key) = prior.graph_keys.get(neighbor_ordinal as usize) else {
                    continue;
                };
                if neighbor_key as usize != record && !merged.contains(&neighbor_key) {
                    merged.push(neighbor_key);
                }
            }
            for neighbor in current {
                if merged.len() == DEFAULT_R {
                    break;
                }
                if neighbor as usize != record && !merged.contains(&neighbor) {
                    merged.push(neighbor);
                }
            }
            write_vamana_row(&mut file, records_start, record_bytes, record, &merged)?;
        }
    }

    file.seek(SeekFrom::Start(VAMANA_SEGMENT_HEADER_BYTES as u64))?;
    let mut crc = crc32fast::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(56))?;
    file.write_all(&crc.finalize().to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug)]
struct VamanaCell {
    entry: u32,
    representatives: Vec<u32>,
    neighbors: Vec<Vec<u32>>,
}

fn write_vamana_cell(
    path: &Path,
    cell: u32,
    key_space: VamanaKeySpace,
    shard: &VamanaCell,
) -> Result<()> {
    let row_count = u32::try_from(shard.neighbors.len())
        .map_err(|_| GaussError::InvalidRequest("Vamana cell rows exceed u32".to_string()))?;
    let representative_count = u32::try_from(shard.representatives.len()).map_err(|_| {
        GaussError::InvalidRequest("Vamana cell representatives exceed u32".to_string())
    })?;
    let mut payload = Vec::with_capacity(
        shard.representatives.len() * 4 + shard.neighbors.len() * (4 + DEFAULT_R * 4),
    );
    for representative in &shard.representatives {
        payload.extend_from_slice(&representative.to_le_bytes());
    }
    for neighbors in &shard.neighbors {
        if neighbors.len() > DEFAULT_R {
            return Err(GaussError::InvalidRequest(
                "Vamana cell row exceeds degree".to_string(),
            ));
        }
        payload.extend_from_slice(&(neighbors.len() as u32).to_le_bytes());
        for slot in 0..DEFAULT_R {
            payload.extend_from_slice(
                &neighbors
                    .get(slot)
                    .copied()
                    .unwrap_or_default()
                    .to_le_bytes(),
            );
        }
    }
    let mut bytes = Vec::with_capacity(VAMANA_CELL_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(VAMANA_CELL_MAGIC);
    bytes.extend_from_slice(&VAMANA_CELL_VERSION.to_le_bytes());
    bytes.extend_from_slice(&cell.to_le_bytes());
    bytes.extend_from_slice(&key_space_code(key_space).to_le_bytes());
    bytes.extend_from_slice(&row_count.to_le_bytes());
    bytes.extend_from_slice(&shard.entry.to_le_bytes());
    bytes.extend_from_slice(&representative_count.to_le_bytes());
    bytes.extend_from_slice(&(DEFAULT_R as u32).to_le_bytes());
    bytes.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    bytes.extend_from_slice(&payload);
    crate::encryption::atomic_write_persistent(path, crate::encryption::FileType::Segment, &bytes)
}

fn read_vamana_cell(
    path: &Path,
    expected_cell: u32,
    key_space: VamanaKeySpace,
    keys: &[u32],
) -> Result<VamanaCell> {
    let bytes = crate::encryption::read_persistent(path)?;
    if bytes.len() < VAMANA_CELL_HEADER_BYTES || &bytes[..8] != VAMANA_CELL_MAGIC {
        return Err(vamana_corrupt(path, "bad or truncated Vamana cell header"));
    }
    let version = vn_u32_bytes(&bytes, 8).unwrap();
    let cell = vn_u32_bytes(&bytes, 12).unwrap();
    let stored_key_space = vn_u32_bytes(&bytes, 16).unwrap();
    let row_count = vn_u32_bytes(&bytes, 20).unwrap() as usize;
    let entry = vn_u32_bytes(&bytes, 24).unwrap();
    let representative_count = vn_u32_bytes(&bytes, 28).unwrap() as usize;
    let degree = vn_u32_bytes(&bytes, 32).unwrap() as usize;
    let expected_crc = vn_u32_bytes(&bytes, 36).unwrap();
    let expected_len =
        VAMANA_CELL_HEADER_BYTES
            .checked_add(representative_count.checked_mul(4).ok_or_else(|| {
                vamana_corrupt(path, "Vamana cell representative length overflow")
            })?)
            .and_then(|len| len.checked_add(row_count.checked_mul(4 + degree * 4)?))
            .ok_or_else(|| vamana_corrupt(path, "Vamana cell length overflow"))?;
    if version != VAMANA_CELL_VERSION
        || cell != expected_cell
        || stored_key_space != key_space_code(key_space)
        || row_count != keys.len()
        || representative_count > STITCH_REPRESENTATIVES
        || degree != DEFAULT_R
        || bytes.len() != expected_len
        || crc32fast::hash(&bytes[VAMANA_CELL_HEADER_BYTES..]) != expected_crc
    {
        return Err(vamana_corrupt(path, "Vamana cell metadata mismatch"));
    }
    let valid_keys = keys.iter().copied().collect::<HashSet<_>>();
    if !valid_keys.contains(&entry) {
        return Err(vamana_corrupt(
            path,
            "Vamana cell entry is outside the cell",
        ));
    }
    let mut offset = VAMANA_CELL_HEADER_BYTES;
    let mut representatives = Vec::with_capacity(representative_count);
    let mut unique_representatives = HashSet::with_capacity(representative_count);
    for _ in 0..representative_count {
        let representative = vn_u32_bytes(&bytes, offset).unwrap();
        offset += 4;
        if !valid_keys.contains(&representative) || !unique_representatives.insert(representative) {
            return Err(vamana_corrupt(
                path,
                "Vamana cell representative is invalid or duplicated",
            ));
        }
        representatives.push(representative);
    }
    let mut neighbors = Vec::with_capacity(row_count);
    for key in keys {
        let len = vn_u32_bytes(&bytes, offset).unwrap() as usize;
        offset += 4;
        if len > DEFAULT_R {
            return Err(vamana_corrupt(path, "Vamana cell row exceeds degree"));
        }
        let mut row_neighbors = Vec::with_capacity(len);
        let mut unique_neighbors = HashSet::with_capacity(len);
        for slot in 0..DEFAULT_R {
            let neighbor = vn_u32_bytes(&bytes, offset).unwrap();
            offset += 4;
            if slot < len {
                if neighbor == *key
                    || !valid_keys.contains(&neighbor)
                    || !unique_neighbors.insert(neighbor)
                {
                    return Err(vamana_corrupt(path, "invalid Vamana cell neighbor"));
                }
                row_neighbors.push(neighbor);
            }
        }
        if row_neighbors.len() != len {
            return Err(vamana_corrupt(path, "invalid Vamana cell row"));
        }
        neighbors.push(row_neighbors);
    }
    Ok(VamanaCell {
        entry,
        representatives,
        neighbors,
    })
}

fn key_space_code(key_space: VamanaKeySpace) -> u32 {
    match key_space {
        VamanaKeySpace::Ordinal => 0,
        VamanaKeySpace::LegacyRecordRows | VamanaKeySpace::RabitqRecord => 1,
    }
}

fn write_vamana_row(
    file: &mut File,
    records_start: usize,
    record_bytes: usize,
    record: usize,
    neighbors: &[u32],
) -> Result<()> {
    file.seek(SeekFrom::Start(
        (records_start + record * record_bytes) as u64,
    ))?;
    file.write_all(&(neighbors.len() as u32).to_le_bytes())?;
    for neighbor in neighbors {
        file.write_all(&neighbor.to_le_bytes())?;
    }
    Ok(())
}

fn read_vamana_row(
    file: &mut File,
    records_start: usize,
    record_bytes: usize,
    record: usize,
) -> Result<Vec<u32>> {
    let start =
        records_start
            .checked_add(record.checked_mul(record_bytes).ok_or_else(|| {
                GaussError::InvalidRequest("Vamana row offset overflow".to_string())
            })?)
            .ok_or_else(|| GaussError::InvalidRequest("Vamana row offset overflow".to_string()))?;
    file.seek(SeekFrom::Start(start as u64))?;
    let mut row = vec![0u8; record_bytes];
    file.read_exact(&mut row)?;
    let len = vn_u32_bytes(&row, 0)
        .ok_or_else(|| GaussError::InvalidRequest("Vamana row is truncated".to_string()))?
        as usize;
    if len > DEFAULT_R {
        return Err(GaussError::InvalidRequest(
            "Vamana row degree exceeds fixed width".to_string(),
        ));
    }
    Ok((0..len)
        .map(|slot| vn_u32_bytes(&row, 4 + slot * 4).expect("validated Vamana row"))
        .collect())
}

fn append_vamana_neighbor(
    file: &mut File,
    records_start: usize,
    record_bytes: usize,
    degree: usize,
    record: u32,
    neighbor: u32,
) -> Result<()> {
    if record == neighbor {
        return Ok(());
    }
    let start = records_start + record as usize * record_bytes;
    file.seek(SeekFrom::Start(start as u64))?;
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut existing = vec![0u8; len * 4];
    file.read_exact(&mut existing)?;
    if existing
        .chunks_exact(4)
        .any(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) == neighbor)
    {
        return Ok(());
    }
    if len >= degree {
        return Err(GaussError::InvalidRequest(
            "StitchGraphs exhausted reserved Vamana degree".to_string(),
        ));
    }
    file.seek(SeekFrom::Start((start + 4 + len * 4) as u64))?;
    file.write_all(&neighbor.to_le_bytes())?;
    file.seek(SeekFrom::Start(start as u64))?;
    file.write_all(&((len + 1) as u32).to_le_bytes())?;
    Ok(())
}

fn vn_u32(file: &crate::encryption::PersistentFile, offset: usize) -> Option<u32> {
    let bytes = file.read_range(offset..offset.checked_add(4)?).ok()?;
    Some(u32::from_le_bytes(bytes.as_ref().try_into().ok()?))
}

fn vn_u32_bytes(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn vn_u64(file: &crate::encryption::PersistentFile, offset: usize) -> Option<u64> {
    let bytes = file.read_range(offset..offset.checked_add(8)?).ok()?;
    Some(u64::from_le_bytes(bytes.as_ref().try_into().ok()?))
}

fn vn_usize(
    file: &crate::encryption::PersistentFile,
    offset: usize,
    path: &Path,
    field: &str,
) -> Result<usize> {
    let value =
        vn_u64(file, offset).ok_or_else(|| vamana_corrupt(path, &format!("missing {field}")))?;
    usize::try_from(value).map_err(|_| vamana_corrupt(path, &format!("{field} exceeds usize")))
}

fn vamana_corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

impl IndexBackend for VamanaBackend {
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        if self.ids.is_empty() || k == 0 {
            return Vec::new();
        }
        let beam = ef_search
            .unwrap_or_else(|| self.l.max(k))
            .max(k)
            .min(self.ids.len());
        let hits = self.beam_search(query, beam);
        let mut out: Vec<String> = hits
            .into_iter()
            .take(k)
            .map(|idx| self.ids[idx].clone())
            .collect();
        if out.len() < k {
            let seen: std::collections::HashSet<String> = out.iter().cloned().collect();
            for (idx, id) in self.ids.iter().enumerate() {
                if out.len() >= k {
                    break;
                }
                if !seen.contains(id) {
                    out.push(self.ids[idx].clone());
                }
            }
        }
        out
    }

    fn default_ef_search(&self, k: usize) -> usize {
        self.l.max(k).max(64)
    }

    fn ef_search_for_recall_target(&self, k: usize, recall_target: f32) -> usize {
        if !(0.5..=1.0).contains(&recall_target) || recall_target.is_nan() {
            return self.default_ef_search(k);
        }
        let factor = if recall_target >= 0.99 {
            6
        } else if recall_target >= 0.95 {
            4
        } else if recall_target >= 0.90 {
            3
        } else if recall_target >= 0.80 {
            2
        } else {
            1
        };
        let beam = self.l.max(k).saturating_mul(factor).max(64);
        beam.min(self.ids.len().max(1))
    }

    fn insert_point(&mut self, point: &Point, vector_dim: usize) -> Result<()> {
        if vector_dim != self.vector_dim {
            return Err(crate::error::GaussError::DimensionMismatch {
                expected: self.vector_dim,
                actual: vector_dim,
            });
        }
        if self.id_to_idx.contains_key(&point.id) {
            return Ok(());
        }
        let v = pad_or_trim(&point.vector, self.vector_dim);
        let idx = self.ids.len();
        self.ids.push(point.id.clone());
        self.id_to_idx.insert(point.id.clone(), idx);
        self.vectors.push(v);
        self.neighbors.push(Vec::new());
        Ok(())
    }

    fn kind(&self) -> IndexKind {
        IndexKind::Vamana
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
        self.ids.len()
    }

    fn is_paged(&self) -> bool {
        false
    }
}

pub fn build(points: &[Point], params: &IndexParams) -> Box<dyn IndexBackend> {
    Box::new(VamanaBackend::build(points, params.vector_dim))
}

fn pad_or_trim(v: &[f32], dim: usize) -> Vec<f32> {
    let mut out = vec![0.0_f32; dim];
    let n = v.len().min(dim);
    out[..n].copy_from_slice(&v[..n]);
    out
}

/// Approximate medoid (point with smallest sum-of-distances to the corpus),
/// used only as the graph entry point — exactness is not required, just
/// reasonable centrality.
///
/// Exact medoid is O(N²) (every candidate vs every other), which dominates the
/// Vamana build at 50K+ and is the reason the index was never benched as a
/// default at scale. We sample `S ≈ 8·√N` candidates and evaluate each against
/// that same sample (O(S²) = O(N) work). A uniform sample's medoid concentrates
/// on the true medoid as N grows, so the entry point stays central while the
/// build cost drops from quadratic to linear. Small corpora keep the exact pass.
fn medoid(vectors: &[Vec<f32>]) -> Option<usize> {
    let n = vectors.len();
    if n == 0 {
        return None;
    }
    const EXACT_THRESHOLD: usize = 2048;
    if n <= EXACT_THRESHOLD {
        let all: Vec<usize> = (0..n).collect();
        return Some(medoid_over(vectors, &all));
    }
    let sample_size = (((n as f64).sqrt() * 8.0).ceil() as usize).clamp(1, n);
    let sample: Vec<usize> = deterministic_permutation(n, 0x4D45_D01D_5EED_u64)
        .into_iter()
        .take(sample_size)
        .collect();
    Some(medoid_over(vectors, &sample))
}

/// Exact medoid restricted to the candidate/reference index set `idxs`:
/// returns the `idxs` element with the smallest sum of squared-L2 distances to
/// every other `idxs` element. O(|idxs|²). Early-breaks once a running sum
/// exceeds the best seen.
fn medoid_over(vectors: &[Vec<f32>], idxs: &[usize]) -> usize {
    let mut best_idx = idxs[0];
    let mut best_sum = f32::INFINITY;
    for &i in idxs {
        let v = &vectors[i];
        let mut sum = 0.0_f32;
        for &j in idxs {
            if i == j {
                continue;
            }
            sum += squared_l2(v, &vectors[j]);
            if sum >= best_sum {
                break;
            }
        }
        if sum < best_sum {
            best_sum = sum;
            best_idx = i;
        }
    }
    best_idx
}

fn deterministic_permutation(n: usize, seed: u64) -> Vec<usize> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut keys: Vec<(u64, usize)> = (0..n)
        .map(|i| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state, i)
        })
        .collect();
    keys.sort_unstable_by_key(|&(k, _)| k);
    keys.into_iter().map(|(_, i)| i).collect()
}

fn greedy_search(
    target: usize,
    start: usize,
    l: usize,
    vectors: &[Vec<f32>],
    neighbors: &[Vec<usize>],
) -> Vec<usize> {
    greedy_search_by_vec(&vectors[target], start, l, vectors, neighbors)
}

fn greedy_search_by_vec(
    query: &[f32],
    start: usize,
    l: usize,
    vectors: &[Vec<f32>],
    neighbors: &[Vec<usize>],
) -> Vec<usize> {
    let n = vectors.len();
    if n == 0 || l == 0 {
        return Vec::new();
    }
    let start = start.min(n - 1);

    // Standard DiskANN / Vamana beam search. The min-heap pops points in
    // increasing distance order *among items that are in the heap at pop
    // time* — but the very first pop is always `start` (the only thing in
    // the heap before the first expansion), and `start` is only the closest
    // to the query by coincidence. The visit-order result list would
    // therefore put `start` at index 0 even when it isn't the nearest
    // neighbour, which breaks the top-k contract. The fix is to collect
    // `(distance_bits, idx)` pairs in pop order, then re-sort by distance
    // before returning so the caller gets closest-first ordering.
    let mut best: BinaryHeap<(std::cmp::Reverse<u32>, usize)> = BinaryHeap::new();
    let mut visited: HashSet<usize> = HashSet::with_capacity(l * 2);
    let start_dist = squared_l2(query, &vectors[start]).to_bits();
    best.push((std::cmp::Reverse(start_dist), start));
    visited.insert(start);

    let mut result: Vec<(u32, usize)> = Vec::with_capacity(l);
    while let Some((_, idx)) = best.pop() {
        let d_bits = squared_l2(query, &vectors[idx]).to_bits();
        result.push((d_bits, idx));
        if result.len() >= l {
            break;
        }
        for &nbr in &neighbors[idx] {
            if visited.insert(nbr) {
                let d_bits = squared_l2(query, &vectors[nbr]).to_bits();
                best.push((std::cmp::Reverse(d_bits), nbr));
            }
        }
    }
    // Re-sort by distance to honour the top-k contract. `to_bits()` is
    // monotonic for non-negative `f32` (squared_l2 is a sum of squares,
    // always ≥ 0), so the bit order matches the numeric order.
    result.sort_unstable_by_key(|&(d, _)| d);
    result.into_iter().map(|(_, idx)| idx).collect()
}

fn robust_prune(
    p: &[f32],
    pool: &[usize],
    vectors: &[Vec<f32>],
    r: usize,
    alpha: f32,
) -> Vec<usize> {
    if pool.is_empty() || r == 0 {
        return Vec::new();
    }
    let mut candidates: Vec<(f32, usize)> = pool
        .iter()
        .map(|&c| (squared_l2(p, &vectors[c]), c))
        .collect();
    candidates.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));

    let mut out: Vec<usize> = Vec::with_capacity(r);
    let mut out_dist: Vec<f32> = Vec::with_capacity(r);
    for (d_p_c, c) in candidates {
        if out.len() >= r {
            break;
        }
        let mut occluded = false;
        for (slot, &d_p_out) in out_dist.iter().enumerate() {
            if d_p_c <= alpha * d_p_out {
                let d_c_out = squared_l2(&vectors[c], &vectors[out[slot]]);
                if d_c_out < d_p_c {
                    occluded = true;
                    break;
                }
            }
        }
        if !occluded {
            out.push(c);
            out_dist.push(d_p_c);
        }
    }
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
    fn algorithm2_vamana_artifact_builds_cells_and_stitches_them() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let vamana_path = temp.path().join(VAMANA_SEGMENT_FILE);
        let vectors = (0..256).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 12, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_vamana_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &vamana_path,
        )
        .unwrap();

        let vamana = VamanaArtifact::open(&vamana_path, &ivf).unwrap();
        assert_eq!(vamana.len(), vectors.len());
        assert_eq!(vamana.vector_dim(), 12);
        assert_eq!(vamana.cells(), ivf.cells());
        assert_eq!(vamana.degree(), DEFAULT_R);

        let mut ordinal_cell = vec![usize::MAX; vectors.len()];
        for cell in 0..ivf.cells() {
            assert!(vamana.entry(cell).is_some());
            for posting in ivf.posting_range(cell).unwrap() {
                ordinal_cell[ivf.posting_ordinal(posting).unwrap() as usize] = cell;
            }
        }
        let mut cross_cell_edges = 0usize;
        for ordinal in 0..vectors.len() {
            let neighbors = vamana.neighbors(ordinal).unwrap();
            let mut visited_neighbors = Vec::new();
            vamana
                .visit_neighbors(ordinal, |neighbor| visited_neighbors.push(neighbor))
                .unwrap();
            assert_eq!(visited_neighbors, neighbors);
            assert!(neighbors.len() <= DEFAULT_R);
            cross_cell_edges += neighbors
                .iter()
                .filter(|neighbor| ordinal_cell[**neighbor as usize] != ordinal_cell[ordinal])
                .count();
        }
        assert!(
            cross_cell_edges >= ivf.cells(),
            "expected stitched cross-cell edges, got {cross_cell_edges}"
        );
        let connectivity = vamana.connectivity_profile(vectors.len()).unwrap();
        assert_eq!(connectivity.nodes, vectors.len());
        assert_eq!(connectivity.original_nodes, vectors.len());
        assert_eq!(connectivity.weak_components, 1);
        assert_eq!(connectivity.original_nodes_without_original_neighbors, 0);

        drop(vamana);

        let mut bytes = std::fs::read(&vamana_path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&vamana_path, bytes).unwrap();
        let error = VamanaArtifact::open(&vamana_path, &ivf).unwrap_err();
        assert!(matches!(error, GaussError::SegmentCorruption { .. }));
    }

    #[test]
    fn resumable_vamana_stops_after_completed_cell_when_cancelled() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let vamana_path = temp.path().join(VAMANA_SEGMENT_FILE);
        let cells_dir = temp.path().join("cells");
        let vectors = (0..256).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 12, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut completed = Vec::new();

        let error = write_vamana_artifact_resumable(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &vamana_path,
            VamanaResumeInput {
                cells_dir: &cells_dir,
                reusable_cells: &BTreeSet::new(),
                cancelled: Some(&cancelled),
            },
            &mut |cell, _| {
                completed.push(cell);
                cancelled.store(true, Ordering::Release);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, GaussError::ResourceExhausted(_)));
        assert_eq!(completed, [0]);
        assert!(
            cells_dir
                .join(crate::build_progress::cell_file_name(0))
                .is_file()
        );
        assert!(VamanaArtifact::open(&vamana_path, &ivf).is_err());
    }

    #[test]
    fn record_key_v3_preserves_v2_entries_and_adjacency() {
        use crate::index::ivf::{IVF_FILE, IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        let ivf_path = temp.path().join(IVF_FILE);
        let v2_path = temp.path().join("vamana-v2.gdx");
        let v3_path = temp.path().join("vamana-v3.gdx");
        let vectors = (0..256).map(|i| lcg_vector(i, 12)).collect::<Vec<_>>();
        write_ivf_artifact(vectors.as_slice(), 12, 8, &ivf_path).unwrap();
        let ivf = IvfArtifact::open(&ivf_path).unwrap();
        write_vamana_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::L2,
            &v2_path,
        )
        .unwrap();
        write_vamana_artifact(
            vectors.as_slice(),
            &ivf,
            crate::DistanceMetric::Cosine,
            &v3_path,
        )
        .unwrap();

        let v2 = VamanaArtifact::open(&v2_path, &ivf).unwrap();
        let v3 = VamanaArtifact::open(&v3_path, &ivf).unwrap();
        assert!(!v2.uses_rabitq_record_keys());
        assert!(v3.uses_rabitq_record_keys());

        let mut ordinal_to_record = vec![usize::MAX; ivf.len()];
        for record in 0..ivf.len() {
            ordinal_to_record[ivf.posting_ordinal(record).unwrap() as usize] = record;
        }
        for cell in 0..ivf.cells() {
            let v2_entry = v2.entry(cell).unwrap();
            let v3_entry = v3.entry(cell).unwrap() as usize;
            assert_eq!(ivf.posting_ordinal(v3_entry), Some(v2_entry));
        }
        for (ordinal, record) in ordinal_to_record.iter().copied().enumerate() {
            let v2_neighbors = v2.neighbors(ordinal).unwrap();
            let mut v3_neighbors = Vec::new();
            v3.visit_neighbor_keys(record, |neighbor| {
                v3_neighbors.push(ivf.posting_ordinal(neighbor as usize).unwrap());
            })
            .unwrap();
            assert_eq!(v3_neighbors, v2_neighbors);
        }
        assert_eq!(
            v3.ordinal_adjacency(&ivf).unwrap(),
            v2.ordinal_adjacency(&ivf).unwrap()
        );
        assert_eq!(
            v3.connectivity_profile_with_ivf(&ivf, vectors.len())
                .unwrap(),
            v2.connectivity_profile_with_ivf(&ivf, vectors.len())
                .unwrap()
        );

        let legacy_v3_path = temp.path().join("vamana-v3-legacy-magic.gdx");
        let mut legacy_v3 = std::fs::read(&v2_path).unwrap();
        legacy_v3[8..12].copy_from_slice(&3u32.to_le_bytes());
        let records_start = VAMANA_SEGMENT_HEADER_BYTES + ivf.cells() * 4;
        let record_bytes = 4 + DEFAULT_R * 4;
        let v2_rows = legacy_v3.clone();
        for record in 0..ivf.len() {
            let ordinal = ivf.posting_ordinal(record).unwrap() as usize;
            let source = records_start + ordinal * record_bytes;
            let target = records_start + record * record_bytes;
            legacy_v3[target..target + record_bytes]
                .copy_from_slice(&v2_rows[source..source + record_bytes]);
        }
        let mut crc = crc32fast::Hasher::new();
        crc.update(&legacy_v3[VAMANA_SEGMENT_HEADER_BYTES..]);
        legacy_v3[56..60].copy_from_slice(&crc.finalize().to_le_bytes());
        std::fs::write(&legacy_v3_path, legacy_v3).unwrap();
        let legacy_v3 = VamanaArtifact::open(&legacy_v3_path, &ivf).unwrap();
        assert!(!legacy_v3.uses_rabitq_record_keys());
        for cell in 0..ivf.cells() {
            assert_eq!(legacy_v3.entry(cell), v2.entry(cell));
        }
        for (ordinal, record) in ordinal_to_record.iter().copied().enumerate() {
            assert_eq!(legacy_v3.neighbors(ordinal), v2.neighbors(ordinal));
            let mut neighbor_ordinals = Vec::new();
            legacy_v3
                .visit_neighbor_keys(record, |neighbor| {
                    neighbor_ordinals.push(ivf.posting_ordinal(neighbor as usize).unwrap());
                })
                .unwrap();
            assert_eq!(neighbor_ordinals, v2.neighbors(ordinal).unwrap());
        }
        assert_eq!(
            legacy_v3.ordinal_adjacency(&ivf).unwrap(),
            v2.ordinal_adjacency(&ivf).unwrap()
        );
        assert_eq!(
            legacy_v3
                .connectivity_profile_with_ivf(&ivf, vectors.len())
                .unwrap(),
            v2.connectivity_profile_with_ivf(&ivf, vectors.len())
                .unwrap()
        );
    }

    #[test]
    fn stable_id_seed_preserves_topology_across_five_percent_growth() {
        use crate::index::ivf::{IvfArtifact, write_ivf_artifact};

        let temp = tempfile::tempdir().unwrap();
        // 16K is the smallest corpus that reproduced the rejected content-only
        // rebuild's ~80% neighbor loss while remaining practical in CI.
        let original_count = 16_384usize;
        let added = original_count * 5 / 100;
        let dim = 12;
        let original = (0..original_count)
            .map(|ordinal| lcg_vector(ordinal as u64, dim))
            .collect::<Vec<_>>();
        let baseline_ivf_path = temp.path().join("baseline-ivf.gdx");
        let baseline_vamana_path = temp.path().join("baseline-vamana.gdx");
        write_ivf_artifact(
            original.as_slice(),
            dim,
            (original_count as f64).sqrt().round() as usize,
            &baseline_ivf_path,
        )
        .unwrap();
        let baseline_ivf = IvfArtifact::open(&baseline_ivf_path).unwrap();
        write_vamana_artifact(
            original.as_slice(),
            &baseline_ivf,
            crate::DistanceMetric::L2,
            &baseline_vamana_path,
        )
        .unwrap();
        let baseline = VamanaArtifact::open(&baseline_vamana_path, &baseline_ivf).unwrap();
        let mut seed = StableGraphSeed::new(original_count + added);
        for ordinal in 0..original_count {
            seed.insert(ordinal, baseline.neighbors(ordinal).unwrap())
                .unwrap();
        }

        let mut candidate_vectors = original;
        candidate_vectors
            .extend((0..added).map(|ordinal| lcg_vector(100_000 + ordinal as u64, dim)));
        let candidate_ivf_path = temp.path().join("candidate-ivf.gdx");
        let candidate_vamana_path = temp.path().join("candidate-vamana.gdx");
        write_ivf_artifact(
            candidate_vectors.as_slice(),
            dim,
            (candidate_vectors.len() as f64).sqrt().round() as usize,
            &candidate_ivf_path,
        )
        .unwrap();
        let candidate_ivf = IvfArtifact::open(&candidate_ivf_path).unwrap();
        write_vamana_artifact_seeded(
            candidate_vectors.as_slice(),
            &candidate_ivf,
            crate::DistanceMetric::L2,
            &candidate_vamana_path,
            &seed,
        )
        .unwrap();
        let candidate = VamanaArtifact::open(&candidate_vamana_path, &candidate_ivf).unwrap();

        let mut losses = Vec::with_capacity(original_count);
        for ordinal in 0..original_count {
            let baseline_neighbors = baseline
                .neighbors(ordinal)
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>();
            let retained = candidate
                .neighbors(ordinal)
                .unwrap()
                .into_iter()
                .filter(|neighbor| baseline_neighbors.contains(neighbor))
                .count();
            losses.push(1.0 - retained as f64 / baseline_neighbors.len() as f64);
        }
        losses.sort_by(f64::total_cmp);
        let mean = losses.iter().sum::<f64>() / losses.len() as f64;
        let p95 = losses[(losses.len() * 95).div_ceil(100) - 1];
        assert!(mean <= 0.055, "mean original-neighbor loss {mean:.6}");
        assert!(p95 <= 0.25, "p95 original-neighbor loss {p95:.6}");
        let connectivity = candidate.connectivity_profile(original_count).unwrap();
        assert_eq!(connectivity.weak_components, 1);
        assert_eq!(connectivity.original_nodes_without_original_neighbors, 0);
    }

    #[test]
    fn build_with_zero_points_is_empty() {
        let backend = VamanaBackend::build(&[], 16);
        assert_eq!(backend.indexed_points(), 0);
        assert!(
            backend
                .candidate_ids_with_ef(&[0.0; 16], 10, None)
                .is_empty()
        );
    }

    #[test]
    fn build_with_one_point_returns_self() {
        let backend = VamanaBackend::build(&[p("a", vec![1.0; 16])], 16);
        assert_eq!(backend.indexed_points(), 1);
        let hits = backend.candidate_ids_with_ef(&[0.5; 16], 1, None);
        assert_eq!(hits, vec!["a".to_string()]);
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
        assert_eq!(idx.kind(), IndexKind::Vamana);
        assert_eq!(idx.indexed_points(), 2);
        assert!(idx.contains("a"));
        assert!(!idx.contains("missing"));
        assert!(!idx.is_paged());
        assert!(!idx.is_hnsw());
        assert!(!idx.is_flat_fallback());
        assert!(!idx.uses_sq8());
    }

    #[test]
    fn search_finds_self_on_orthonormal_basis() {
        let dim = 16;
        let n = 16;
        let points: Vec<Point> = (0..n)
            .map(|i| {
                let mut v = vec![0.0; dim];
                v[i] = 1.0;
                p(&format!("p{i}"), v)
            })
            .collect();
        let backend = VamanaBackend::build(&points, dim);
        for i in 0..n {
            let mut q = vec![0.0; dim];
            q[i] = 1.0;
            let hits = backend.candidate_ids_with_ef(&q, 1, None);
            assert_eq!(
                hits.first().map(String::as_str),
                Some(format!("p{i}").as_str())
            );
        }
    }

    #[test]
    fn recall_at_10_above_0_95_on_random_500x64() {
        let dim = 64;
        let n = 500;
        let points: Vec<Point> = (0..n)
            .map(|i| p(&format!("p{i}"), lcg_vector(i as u64, dim)))
            .collect();
        let backend = VamanaBackend::build(&points, dim);
        let mut hits = 0usize;
        for i in 0..n {
            let q = lcg_vector(i as u64, dim);
            let result = backend.candidate_ids_with_ef(&q, 10, None);
            if result.iter().any(|id| id == &format!("p{i}")) {
                hits += 1;
            }
        }
        let recall = hits as f32 / n as f32;
        assert!(
            recall >= 0.95,
            "vamana recall@10 = {recall:.4} below 0.95 (hits={hits}/{n})"
        );
    }

    #[test]
    fn medoid_over_picks_geometric_center() {
        // Three points on a line; the middle one has the smallest sum of
        // squared distances and must be chosen.
        let vectors = vec![vec![0.0_f32], vec![1.0_f32], vec![5.0_f32]];
        assert_eq!(medoid_over(&vectors, &[0, 1, 2]), 1);
    }

    #[test]
    fn sampled_medoid_build_holds_recall_above_threshold() {
        // N beyond EXACT_THRESHOLD (2048) so the sampled-medoid path runs.
        // A usable (central) entry point must keep self-recall high.
        let dim = 32;
        let n: usize = 2300;
        let points: Vec<Point> = (0..n)
            .map(|i| p(&format!("p{i}"), lcg_vector(i as u64, dim)))
            .collect();
        let backend = VamanaBackend::build(&points, dim);
        let mut hits = 0usize;
        for i in (0..n).step_by(5) {
            let q = lcg_vector(i as u64, dim);
            let result = backend.candidate_ids_with_ef(&q, 10, None);
            if result.iter().any(|id| id == &format!("p{i}")) {
                hits += 1;
            }
        }
        let probes = n.div_ceil(5);
        let recall = hits as f32 / probes as f32;
        assert!(
            recall >= 0.90,
            "sampled-medoid vamana recall@10 = {recall:.4} below 0.90 (hits={hits}/{probes})"
        );
    }

    #[test]
    fn ef_search_curve_is_monotonic() {
        let backend = VamanaBackend::build(&[p("x", vec![1.0; 16])], 16).with_params(32, 100, 1.2);
        let high = backend.ef_search_for_recall_target(10, 0.99);
        let mid = backend.ef_search_for_recall_target(10, 0.95);
        let low = backend.ef_search_for_recall_target(10, 0.80);
        assert!(high >= mid && mid >= low, "{high} {mid} {low}");
    }

    #[test]
    fn insert_point_appends_and_dim_rejected() {
        let mut backend = VamanaBackend::build(&[p("a", vec![1.0; 16])], 16);
        backend.insert_point(&p("b", vec![-1.0; 16]), 16).unwrap();
        assert_eq!(backend.indexed_points(), 2);
        assert!(backend.contains("b"));
        backend.insert_point(&p("a", vec![0.0; 16]), 16).unwrap();
        assert_eq!(backend.indexed_points(), 2);

        let err = backend
            .insert_point(&p("c", vec![-1.0; 16]), 32)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::error::GaussError::DimensionMismatch { .. }
        ));
    }

    #[test]
    fn robust_prune_respects_r_cap() {
        let dim = 4;
        let p_vec = vec![0.0, 0.0, 0.0, 0.0];
        let candidates: Vec<Vec<f32>> = (0..20)
            .map(|i| {
                let mut v = vec![0.0; dim];
                v[i % dim] = (i as f32) * 0.01 + 0.001;
                v
            })
            .collect();
        let pool: Vec<usize> = (0..candidates.len()).collect();
        let pruned = robust_prune(&p_vec, &pool, &candidates, 5, 1.2);
        assert!(pruned.len() <= 5);
    }

    #[test]
    fn local_graph_reverse_edges_respect_degree_budget() {
        let vectors = (0..512)
            .map(|row| {
                (0..16)
                    .map(|dim| ((row * 37 + dim * 19) % 997) as f32 / 997.0)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (_, neighbors) = build_local_graph(&vectors, 8, 32, 1.2);
        assert!(neighbors.iter().all(|row| row.len() <= 8));
    }
}
