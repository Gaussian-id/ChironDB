//! Mmap-backed H²QG searcher for LS-Vec Algorithm 2 segments.

use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use chirondb_types::distance::squared_l2;

use crate::h2qg::OrdF32;
use crate::index::diskann::{DISKANN_FILE, DiskAnnArtifact, DiskAnnIoStats};
use crate::index::ivf::{IVF_FILE, IvfArtifact, VectorSource};
use crate::index::rabitq::{
    RABITQ_FILE, RabitqArtifact, RabitqDistanceEstimate, RabitqDistanceTable,
    RabitqGlobalQueryTable, RabitqRecord, migrate_legacy_v1_artifact,
};
use crate::index::search_metrics::record_search_metric;
use crate::index::vamana::DEFAULT_R;
use crate::index::vamana::{VAMANA_SEGMENT_FILE, VamanaArtifact};
use crate::index::{
    FilterPredicate, IndexBackend, IndexKind, OrdinalFilterPredicate, rotate_for_cascade,
};
use crate::{DistanceMetric, GaussError, Point, Result};

const L1_INFLATION: usize = 8;
/// Lower-tier cosine partitions overlap heavily on the unit sphere:
/// maximum-radius routing admitted every GloVe cell, while fixed sqrt(nlist)
/// probing missed boundary neighbors. Preserve the nominal `(nlist / 2) * k`
/// extra-cell candidate budget by searching the nearest quarter of cells with
/// a `2 * k` beam. This trades redundant coarse breadth for enough local graph
/// depth to retain the measured recall floor. It is an engine invariant, not a
/// public nprobe knob; strict cosine SLOs retain radius-safe routing.
const COSINE_GRAPH_CELL_DIVISOR: usize = 4;
const COSINE_GRAPH_BEAM_MULTIPLIER: usize = 2;
/// The measured 0.95/0.97 product operating point.
pub const RESCORE_INFLATION: usize = 4;
/// Below this size an exact mmap scan is both cheap and materially safer than
/// compressing the candidate path. The legacy 10K HNSW threshold was calibrated
/// for a different graph; LS-VEC's 2-bit navigation measured below the product
/// recall floor at 12K, so small sealed segments stay exact.
const LSVEC_EXACT_THRESHOLD: usize = 50_000;

#[derive(Clone, Copy, Debug)]
struct QuantizedCandidate {
    distance: RabitqDistanceEstimate,
    ordinal: usize,
}

#[inline]
fn pack_graph_key(distance: f32, record: usize) -> u64 {
    debug_assert!(distance.is_finite() && distance >= 0.0);
    debug_assert!(u32::try_from(record).is_ok());
    (u64::from(distance.to_bits()) << 32) | u64::from(record as u32)
}

#[inline]
fn unpack_graph_key(key: u64) -> (f32, usize) {
    (f32::from_bits((key >> 32) as u32), key as u32 as usize)
}

struct RabitqQueryTables {
    global: Option<RabitqGlobalQueryTable>,
    cells: Vec<Option<RabitqDistanceTable>>,
}

#[derive(Clone, Copy)]
struct CandidateFilter<'a> {
    string: Option<&'a dyn FilterPredicate>,
    ordinal: Option<&'a dyn OrdinalFilterPredicate>,
}

impl CandidateFilter<'_> {
    #[inline(always)]
    fn allows<const FILTERED: bool>(&self, index: &IvfSegmentIndex, ordinal: usize) -> bool {
        if !FILTERED {
            return true;
        }
        if let Some(predicate) = self.ordinal {
            let Ok(ordinal) = u32::try_from(ordinal) else {
                return false;
            };
            return predicate.matches_ordinal(&index.segment_id, ordinal);
        }
        self.string.is_none_or(|predicate| {
            index
                .store
                .id(ordinal)
                .is_some_and(|id| predicate.matches(id))
        })
    }

    #[inline(always)]
    fn navigable<const FILTERED: bool>(&self, index: &IvfSegmentIndex, ordinal: usize) -> bool {
        if !FILTERED {
            return true;
        }
        if let Some(predicate) = self.ordinal {
            let Ok(ordinal) = u32::try_from(ordinal) else {
                return false;
            };
            return predicate.navigable_ordinal(&index.segment_id, ordinal);
        }
        self.string.is_none_or(|predicate| {
            index
                .store
                .id(ordinal)
                .is_some_and(|id| predicate.navigable(id))
        })
    }
}

enum VisitedOrdinals {
    Dense(Vec<bool>),
    Sparse(HashSet<usize>),
}

impl VisitedOrdinals {
    fn insert(&mut self, ordinal: usize) -> bool {
        match self {
            Self::Dense(visited) => {
                let first = !visited[ordinal];
                visited[ordinal] = true;
                first
            }
            Self::Sparse(visited) => visited.insert(ordinal),
        }
    }
}

/// L0 IVF → L1 residual RaBitQ-2b → L2 stitched Vamana → L3 primary rerank.
#[derive(Debug)]
pub struct IvfSegmentIndex {
    segment_id: String,
    ivf: IvfArtifact,
    rabitq: RabitqArtifact,
    vamana: Option<VamanaArtifact>,
    diskann: Option<Arc<DiskAnnArtifact>>,
    store: IvfVectorStore,
    centroids: Vec<Vec<f32>>,
    rotated_centroids: Vec<Vec<f32>>,
    metric: DistanceMetric,
}

#[derive(Debug)]
enum IvfVectorStore {
    Primary(Arc<crate::seal::V4Store>),
    Named(Arc<crate::seal::NamedV4Store>),
}

impl IvfVectorStore {
    fn len(&self) -> usize {
        match self {
            Self::Primary(store) => store.len(),
            Self::Named(store) => store.len(),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Primary(store) => store.is_empty(),
            Self::Named(store) => store.is_empty(),
        }
    }

    fn id(&self, ordinal: usize) -> Option<&str> {
        match self {
            Self::Primary(store) => store.id(ordinal),
            Self::Named(store) => store.id(ordinal),
        }
    }

    fn ordinal(&self, id: &str) -> Option<usize> {
        match self {
            Self::Primary(store) => store.ordinal(id),
            Self::Named(store) => store.ordinal(id),
        }
    }

    fn vector_cow(&self, ordinal: usize) -> Option<Cow<'_, [f32]>> {
        match self {
            Self::Primary(store) => store.vector_cow(ordinal),
            Self::Named(store) => store.vector_cow(ordinal),
        }
    }
}

impl VectorSource for IvfVectorStore {
    fn len(&self) -> usize {
        self.len()
    }

    fn vector(&self, ordinal: usize) -> Result<Cow<'_, [f32]>> {
        self.vector_cow(ordinal)
            .ok_or_else(|| GaussError::InvalidRequest("vector ordinal out of range".to_string()))
    }
}

impl IvfSegmentIndex {
    pub fn open(
        dir: &Path,
        store: Arc<crate::seal::V4Store>,
        metric: DistanceMetric,
    ) -> Result<Self> {
        Self::open_files(
            &dir.join(IVF_FILE),
            &dir.join(RABITQ_FILE),
            &dir.join(VAMANA_SEGMENT_FILE),
            None,
            IvfVectorStore::Primary(store),
            metric,
        )
    }

    pub fn open_cold(
        dir: &Path,
        store: Arc<crate::seal::V4Store>,
        metric: DistanceMetric,
    ) -> Result<Self> {
        let diskann = store.diskann().map_or_else(
            || {
                DiskAnnArtifact::open(&dir.join(DISKANN_FILE), store.len(), store.vector_dim())
                    .map(Arc::new)
            },
            Ok,
        )?;
        Self::open_files(
            &dir.join(IVF_FILE),
            &dir.join(RABITQ_FILE),
            &dir.join(VAMANA_SEGMENT_FILE),
            Some(diskann),
            IvfVectorStore::Primary(store),
            metric,
        )
    }

    pub(crate) fn open_named(dir: &Path, name: &str, metric: DistanceMetric) -> Result<Self> {
        Self::open_files(
            &dir.join(crate::seal::named_ivf_file(name)),
            &dir.join(crate::seal::named_rabitq_file(name)),
            &dir.join(crate::seal::named_vamana_file(name)),
            None,
            IvfVectorStore::Named(Arc::new(crate::seal::NamedV4Store::open(dir, name)?)),
            metric,
        )
    }

    fn open_files(
        ivf_path: &Path,
        rabitq_path: &Path,
        vamana_path: &Path,
        diskann: Option<Arc<DiskAnnArtifact>>,
        store: IvfVectorStore,
        metric: DistanceMetric,
    ) -> Result<Self> {
        let segment_id = ivf_path
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| GaussError::InvalidRequest("segment index has no parent id".into()))?;
        let ivf = IvfArtifact::open(ivf_path)?;
        if ivf.len() != store.len() {
            return Err(GaussError::SegmentCorruption {
                path: ivf_path.display().to_string(),
                message: "Algorithm 2 index count disagrees with v4 store".to_string(),
            });
        }
        migrate_legacy_v1_artifact(&store, &ivf, metric, rabitq_path)?;
        let rabitq = RabitqArtifact::open(rabitq_path, &ivf)?;
        let (vamana, diskann) = if let Some(diskann) = diskann {
            (None, Some(diskann))
        } else {
            (Some(VamanaArtifact::open(vamana_path, &ivf)?), None)
        };
        let centroids = ivf.centroids();
        let rotated_centroids = centroids
            .iter()
            .map(|centroid| rotate_for_cascade(centroid))
            .collect();
        Ok(Self {
            segment_id,
            ivf,
            rabitq,
            vamana,
            diskann,
            store,
            centroids,
            rotated_centroids,
            metric,
        })
    }

    fn search(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        self.search_controlled(query, k, ef_search, recall_target, filter, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn search_controlled(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        ordinal_filter: Option<&dyn OrdinalFilterPredicate>,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<String> {
        if k == 0 || query.len() != self.vector_dim() || self.store.is_empty() {
            return Vec::new();
        }
        if cancellation_requested(cancelled) {
            return Vec::new();
        }
        let mut prepared = query.to_vec();
        if self.metric == DistanceMetric::Cosine {
            crate::search::normalize(&mut prepared);
        }
        let filter = CandidateFilter {
            string: filter,
            ordinal: ordinal_filter,
        };
        // Small sealed segments keep LS-VEC's persisted format but use an
        // exact candidate pass. Below the measured LS-VEC threshold, a graph
        // cannot repay approximation error or traversal overhead.
        if self.store.len() < LSVEC_EXACT_THRESHOLD || recall_target >= 1.0 {
            return if filter.string.is_none() && filter.ordinal.is_none() {
                self.search_exact_controlled::<false>(query, k, filter, cancelled)
            } else {
                self.search_exact_controlled::<true>(query, k, filter, cancelled)
            };
        }
        let rescore_inflation =
            rescore_inflation_for_recall_target(k, recall_target).unwrap_or(RESCORE_INFLATION);
        if filter.string.is_none() && filter.ordinal.is_none() {
            self.search_compressed_controlled::<false>(
                query,
                &prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                cancelled,
            )
            .0
        } else {
            self.search_compressed_controlled::<true>(
                query,
                &prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                cancelled,
            )
            .0
        }
    }

    #[cfg(test)]
    fn search_exact(
        &self,
        query: &[f32],
        k: usize,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        let filter = CandidateFilter {
            string: filter,
            ordinal: None,
        };
        if filter.string.is_some() {
            self.search_exact_controlled::<true>(query, k, filter, None)
        } else {
            self.search_exact_controlled::<false>(query, k, filter, None)
        }
    }

    fn search_exact_controlled<const FILTERED: bool>(
        &self,
        query: &[f32],
        k: usize,
        filter: CandidateFilter<'_>,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<String> {
        let mut exact = Vec::new();
        for ordinal in 0..self.store.len() {
            if cancellation_requested(cancelled) {
                break;
            }
            if !filter.allows::<FILTERED>(self, ordinal) {
                record_search_metric!(FilterRejections, 1);
                continue;
            }
            if let Some(distance) = self.exact_distance(query, ordinal) {
                exact.push((distance, ordinal));
            }
        }
        keep_nearest(&mut exact, k);
        exact
            .into_iter()
            .filter_map(|(_, ordinal)| self.store.id(ordinal).map(str::to_string))
            .collect()
    }

    #[cfg(test)]
    fn search_compressed(
        &self,
        query: &[f32],
        prepared: &[f32],
        k: usize,
        ef_search: Option<usize>,
        rescore_inflation: usize,
        filter: Option<&dyn FilterPredicate>,
    ) -> (Vec<String>, usize) {
        let filter = CandidateFilter {
            string: filter,
            ordinal: None,
        };
        if filter.string.is_some() {
            self.search_compressed_controlled::<true>(
                query,
                prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                None,
            )
        } else {
            self.search_compressed_controlled::<false>(
                query,
                prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                None,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn search_compressed_controlled<const FILTERED: bool>(
        &self,
        query: &[f32],
        prepared: &[f32],
        k: usize,
        ef_search: Option<usize>,
        rescore_inflation: usize,
        filter: CandidateFilter<'_>,
        cancelled: Option<&AtomicBool>,
    ) -> (Vec<String>, usize) {
        if self.rabitq.uses_global_query_table() {
            self.search_compressed_controlled_for_basis::<true, FILTERED>(
                query,
                prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                cancelled,
            )
        } else {
            self.search_compressed_controlled_for_basis::<false, FILTERED>(
                query,
                prepared,
                k,
                ef_search,
                rescore_inflation,
                filter,
                cancelled,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn search_compressed_controlled_for_basis<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        query: &[f32],
        prepared: &[f32],
        k: usize,
        ef_search: Option<usize>,
        rescore_inflation: usize,
        filter: CandidateFilter<'_>,
        cancelled: Option<&AtomicBool>,
    ) -> (Vec<String>, usize) {
        debug_assert_eq!(GLOBAL, self.rabitq.uses_global_query_table());
        if cancellation_requested(cancelled) {
            return (Vec::new(), 0);
        }
        let ef = ef_search
            .unwrap_or_else(|| self.default_ef_search(k))
            .max(k)
            .min(self.store.len());
        // L0: rank coarse centroids, probing at least sqrt(nlist) and enough
        // postings to feed the bounded L1 pool.
        let mut cells = self
            .centroids
            .iter()
            .enumerate()
            .map(|(cell, centroid)| (squared_l2(prepared, centroid), cell))
            .collect::<Vec<_>>();
        cells.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let min_probe = ((self.cells() as f64).sqrt().ceil() as usize).clamp(1, self.cells());
        let posting_target = ef.saturating_mul(L1_INFLATION).max(k);
        let mut selected_cells = Vec::new();
        let mut posting_count = 0usize;
        for &(_, cell) in &cells {
            if cancellation_requested(cancelled) {
                return (Vec::new(), 0);
            }
            posting_count += self.ivf.posting_range(cell).map_or(0, |range| range.len());
            selected_cells.push(cell);
            if selected_cells.len() >= min_probe && posting_count >= posting_target {
                break;
            }
        }

        // L1: resident L2 segments navigate the persisted mini-Vamana inside
        // each selected cell. A cell can contribute at most k final winners.
        // The same analytical rho*k confidence floor used by exact rerank
        // gives its approximate graph enough search width without exhaustively
        // RaBitQ-scoring every posting.
        //
        // Cosine retains the exhaustive selected-cell pass before its broader
        // cell-graph routing below: correlated angular data measured too close
        // to the recall contract when both stages used approximate traversal.
        // Cold DiskANN segments retain the posting scan because their graph
        // pages are fetched lazily and do not expose the persisted cell entry
        // points used by the resident Vamana artifact.
        let rotated_query = rotate_for_cascade(prepared);
        let mut tables = RabitqQueryTables {
            global: GLOBAL
                .then(|| self.rabitq.prepare_global_query_table(&rotated_query))
                .flatten(),
            cells: (0..self.cells()).map(|_| None).collect(),
        };
        debug_assert_eq!(
            tables.global.is_some(),
            self.rabitq.uses_global_query_table()
        );
        let mut l1 = if let (DistanceMetric::L2, Some(vamana)) = (self.metric, &self.vamana) {
            let cell_width = k.saturating_mul(rescore_inflation).max(k);
            // Vec<bool> is bit-packed: one bit per resident ordinal (125 KiB
            // at SIFT1M) and direct indexing avoids hashing every graph edge.
            // Cold DiskANN segments take the posting-scan branch below.
            let mut visited = VisitedOrdinals::Dense(vec![false; self.store.len()]);
            let mut candidates =
                Vec::with_capacity(selected_cells.len().saturating_mul(cell_width));
            for &cell in &selected_cells {
                if cancellation_requested(cancelled) {
                    return (Vec::new(), 0);
                }
                let Some(entry) = vamana.entry(cell).map(|ordinal| ordinal as usize) else {
                    continue;
                };
                candidates.extend(self.score_cell_graph::<GLOBAL, FILTERED>(
                    entry,
                    cell,
                    cell_width,
                    &rotated_query,
                    filter,
                    &mut tables,
                    &mut visited,
                    cancelled,
                ));
            }
            candidates
        } else {
            self.score_cells_controlled::<GLOBAL, FILTERED>(
                &selected_cells,
                &rotated_query,
                filter,
                &mut tables,
                cancelled,
            )
        };
        if cancellation_requested(cancelled) {
            return (Vec::new(), 0);
        }
        let uses_cosine_cell_graph = self.metric == DistanceMetric::Cosine
            && self.vamana.is_some()
            && rescore_inflation == RESCORE_INFLATION;
        if uses_cosine_cell_graph {
            let vamana = self.vamana.as_ref().expect("checked cosine Vamana");
            let mut selected = vec![false; self.cells()];
            for &cell in &selected_cells {
                selected[cell] = true;
            }
            let mut local_visited = VisitedOrdinals::Dense(vec![false; self.store.len()]);
            let graph_cells = self.cells().div_ceil(COSINE_GRAPH_CELL_DIVISOR);
            for &(_, cell) in cells.iter().take(graph_cells) {
                if selected[cell] {
                    continue;
                }
                let Some(entry) = vamana.entry(cell).map(|ordinal| ordinal as usize) else {
                    continue;
                };
                l1.extend(self.score_cell_graph::<GLOBAL, FILTERED>(
                    entry,
                    cell,
                    k.saturating_mul(COSINE_GRAPH_BEAM_MULTIPLIER),
                    &rotated_query,
                    filter,
                    &mut tables,
                    &mut local_visited,
                    cancelled,
                ));
                if cancellation_requested(cancelled) {
                    return (Vec::new(), 0);
                }
            }
        }
        let navigation_width = if uses_cosine_cell_graph {
            let width = confidence_rescore_limit(&mut l1, k, ef.max(k));
            l1.truncate(width);
            width
        } else {
            keep_quantized_by_lower_bound(&mut l1, ef.max(k));
            ef.max(k)
        };
        if l1.is_empty() {
            return (Vec::new(), 0);
        }

        // The first candidates' RaBitQ upper confidence bounds give an upper
        // bound on the kth routing distance without touching the f32 store.
        // A cell can be pruned only when its centroid/radius lower bound is
        // strictly worse. This is valid for squared L2 directly and for
        // cosine after normalization; raw dot product has no metric-ball
        // lower bound. L2's measured 0.95/0.97 tier stays on bounded
        // IVF/Vamana. Cold cosine segments and stricter L2 SLOs retain
        // radius-safe routing; hot cosine segments use the bounded cell graph
        // above. V1 IVF artifacts have no radii and keep fixed probing until
        // resealed.
        if !uses_cosine_cell_graph
            && radius_routing_enabled(
                self.metric,
                self.ivf.cell_radius(0).is_some(),
                rescore_inflation,
            )
        {
            let upper_bound = l1
                .iter()
                .take(k)
                .map(|candidate| candidate.distance.upper_bound)
                .reduce(f32::max);
            let upper_bound = if l1.len() >= k {
                upper_bound.unwrap_or(f32::INFINITY)
            } else {
                f32::INFINITY
            };
            let mut already_selected = vec![false; self.cells()];
            for &cell in &selected_cells {
                already_selected[cell] = true;
            }
            let extra_cells = cells
                .iter()
                .filter_map(|&(centroid_distance, cell)| {
                    if already_selected[cell] {
                        return None;
                    }
                    let radius = self.ivf.cell_radius(cell)?;
                    let gap = (centroid_distance.sqrt() - radius).max(0.0);
                    let lower_bound = gap * gap;
                    (lower_bound <= upper_bound * (1.0 + 8.0 * f32::EPSILON)).then_some(cell)
                })
                .collect::<Vec<_>>();
            if !extra_cells.is_empty() {
                l1.extend(self.score_cells_controlled::<GLOBAL, FILTERED>(
                    &extra_cells,
                    &rotated_query,
                    filter,
                    &mut tables,
                    cancelled,
                ));
                if cancellation_requested(cancelled) {
                    return (Vec::new(), 0);
                }
                keep_quantized_by_lower_bound(&mut l1, ef.max(k));
            }
        }

        // L2: ordinary RaBitQ winners seed a bounded stitched-Vamana beam.
        // Lower-tier hot cosine has already traversed persisted cell-local
        // Vamana graphs across its complete engine-owned routing budget and
        // retained every bound-competitive survivor. Hand that set directly
        // to L3 instead of traversing the same graph records again.
        let mut bounded = if uses_cosine_cell_graph {
            l1
        } else if self
            .vamana
            .as_ref()
            .is_some_and(VamanaArtifact::uses_rabitq_record_keys)
        {
            self.navigate_record_graph::<GLOBAL, FILTERED>(
                &l1,
                navigation_width,
                &rotated_query,
                filter,
                &mut tables,
                cancelled,
            )
        } else {
            // Every graph hop is scored from the resident 2-bit code and
            // per-vector factors; f32 vector pages remain untouched. Resident
            // Vamana ordinals use a compact bitmap, while cold DiskANN keeps a
            // sparse set to avoid a corpus-sized allocation.
            let mut visited = if self.vamana.is_some() {
                VisitedOrdinals::Dense(vec![false; self.store.len()])
            } else {
                VisitedOrdinals::Sparse(HashSet::with_capacity(navigation_width.saturating_mul(4)))
            };
            let mut candidates = BinaryHeap::<Reverse<(OrdF32, usize)>>::new();
            let mut navigation = BinaryHeap::<(OrdF32, usize)>::new();
            let mut results = BinaryHeap::<(OrdF32, usize)>::new();
            for candidate in l1.iter().take(navigation_width) {
                if self.store.id(candidate.ordinal).is_none() {
                    continue;
                }
                if !filter.navigable::<FILTERED>(self, candidate.ordinal) {
                    continue;
                }
                if visited.insert(candidate.ordinal) {
                    candidates.push(Reverse((
                        OrdF32(candidate.distance.estimate),
                        candidate.ordinal,
                    )));
                    navigation.push((OrdF32(candidate.distance.estimate), candidate.ordinal));
                    if filter.allows::<FILTERED>(self, candidate.ordinal) {
                        results.push((OrdF32(candidate.distance.estimate), candidate.ordinal));
                    }
                }
            }
            while let Some(Reverse((OrdF32(candidate_distance), ordinal))) = candidates.pop() {
                if cancellation_requested(cancelled) {
                    return (Vec::new(), 0);
                }
                let worst = navigation.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                if navigation.len() >= navigation_width && candidate_distance > worst {
                    break;
                }
                self.visit_neighbors(ordinal, |neighbor| {
                    if cancellation_requested(cancelled) {
                        return;
                    }
                    let neighbor = neighbor as usize;
                    if self.store.id(neighbor).is_none() {
                        return;
                    }
                    if !filter.navigable::<FILTERED>(self, neighbor) || !visited.insert(neighbor) {
                        return;
                    }
                    if let Some(distance) =
                        self.quantized_distance::<GLOBAL>(neighbor, &rotated_query, &mut tables)
                    {
                        let worst = navigation.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                        if navigation.len() < navigation_width || distance < worst {
                            candidates.push(Reverse((OrdF32(distance), neighbor)));
                            navigation.push((OrdF32(distance), neighbor));
                            if navigation.len() > navigation_width {
                                navigation.pop();
                            }
                        }
                        if filter.allows::<FILTERED>(self, neighbor) {
                            let result_worst =
                                results.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                            if results.len() < navigation_width || distance < result_worst {
                                results.push((OrdF32(distance), neighbor));
                                if results.len() > navigation_width {
                                    results.pop();
                                }
                            }
                        }
                    }
                });
            }

            results
                .into_iter()
                .filter_map(|(_, ordinal)| {
                    self.quantized_distance_estimate::<GLOBAL>(ordinal, &rotated_query, &mut tables)
                        .map(|distance| QuantizedCandidate { distance, ordinal })
                })
                .collect::<Vec<_>>()
        };

        // L3: rho*k is the analytical floor, not a hard truncation. Preserve
        // every survivor whose RaBitQ lower bound can still beat the kth
        // smallest upper bound, then touch only that exact-vector frontier.
        let rescore_floor = k.saturating_mul(rescore_inflation).max(k);
        let rescore_limit = confidence_rescore_limit(&mut bounded, k, rescore_floor);
        let rerank_ordinals = bounded
            .into_iter()
            .take(rescore_limit)
            .map(|candidate| candidate.ordinal)
            .collect::<Vec<_>>();
        if cancellation_requested(cancelled) {
            return (Vec::new(), 0);
        }
        let mut rescored: Vec<(f32, usize)> = if let Some(diskann) = &self.diskann {
            diskann
                .vectors(&rerank_ordinals)
                .into_iter()
                .zip(rerank_ordinals)
                .filter_map(|(vector, ordinal)| {
                    vector
                        .and_then(|vector| self.distance_to_vector(query, &vector))
                        .map(|distance| (distance, ordinal))
                })
                .collect()
        } else {
            rerank_ordinals
                .into_iter()
                .filter_map(|ordinal| {
                    self.exact_distance(query, ordinal)
                        .map(|distance| (distance, ordinal))
                })
                .collect()
        };
        let exact_distance_calls = rescored.len();
        keep_nearest(&mut rescored, k);
        let ids = rescored
            .into_iter()
            .filter_map(|(_, ordinal)| self.store.id(ordinal).map(str::to_string))
            .collect();
        (ids, exact_distance_calls)
    }

    fn exact_distance(&self, query: &[f32], ordinal: usize) -> Option<f32> {
        if let Some(diskann) = &self.diskann {
            return diskann
                .vector(ordinal)
                .and_then(|vector| self.distance_to_vector(query, &vector));
        }
        let vector = self.store.vector_cow(ordinal)?;
        self.distance_to_vector(query, &vector)
    }

    fn distance_to_vector(&self, query: &[f32], vector: &[f32]) -> Option<f32> {
        match self.metric {
            DistanceMetric::L2 => Some(squared_l2(query, vector)),
            metric => metric.score(query, vector).ok().map(|score| -score),
        }
        .inspect(|_| {
            record_search_metric!(ExactReranks, 1);
        })
    }

    #[cfg(test)]
    fn neighbors(&self, ordinal: usize) -> Option<Vec<u32>> {
        if let Some(diskann) = &self.diskann {
            diskann.neighbors(ordinal)
        } else {
            self.vamana.as_ref()?.neighbors(ordinal)
        }
    }

    fn visit_neighbors(&self, ordinal: usize, mut visit: impl FnMut(u32)) {
        if let Some(diskann) = &self.diskann {
            for neighbor in diskann.neighbors(ordinal).unwrap_or_default() {
                visit(neighbor);
            }
        } else if let Some(vamana) = &self.vamana {
            let _ = vamana.visit_neighbors(ordinal, visit);
        }
    }

    pub fn diskann_io_stats(&self) -> DiskAnnIoStats {
        self.diskann
            .as_ref()
            .map_or_else(DiskAnnIoStats::default, |diskann| diskann.stats())
    }

    pub fn reset_diskann_io_stats(&self) {
        if let Some(diskann) = &self.diskann {
            diskann.reset_stats();
        }
    }

    pub(crate) fn diskann_vector(&self, ordinal: usize) -> Option<Vec<f32>> {
        self.diskann.as_ref()?.vector(ordinal)
    }

    pub(crate) fn uses_diskann(&self) -> bool {
        self.diskann.is_some()
    }

    fn quantized_distance<const GLOBAL: bool>(
        &self,
        ordinal: usize,
        rotated_query: &[f32],
        tables: &mut RabitqQueryTables,
    ) -> Option<f32> {
        let cell = self.rabitq.cell(ordinal)?;
        let table = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables)?;
        record_search_metric!(EstimatorCalls, 1);
        self.rabitq
            .estimate_squared_l2_with_table_for_basis::<GLOBAL>(ordinal, table)
    }

    fn quantized_distance_estimate<const GLOBAL: bool>(
        &self,
        ordinal: usize,
        rotated_query: &[f32],
        tables: &mut RabitqQueryTables,
    ) -> Option<RabitqDistanceEstimate> {
        let cell = self.rabitq.cell(ordinal)?;
        let table = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables)?;
        record_search_metric!(EstimatorCalls, 1);
        self.rabitq
            .distance_estimate_with_table_for_basis::<GLOBAL>(ordinal, table)
    }

    fn query_distance_table<'a, const GLOBAL: bool>(
        &self,
        cell: usize,
        rotated_query: &[f32],
        tables: &'a mut RabitqQueryTables,
    ) -> Option<&'a RabitqDistanceTable> {
        if tables.cells.get(cell)?.is_none() {
            let rotated_centroid = self.rotated_centroids.get(cell)?;
            let prepared = if GLOBAL {
                self.rabitq.prepare_global_cell_distance_table(
                    rotated_query,
                    rotated_centroid,
                    tables.global.as_ref()?,
                )?
            } else {
                let residual = rotated_residual(rotated_query, rotated_centroid);
                self.rabitq.prepare_distance_table(&residual)?
            };
            *tables.cells.get_mut(cell)? = Some(prepared);
        }
        tables.cells.get(cell)?.as_ref()
    }

    #[cfg(test)]
    fn score_cells(
        &self,
        cells: &[usize],
        rotated_query: &[f32],
        filter: Option<&dyn FilterPredicate>,
        tables: &mut RabitqQueryTables,
    ) -> Vec<QuantizedCandidate> {
        let filter = CandidateFilter {
            string: filter,
            ordinal: None,
        };
        if self.rabitq.uses_global_query_table() {
            self.score_cells_controlled::<true, true>(cells, rotated_query, filter, tables, None)
        } else {
            self.score_cells_controlled::<false, true>(cells, rotated_query, filter, tables, None)
        }
    }

    fn score_cells_controlled<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        cells: &[usize],
        rotated_query: &[f32],
        filter: CandidateFilter<'_>,
        tables: &mut RabitqQueryTables,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<QuantizedCandidate> {
        use rayon::prelude::*;

        #[cfg(feature = "search-metrics")]
        let posting_records = cells
            .iter()
            .map(|&cell| self.ivf.posting_range(cell).map_or(0, |range| range.len()))
            .sum::<usize>();
        record_search_metric!(PostingScanCalls, 1);
        record_search_metric!(CellsTouched, cells.len());
        record_search_metric!(PostingRecordsScanned, posting_records);

        for &cell in cells {
            if cancellation_requested(cancelled) {
                return Vec::new();
            }
            if self
                .query_distance_table::<GLOBAL>(cell, rotated_query, tables)
                .is_none()
            {
                continue;
            }
        }
        let cell_tables = &tables.cells;
        #[cfg(feature = "search-metrics")]
        let metric_collector = crate::index::search_metrics::current();
        // The binding inside this closure is consumed by feature-gated metric
        // flushes. In the default build those macros disappear, leaving the
        // binding as a deliberate return-only staging value.
        #[allow(clippy::let_and_return)]
        let score_cell = |&cell: &usize| {
            #[cfg(feature = "search-metrics")]
            let _metric_attachment = crate::index::search_metrics::attach(metric_collector.clone());
            if cancellation_requested(cancelled) {
                return Vec::new();
            }
            let Some(table) = cell_tables.get(cell).and_then(Option::as_ref) else {
                return Vec::new();
            };
            #[cfg(feature = "search-metrics")]
            let mut estimator_calls = 0usize;
            #[cfg(feature = "search-metrics")]
            let mut valid_admissions = 0usize;
            #[cfg(feature = "search-metrics")]
            let mut invalid_admissions = 0usize;
            #[cfg(feature = "search-metrics")]
            let mut filter_rejections = 0usize;
            let candidates = self
                .ivf
                .posting_range(cell)
                .expect("validated IVF cell")
                .filter_map(|posting| {
                    let ordinal = self
                        .ivf
                        .posting_ordinal(posting)
                        .expect("validated IVF posting") as usize;
                    if !filter.allows::<FILTERED>(self, ordinal) {
                        #[cfg(feature = "search-metrics")]
                        {
                            filter_rejections += 1;
                        }
                        return None;
                    }
                    #[cfg(feature = "search-metrics")]
                    {
                        estimator_calls += 1;
                    }
                    let distance = self
                        .rabitq
                        .distance_estimate_for_posting_with_table_for_basis::<GLOBAL>(
                            posting, ordinal, table,
                        );
                    if distance.is_some() {
                        #[cfg(feature = "search-metrics")]
                        {
                            valid_admissions += 1;
                        }
                    } else {
                        #[cfg(feature = "search-metrics")]
                        {
                            invalid_admissions += 1;
                        }
                    }
                    distance.map(|distance| QuantizedCandidate { distance, ordinal })
                })
                .collect::<Vec<_>>();
            record_search_metric!(EstimatorCalls, estimator_calls);
            record_search_metric!(PostingScanEstimatorCalls, estimator_calls);
            record_search_metric!(ValidRecordAdmissions, valid_admissions);
            record_search_metric!(InvalidRecordAdmissions, invalid_admissions);
            record_search_metric!(FilterRejections, filter_rejections);
            candidates
        };
        let cell_candidates = if rayon::current_thread_index().is_some() {
            cells.iter().map(&score_cell).collect::<Vec<_>>()
        } else {
            crate::search_pool::SEARCH_POOL
                .install(|| cells.par_iter().map(&score_cell).collect::<Vec<_>>())
        };
        let mut candidates = Vec::new();
        for cell in cell_candidates {
            candidates.extend(cell);
        }
        candidates
    }

    #[allow(clippy::too_many_arguments)]
    fn navigate_record_graph<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        seeds: &[QuantizedCandidate],
        width: usize,
        rotated_query: &[f32],
        filter: CandidateFilter<'_>,
        tables: &mut RabitqQueryTables,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<QuantizedCandidate> {
        let Some(vamana) = self.vamana.as_ref() else {
            return Vec::new();
        };
        record_search_metric!(GraphTraversals, 1);
        let mut visited = VisitedOrdinals::Dense(vec![false; self.store.len()]);
        let mut candidates = BinaryHeap::<Reverse<(OrdF32, usize)>>::new();
        let mut navigation = BinaryHeap::<(OrdF32, usize)>::new();
        let mut results = BinaryHeap::<(OrdF32, usize)>::new();
        for candidate in seeds.iter().take(width) {
            let Some(record) = self.rabitq.record_for_ordinal_key(candidate.ordinal) else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            let record_index = RabitqArtifact::record_index(record);
            if self.store.id(candidate.ordinal).is_none() {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            }
            if !filter.navigable::<FILTERED>(self, candidate.ordinal) {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            }
            if visited.insert(record_index) {
                candidates.push(Reverse((OrdF32(candidate.distance.estimate), record_index)));
                navigation.push((OrdF32(candidate.distance.estimate), record_index));
                if filter.allows::<FILTERED>(self, candidate.ordinal) {
                    results.push((OrdF32(candidate.distance.estimate), record_index));
                    record_search_metric!(HeapPushes, 1);
                } else {
                    record_search_metric!(FilterRejections, 1);
                }
                record_search_metric!(ValidRecordAdmissions, 1);
                record_search_metric!(HeapPushes, 2);
            }
        }
        while let Some(Reverse((OrdF32(candidate_distance), record_index))) = candidates.pop() {
            record_search_metric!(HeapPops, 1);
            if cancellation_requested(cancelled) {
                return Vec::new();
            }
            let worst = navigation.peek().map_or(f32::INFINITY, |entry| entry.0.0);
            if navigation.len() >= width && candidate_distance > worst {
                break;
            }
            let _ = vamana.visit_neighbor_keys(record_index, |neighbor| {
                record_search_metric!(GraphHops, 1);
                if cancellation_requested(cancelled) {
                    return;
                }
                let neighbor = neighbor as usize;
                let Some(record) = self.rabitq.record_at(neighbor) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                let Some(ordinal) = self
                    .ivf
                    .posting_ordinal(neighbor)
                    .map(|value| value as usize)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                if self.store.id(ordinal).is_none() {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !filter.navigable::<FILTERED>(self, ordinal) {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !visited.insert(neighbor) {
                    return;
                }
                let Some(cell) = self.rabitq.record_cell(record) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                let Some(table) = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                record_search_metric!(EstimatorCalls, 1);
                let Some(distance) = self
                    .rabitq
                    .estimate_squared_l2_for_record_with_table_for_basis::<GLOBAL>(record, table)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                record_search_metric!(ValidRecordAdmissions, 1);
                let worst = navigation.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                if navigation.len() < width || distance < worst {
                    candidates.push(Reverse((OrdF32(distance), neighbor)));
                    navigation.push((OrdF32(distance), neighbor));
                    record_search_metric!(HeapPushes, 2);
                    if navigation.len() > width {
                        navigation.pop();
                        record_search_metric!(HeapPops, 1);
                    }
                }
                if filter.allows::<FILTERED>(self, ordinal) {
                    let result_worst = results.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                    if results.len() < width || distance < result_worst {
                        results.push((OrdF32(distance), neighbor));
                        record_search_metric!(HeapPushes, 1);
                        if results.len() > width {
                            results.pop();
                            record_search_metric!(HeapPops, 1);
                        }
                    }
                } else {
                    record_search_metric!(FilterRejections, 1);
                }
            });
        }
        results
            .into_iter()
            .filter_map(|(_, record_index)| {
                let record = self.rabitq.record_at(record_index)?;
                let ordinal = self.ivf.posting_ordinal(record_index)? as usize;
                let cell = self.rabitq.record_cell(record)?;
                let table = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables)?;
                record_search_metric!(EstimatorCalls, 1);
                self.rabitq
                    .distance_estimate_for_record_with_table_for_basis::<GLOBAL>(record, table)
                    .map(|distance| QuantizedCandidate { distance, ordinal })
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn score_cell_graph<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        entry: usize,
        cell: usize,
        width: usize,
        rotated_query: &[f32],
        filter: CandidateFilter<'_>,
        tables: &mut RabitqQueryTables,
        visited: &mut VisitedOrdinals,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<QuantizedCandidate> {
        record_search_metric!(GraphTraversals, 1);
        record_search_metric!(CellsTouched, 1);
        record_search_metric!(EntriesTouched, 1);
        if self
            .vamana
            .as_ref()
            .is_some_and(VamanaArtifact::uses_rabitq_record_keys)
        {
            return self.score_cell_graph_records::<GLOBAL, FILTERED>(
                entry,
                cell,
                width,
                rotated_query,
                filter,
                tables,
                visited,
                cancelled,
            );
        }
        self.score_cell_graph_ordinals::<GLOBAL, FILTERED>(
            entry,
            cell,
            width,
            rotated_query,
            filter,
            tables,
            visited,
            cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn score_cell_graph_ordinals<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        entry: usize,
        cell: usize,
        width: usize,
        rotated_query: &[f32],
        filter: CandidateFilter<'_>,
        tables: &mut RabitqQueryTables,
        visited: &mut VisitedOrdinals,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<QuantizedCandidate> {
        // Search the cell-local mini-Vamana to the caller's bounded width,
        // then let the persisted RaBitQ confidence bounds choose the
        // cross-cell navigation and exact-rerank frontier.
        let width = width.max(1);
        let Some(table) = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables) else {
            return Vec::new();
        };
        let Some(entry_record) = self.rabitq.record_for_ordinal_in_cell(entry, cell) else {
            return Vec::new();
        };
        if self.store.id(entry).is_none() {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        }
        if !filter.navigable::<FILTERED>(self, entry) {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        }
        record_search_metric!(EstimatorCalls, 1);
        let Some(entry_distance) = self
            .rabitq
            .distance_estimate_for_record_with_table_for_basis::<GLOBAL>(entry_record, table)
        else {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        };
        record_search_metric!(ValidRecordAdmissions, 1);
        let mut candidates = BinaryHeap::<Reverse<(OrdF32, usize)>>::new();
        let mut navigation = BinaryHeap::<(OrdF32, usize)>::new();
        let mut results = BinaryHeap::<(OrdF32, usize)>::new();
        visited.insert(entry);
        candidates.push(Reverse((OrdF32(entry_distance.estimate), entry)));
        navigation.push((OrdF32(entry_distance.estimate), entry));
        if filter.allows::<FILTERED>(self, entry) {
            results.push((OrdF32(entry_distance.estimate), entry));
            record_search_metric!(HeapPushes, 1);
        } else {
            record_search_metric!(FilterRejections, 1);
        }
        record_search_metric!(HeapPushes, 2);
        while let Some(Reverse((OrdF32(candidate_distance), ordinal))) = candidates.pop() {
            record_search_metric!(HeapPops, 1);
            if cancellation_requested(cancelled) {
                return Vec::new();
            }
            let worst = navigation
                .peek()
                .map_or(f32::INFINITY, |candidate| candidate.0.0);
            if navigation.len() >= width && candidate_distance > worst {
                break;
            }
            self.visit_neighbors(ordinal, |neighbor| {
                record_search_metric!(GraphHops, 1);
                if cancellation_requested(cancelled) {
                    return;
                }
                let neighbor = neighbor as usize;
                let Some(record) = self.rabitq.record_for_ordinal_in_cell(neighbor, cell) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                if self.store.id(neighbor).is_none() {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !filter.navigable::<FILTERED>(self, neighbor) {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !visited.insert(neighbor) {
                    return;
                }
                record_search_metric!(EstimatorCalls, 1);
                if let Some(distance) = self
                    .rabitq
                    .estimate_squared_l2_for_record_with_table_for_basis::<GLOBAL>(record, table)
                {
                    record_search_metric!(ValidRecordAdmissions, 1);
                    let worst = navigation
                        .peek()
                        .map_or(f32::INFINITY, |candidate| candidate.0.0);
                    if navigation.len() < width || distance < worst {
                        candidates.push(Reverse((OrdF32(distance), neighbor)));
                        navigation.push((OrdF32(distance), neighbor));
                        record_search_metric!(HeapPushes, 2);
                        if navigation.len() > width {
                            navigation.pop();
                            record_search_metric!(HeapPops, 1);
                        }
                    }
                    if filter.allows::<FILTERED>(self, neighbor) {
                        let result_worst = results
                            .peek()
                            .map_or(f32::INFINITY, |candidate| candidate.0.0);
                        if results.len() < width || distance < result_worst {
                            results.push((OrdF32(distance), neighbor));
                            record_search_metric!(HeapPushes, 1);
                            if results.len() > width {
                                results.pop();
                                record_search_metric!(HeapPops, 1);
                            }
                        }
                    } else {
                        record_search_metric!(FilterRejections, 1);
                    }
                }
            });
        }
        results
            .into_iter()
            .filter_map(|(_, ordinal)| {
                if !filter.allows::<FILTERED>(self, ordinal) {
                    return None;
                }
                let record = self.rabitq.record_for_ordinal_in_cell(ordinal, cell)?;
                record_search_metric!(EstimatorCalls, 1);
                self.rabitq
                    .distance_estimate_for_record_with_table_for_basis::<GLOBAL>(record, table)
                    .map(|distance| QuantizedCandidate { distance, ordinal })
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn score_cell_graph_records<const GLOBAL: bool, const FILTERED: bool>(
        &self,
        entry: usize,
        cell: usize,
        width: usize,
        rotated_query: &[f32],
        filter: CandidateFilter<'_>,
        tables: &mut RabitqQueryTables,
        visited: &mut VisitedOrdinals,
        cancelled: Option<&AtomicBool>,
    ) -> Vec<QuantizedCandidate> {
        let _span = tracing::info_span!(
            "gaussdb.search.lsvec.score_cell_graph",
            cell,
            width,
            key_space = "rabitq_record"
        )
        .entered();
        let width = width.max(1);
        let Some(vamana) = self.vamana.as_ref() else {
            return Vec::new();
        };
        let Some(table) = self.query_distance_table::<GLOBAL>(cell, rotated_query, tables) else {
            return Vec::new();
        };
        let Some(entry_record) = self.rabitq.record_at(entry) else {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        };
        if self.rabitq.record_cell(entry_record) != Some(cell) {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        }
        let Some(entry_ordinal) = self.ivf.posting_ordinal(entry).map(|value| value as usize)
        else {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        };
        if self.store.id(entry_ordinal).is_none() {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        }
        if !filter.navigable::<FILTERED>(self, entry_ordinal) {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        }
        record_search_metric!(EstimatorCalls, 1);
        let Some(entry_distance) = self
            .rabitq
            .distance_estimate_for_record_with_table_for_basis::<GLOBAL>(entry_record, table)
        else {
            record_search_metric!(InvalidRecordAdmissions, 1);
            return Vec::new();
        };
        record_search_metric!(ValidRecordAdmissions, 1);
        let mut candidates = BinaryHeap::<Reverse<u64>>::new();
        let mut navigation = BinaryHeap::<u64>::new();
        let mut results = BinaryHeap::<u64>::new();
        visited.insert(entry);
        let entry_key = pack_graph_key(entry_distance.estimate, entry);
        candidates.push(Reverse(entry_key));
        navigation.push(entry_key);
        if filter.allows::<FILTERED>(self, entry_ordinal) {
            results.push(entry_key);
            record_search_metric!(HeapPushes, 1);
        } else {
            record_search_metric!(FilterRejections, 1);
        }
        record_search_metric!(HeapPushes, 2);
        while let Some(Reverse(candidate)) = candidates.pop() {
            record_search_metric!(HeapPops, 1);
            let (candidate_distance, record_index) = unpack_graph_key(candidate);
            if cancellation_requested(cancelled) {
                return Vec::new();
            }
            let worst = navigation
                .peek()
                .map_or(f32::INFINITY, |candidate| unpack_graph_key(*candidate).0);
            if navigation.len() >= width && candidate_distance > worst {
                break;
            }
            let mut records = [RabitqRecord::default(); DEFAULT_R];
            let mut record_count = 0usize;
            let _ = vamana.visit_neighbor_keys(record_index, |neighbor| {
                record_search_metric!(GraphHops, 1);
                if cancellation_requested(cancelled) || record_count == DEFAULT_R {
                    return;
                }
                let neighbor = neighbor as usize;
                let Some(record) = self.rabitq.record_at(neighbor) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                if self.rabitq.record_cell(record) != Some(cell) {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                let Some(ordinal) = self
                    .ivf
                    .posting_ordinal(neighbor)
                    .map(|value| value as usize)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                if self.store.id(ordinal).is_none() {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !filter.navigable::<FILTERED>(self, ordinal) {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                }
                if !visited.insert(neighbor) {
                    return;
                }
                records[record_count] = record;
                record_count += 1;
                record_search_metric!(ValidRecordAdmissions, 1);
            });
            let mut distances = [0.0f32; DEFAULT_R];
            record_search_metric!(EstimatorCalls, record_count);
            if self
                .rabitq
                .estimate_squared_l2_for_records_with_table_for_basis::<GLOBAL>(
                    &records[..record_count],
                    table,
                    &mut distances[..record_count],
                )
                .is_none()
            {
                return Vec::new();
            }
            for (&record, &distance) in records[..record_count]
                .iter()
                .zip(&distances[..record_count])
            {
                let record_index = RabitqArtifact::record_index(record);
                let worst = navigation
                    .peek()
                    .map_or(f32::INFINITY, |candidate| unpack_graph_key(*candidate).0);
                if navigation.len() < width || distance < worst {
                    let key = pack_graph_key(distance, record_index);
                    candidates.push(Reverse(key));
                    navigation.push(key);
                    record_search_metric!(HeapPushes, 2);
                    if navigation.len() > width {
                        navigation.pop();
                        record_search_metric!(HeapPops, 1);
                    }
                }
                let Some(ordinal) = self
                    .ivf
                    .posting_ordinal(record_index)
                    .map(|value| value as usize)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    continue;
                };
                if self.store.id(ordinal).is_none() {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    continue;
                }
                if filter.allows::<FILTERED>(self, ordinal) {
                    let result_worst = results
                        .peek()
                        .map_or(f32::INFINITY, |candidate| unpack_graph_key(*candidate).0);
                    if results.len() < width || distance < result_worst {
                        results.push(pack_graph_key(distance, record_index));
                        record_search_metric!(HeapPushes, 1);
                        if results.len() > width {
                            results.pop();
                            record_search_metric!(HeapPops, 1);
                        }
                    }
                } else {
                    record_search_metric!(FilterRejections, 1);
                }
            }
        }
        results
            .into_iter()
            .filter_map(|key| {
                let (_, record_index) = unpack_graph_key(key);
                let record = self.rabitq.record_at(record_index)?;
                let ordinal = self.ivf.posting_ordinal(record_index)? as usize;
                record_search_metric!(EstimatorCalls, 1);
                self.rabitq
                    .distance_estimate_for_record_with_table_for_basis::<GLOBAL>(record, table)
                    .map(|distance| QuantizedCandidate { distance, ordinal })
            })
            .collect()
    }

    /// Benchmark-only oracle for the roadmap's 1/4/16 seed decision.
    ///
    /// This is deliberately absent from the product [`IndexBackend`] surface.
    /// It starts one validity-safe traversal from either the nearest centroid
    /// entries (the realizable policy) or known-nearest IDs (an offline
    /// ceiling), then uses exact distances from the visited frontier to bound
    /// the existing radius-safe posting fallback. Only records that map to a
    /// live posting may occupy either heap. The method is compiled only with
    /// `search-metrics`, so it cannot become a customer-facing seed knob.
    #[cfg(feature = "search-metrics")]
    pub fn diagnose_upper_layer_seed_search(
        &self,
        query: &[f32],
        k: usize,
        ef_search: usize,
        seed_count: usize,
        offline_seed_ids: Option<&[u32]>,
    ) -> Result<Vec<String>> {
        if query.len() != self.vector_dim() || k == 0 || seed_count == 0 {
            return Err(GaussError::InvalidRequest(
                "upper-layer oracle requires a non-empty, dimension-matched query".to_string(),
            ));
        }
        if self.metric != DistanceMetric::Cosine
            || !self.rabitq.uses_global_query_table()
            || !self
                .vamana
                .as_ref()
                .is_some_and(VamanaArtifact::uses_rabitq_record_keys)
            || self.ivf.cell_radius(0).is_none()
        {
            return Err(GaussError::InvalidRequest(
                "upper-layer oracle requires a resident cosine LS-VEC segment with radii and record-key Vamana"
                    .to_string(),
            ));
        }

        let mut prepared = query.to_vec();
        crate::search::normalize(&mut prepared);
        let rotated_query = rotate_for_cascade(&prepared);
        let mut tables = RabitqQueryTables {
            global: self.rabitq.prepare_global_query_table(&rotated_query),
            cells: (0..self.cells()).map(|_| None).collect(),
        };
        let vamana = self.vamana.as_ref().expect("validated Vamana oracle");
        let width = ef_search.max(k).min(self.store.len());

        let seed_records = if let Some(ids) = offline_seed_ids {
            ids.iter()
                .take(seed_count)
                .filter_map(|id| self.store.ordinal(&id.to_string()))
                .filter_map(|ordinal| self.rabitq.record_for_ordinal_key(ordinal))
                .map(RabitqArtifact::record_index)
                .collect::<Vec<_>>()
        } else {
            let mut cells = self
                .centroids
                .iter()
                .enumerate()
                .map(|(cell, centroid)| (squared_l2(&prepared, centroid), cell))
                .collect::<Vec<_>>();
            cells.sort_unstable_by(|left, right| {
                left.0
                    .total_cmp(&right.0)
                    .then_with(|| left.1.cmp(&right.1))
            });
            cells
                .into_iter()
                .filter_map(|(_, cell)| vamana.entry(cell).map(|entry| entry as usize))
                .take(seed_count)
                .collect::<Vec<_>>()
        };
        if seed_records.len() != seed_count {
            return Err(GaussError::InvalidRequest(format!(
                "upper-layer oracle resolved {} of {seed_count} seeds",
                seed_records.len()
            )));
        }

        record_search_metric!(GraphTraversals, 1);
        record_search_metric!(EntriesTouched, seed_records.len());
        let mut visited = VisitedOrdinals::Dense(vec![false; self.store.len()]);
        let mut candidates = BinaryHeap::<Reverse<u64>>::new();
        let mut found = BinaryHeap::<u64>::new();
        for record_index in seed_records {
            let Some(record) = self.rabitq.record_at(record_index) else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            let Some(ordinal) = self
                .ivf
                .posting_ordinal(record_index)
                .map(|ordinal| ordinal as usize)
            else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            if self.store.id(ordinal).is_none() || !visited.insert(record_index) {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            }
            let Some(cell) = self.rabitq.record_cell(record) else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            let Some(table) = self.query_distance_table::<true>(cell, &rotated_query, &mut tables)
            else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            record_search_metric!(EstimatorCalls, 1);
            let Some(distance) = self
                .rabitq
                .estimate_squared_l2_for_record_with_table_for_basis::<true>(record, table)
            else {
                record_search_metric!(InvalidRecordAdmissions, 1);
                continue;
            };
            record_search_metric!(ValidRecordAdmissions, 1);
            let key = pack_graph_key(distance, record_index);
            candidates.push(Reverse(key));
            found.push(key);
            record_search_metric!(HeapPushes, 2);
        }

        while let Some(Reverse(candidate)) = candidates.pop() {
            record_search_metric!(HeapPops, 1);
            let (candidate_distance, record_index) = unpack_graph_key(candidate);
            let worst = found
                .peek()
                .map_or(f32::INFINITY, |candidate| unpack_graph_key(*candidate).0);
            if found.len() >= width && candidate_distance > worst {
                break;
            }
            let _ = vamana.visit_neighbor_keys(record_index, |neighbor| {
                record_search_metric!(GraphHops, 1);
                let neighbor = neighbor as usize;
                let Some(record) = self.rabitq.record_at(neighbor) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                let Some(ordinal) = self
                    .ivf
                    .posting_ordinal(neighbor)
                    .map(|ordinal| ordinal as usize)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                // Validate before visitation: invalid/orphan records never
                // consume the bounded frontier or result capacity.
                if self.store.id(ordinal).is_none() || !visited.insert(neighbor) {
                    return;
                }
                let Some(cell) = self.rabitq.record_cell(record) else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                let Some(table) =
                    self.query_distance_table::<true>(cell, &rotated_query, &mut tables)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                record_search_metric!(EstimatorCalls, 1);
                let Some(distance) = self
                    .rabitq
                    .estimate_squared_l2_for_record_with_table_for_basis::<true>(record, table)
                else {
                    record_search_metric!(InvalidRecordAdmissions, 1);
                    return;
                };
                record_search_metric!(ValidRecordAdmissions, 1);
                let worst = found
                    .peek()
                    .map_or(f32::INFINITY, |candidate| unpack_graph_key(*candidate).0);
                if found.len() < width || distance < worst {
                    let key = pack_graph_key(distance, neighbor);
                    candidates.push(Reverse(key));
                    found.push(key);
                    record_search_metric!(HeapPushes, 2);
                    if found.len() > width {
                        found.pop();
                        record_search_metric!(HeapPops, 1);
                    }
                }
            });
        }

        let mut graph_candidates = found
            .into_iter()
            .filter_map(|key| {
                let (_, record_index) = unpack_graph_key(key);
                let record = self.rabitq.record_at(record_index)?;
                let ordinal = self.ivf.posting_ordinal(record_index)? as usize;
                self.store.id(ordinal)?;
                let cell = self.rabitq.record_cell(record)?;
                let table = self.query_distance_table::<true>(cell, &rotated_query, &mut tables)?;
                record_search_metric!(EstimatorCalls, 1);
                self.rabitq
                    .distance_estimate_for_record_with_table_for_basis::<true>(record, table)
                    .map(|distance| QuantizedCandidate { distance, ordinal })
            })
            .collect::<Vec<_>>();

        // Exact-score the bounded graph frontier before radius admission.
        // This is an offline diagnostic cost, not a new production stage.
        let mut graph_exact = graph_candidates
            .iter()
            .filter_map(|candidate| {
                self.exact_distance(query, candidate.ordinal)
                    .map(|distance| (distance, candidate.ordinal))
            })
            .collect::<Vec<_>>();
        graph_exact.sort_unstable_by(|left, right| {
            left.0
                .total_cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        let routing_upper_bound = graph_exact
            .get(k.saturating_sub(1))
            // Exact cosine ranking stores `-cos(q, x)`, while IVF radii and
            // centroid bounds use squared L2 on normalized vectors:
            // `||q-x||² = 2 * (1-cos(q,x))`.
            .map_or(f32::INFINITY, |candidate| 2.0 * (candidate.0 + 1.0));
        let radius_cells = (0..self.cells())
            .filter(|&cell| {
                let centroid_distance = squared_l2(&prepared, &self.centroids[cell]);
                let radius = self.ivf.cell_radius(cell).expect("validated IVF radius");
                let gap = (centroid_distance.sqrt() - radius).max(0.0);
                let lower_bound = gap * gap;
                lower_bound <= routing_upper_bound * (1.0 + 8.0 * f32::EPSILON)
            })
            .collect::<Vec<_>>();

        let mut bounded = self.score_cells_controlled::<true, false>(
            &radius_cells,
            &rotated_query,
            CandidateFilter {
                string: None,
                ordinal: None,
            },
            &mut tables,
            None,
        );
        bounded.append(&mut graph_candidates);
        bounded.sort_unstable_by(|left, right| {
            left.ordinal.cmp(&right.ordinal).then_with(|| {
                left.distance
                    .lower_bound
                    .total_cmp(&right.distance.lower_bound)
            })
        });
        bounded.dedup_by_key(|candidate| candidate.ordinal);
        keep_quantized_by_lower_bound(&mut bounded, width);
        let rescore_floor = k.saturating_mul(
            rescore_inflation_for_recall_target(k, 0.99).unwrap_or(RESCORE_INFLATION),
        );
        let rescore_limit = confidence_rescore_limit(&mut bounded, k, rescore_floor);

        let mut exact_ordinals = graph_exact
            .iter()
            .map(|(_, ordinal)| *ordinal)
            .collect::<HashSet<_>>();
        let mut rescored = graph_exact;
        for candidate in bounded.into_iter().take(rescore_limit) {
            if !exact_ordinals.insert(candidate.ordinal) {
                continue;
            }
            if let Some(distance) = self.exact_distance(query, candidate.ordinal) {
                rescored.push((distance, candidate.ordinal));
            }
        }
        keep_nearest(&mut rescored, k);
        let result = rescored
            .into_iter()
            .filter_map(|(_, ordinal)| self.store.id(ordinal).map(str::to_string))
            .collect::<Vec<_>>();
        record_search_metric!(ReturnedCount, result.len());
        record_search_metric!(UnderfilledCount, usize::from(result.len() != k));
        if result.len() != k {
            return Err(GaussError::InvalidRequest(format!(
                "upper-layer oracle underfilled: expected {k}, returned {}",
                result.len()
            )));
        }
        Ok(result)
    }
}

fn cancellation_requested(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn rotated_residual(rotated_query: &[f32], rotated_centroid: &[f32]) -> Vec<f32> {
    rotated_query
        .iter()
        .zip(rotated_centroid)
        .map(|(value, center)| value - center)
        .collect()
}

fn radius_routing_enabled(
    metric: DistanceMetric,
    has_radii: bool,
    rescore_inflation: usize,
) -> bool {
    has_radii
        && match metric {
            DistanceMetric::Cosine => true,
            DistanceMetric::L2 => rescore_inflation > RESCORE_INFLATION,
            DistanceMetric::Dot => false,
        }
}

/// Engine-owned L3 candidate inflation derived from paper Corollary 10:
/// `ρ* = 1 + (8 / 2^(2b)) * ln(k / (1-r))`, with the persisted `b=2`.
///
/// `None` means exact scan: finite candidate inflation cannot certify a target
/// of exactly 1.0. Invalid targets retain the measured 0.95/0.97 default
/// instead of allowing a malformed request to shrink the rerank pool.
pub fn rescore_inflation_for_recall_target(k: usize, recall_target: f32) -> Option<usize> {
    if recall_target >= 1.0 {
        return None;
    }
    if !(0.5..1.0).contains(&recall_target) || recall_target.is_nan() {
        return Some(RESCORE_INFLATION);
    }
    let k = k.max(1) as f32;
    let rho = 1.0 + 0.5 * (k / (1.0 - recall_target)).ln();
    Some((rho.ceil() as usize).max(1))
}

fn keep_nearest(candidates: &mut Vec<(f32, usize)>, limit: usize) {
    let compare =
        |a: &(f32, usize), b: &(f32, usize)| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1));
    if candidates.len() > limit {
        candidates.select_nth_unstable_by(limit, compare);
        candidates.truncate(limit);
    }
    candidates.sort_unstable_by(compare);
}

fn keep_quantized_by_lower_bound(candidates: &mut Vec<QuantizedCandidate>, limit: usize) {
    let compare = |left: &QuantizedCandidate, right: &QuantizedCandidate| {
        left.distance
            .lower_bound
            .total_cmp(&right.distance.lower_bound)
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    };
    if candidates.len() > limit {
        candidates.select_nth_unstable_by(limit, compare);
        candidates.truncate(limit);
    }
    candidates.sort_unstable_by(compare);
}

fn confidence_rescore_limit(
    candidates: &mut [QuantizedCandidate],
    k: usize,
    analytical_floor: usize,
) -> usize {
    if candidates.is_empty() || k == 0 {
        return 0;
    }
    let upper_limit = k.min(candidates.len());
    let mut upper_bounds = BinaryHeap::with_capacity(upper_limit);
    for candidate in candidates.iter() {
        let upper = (OrdF32(candidate.distance.upper_bound), candidate.ordinal);
        if upper_bounds.len() < upper_limit {
            upper_bounds.push(upper);
        } else if upper_bounds.peek().is_some_and(|worst| upper < *worst) {
            upper_bounds.pop();
            upper_bounds.push(upper);
        }
    }
    let kth_upper = upper_bounds
        .peek()
        .map_or(f32::INFINITY, |(upper, _)| upper.0);
    let competitive = |candidate: &QuantizedCandidate| {
        candidate.distance.lower_bound <= kth_upper * (1.0 + 8.0 * f32::EPSILON)
    };
    let mut bound_limit = 0;
    for index in 0..candidates.len() {
        if competitive(&candidates[index]) {
            candidates.swap(bound_limit, index);
            bound_limit += 1;
        }
    }
    let floor = analytical_floor.min(candidates.len());
    if bound_limit >= floor || floor == candidates.len() {
        return bound_limit.max(floor);
    }
    let compare = |left: &QuantizedCandidate, right: &QuantizedCandidate| {
        left.distance
            .lower_bound
            .total_cmp(&right.distance.lower_bound)
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    };
    candidates.select_nth_unstable_by(floor, compare);
    floor
}

impl IndexBackend for IvfSegmentIndex {
    fn candidate_ids_with_ef(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
    ) -> Vec<String> {
        self.search(
            query,
            k,
            ef_search,
            crate::h2qg::DEFAULT_RECALL_TARGET,
            None,
        )
    }

    fn candidate_ids_with_ef_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        self.search(
            query,
            k,
            ef_search,
            crate::h2qg::DEFAULT_RECALL_TARGET,
            filter,
        )
    }

    fn candidate_ids_with_recall_target(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
    ) -> Vec<String> {
        self.search(query, k, ef_search, recall_target, filter)
    }

    fn candidate_ids_with_recall_target_cancellable(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        cancelled: &AtomicBool,
    ) -> Vec<String> {
        self.search_controlled(
            query,
            k,
            ef_search,
            recall_target,
            filter,
            None,
            Some(cancelled),
        )
    }

    fn candidate_ids_with_recall_target_ordinal_filter(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        ordinal_filter: Option<&dyn OrdinalFilterPredicate>,
    ) -> Vec<String> {
        self.search_controlled(
            query,
            k,
            ef_search,
            recall_target,
            filter,
            ordinal_filter,
            None,
        )
    }

    fn candidate_ids_with_recall_target_ordinal_filter_cancellable(
        &self,
        query: &[f32],
        k: usize,
        ef_search: Option<usize>,
        recall_target: f32,
        filter: Option<&dyn FilterPredicate>,
        ordinal_filter: Option<&dyn OrdinalFilterPredicate>,
        cancelled: &AtomicBool,
    ) -> Vec<String> {
        self.search_controlled(
            query,
            k,
            ef_search,
            recall_target,
            filter,
            ordinal_filter,
            Some(cancelled),
        )
    }

    fn default_ef_search(&self, k: usize) -> usize {
        k.saturating_mul(8).max(64).min(self.store.len())
    }

    fn ef_search_for_recall_target(&self, k: usize, recall_target: f32) -> usize {
        let factor = if recall_target >= 0.99 {
            16
        } else if recall_target >= 0.95 {
            8
        } else if recall_target >= 0.90 {
            6
        } else {
            4
        };
        k.saturating_mul(factor).max(64).min(self.store.len())
    }

    fn insert_point(&mut self, _point: &Point, _vector_dim: usize) -> Result<()> {
        Err(GaussError::InvalidRequest(
            "sealed IVF segment indexes are immutable".to_string(),
        ))
    }

    fn kind(&self) -> IndexKind {
        IndexKind::Ivf
    }

    fn indexed_points(&self) -> usize {
        self.store.len()
    }

    fn vector_dim(&self) -> usize {
        self.ivf.vector_dim()
    }

    fn contains(&self, id: &str) -> bool {
        self.store.ordinal(id).is_some()
    }

    fn cells(&self) -> usize {
        self.ivf.cells()
    }

    fn is_paged(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Reverse,
        collections::{BinaryHeap, HashSet},
        hint::black_box,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use rayon::prelude::*;

    use super::{
        IvfSegmentIndex, QuantizedCandidate, RESCORE_INFLATION, RabitqDistanceEstimate,
        confidence_rescore_limit, keep_nearest, pack_graph_key, radius_routing_enabled,
        rescore_inflation_for_recall_target, rotated_residual,
    };
    use crate::DistanceMetric;
    use crate::h2qg::OrdF32;
    use crate::index::{FilterPredicate, IndexBackend, rotate_for_cascade};
    use crate::model::Point;
    use crate::seal::{SealConfig, SealIndexKind, V4Store, build_segment};

    #[test]
    fn packed_graph_key_matches_tuple_order() {
        let mut state = 0x5041_434b_4544_4b45u64;
        for _ in 0..10_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let left_bits = ((state >> 32) as u32).min(0x7f7f_ffff);
            let left_record = state as u32;
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let right_bits = ((state >> 32) as u32).min(0x7f7f_ffff);
            let right_record = state as u32;
            let left_distance = f32::from_bits(left_bits);
            let right_distance = f32::from_bits(right_bits);
            let tuple_order = (OrdF32(left_distance), left_record as usize)
                .cmp(&(OrdF32(right_distance), right_record as usize));
            let packed_order = pack_graph_key(left_distance, left_record as usize)
                .cmp(&pack_graph_key(right_distance, right_record as usize));
            assert_eq!(packed_order, tuple_order);
            assert_eq!(
                super::unpack_graph_key(pack_graph_key(left_distance, left_record as usize)),
                (left_distance, left_record as usize)
            );
        }
    }

    #[test]
    fn bounded_l1_selection_matches_full_sort_prefix() {
        let mut candidates = (0..257)
            .map(|ordinal| (((ordinal * 73) % 101) as f32, ordinal))
            .collect::<Vec<_>>();
        let mut expected = candidates.clone();
        expected.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        expected.truncate(37);

        keep_nearest(&mut candidates, 37);
        assert_eq!(candidates, expected);
    }

    #[test]
    fn rotated_subtraction_matches_rotating_the_residual() {
        let query = [3.0, -2.0, 7.0, 1.0];
        let centroid = [1.0, 4.0, -1.0, 2.0];
        let expected = rotate_for_cascade(
            &query
                .iter()
                .zip(centroid)
                .map(|(value, center)| value - center)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            rotated_residual(&rotate_for_cascade(&query), &rotate_for_cascade(&centroid)),
            expected
        );
    }

    #[test]
    fn algorithm2_generation_is_byte_deterministic() {
        let dim = 16;
        let points = (0..512)
            .map(|ordinal| Point {
                id: format!("p{ordinal:04}"),
                vector: lcg_vector(ordinal as u64, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::json!({"ordinal": ordinal}),
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let config = SealConfig {
            vector_dim: dim,
            metric: DistanceMetric::Cosine,
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: SealIndexKind::Algorithm2,
            base_lsn: 11,
            end_lsn: 29,
        };
        build_segment(points.as_slice(), &first, config).unwrap();
        build_segment(points.as_slice(), &second, config).unwrap();

        let file_names = |directory: &std::path::Path| {
            let mut names = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let first_names = file_names(&first);
        assert_eq!(first_names, file_names(&second));
        for name in first_names {
            assert_eq!(
                std::fs::read(first.join(&name)).unwrap(),
                std::fs::read(second.join(&name)).unwrap(),
                "Algorithm 2 artifact is nondeterministic: {}",
                name.to_string_lossy()
            );
        }
    }

    #[test]
    fn rescore_inflation_is_slo_derived_and_restart_stable() {
        assert_eq!(rescore_inflation_for_recall_target(10, 0.95), Some(4));
        assert_eq!(rescore_inflation_for_recall_target(10, 0.97), Some(4));
        assert_eq!(rescore_inflation_for_recall_target(10, 0.99), Some(5));
        assert_eq!(rescore_inflation_for_recall_target(10, 1.0), None);
        assert_eq!(
            rescore_inflation_for_recall_target(10, f32::NAN),
            Some(RESCORE_INFLATION)
        );
    }

    #[test]
    fn radius_routing_is_metric_and_slo_aware() {
        assert!(!radius_routing_enabled(
            DistanceMetric::L2,
            true,
            RESCORE_INFLATION
        ));
        assert!(radius_routing_enabled(
            DistanceMetric::L2,
            true,
            RESCORE_INFLATION + 1
        ));
        assert!(radius_routing_enabled(
            DistanceMetric::Cosine,
            true,
            RESCORE_INFLATION
        ));
        assert!(radius_routing_enabled(
            DistanceMetric::Cosine,
            true,
            RESCORE_INFLATION + 1
        ));
        assert!(!radius_routing_enabled(
            DistanceMetric::Dot,
            true,
            RESCORE_INFLATION + 1
        ));
        assert!(!radius_routing_enabled(
            DistanceMetric::L2,
            false,
            RESCORE_INFLATION + 1
        ));
    }

    #[test]
    fn confidence_rescore_limit_expands_past_rho_floor_only_when_bounds_overlap() {
        let mut candidates = [
            QuantizedCandidate {
                distance: RabitqDistanceEstimate {
                    estimate: 1.0,
                    lower_bound: 0.9,
                    upper_bound: 1.1,
                },
                ordinal: 0,
            },
            QuantizedCandidate {
                distance: RabitqDistanceEstimate {
                    estimate: 1.1,
                    lower_bound: 1.0,
                    upper_bound: 1.2,
                },
                ordinal: 1,
            },
            QuantizedCandidate {
                distance: RabitqDistanceEstimate {
                    estimate: 2.0,
                    lower_bound: 1.1,
                    upper_bound: 2.9,
                },
                ordinal: 2,
            },
            QuantizedCandidate {
                distance: RabitqDistanceEstimate {
                    estimate: 2.1,
                    lower_bound: 1.3,
                    upper_bound: 2.9,
                },
                ordinal: 3,
            },
        ];
        assert_eq!(confidence_rescore_limit(&mut candidates, 2, 2), 3);
        assert_eq!(confidence_rescore_limit(&mut candidates, 2, 4), 4);
    }

    #[test]
    fn confidence_rescore_partition_matches_full_sort_reference() {
        fn reference(
            candidates: &mut [QuantizedCandidate],
            k: usize,
            analytical_floor: usize,
        ) -> usize {
            if candidates.is_empty() || k == 0 {
                return 0;
            }
            let mut upper_bounds = candidates
                .iter()
                .map(|candidate| (candidate.distance.upper_bound, candidate.ordinal))
                .collect::<Vec<_>>();
            let upper_limit = k.min(upper_bounds.len());
            super::keep_nearest(&mut upper_bounds, upper_limit);
            let kth_upper = upper_bounds
                .last()
                .map_or(f32::INFINITY, |(upper, _)| *upper);
            candidates.sort_unstable_by(|left, right| {
                left.distance
                    .lower_bound
                    .total_cmp(&right.distance.lower_bound)
                    .then_with(|| left.ordinal.cmp(&right.ordinal))
            });
            let bound_limit = candidates.partition_point(|candidate| {
                candidate.distance.lower_bound <= kth_upper * (1.0 + 8.0 * f32::EPSILON)
            });
            analytical_floor.max(bound_limit).min(candidates.len())
        }

        let candidates = (0..4096)
            .map(|ordinal| {
                let estimate = ((ordinal * 37) % 997) as f32 / 31.0;
                let error = ((ordinal * 13) % 17) as f32 / 32.0;
                QuantizedCandidate {
                    distance: RabitqDistanceEstimate {
                        estimate,
                        lower_bound: (estimate - error).max(0.0),
                        upper_bound: estimate + error,
                    },
                    ordinal,
                }
            })
            .collect::<Vec<_>>();
        for &(k, floor) in &[(1, 1), (10, 40), (10, 4096), (64, 256)] {
            let mut expected = candidates.clone();
            let mut actual = candidates.clone();
            let expected_limit = reference(&mut expected, k, floor);
            let actual_limit = confidence_rescore_limit(&mut actual, k, floor);
            let mut expected_ordinals = expected[..expected_limit]
                .iter()
                .map(|candidate| candidate.ordinal)
                .collect::<Vec<_>>();
            let mut actual_ordinals = actual[..actual_limit]
                .iter()
                .map(|candidate| candidate.ordinal)
                .collect::<Vec<_>>();
            expected_ordinals.sort_unstable();
            actual_ordinals.sort_unstable();
            assert_eq!(actual_limit, expected_limit);
            assert_eq!(actual_ordinals, expected_ordinals);
        }
    }

    #[test]
    fn compressed_navigation_uses_rho_floor_plus_bounds_and_returns_exact_order() {
        let dim = 16;
        let points = (0..256)
            .map(|ordinal| Point {
                id: format!("p{ordinal:03}"),
                vector: lcg_vector(ordinal as u64, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
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
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();
        let query = lcg_vector(17, dim);
        let k = 10;
        let (actual, exact_calls) = index.search_compressed(
            &query,
            &query,
            k,
            Some(points.len()),
            RESCORE_INFLATION,
            None,
        );

        let mut expected = points
            .iter()
            .enumerate()
            .map(|(ordinal, point)| {
                (
                    chirondb_types::distance::squared_l2(&query, &point.vector),
                    ordinal,
                )
            })
            .collect::<Vec<_>>();
        keep_nearest(&mut expected, k);
        let expected = expected
            .into_iter()
            .map(|(_, ordinal)| points[ordinal].id.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert!(
            exact_calls >= RESCORE_INFLATION * k && exact_calls <= points.len(),
            "compressed navigation touched {exact_calls} f32 rows for rho={}, k={k}",
            RESCORE_INFLATION
        );
        let rho_099 = rescore_inflation_for_recall_target(k, 0.99).unwrap();
        let (high_recall, high_recall_exact_calls) =
            index.search_compressed(&query, &query, k, Some(points.len()), rho_099, None);
        assert_eq!(high_recall, expected);
        assert!(
            high_recall_exact_calls >= rho_099 * k && high_recall_exact_calls <= points.len(),
            "0.99 navigation touched {high_recall_exact_calls} f32 rows for rho={rho_099}, k={k}"
        );

        let saturated = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .stack_size(512 * 1024)
            .build()
            .unwrap();
        saturated.install(|| {
            (0..256usize).into_par_iter().for_each(|_| {
                let (hits, calls) = index.search_compressed(
                    &query,
                    &query,
                    k,
                    Some(points.len()),
                    RESCORE_INFLATION,
                    None,
                );
                assert_eq!(hits, expected);
                assert!(calls >= RESCORE_INFLATION * k);
                assert!(calls <= points.len());
            });
        });
    }

    #[test]
    fn cancellable_search_stops_during_candidate_selection() {
        let dim = 16;
        let points = (0..64)
            .map(|ordinal| Point {
                id: format!("p{ordinal:03}"),
                vector: lcg_vector(ordinal as u64, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
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
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();
        let cancelled = AtomicBool::new(false);
        let predicate_calls = AtomicUsize::new(0);
        let cancel_after_seven = |_id: &str| {
            if predicate_calls.fetch_add(1, Ordering::Relaxed) == 6 {
                cancelled.store(true, Ordering::Release);
            }
            true
        };

        let hits = index.candidate_ids_with_recall_target_cancellable(
            &lcg_vector(17, dim),
            10,
            Some(64),
            0.95,
            Some(&cancel_after_seven),
            &cancelled,
        );

        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(predicate_calls.load(Ordering::Relaxed), 7);
        assert!(hits.len() <= 7);
    }

    #[test]
    fn sealed_search_specializes_unfiltered_and_prefers_ordinal_filter() {
        let dim = 16;
        let points = (0..64)
            .map(|ordinal| Point {
                id: format!("p{ordinal:03}"),
                vector: lcg_vector(ordinal as u64, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
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
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();
        let unfiltered =
            index.candidate_ids_with_recall_target(&points[17].vector, 10, None, 1.0, None);
        let string_calls = AtomicUsize::new(0);
        let allow_all = |_id: &str| {
            string_calls.fetch_add(1, Ordering::Relaxed);
            true
        };
        let filtered = index.candidate_ids_with_recall_target(
            &points[17].vector,
            10,
            None,
            1.0,
            Some(&allow_all),
        );
        assert_eq!(unfiltered, filtered);
        assert_eq!(string_calls.load(Ordering::Relaxed), points.len());

        let mut ordinals = crate::ordinal::SegmentOrdinalSet::new();
        ordinals.insert("segment", 17);
        let string_filter =
            |_id: &str| -> bool { panic!("sealed ordinal filtering must not consult point IDs") };

        let hits = index.candidate_ids_with_recall_target_ordinal_filter(
            &points[17].vector,
            10,
            None,
            1.0,
            Some(&string_filter),
            Some(&ordinals),
        );

        assert_eq!(hits, vec!["p017".to_string()]);
    }

    #[test]
    fn compressed_filter_keeps_rejected_rows_as_navigation_bridges() {
        struct ReachabilityFilter {
            admitted: HashSet<String>,
            bridge_checks: AtomicUsize,
        }

        impl FilterPredicate for ReachabilityFilter {
            fn matches(&self, id: &str) -> bool {
                self.admitted.contains(id)
            }

            fn navigable(&self, id: &str) -> bool {
                if !self.matches(id) {
                    self.bridge_checks.fetch_add(1, Ordering::Relaxed);
                }
                true
            }
        }

        let dim = 16;
        let points = (0..64)
            .map(|ordinal| Point {
                id: format!("p{ordinal:03}"),
                vector: lcg_vector(ordinal as u64, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
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
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();
        let predicate = ReachabilityFilter {
            admitted: (0..64)
                .step_by(8)
                .map(|ordinal| format!("p{ordinal:03}"))
                .collect(),
            bridge_checks: AtomicUsize::new(0),
        };
        let query = points[17].vector.clone();

        // Call the compressed leg directly so this unit test covers the
        // navigation/result split without manufacturing a 50k-point segment
        // merely to bypass the production small-segment exact dispatch.
        let (hits, _) = index.search_compressed(
            &query,
            &query,
            4,
            Some(64),
            RESCORE_INFLATION,
            Some(&predicate),
        );

        assert_eq!(hits.len(), 4);
        assert!(hits.iter().all(|id| predicate.admitted.contains(id)));
        assert!(predicate.bridge_checks.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn cosine_cell_graph_preserves_recall_and_bound_driven_exact_work() {
        let dim = 32;
        let points = (0..2_048)
            .map(|ordinal| Point {
                id: format!("p{ordinal:04}"),
                vector: lcg_vector(ordinal as u64 + 200_000, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
        build_segment(
            points.as_slice(),
            &segment,
            SealConfig {
                vector_dim: dim,
                metric: DistanceMetric::Cosine,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::Cosine).unwrap();
        let query = lcg_vector(200_017, dim);
        let expected = index.search_exact(&query, 10, None);
        let mut prepared = query.clone();
        crate::search::normalize(&mut prepared);
        #[cfg(feature = "search-metrics")]
        crate::index::search_metrics::reset();
        let (actual, exact_calls) =
            index.search_compressed(&query, &prepared, 10, Some(64), RESCORE_INFLATION, None);
        #[cfg(feature = "search-metrics")]
        {
            let metrics = crate::index::search_metrics::snapshot();
            assert!(metrics.graph_traversals > 0, "{metrics:?}");
            assert!(metrics.graph_hops > 0, "{metrics:?}");
            assert!(metrics.cells_touched > 0, "{metrics:?}");
            assert!(metrics.estimator_calls > 0, "{metrics:?}");
            assert_eq!(metrics.exact_reranks, exact_calls as u64, "{metrics:?}");
            assert!(metrics.heap_pushes >= metrics.heap_pops, "{metrics:?}");
        }
        let expected = expected.into_iter().collect::<HashSet<_>>();
        let intersection = actual
            .iter()
            .filter(|id| expected.contains(id.as_str()))
            .count();
        assert_eq!(actual.len(), 10);
        assert!(
            intersection >= 9,
            "cosine cell graph recall@10 = {:.3}",
            intersection as f32 / 10.0
        );
        assert!(
            exact_calls >= RESCORE_INFLATION * 10 && exact_calls <= points.len(),
            "cosine cell graph used {exact_calls} exact rows"
        );
        let strict_inflation = rescore_inflation_for_recall_target(10, 0.99).unwrap();
        let (strict, strict_exact_calls) =
            index.search_compressed(&query, &prepared, 10, Some(64), strict_inflation, None);
        let strict_intersection = strict
            .iter()
            .filter(|id| expected.contains(id.as_str()))
            .count();
        assert!(
            strict_intersection >= 9,
            "strict cosine radius route recall@10 = {:.3}",
            strict_intersection as f32 / 10.0
        );
        assert!(
            strict_exact_calls <= 64,
            "strict cosine radius route exceeded ef: {strict_exact_calls}"
        );

        let allowed = points
            .iter()
            .enumerate()
            .filter(|(ordinal, _)| ordinal % 3 == 0)
            .map(|(_, point)| point.id.clone())
            .collect::<HashSet<_>>();
        let (filtered, _) = index.search_compressed(
            &query,
            &prepared,
            10,
            Some(64),
            RESCORE_INFLATION,
            Some(&allowed),
        );
        assert_eq!(filtered.len(), 10);
        assert!(filtered.iter().all(|id| allowed.contains(id)));
    }

    #[cfg(feature = "search-metrics")]
    #[test]
    fn upper_layer_seed_oracle_is_exact_k_and_records_bounded_fallback() {
        let dim = 32;
        let points = (0..2_048)
            .map(|ordinal| Point {
                id: ordinal.to_string(),
                vector: lcg_vector(ordinal as u64 + 300_000, dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::Value::Null,
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
        build_segment(
            points.as_slice(),
            &segment,
            SealConfig {
                vector_dim: dim,
                metric: DistanceMetric::Cosine,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::Cosine).unwrap();
        let query = lcg_vector(300_017, dim);
        let exact = index.search_exact(&query, 10, None);
        let oracle_ids = exact
            .iter()
            .map(|id| id.parse::<u32>().unwrap())
            .collect::<Vec<_>>();

        crate::index::search_metrics::reset();
        let routed = index
            .diagnose_upper_layer_seed_search(&query, 10, 64, 4, None)
            .unwrap();
        let routed_metrics = crate::index::search_metrics::snapshot();
        assert_eq!(routed.len(), 10);
        assert!(routed_metrics.graph_hops > 0, "{routed_metrics:?}");
        assert!(
            routed_metrics.posting_scan_estimator_calls <= routed_metrics.estimator_calls,
            "{routed_metrics:?}"
        );
        assert_eq!(routed_metrics.returned_count, 10, "{routed_metrics:?}");
        assert_eq!(routed_metrics.underfilled_count, 0, "{routed_metrics:?}");

        crate::index::search_metrics::reset();
        let oracle = index
            .diagnose_upper_layer_seed_search(&query, 10, 64, 4, Some(&oracle_ids))
            .unwrap();
        let oracle_metrics = crate::index::search_metrics::snapshot();
        assert_eq!(oracle.len(), 10);
        assert_eq!(oracle_metrics.returned_count, 10, "{oracle_metrics:?}");
        assert_eq!(oracle_metrics.invalid_record_admissions, 0);
        let oracle_recall = oracle.iter().filter(|id| exact.contains(id)).count();
        assert!(oracle_recall >= 9, "oracle recall@10 = {oracle_recall}/10");
    }

    #[test]
    fn compressed_cascade_recall_at_10_vs_brute_force() {
        let dim = 16;
        let cluster_count = 40;
        let points_per_cluster = 20;
        let centers = (0..cluster_count)
            .map(|cluster| {
                lcg_vector(cluster as u64 + 80_000, dim)
                    .into_iter()
                    .map(|value| value * 8.0)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let points = centers
            .iter()
            .enumerate()
            .flat_map(|(cluster, center)| {
                (0..points_per_cluster).map(move |offset| {
                    let noise = lcg_vector((cluster * points_per_cluster + offset) as u64, dim);
                    Point {
                        id: format!("c{cluster:02}p{offset:02}"),
                        vector: center
                            .iter()
                            .zip(noise)
                            .map(|(value, noise)| value + noise * 0.2)
                            .collect(),
                        vectors: Default::default(),
                        sparse_vector: None,
                        payload: serde_json::Value::Null,
                    }
                })
            })
            .collect::<Vec<_>>();
        let temp = tempfile::tempdir().unwrap();
        let segment = temp.path().join("segment");
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
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();

        let k = 10;
        let mut intersection = 0usize;
        let queries = 30;
        for query_index in 0..queries {
            let noise = lcg_vector(query_index as u64 + 900_000, dim);
            let query = centers[query_index % centers.len()]
                .iter()
                .zip(noise)
                .map(|(value, noise)| value + noise * 0.1)
                .collect::<Vec<_>>();
            let (actual, exact_calls) =
                index.search_compressed(&query, &query, k, Some(128), RESCORE_INFLATION, None);
            let mut expected = points
                .iter()
                .enumerate()
                .map(|(ordinal, point)| {
                    (
                        chirondb_types::distance::squared_l2(&query, &point.vector),
                        ordinal,
                    )
                })
                .collect::<Vec<_>>();
            keep_nearest(&mut expected, k);
            let expected = expected
                .into_iter()
                .map(|(_, ordinal)| points[ordinal].id.as_str())
                .collect::<HashSet<_>>();
            intersection += actual
                .iter()
                .filter(|id| expected.contains(id.as_str()))
                .count();
            assert!(exact_calls <= RESCORE_INFLATION * k);
        }
        let recall = intersection as f32 / (queries * k) as f32;
        assert!(
            recall >= 0.85,
            "compressed cascade recall@10 {recall:.4} is below the local floor"
        );
    }

    #[test]
    #[ignore = "release-only P-F latency A/B; requires GAUSSDB_PF_SEGMENT_DIR"]
    fn compressed_navigation_latency_beats_f32_navigation_baseline() {
        let segment = std::path::PathBuf::from(
            std::env::var("GAUSSDB_PF_SEGMENT_DIR")
                .expect("set GAUSSDB_PF_SEGMENT_DIR to an Algorithm 2 sealed segment"),
        );
        let store = Arc::new(V4Store::open(&segment).unwrap());
        let index = IvfSegmentIndex::open(&segment, store, DistanceMetric::L2).unwrap();
        run_navigation_latency_ab(&index);
    }

    fn run_navigation_latency_ab(index: &IvfSegmentIndex) {
        let queries = (0..20)
            .map(|query| lcg_vector(100_000 + query, index.vector_dim()))
            .collect::<Vec<_>>();
        let k = 10;
        let ef = 128;

        for query in queries.iter().take(5) {
            black_box(index.search_compressed(query, query, k, Some(ef), RESCORE_INFLATION, None));
            black_box(search_f32_navigation_baseline(index, query, k, ef));
        }

        let time_compressed = || {
            let started = Instant::now();
            for query in &queries {
                black_box(index.search_compressed(
                    query,
                    query,
                    k,
                    Some(ef),
                    RESCORE_INFLATION,
                    None,
                ));
            }
            started.elapsed()
        };
        let time_baseline = || {
            let started = Instant::now();
            for query in &queries {
                black_box(search_f32_navigation_baseline(index, query, k, ef));
            }
            started.elapsed()
        };
        let mut compressed = Duration::ZERO;
        let mut baseline = Duration::ZERO;
        for round in 0..4 {
            if round % 2 == 0 {
                baseline += time_baseline();
                compressed += time_compressed();
            } else {
                compressed += time_compressed();
                baseline += time_baseline();
            }
        }
        let timed_queries = queries.len() * 4;
        let speedup = baseline.as_secs_f64() / compressed.as_secs_f64();
        eprintln!(
            "P-F navigation latency: compressed={:.3}ms/query f32-baseline={:.3}ms/query speedup={speedup:.2}x",
            compressed.as_secs_f64() * 1_000.0 / timed_queries as f64,
            baseline.as_secs_f64() * 1_000.0 / timed_queries as f64,
        );
        assert!(
            compressed < baseline,
            "compressed navigation did not beat the f32 baseline: {speedup:.2}x"
        );
    }

    fn search_f32_navigation_baseline(
        index: &IvfSegmentIndex,
        query: &[f32],
        k: usize,
        ef: usize,
    ) -> Vec<String> {
        let mut cells = index
            .centroids
            .iter()
            .enumerate()
            .map(|(cell, centroid)| (chirondb_types::distance::squared_l2(query, centroid), cell))
            .collect::<Vec<_>>();
        cells.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let min_probe = ((index.cells() as f64).sqrt().ceil() as usize).clamp(1, index.cells());
        let posting_target = ef.saturating_mul(super::L1_INFLATION).max(k);
        let mut selected_cells = Vec::new();
        let mut posting_count = 0usize;
        for &(_, cell) in &cells {
            posting_count += index.ivf.posting_range(cell).map_or(0, |range| range.len());
            selected_cells.push(cell);
            if selected_cells.len() >= min_probe && posting_count >= posting_target {
                break;
            }
        }
        let rotated_query = rotate_for_cascade(query);
        let mut tables = super::RabitqQueryTables {
            global: index.rabitq.prepare_global_query_table(&rotated_query),
            cells: (0..index.cells()).map(|_| None).collect(),
        };
        let mut l1 = index.score_cells(&selected_cells, &rotated_query, None, &mut tables);
        super::keep_quantized_by_lower_bound(&mut l1, ef.max(k));

        let mut visited = HashSet::with_capacity(ef.saturating_mul(4));
        let mut candidates = BinaryHeap::<Reverse<(OrdF32, usize)>>::new();
        let mut found = BinaryHeap::<(OrdF32, usize)>::new();
        for candidate in l1.iter().take(ef) {
            if visited.insert(candidate.ordinal)
                && let Some(distance) = index.exact_distance(query, candidate.ordinal)
            {
                candidates.push(Reverse((OrdF32(distance), candidate.ordinal)));
                found.push((OrdF32(distance), candidate.ordinal));
            }
        }
        while let Some(Reverse((OrdF32(candidate_distance), ordinal))) = candidates.pop() {
            let worst = found.peek().map_or(f32::INFINITY, |entry| entry.0.0);
            if found.len() >= ef && candidate_distance > worst {
                break;
            }
            for neighbor in index.neighbors(ordinal).unwrap_or_default() {
                let neighbor = neighbor as usize;
                if !visited.insert(neighbor) {
                    continue;
                }
                let Some(distance) = index.exact_distance(query, neighbor) else {
                    continue;
                };
                let worst = found.peek().map_or(f32::INFINITY, |entry| entry.0.0);
                if found.len() < ef || distance < worst {
                    candidates.push(Reverse((OrdF32(distance), neighbor)));
                    found.push((OrdF32(distance), neighbor));
                    if found.len() > ef {
                        found.pop();
                    }
                }
            }
        }
        found
            .into_sorted_vec()
            .into_iter()
            .take(k)
            .filter_map(|(_, ordinal)| index.store.id(ordinal).map(str::to_string))
            .collect()
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
}
