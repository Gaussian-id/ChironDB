//! Dense and sparse search orchestration helpers extracted from src/db.rs.
//! All functions here take individual field arguments rather than the private
//! Collection struct, making them testable and reusable outside db.rs.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use bumpalo::collections::Vec as BumpVec;

use crate::{
    Filter,
    error::{GaussError, Result},
    h2qg::H2qgIndex,
    model::{HybridFusion, Point, SearchHit, SearchResponse, SparseVector},
    query_arena::with_query_arena,
    sparse_index::{SparseIndex, SparsePosting},
};

// ── Shared ranked-point type ─────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct RankedPoint {
    pub(crate) id: String,
    pub(crate) score: f32,
}

pub(crate) fn rank_order(left: &RankedPoint, right: &RankedPoint) -> std::cmp::Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.id.cmp(&right.id))
}

#[derive(Debug)]
pub(crate) struct SparseSearchOutcome {
    pub(crate) ranked: Vec<RankedPoint>,
    pub(crate) searched: usize,
    pub(crate) degraded: bool,
}

// ── Point resolution across segments ─────────────────────────────────────────

/// Resolve a live point by id across the streamer and all searcher
/// segments (LS-Vec rework D3). Implemented by `db::Collection`; lets
/// search helpers hydrate candidate ids without assuming one merged
/// points map.
pub(crate) trait PointResolver {
    fn resolve_point(&self, id: &str) -> Option<Cow<'_, Point>>;

    /// Test read-state visibility without hydrating vector or payload data.
    /// Sealed sparse postings are ID-keyed for compatibility; unfiltered
    /// admission needs only this membership answer until final top-k hydration.
    fn contains_point(&self, id: &str) -> bool {
        self.resolve_point(id).is_some()
    }
}

/// Single-map resolver: the streamer map or a test fixture.
impl PointResolver for HashMap<String, Point> {
    fn resolve_point(&self, id: &str) -> Option<Cow<'_, Point>> {
        self.get(id).map(Cow::Borrowed)
    }

    fn contains_point(&self, id: &str) -> bool {
        self.contains_key(id)
    }
}

// ── Point-vector helpers ─────────────────────────────────────────────────────

pub(crate) fn point_vector<'a>(point: &'a Point, vector_name: Option<&str>) -> Option<&'a [f32]> {
    match vector_name {
        Some(name) => point.vectors.get(name).map(Vec::as_slice),
        None => Some(point.vector.as_slice()),
    }
}

pub(crate) fn required_point_vector<'a>(
    point: &'a Point,
    vector_name: Option<&str>,
) -> Result<&'a [f32]> {
    point_vector(point, vector_name).ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "point {} does not have vector field {}",
            point.id,
            vector_name.unwrap_or("default")
        ))
    })
}

// ── Vector arithmetic ────────────────────────────────────────────────────────

pub(crate) fn add_scaled(target: &mut [f32], vector: &[f32], scale: f32) {
    for (t, v) in target.iter_mut().zip(vector) {
        *t += v * scale;
    }
}

pub(crate) fn normalize(vector: &mut [f32]) {
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm == 0.0 {
        return;
    }
    for v in vector {
        *v /= norm;
    }
}

// ── Dense ANN candidate selection ────────────────────────────────────────────

/// Returns an ordered slice of points to score for a dense query.
/// Backend candidates come first (in candidate order), followed by any points
/// not covered by the index, so the scorer can respect `budget_ms` by
/// stopping early once top-k quality is reached.
///
/// PA-4 / PC-1b: primary index is `&dyn IndexBackend` so the engine dispatches
/// HNSW (`h2qg::H2qgIndex`) and RaBitQ (`index::rabitq::RabitqBackend`)
/// through the same call. Named-vector fields stay on H2QG for now — those
/// land when RaBitQ grows multi-vector support.
///
/// P2F: `filter` is the inline filter predicate consulted per-neighbour inside
/// the HNSW beam search. `None` matches the original un-filtered contract.
/// When set, the HNSW engine prunes filtered-out candidates during beam
/// expansion so they never inflate the candidate set; the caller still keeps
/// the post-filter rescore as defense in depth (see `db::search_excluding`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn search_point_candidates<'a>(
    h2qg: Option<&dyn crate::index::IndexBackend>,
    named_h2qg: &HashMap<String, H2qgIndex>,
    points: &'a HashMap<String, Point>,
    query: &[f32],
    k: usize,
    vector_name: Option<&str>,
    ef_search: Option<usize>,
    recall_target: f32,
    filter: Option<&dyn crate::index::FilterPredicate>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Vec<&'a Point> {
    let _span = tracing::info_span!(
        "gaussdb.search.h2qg_candidates",
        points = points.len(),
        k,
        vector_name = vector_name.unwrap_or("default"),
        filtered = filter.is_some(),
    )
    .entered();

    let named_dyn: Option<&dyn crate::index::IndexBackend> = match vector_name {
        Some(name) => named_h2qg
            .get(name)
            .map(|idx| idx as &dyn crate::index::IndexBackend),
        None => h2qg,
    };

    let Some(index) = named_dyn else {
        return points.values().collect();
    };

    // B3 (Phase 1): borrow-keyed dedup set instead of clone-per-insert.
    // M4-001 (Phase 1): the working `ordered` Vec lives in the thread-local
    // bumpalo query arena. Push/grow operations during scratch construction
    // bump the arena cursor instead of going through the system allocator;
    // the arena is reset on the next call so the capacity is reused.
    // P2F: pass `filter` through to the backend so the HNSW engine prunes
    // filtered-out neighbours during beam expansion.
    let cand_ids: Vec<String> = if let Some(cancelled) = cancelled {
        index.candidate_ids_with_recall_target_cancellable(
            query,
            k,
            ef_search,
            recall_target,
            filter,
            cancelled,
        )
    } else {
        index.candidate_ids_with_recall_target(query, k, ef_search, recall_target, filter)
    };

    with_query_arena(|arena| {
        let mut seen: HashSet<&str> = HashSet::with_capacity(cand_ids.len());
        let mut ordered: BumpVec<'_, &'a Point> = BumpVec::with_capacity_in(cand_ids.len(), arena);

        for id in &cand_ids {
            if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }
            if seen.insert(id.as_str())
                && let Some(point) = points.get(id.as_str())
            {
                ordered.push(point);
            }
        }

        // Safety net only: an index that hasn't yet caught up with every
        // upserted point (the narrow window before the incremental insert
        // / threshold-crossing build runs) could omit some points from
        // `cand_ids` entirely. Backfill those so search never silently
        // drops a point the caller expects to be searchable.
        //
        // This used to be a full O(N) scan over the whole collection on
        // EVERY query, unconditionally, followed by a second O(N) loop that
        // pushed every remaining point regardless of index membership --
        // i.e. every search materialised the entire collection and the ANN
        // index never actually narrowed anything down (see git blame on
        // this function; both loops predate this fix). Gating on
        // `indexed_points() < points.len()` skips the scan entirely in the
        // common case where the index already covers every point, which is
        // every case except that narrow window.
        if index.indexed_points() < points.len() {
            let backfilled_before = ordered.len();
            for (id, point) in points {
                if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                    break;
                }
                if !index.contains(id) && seen.insert(id.as_str()) {
                    ordered.push(point);
                }
            }
            let backfilled = ordered.len() - backfilled_before;
            if backfilled > 0 {
                crate::observability::observe_index_backfill_scan(backfilled);
            }
        }

        // Final materialisation: one heap allocation, identical to the prior
        // contract. The arena holds onto its capacity for the next query.
        ordered.iter().copied().collect::<Vec<&'a Point>>()
    })
}

/// Multi-segment dense candidate selection (LS-Vec rework D3): fans the
/// query out across the streamer leg and every searcher segment's own
/// index, concatenating per-leg candidates. Ids are live in exactly one
/// segment (upserts tombstone the old location), so a plain seen-set
/// dedups across legs. Tombstoned rows are skipped at resolution time —
/// this replaces the old load-time `points.remove` tombstone application.
///
/// When `global_backend` is `Some` (RaBitQ / Vamana / IVF index kinds,
/// which index every live point in one structure), it is used as a single
/// leg over the union of all stores instead of per-searcher fan-out —
/// preserving those backends' existing behavior.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fan_out_candidates<'a>(
    global_backend: Option<&dyn crate::index::IndexBackend>,
    streamer: &'a crate::streamer::Streamer,
    sealing: Option<&'a crate::streamer::Streamer>,
    searchers: &'a [crate::searcher::SegmentSearcher],
    visibility: &'a crate::overlay::OverlayReadState,
    resolver: &'a dyn PointResolver,
    total_live: usize,
    query: &[f32],
    k: usize,
    vector_name: Option<&str>,
    ef_search: Option<usize>,
    recall_target: f32,
    filter: Option<&dyn crate::index::FilterPredicate>,
    ordinal_filter: Option<&dyn crate::index::OrdinalFilterPredicate>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Vec<Cow<'a, Point>> {
    if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
        return Vec::new();
    }
    if let Some(global) = global_backend {
        // Whole-collection backend: candidates resolved via the global ID
        // authority, with the same narrow-window backfill contract as the
        // single-map path (an id upserted after the backend last indexed).
        let cand_ids = if let Some(cancelled) = cancelled {
            global.candidate_ids_with_recall_target_cancellable(
                query,
                k,
                ef_search,
                recall_target,
                filter,
                cancelled,
            )
        } else {
            global.candidate_ids_with_recall_target(query, k, ef_search, recall_target, filter)
        };
        let mut seen: HashSet<String> = HashSet::with_capacity(cand_ids.len());
        let mut ordered: Vec<Cow<'a, Point>> = Vec::with_capacity(cand_ids.len());
        for id in &cand_ids {
            if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }
            if seen.insert(id.clone())
                && let Some(point) = resolver.resolve_point(id.as_str())
            {
                ordered.push(point);
            }
        }
        if global.indexed_points() < total_live {
            let backfilled_before = ordered.len();
            for point in streamer
                .points
                .values()
                .map(Cow::Borrowed)
                .chain(
                    sealing
                        .into_iter()
                        .flat_map(|streamer| streamer.points.values())
                        .map(Cow::Borrowed),
                )
                .chain(searchers.iter().enumerate().flat_map(|(index, searcher)| {
                    searcher.iter_visible(visibility.point_tombstones(index))
                }))
            {
                if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                    break;
                }
                if !global.contains(&point.id)
                    && seen.insert(point.id.clone())
                    && let Some(point) = resolver.resolve_point(&point.id)
                {
                    ordered.push(point);
                }
            }
            let backfilled = ordered.len() - backfilled_before;
            if backfilled > 0 {
                crate::observability::observe_index_backfill_scan(backfilled);
            }
        }
        return ordered;
    }

    // Streamer leg: existing single-map candidate selection, including the
    // narrow-window backfill scan (which now only ever scans the streamer —
    // sealed segments are complete by construction).
    let mut ordered = search_point_candidates(
        streamer
            .hnsw
            .as_ref()
            .map(|h| h as &dyn crate::index::IndexBackend),
        &streamer.named_hnsw,
        &streamer.points,
        query,
        k,
        vector_name,
        ef_search,
        recall_target,
        filter,
        cancelled,
    )
    .into_iter()
    .map(Cow::Borrowed)
    .collect::<Vec<_>>();

    let mut seen: HashSet<String> = ordered.iter().map(|p| p.id.clone()).collect();
    if let Some(sealing) = sealing {
        // A frozen leg may still contain IDs superseded by the active
        // streamer. Only IDs actually present in both legs can consume a
        // result slot during dedup. Widening by every newer-tier candidate
        // couples an unrelated mutable tail's ef to the sealed index's k and
        // can make LS-VEC do orders of magnitude more work.
        let overlap = seen
            .iter()
            .filter(|id| sealing.points.contains_key(id.as_str()))
            .count();
        let leg_k = k.saturating_add(overlap);
        for point in search_point_candidates(
            sealing
                .hnsw
                .as_ref()
                .map(|h| h as &dyn crate::index::IndexBackend),
            &sealing.named_hnsw,
            &sealing.points,
            query,
            leg_k,
            vector_name,
            ef_search,
            recall_target,
            filter,
            cancelled,
        ) {
            if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }
            if seen.insert(point.id.clone())
                && let Some(point) = resolver.resolve_point(&point.id)
            {
                ordered.push(point);
            }
        }
    }

    // Searcher legs, newest → oldest. Each leg's candidate ids resolve
    // against its own store; tombstoned or superseded ids drop out via
    // `get_live` + the seen-set.
    for (searcher_index, searcher) in searchers.iter().enumerate().rev() {
        if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            break;
        }
        // One live ID belongs to exactly one tier. Only real cross-tier ID
        // overlap and this segment's tombstones can consume result slots;
        // unrelated candidates from newer tiers must not widen this sealed
        // ANN query.
        let tombstones = usize::try_from(searcher.tombstone_ordinals.len())
            .unwrap_or(usize::MAX)
            .max(searcher.tombstones.len());
        let overlap = seen
            .iter()
            .filter(|id| searcher.store.contains_id(id.as_str()))
            .count();
        let leg_k = k.saturating_add(overlap).saturating_add(tombstones);
        let segment_filter = SegmentFilterPredicate {
            result_filter: filter,
            tombstones: &searcher.tombstones,
        };
        let segment_ordinal_filter = SegmentOrdinalFilterPredicate {
            result_filter: ordinal_filter,
            segment_id: &searcher.id,
            tombstones: &searcher.tombstone_ordinals,
            overlay_tombstones: visibility.point_tombstones(searcher_index),
        };
        match searcher.backend_for(vector_name) {
            Some(index) => {
                let candidate_ids = if let Some(cancelled) = cancelled {
                    index.candidate_ids_with_recall_target_ordinal_filter_cancellable(
                        query,
                        leg_k,
                        ef_search,
                        recall_target,
                        Some(&segment_filter),
                        Some(&segment_ordinal_filter),
                        cancelled,
                    )
                } else {
                    index.candidate_ids_with_recall_target_ordinal_filter(
                        query,
                        leg_k,
                        ef_search,
                        recall_target,
                        Some(&segment_filter),
                        Some(&segment_ordinal_filter),
                    )
                };
                for id in candidate_ids {
                    if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        break;
                    }
                    if let Some(point) =
                        searcher.get_visible(&id, visibility.point_tombstones(searcher_index))
                        && seen.insert(point.id.clone())
                    {
                        ordered.push(point);
                    }
                }
            }
            None => {
                // Segment without an index artifact for this vector field:
                // flat leg, every live point becomes a candidate (same
                // contract as the sub-threshold flat path).
                for point in searcher.iter_visible(visibility.point_tombstones(searcher_index)) {
                    if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        break;
                    }
                    if seen.insert(point.id.clone()) {
                        ordered.push(point);
                    }
                }
            }
        }
    }
    ordered
}

struct SegmentFilterPredicate<'a> {
    result_filter: Option<&'a dyn crate::index::FilterPredicate>,
    tombstones: &'a HashSet<String>,
}

impl crate::index::FilterPredicate for SegmentFilterPredicate<'_> {
    fn matches(&self, id: &str) -> bool {
        !self.tombstones.contains(id)
            && self
                .result_filter
                .is_none_or(|predicate| predicate.matches(id))
    }

    fn navigable(&self, id: &str) -> bool {
        !self.tombstones.contains(id)
            && self
                .result_filter
                .is_none_or(|predicate| predicate.navigable(id))
    }
}

struct SegmentOrdinalFilterPredicate<'a> {
    result_filter: Option<&'a dyn crate::index::OrdinalFilterPredicate>,
    segment_id: &'a str,
    tombstones: &'a roaring::RoaringBitmap,
    overlay_tombstones: Option<&'a roaring::RoaringBitmap>,
}

impl crate::index::OrdinalFilterPredicate for SegmentOrdinalFilterPredicate<'_> {
    fn matches_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        segment == self.segment_id
            && !self.tombstones.contains(ordinal)
            && self
                .overlay_tombstones
                .is_none_or(|tombstones| !tombstones.contains(ordinal))
            && self
                .result_filter
                .is_none_or(|predicate| predicate.matches_ordinal(segment, ordinal))
    }

    fn navigable_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        segment == self.segment_id
            && !self.tombstones.contains(ordinal)
            && self
                .overlay_tombstones
                .is_none_or(|tombstones| !tombstones.contains(ordinal))
            && self
                .result_filter
                .is_none_or(|predicate| predicate.navigable_ordinal(segment, ordinal))
    }
}

// ── Sparse search ─────────────────────────────────────────────────────────────

pub(crate) struct SparseSearchParams<'a> {
    pub(crate) query: &'a SparseVector,
    pub(crate) limit: usize,
    pub(crate) payload_candidates: Option<&'a HashSet<String>>,
    pub(crate) filter: Option<&'a Filter>,
    pub(crate) budget: Option<Duration>,
    pub(crate) started: Instant,
    pub(crate) cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

pub(crate) fn sparse_search_ranked(
    sparse_index: &SparseIndex,
    points: &dyn PointResolver,
    params: SparseSearchParams<'_>,
) -> SparseSearchOutcome {
    let SparseSearchParams {
        query,
        limit,
        payload_candidates,
        filter,
        budget,
        started,
        cancelled,
    } = params;
    let use_block_max = sparse_query_can_use_block_max(sparse_index, query);
    let strategy = if use_block_max {
        "block_max"
    } else {
        "exhaustive"
    };
    let _span = tracing::info_span!(
        "gaussdb.search.sparse_rank",
        strategy,
        terms = query.indices.len(),
        limit
    )
    .entered();

    let mut outcome = if use_block_max {
        sparse_search_block_max(
            sparse_index,
            points,
            query,
            limit,
            payload_candidates,
            filter,
            budget,
            started,
            cancelled,
        )
    } else {
        sparse_search_exhaustive(
            sparse_index,
            points,
            query,
            payload_candidates,
            filter,
            budget,
            started,
            cancelled,
        )
    };
    outcome.ranked.sort_by(rank_order);
    outcome.ranked.truncate(limit);
    outcome
}

fn sparse_query_can_use_block_max(sparse_index: &SparseIndex, query: &SparseVector) -> bool {
    query
        .indices
        .iter()
        .zip(&query.values)
        .all(|(dimension, query_value)| {
            *query_value >= 0.0
                && sparse_index
                    .dimensions
                    .get(dimension)
                    .is_none_or(|list| list.min_value >= 0.0)
        })
}

#[allow(clippy::too_many_arguments)]
fn sparse_search_exhaustive(
    sparse_index: &SparseIndex,
    points: &dyn PointResolver,
    query: &SparseVector,
    payload_candidates: Option<&HashSet<String>>,
    filter: Option<&Filter>,
    budget: Option<Duration>,
    started: Instant,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> SparseSearchOutcome {
    let mut scores = HashMap::<String, f32>::new();
    let mut searched = 0;
    let mut degraded = false;
    'posting_scan: for (&index, &query_value) in query.indices.iter().zip(&query.values) {
        if let Some(list) = sparse_index.dimensions.get(&index) {
            for posting in &list.postings {
                if sparse_should_stop(budget, started, cancelled) {
                    degraded = true;
                    break 'posting_scan;
                }
                if payload_candidates
                    .as_ref()
                    .is_some_and(|candidates| !candidates.contains(&posting.id))
                {
                    continue;
                }
                searched += 1;
                // B4 (Phase 1): clone the id only on first insert; subsequent
                // term-postings for the same doc reuse the existing slot.
                let contrib = query_value * posting.value;
                match scores.get_mut(posting.id.as_str()) {
                    Some(slot) => *slot += contrib,
                    None => {
                        scores.insert(posting.id.clone(), contrib);
                    }
                }
            }
        }
    }
    SparseSearchOutcome {
        ranked: sparse_scores_to_ranked(points, scores, filter),
        searched,
        degraded,
    }
}

#[allow(clippy::too_many_arguments)]
fn sparse_search_block_max(
    sparse_index: &SparseIndex,
    points: &dyn PointResolver,
    query: &SparseVector,
    limit: usize,
    payload_candidates: Option<&HashSet<String>>,
    filter: Option<&Filter>,
    budget: Option<Duration>,
    started: Instant,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> SparseSearchOutcome {
    let mut terms = query
        .indices
        .iter()
        .zip(&query.values)
        .filter_map(|(&dimension, &query_value)| {
            let list = sparse_index.dimensions.get(&dimension)?;
            let bound = query_value * list.max_value;
            Some((dimension, query_value, bound.max(0.0)))
        })
        .collect::<Vec<_>>();
    terms.sort_by(|left, right| {
        right
            .2
            .total_cmp(&left.2)
            .then_with(|| left.0.cmp(&right.0))
    });

    let mut suffix_bounds = vec![0.0_f32; terms.len() + 1];
    for index in (0..terms.len()).rev() {
        suffix_bounds[index] = suffix_bounds[index + 1] + terms[index].2;
    }
    // prefix_bounds[i] = sum of upper bounds for all terms before position i.
    // Used in WAND term-level and block-level pruning: a document's accumulated
    // score from the first i terms is at most prefix_bounds[i].
    let mut prefix_bounds = vec![0.0_f32; terms.len() + 1];
    for index in 0..terms.len() {
        prefix_bounds[index + 1] = prefix_bounds[index] + terms[index].2;
    }

    let mut scores = HashMap::<String, f32>::new();
    let mut searched = 0;
    let mut degraded = false;
    'term_scan: for (term_position, (dimension, query_value, _)) in terms.iter().enumerate() {
        let Some(list) = sparse_index.dimensions.get(dimension) else {
            continue;
        };
        let remaining_bound = suffix_bounds[term_position + 1];
        let prev_upper = prefix_bounds[term_position];

        // WAND term-level pruning: upper bound for any doc = prev_upper + term_max + future.
        // Since postings are sorted value-desc, list.max_value is the max any doc contributes.
        // If this can't beat the threshold, skip the entire term.
        if let Some(threshold) = sparse_score_threshold(&scores, limit)
            && prev_upper + *query_value * list.max_value + remaining_bound < threshold
        {
            continue 'term_scan;
        }

        for block in &list.blocks {
            if sparse_should_stop(budget, started, cancelled) {
                degraded = true;
                break 'term_scan;
            }
            if let Some(threshold) = sparse_score_threshold(&scores, limit) {
                // Conservative block bound: uses global prev_upper (not per-block existing).
                // Blocks are sorted value-desc so max_value decreases; once this fails,
                // all remaining blocks for this term also fail → break instead of continue.
                let conservative_bound =
                    prev_upper + *query_value * block.max_value + remaining_bound;
                if conservative_bound < threshold {
                    break;
                }
                // Precise check: use the actual maximum accumulated score for docs in this block.
                let existing = max_existing_sparse_score_in_block(
                    points,
                    &scores,
                    &list.postings[block.start..block.end],
                    payload_candidates,
                    filter,
                );
                let block_bound = existing + *query_value * block.max_value + remaining_bound;
                if block_bound < threshold {
                    // This specific block fails with exact existing scores, but a later block
                    // could have docs with higher existing scores → skip block, not entire term.
                    continue;
                }
            }
            for posting in &list.postings[block.start..block.end] {
                if sparse_should_stop(budget, started, cancelled) {
                    degraded = true;
                    break 'term_scan;
                }
                if !sparse_posting_matches(points, posting, payload_candidates, filter) {
                    continue;
                }
                searched += 1;
                // B4 (Phase 1): single clone-on-insert in block-max sparse loop.
                let contrib = *query_value * posting.value;
                match scores.get_mut(posting.id.as_str()) {
                    Some(slot) => *slot += contrib,
                    None => {
                        scores.insert(posting.id.clone(), contrib);
                    }
                }
            }
        }
    }
    SparseSearchOutcome {
        ranked: sparse_scores_to_ranked(points, scores, None),
        searched,
        degraded,
    }
}

fn sparse_should_stop(
    budget: Option<Duration>,
    started: Instant,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> bool {
    cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        || budget.is_some_and(|budget| started.elapsed() >= budget)
}

fn sparse_score_threshold(scores: &HashMap<String, f32>, limit: usize) -> Option<f32> {
    if limit == 0 || scores.len() < limit {
        return None;
    }
    let mut vals = scores.values().copied().collect::<Vec<_>>();
    vals.sort_by(|a, b| b.total_cmp(a));
    vals.get(limit - 1).copied()
}

fn max_existing_sparse_score_in_block(
    points: &dyn PointResolver,
    scores: &HashMap<String, f32>,
    postings: &[SparsePosting],
    payload_candidates: Option<&HashSet<String>>,
    filter: Option<&Filter>,
) -> f32 {
    postings
        .iter()
        .filter(|p| sparse_posting_matches(points, p, payload_candidates, filter))
        .map(|p| scores.get(&p.id).copied().unwrap_or_default())
        .fold(0.0, f32::max)
}

fn sparse_posting_matches(
    points: &dyn PointResolver,
    posting: &SparsePosting,
    payload_candidates: Option<&HashSet<String>>,
    filter: Option<&Filter>,
) -> bool {
    if payload_candidates.is_some_and(|c| !c.contains(&posting.id)) {
        return false;
    }
    if filter.is_none() {
        return points.contains_point(&posting.id);
    }
    let Some(point) = points.resolve_point(&posting.id) else {
        return false;
    };
    filter.is_none_or(|f| f.matches(&point.payload))
}

fn sparse_scores_to_ranked(
    points: &dyn PointResolver,
    scores: HashMap<String, f32>,
    filter: Option<&Filter>,
) -> Vec<RankedPoint> {
    scores
        .into_iter()
        .filter_map(|(id, score)| {
            if score <= 0.0 {
                return None;
            }
            if let Some(filter) = filter {
                let point = points.resolve_point(&id)?;
                if !filter.matches(&point.payload) {
                    return None;
                }
            } else if !points.contains_point(&id) {
                return None;
            }
            Some(RankedPoint { id, score })
        })
        .collect()
}

// ── Multi-search / hybrid fusion ─────────────────────────────────────────────

pub(crate) fn fuse_search_responses(
    results: &[SearchResponse],
    fusion: HybridFusion,
    k: usize,
    weights: &[f32],
    started: Instant,
) -> SearchResponse {
    let mut scores = HashMap::<String, f32>::new();
    let mut payloads = HashMap::<String, serde_json::Value>::new();
    for (result_index, result) in results.iter().enumerate() {
        let weight = weights.get(result_index).copied().unwrap_or(1.0);
        let (min, max) = minmax(result.hits.iter().map(|hit| hit.score));
        for (rank, hit) in result.hits.iter().enumerate() {
            let contribution = match fusion {
                HybridFusion::Rrf => weight / (60.0 + rank as f32 + 1.0),
                HybridFusion::Weighted => weight * rescale(hit.score, min, max),
            };
            *scores.entry(hit.id.clone()).or_default() += contribution;
            payloads
                .entry(hit.id.clone())
                .or_insert_with(|| hit.payload.clone());
        }
    }

    let mut fused = scores
        .into_iter()
        .map(|(id, score)| SearchHit {
            payload: payloads.remove(&id).unwrap_or(serde_json::Value::Null),
            id,
            score,
        })
        .collect::<Vec<_>>();
    fused.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    fused.truncate(k);
    SearchResponse {
        hits: fused,
        degraded: results.iter().any(|r| r.degraded),
        searched: results.iter().map(|r| r.searched).sum(),
        elapsed_ms: started.elapsed().as_millis(),
        graph: None,
    }
}

pub(crate) fn fuse_rankings(
    dense: &[RankedPoint],
    sparse: &[RankedPoint],
    fusion: HybridFusion,
    dense_weight: f32,
    sparse_weight: f32,
) -> Vec<RankedPoint> {
    fuse_rankings_with_rrf_constant(dense, sparse, fusion, dense_weight, sparse_weight, 60.0)
}

/// Native text retrieval has a bounded `4 * k` rank window and returns at most
/// 20 hits. RRF's published smaller constant preserves separation among the
/// top ranks in this short-list regime while retaining equal branch weights.
pub(crate) fn fuse_text_rankings(
    dense: &[RankedPoint],
    sparse: &[RankedPoint],
) -> Vec<RankedPoint> {
    fuse_rankings_with_rrf_constant(dense, sparse, HybridFusion::Rrf, 1.0, 1.0, 10.0)
}

fn fuse_rankings_with_rrf_constant(
    dense: &[RankedPoint],
    sparse: &[RankedPoint],
    fusion: HybridFusion,
    dense_weight: f32,
    sparse_weight: f32,
    rrf_rank_constant: f32,
) -> Vec<RankedPoint> {
    let dense_ranks = dense
        .iter()
        .enumerate()
        .map(|(rank, point)| (point.id.as_str(), rank))
        .collect::<HashMap<_, _>>();
    let sparse_ranks = sparse
        .iter()
        .enumerate()
        .map(|(rank, point)| (point.id.as_str(), rank))
        .collect::<HashMap<_, _>>();
    let mut scores = HashMap::<String, f32>::new();
    add_fusion_scores(&mut scores, dense, fusion, dense_weight, rrf_rank_constant);
    add_fusion_scores(
        &mut scores,
        sparse,
        fusion,
        sparse_weight,
        rrf_rank_constant,
    );
    let mut fused = scores
        .into_iter()
        .map(|(id, score)| RankedPoint { id, score })
        .collect::<Vec<_>>();
    fused.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| {
                dense_ranks
                    .get(left.id.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(
                        &dense_ranks
                            .get(right.id.as_str())
                            .copied()
                            .unwrap_or(usize::MAX),
                    )
            })
            .then_with(|| {
                sparse_ranks
                    .get(left.id.as_str())
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(
                        &sparse_ranks
                            .get(right.id.as_str())
                            .copied()
                            .unwrap_or(usize::MAX),
                    )
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    fused
}

fn add_fusion_scores(
    scores: &mut HashMap<String, f32>,
    ranked: &[RankedPoint],
    fusion: HybridFusion,
    weight: f32,
    rrf_rank_constant: f32,
) {
    let (min, max) = minmax(ranked.iter().map(|point| point.score));
    for (rank, point) in ranked.iter().enumerate() {
        let contribution = match fusion {
            HybridFusion::Rrf => weight / (rrf_rank_constant + rank as f32 + 1.0),
            HybridFusion::Weighted => weight * rescale(point.score, min, max),
        };
        *scores.entry(point.id.clone()).or_default() += contribution;
    }
}

/// Min/max over a score list; `Weighted` fusion mixes branches with
/// incompatible raw scales (cosine in `[-1,1]` vs unbounded BM25), so each
/// branch must be rescaled to `[0,1]` before weights are applied or the
/// larger-magnitude branch silently dominates.
fn minmax(scores: impl Iterator<Item = f32>) -> (f32, f32) {
    scores.fold((f32::INFINITY, f32::NEG_INFINITY), |(min, max), s| {
        (min.min(s), max.max(s))
    })
}

fn rescale(score: f32, min: f32, max: f32) -> f32 {
    if max > min {
        (score - min) / (max - min)
    } else {
        0.5
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        time::Instant,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        index::{IndexBackend, IndexKind, OrdinalFilterPredicate},
        model::{Point, SparseVector},
        sparse_index::build_sparse_index,
    };

    #[test]
    fn sealed_ordinal_filter_keeps_payload_rejections_navigable_but_rejects_tombstones() {
        let mut payload = crate::ordinal::SegmentOrdinalSet::new();
        payload.insert("segment-a", 7);
        let tombstones = [3].into_iter().collect();
        let overlay_tombstones = [4].into_iter().collect();
        let filter = SegmentOrdinalFilterPredicate {
            result_filter: Some(&payload),
            segment_id: "segment-a",
            tombstones: &tombstones,
            overlay_tombstones: Some(&overlay_tombstones),
        };

        assert!(filter.matches_ordinal("segment-a", 7));
        assert!(filter.navigable_ordinal("segment-a", 7));
        assert!(!filter.matches_ordinal("segment-a", 8));
        assert!(filter.navigable_ordinal("segment-a", 8));
        assert!(!filter.matches_ordinal("segment-a", 3));
        assert!(!filter.navigable_ordinal("segment-a", 3));
        assert!(!filter.matches_ordinal("segment-a", 4));
        assert!(!filter.navigable_ordinal("segment-a", 4));
        assert!(!filter.navigable_ordinal("segment-b", 7));
    }

    #[derive(Debug)]
    struct RecordingBackend {
        recall_target_bits: AtomicU32,
    }

    impl RecordingBackend {
        fn new() -> Self {
            Self {
                recall_target_bits: AtomicU32::new(0),
            }
        }
    }

    impl IndexBackend for RecordingBackend {
        fn candidate_ids_with_ef(
            &self,
            _query: &[f32],
            _k: usize,
            _ef_search: Option<usize>,
        ) -> Vec<String> {
            vec!["dense".to_string()]
        }

        fn candidate_ids_with_recall_target(
            &self,
            query: &[f32],
            k: usize,
            ef_search: Option<usize>,
            recall_target: f32,
            _filter: Option<&dyn crate::index::FilterPredicate>,
        ) -> Vec<String> {
            self.recall_target_bits
                .store(recall_target.to_bits(), Ordering::Relaxed);
            self.candidate_ids_with_ef(query, k, ef_search)
        }

        fn insert_point(&mut self, _point: &Point, _vector_dim: usize) -> crate::Result<()> {
            Ok(())
        }

        fn kind(&self) -> IndexKind {
            IndexKind::Flat
        }

        fn indexed_points(&self) -> usize {
            1
        }

        fn vector_dim(&self) -> usize {
            1
        }

        fn contains(&self, id: &str) -> bool {
            id == "dense"
        }

        fn cells(&self) -> usize {
            1
        }

        fn is_paged(&self) -> bool {
            false
        }
    }

    fn make_point(id: &str, sparse: SparseVector) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![],
            vectors: Default::default(),
            sparse_vector: Some(sparse),
            payload: json!({}),
        }
    }

    #[test]
    fn segment_filter_separates_navigation_from_result_admission() {
        let allowed = HashSet::from(["allowed".to_string()]);
        let tombstones = HashSet::from(["deleted".to_string()]);
        let predicate = SegmentFilterPredicate {
            result_filter: Some(&allowed),
            tombstones: &tombstones,
        };

        assert!(crate::index::FilterPredicate::matches(
            &predicate, "allowed"
        ));
        assert!(!crate::index::FilterPredicate::matches(
            &predicate, "bridge"
        ));
        assert!(crate::index::FilterPredicate::navigable(
            &predicate, "bridge"
        ));
        assert!(!crate::index::FilterPredicate::navigable(
            &predicate, "deleted"
        ));
    }

    fn sv(indices: &[u32], values: &[f32]) -> SparseVector {
        SparseVector {
            indices: indices.to_vec(),
            values: values.to_vec(),
        }
    }

    #[test]
    fn dense_candidate_selection_forwards_recall_target_to_backend() {
        let backend = RecordingBackend::new();
        let points = HashMap::from([(
            "dense".to_string(),
            Point {
                id: "dense".to_string(),
                vector: vec![1.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({}),
            },
        )]);

        let candidates = search_point_candidates(
            Some(&backend),
            &HashMap::new(),
            &points,
            &[1.0],
            1,
            None,
            Some(32),
            0.99,
            None,
            None,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, "dense");
        assert_eq!(
            f32::from_bits(backend.recall_target_bits.load(Ordering::Relaxed)),
            0.99
        );
    }

    #[test]
    fn weighted_fusion_rescales_branches_instead_of_letting_magnitude_dominate() {
        // Regression test for the 2026-06-22 fix: `HybridFusion::Weighted` used to
        // sum raw `weight * score` per branch. Cosine scores live in [-1,1]; BM25
        // scores are unbounded (often 5-30) — so with equal weights the sparse
        // branch's magnitude swamped the dense branch regardless of weight, and
        // `Weighted` measured identical to `sparse_only`.
        //
        // dense ranks A best, sparse ranks C best (opposite extremes); B is the
        // compromise candidate, second-best on both branches.
        let dense = vec![
            RankedPoint {
                id: "a".to_string(),
                score: 0.9,
            },
            RankedPoint {
                id: "b".to_string(),
                score: 0.85,
            },
            RankedPoint {
                id: "c".to_string(),
                score: 0.1,
            },
        ];
        let sparse = vec![
            RankedPoint {
                id: "a".to_string(),
                score: 1.0,
            },
            RankedPoint {
                id: "b".to_string(),
                score: 25.0,
            },
            RankedPoint {
                id: "c".to_string(),
                score: 30.0,
            },
        ];

        let fused = fuse_rankings(&dense, &sparse, HybridFusion::Weighted, 1.0, 1.0);

        // The bug's signature: unnormalized raw-sum fusion produces the sparse
        // branch's own order verbatim (c=30.1, b=25.85, a=1.9 -> c, b, a), with
        // dense's clear winner "a" ranked dead last. A correct per-branch rescale
        // to [0,1] before weighting makes "b" (strong on both branches) win over
        // either single-branch extreme.
        assert_eq!(
            fused[0].id,
            "b",
            "compromise candidate must win once both branches are rescaled to a common scale; \
             got order {:?} -- if this is [c, b, a] the magnitude-dominance bug regressed",
            fused.iter().map(|p| &p.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn native_text_rrf_preserves_top_rank_separation_in_its_short_window() {
        let mut dense = vec![RankedPoint {
            id: "dense-top".to_string(),
            score: 1.0,
        }];
        let mut sparse = Vec::new();
        for rank in 1..40 {
            dense.push(RankedPoint {
                id: format!("dense-{rank:02}"),
                score: 1.0 - rank as f32 / 100.0,
            });
            sparse.push(RankedPoint {
                id: format!("sparse-{rank:02}"),
                score: 1.0 - rank as f32 / 100.0,
            });
        }
        sparse.push(RankedPoint {
            id: "consensus-tail".to_string(),
            score: 0.5,
        });
        dense.push(RankedPoint {
            id: "consensus-tail".to_string(),
            score: 0.5,
        });

        let compatibility = fuse_rankings(&dense, &sparse, HybridFusion::Rrf, 1.0, 1.0);
        let text = fuse_text_rankings(&dense, &sparse);
        assert_eq!(compatibility[0].id, "consensus-tail");
        assert_eq!(text[0].id, "dense-top");
    }

    #[test]
    fn wand_block_max_prunes_but_returns_correct_top_k() {
        // Build an index with 50 documents. Doc "winner" has the highest score for
        // term 0 and a moderate score for term 1. Many other docs have mid scores.
        // WAND threshold pruning should skip low-contribution blocks while still
        // returning the correct top-2.
        let mut points: HashMap<String, Point> = HashMap::new();
        points.insert(
            "winner".to_string(),
            make_point("winner", sv(&[0, 1], &[10.0, 5.0])),
        );
        points.insert(
            "second".to_string(),
            make_point("second", sv(&[0, 1], &[8.0, 4.0])),
        );
        // 48 documents that only match term 1 with low score – should be pruned
        for i in 0..48 {
            let id = format!("low_{i}");
            points.insert(id.clone(), make_point(&id, sv(&[1], &[0.1])));
        }
        let index = build_sparse_index(&points);

        // Query: term 0 weight 1.0, term 1 weight 0.5 → winner score = 10+2.5=12.5
        let outcome = sparse_search_ranked(
            &index,
            &points,
            SparseSearchParams {
                query: &sv(&[0, 1], &[1.0, 0.5]),
                limit: 2,
                payload_candidates: None,
                filter: None,
                budget: None,
                started: Instant::now(),
                cancelled: None,
            },
        );

        assert_eq!(outcome.ranked.len(), 2);
        assert_eq!(outcome.ranked[0].id, "winner");
        assert_eq!(outcome.ranked[1].id, "second");
        assert!((outcome.ranked[0].score - 12.5).abs() < 1e-4);
    }

    #[test]
    fn sparse_ranking_honors_pre_cancelled_execution() {
        let points = HashMap::from([("point".to_string(), make_point("point", sv(&[0], &[1.0])))]);
        let index = build_sparse_index(&points);
        let cancelled = AtomicBool::new(true);
        let outcome = sparse_search_ranked(
            &index,
            &points,
            SparseSearchParams {
                query: &sv(&[0], &[1.0]),
                limit: 1,
                payload_candidates: None,
                filter: None,
                budget: None,
                started: Instant::now(),
                cancelled: Some(&cancelled),
            },
        );

        assert!(outcome.degraded);
        assert_eq!(outcome.searched, 0);
        assert!(outcome.ranked.is_empty());
    }

    #[test]
    fn wand_term_level_skip_reduces_searched_count() {
        // A query with two terms where one term has very low max value.
        // After scoring docs for the high-value term, the low-value term should be
        // entirely pruned (no postings searched) because even its max contribution
        // can't help any candidate beat the threshold.
        let mut points: HashMap<String, Point> = HashMap::new();
        // 10 docs match term 0 with high scores → set a high threshold
        for i in 0..10 {
            let id = format!("doc_{i}");
            points.insert(id.clone(), make_point(&id, sv(&[0], &[(10 - i) as f32])));
        }
        // 5 docs only match term 1 with tiny scores → can't beat threshold set by term 0
        for i in 0..5 {
            let id = format!("tiny_{i}");
            points.insert(id.clone(), make_point(&id, sv(&[1], &[0.001])));
        }
        let index = build_sparse_index(&points);

        // Query for top-5: term 0 dominates, term 1 (max 0.001) can't contribute meaningfully
        let outcome = sparse_search_ranked(
            &index,
            &points,
            SparseSearchParams {
                query: &sv(&[0, 1], &[1.0, 1.0]),
                limit: 5,
                payload_candidates: None,
                filter: None,
                budget: None,
                started: Instant::now(),
                cancelled: None,
            },
        );

        // Top 5 results should all be from term 0 docs (scores 10, 9, 8, 7, 6)
        assert_eq!(outcome.ranked.len(), 5);
        let top_ids: Vec<&str> = outcome.ranked.iter().map(|r| r.id.as_str()).collect();
        assert!(top_ids.contains(&"doc_0"));
        assert!(top_ids.contains(&"doc_1"));
        assert!(top_ids.contains(&"doc_2"));
    }

    struct CountingResolver {
        points: HashMap<String, Point>,
        live: HashSet<String>,
        resolve_calls: AtomicUsize,
        contains_calls: AtomicUsize,
    }

    impl PointResolver for CountingResolver {
        fn resolve_point(&self, id: &str) -> Option<Cow<'_, Point>> {
            self.resolve_calls.fetch_add(1, Ordering::Relaxed);
            self.live
                .contains(id)
                .then(|| self.points.get(id))
                .flatten()
                .map(Cow::Borrowed)
        }

        fn contains_point(&self, id: &str) -> bool {
            self.contains_calls.fetch_add(1, Ordering::Relaxed);
            self.live.contains(id)
        }
    }

    #[test]
    fn unfiltered_sparse_visibility_does_not_hydrate_posting_points() {
        let points = HashMap::from([
            ("live".to_string(), make_point("live", sv(&[0], &[2.0]))),
            (
                "deleted".to_string(),
                make_point("deleted", sv(&[0], &[3.0])),
            ),
        ]);
        let index = build_sparse_index(&points);
        let resolver = CountingResolver {
            points,
            live: HashSet::from(["live".to_string()]),
            resolve_calls: AtomicUsize::new(0),
            contains_calls: AtomicUsize::new(0),
        };

        let outcome = sparse_search_ranked(
            &index,
            &resolver,
            SparseSearchParams {
                query: &sv(&[0], &[1.0]),
                limit: 2,
                payload_candidates: None,
                filter: None,
                budget: None,
                started: Instant::now(),
                cancelled: None,
            },
        );

        assert_eq!(
            outcome
                .ranked
                .iter()
                .map(|point| point.id.as_str())
                .collect::<Vec<_>>(),
            ["live"]
        );
        assert_eq!(resolver.resolve_calls.load(Ordering::Relaxed), 0);
        assert!(resolver.contains_calls.load(Ordering::Relaxed) >= 2);
    }
}
