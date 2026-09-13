//! Shared graph-constraint expansion and exact P1 retrieval.
//!
//! The caller owns the collection read guard for this entire module call. That
//! guard plus one pinned overlay read state is the G0 `CollectionReadState`:
//! graph expansion, point resolution, vector scoring, and payload hydration
//! cannot observe independently published component versions.

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
    time::Instant,
};

use serde_json::Value;

use crate::{
    Filter, GaussError, Result,
    graph::{
        ExactGraphSearchRequest, ExactGraphSearchResponse, GraphConstraint, GraphDirection,
        GraphDispatchTrace, GraphEpoch, GraphError, GraphErrorCode, GraphEstimateTrace,
        GraphEstimatorKind, GraphNamespace, GraphPlanCostTrace, GraphPlanGuard, GraphPlanTrace,
        GraphProbeTrace, GraphQueryWarning, GraphRetrievalPlan, GraphSpecificityInterval,
        GraphTraversalEdgeRow, GraphTraversalNode, GraphTraversalNodeRow, GraphTraversalPathRow,
        GraphTraversalQueryRequest, GraphTraversalQueryResult, GraphTraversalReturn,
        GraphTraversalRows, GraphWarning, TraversalBudget, TraversalResult,
    },
    graph_estimator::{
        BoundedProbeObservation, GraphContractMode, GraphEnvelopeQuery, GraphExecutionCalibration,
        GraphFilterShape, GraphProfileQuery, estimate_bounded_probe,
    },
    graph_planner::{
        GraphPlanCosts, GraphPlanFailurePolicy, GraphPlanSelection, GraphPlannerDecision,
        GraphPlannerGuard, GraphPlannerInput, GraphPlannerState, GraphStatementMode,
        graph_shadow_candidates, select_graph_plan,
    },
    model::{HybridFusion, HybridSearchRequest, SearchHit, SearchRequest, SearchResponse},
    observability::OperationGuard,
    ordinal::SegmentOrdinalSet,
    search::{RankedPoint, fuse_rankings, point_vector, rank_order, sparse_search_ranked},
};

use super::{
    Collection, CollectionReadResolver, Db, SearchInflightGuard, audit_context,
    graph_runtime::active_mutable_graph, validate_filter_complexity, validate_k,
    validate_sparse_vector, validate_vector_name,
};

const DEFAULT_GRAPH_NAMESPACE: &str = "@chiron:default";
const RANKED_POINT_BUDGET_BYTES: u64 = 1_152;
pub(super) const GRAPH_PLANNER_POLICY_VERSION: u32 = 1;
pub(super) const GRAPH_BRANCH_DEPTH_POLICY_VERSION: u32 = 1;

pub(super) struct PinnedGraphExpansion {
    pub(super) nodes: Vec<GraphTraversalNode>,
    pub(super) traversal: TraversalResult,
    pub(super) graph_epoch: GraphEpoch,
    pub(super) backfill_pending: bool,
    pub(super) internal_edges_examined: u64,
}

#[derive(Clone, Copy)]
enum TraversalCapture {
    Nodes,
    Edges,
    Paths { limit: usize },
}

struct RawPinnedGraphExpansion {
    execution: crate::graph_traversal::TraversalExecution,
    graph_epoch: GraphEpoch,
    backfill_pending: bool,
    unassigned_depth_zero: Vec<String>,
}

struct TraversalRunOptions<'a> {
    statement_filter: Option<&'a crate::Filter>,
    capture: TraversalCapture,
}

/// Traversal view that preserves the mutable graph's exact visibility while
/// adding vector-location knowledge needed to observe a local reference that
/// followed a live point supersession. The public counter advances only after
/// the traversal has authorized the neighbour.
struct RetrievalTraversalGraph<'a> {
    graph: &'a crate::mutable_graph::MutableGraphState,
    collection: &'a Collection,
    resolver: &'a crate::graph_resolver::PointIncarnationResolver,
}

impl crate::graph_traversal::TraversalGraph for RetrievalTraversalGraph<'_> {
    type EdgeIds<'a>
        = crate::mutable_graph::adjacency::EdgeCandidates<'a>
    where
        Self: 'a;

    fn outgoing(
        &self,
        namespace: &GraphNamespace,
        nid: crate::graph::Nid,
    ) -> Result<Self::EdgeIds<'_>> {
        self.graph.edge_candidates(namespace, nid, false)
    }

    fn incoming(
        &self,
        namespace: &GraphNamespace,
        nid: crate::graph::Nid,
    ) -> Result<Self::EdgeIds<'_>> {
        self.graph.edge_candidates(namespace, nid, true)
    }

    fn edge_visible(&self, edge_id: crate::graph::EdgeId) -> bool {
        self.graph.edge_visible(edge_id)
    }

    fn edge_properties(&self, edge_id: crate::graph::EdgeId) -> Result<Option<Cow<'_, Value>>> {
        self.graph.edge_properties(edge_id)
    }

    fn cursor_memory_bytes(&self) -> u64 {
        self.graph.adjacency_cursor_memory_bytes()
    }

    fn property_memory_bytes(&self, edge_id: crate::graph::EdgeId) -> u64 {
        if self.graph.has_mutable_properties(edge_id) {
            0
        } else {
            (crate::graph::MAX_EDGE_PROPERTY_BYTES as u64) * 64 + 2 * 4096
        }
    }

    fn local_reference_superseded(&self, base: u32, neighbor: crate::graph::Nid) -> bool {
        let Some(generation) = self.collection.graph_generation.as_ref() else {
            return false;
        };
        let Some(base) = generation.bases.get(base as usize) else {
            return false;
        };
        let Some(point_id) = self.resolver.live_point_id(neighbor) else {
            return false;
        };
        match self.collection.id_index.get(point_id) {
            Some(crate::searcher::SegLoc::Searcher(index)) => self
                .collection
                .searchers
                .get(*index as usize)
                .is_none_or(|searcher| searcher.id != base.id),
            Some(crate::searcher::SegLoc::Streamer | crate::searcher::SegLoc::Sealing) => true,
            None => false,
        }
    }
}

/// Planner-supplied, calibration-versioned controls for one P3 execution.
///
/// There is deliberately no `Default`: D6 must supply measured values instead
/// of turning an uncalibrated executor constant into a public contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P3ProgressivePolicy {
    pub(super) initial_factor: usize,
    pub(super) growth_factor: usize,
    pub(super) max_candidates: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum P3Termination {
    KSurvivors,
    ExactFallback,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P3GraphSearchOutcome {
    pub(super) response: SearchResponse,
    pub(super) termination: P3Termination,
    pub(super) cumulative_windows: Vec<usize>,
    pub(super) ann_candidates_materialized: usize,
    pub(super) candidates_probed: usize,
    pub(super) target_probes: usize,
    pub(super) anchor_frontier_nodes: usize,
    pub(super) internal_edges_examined: u64,
}

/// Independent, calibration-owned branch policies for fused P3H. Separate
/// controls are required because dense ANN and sparse posting cursors need not
/// advance at the same rate or terminate at the same depth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P3HybridProgressivePolicy {
    pub(super) dense: P3ProgressivePolicy,
    pub(super) sparse: P3ProgressivePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum P3HybridTermination {
    RrfBoundClosed,
    ExactFallback,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P3HybridSearchOutcome {
    pub(super) response: SearchResponse,
    pub(super) termination: P3HybridTermination,
    pub(super) dense_windows: Vec<usize>,
    pub(super) sparse_windows: Vec<usize>,
    pub(super) dense_depth: usize,
    pub(super) sparse_depth: usize,
    pub(super) dense_admitted: usize,
    pub(super) sparse_admitted: usize,
    pub(super) candidates_seen: usize,
    pub(super) reachability_decisions: usize,
    pub(super) target_probes: usize,
    pub(super) anchor_frontier_nodes: usize,
    pub(super) kth_score: Option<f32>,
    pub(super) stopping_bound: f32,
    pub(super) internal_edges_examined: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum P4Termination {
    Beam,
    ExactFallback,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P4SearchOutcome {
    pub(super) response: SearchResponse,
    pub(super) termination: P4Termination,
    pub(super) admitted_points: usize,
    pub(super) dense_candidates: usize,
    pub(super) sparse_candidates: usize,
    /// Calls where an LS-VEC navigation row was not graph-admitted but was
    /// retained as a legal stepping stone. D6 may expose only this aggregate.
    pub(super) non_admitted_navigation_checks: usize,
}

/// Planner/calibration-owned work ceiling for one P5 execution. There is no
/// default: D6 must version and bind this limit to the recall envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P5BestFirstPolicy {
    pub(super) max_expansions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GraphDispatchPolicies {
    pub(super) p3: P3ProgressivePolicy,
    pub(super) p3h: P3HybridProgressivePolicy,
    pub(super) p5: P5BestFirstPolicy,
}

impl TryFrom<GraphExecutionCalibration> for GraphDispatchPolicies {
    type Error = GaussError;

    fn try_from(value: GraphExecutionCalibration) -> Result<Self> {
        let as_usize = |name: &str, value: u32| {
            usize::try_from(value).map_err(|_| {
                GaussError::InvalidRequest(format!(
                    "graph calibration {name} does not fit this platform"
                ))
            })
        };
        Ok(Self {
            p3: P3ProgressivePolicy {
                initial_factor: as_usize("P3 initial factor", value.p3_initial_factor)?,
                growth_factor: as_usize("P3 growth factor", value.p3_growth_factor)?,
                max_candidates: as_usize("P3 candidate cap", value.p3_max_candidates)?,
            },
            p3h: P3HybridProgressivePolicy {
                dense: P3ProgressivePolicy {
                    initial_factor: as_usize(
                        "P3H dense initial factor",
                        value.p3h_dense_initial_factor,
                    )?,
                    growth_factor: as_usize(
                        "P3H dense growth factor",
                        value.p3h_dense_growth_factor,
                    )?,
                    max_candidates: as_usize(
                        "P3H dense candidate cap",
                        value.p3h_dense_max_candidates,
                    )?,
                },
                sparse: P3ProgressivePolicy {
                    initial_factor: as_usize(
                        "P3H sparse initial factor",
                        value.p3h_sparse_initial_factor,
                    )?,
                    growth_factor: as_usize(
                        "P3H sparse growth factor",
                        value.p3h_sparse_growth_factor,
                    )?,
                    max_candidates: as_usize(
                        "P3H sparse candidate cap",
                        value.p3h_sparse_max_candidates,
                    )?,
                },
            },
            p5: P5BestFirstPolicy {
                max_expansions: as_usize("P5 expansion cap", value.p5_max_expansions)?,
            },
        })
    }
}

#[derive(Clone, Debug)]
pub(super) enum PreparedGraphDispatch {
    Exact {
        graph: GraphConstraint,
        trace: GraphDispatchTrace,
    },
    Calibrated {
        graph: GraphConstraint,
        selection: GraphPlanSelection,
        policies: GraphDispatchPolicies,
        trace: GraphDispatchTrace,
        shadow: Option<super::graph_shadow::GraphShadowSpec>,
    },
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn exact_dispatch(
    graph: GraphConstraint,
    guard: GraphPlanGuard,
    warnings: Vec<GraphQueryWarning>,
    started: Instant,
) -> PreparedGraphDispatch {
    PreparedGraphDispatch::Exact {
        graph,
        trace: GraphDispatchTrace {
            graph_epoch: None,
            graph_estimate: GraphEstimateTrace {
                estimator: GraphEstimatorKind::Default,
                specificity: None,
                calibration_version: None,
                envelope_version: None,
                overlay_lsn_lag: None,
                probe: None,
                elapsed_us: elapsed_us(started),
            },
            graph_plan: GraphPlanTrace {
                chosen: GraphRetrievalPlan::P1Exact,
                guard: Some(guard),
                modelled_costs: None,
                degraded: false,
                exact_fallback: false,
                dense_branch_depth: None,
                sparse_branch_depth: None,
                elapsed_us: 0,
            },
            graph_expand: crate::graph::GraphExpandTrace::default(),
            fuse: None,
            warnings,
        },
    }
}

fn public_planner_guard(guard: GraphPlannerGuard) -> GraphPlanGuard {
    match guard {
        GraphPlannerGuard::ProbeAmbiguous => GraphPlanGuard::ProbeAmbiguous,
        GraphPlannerGuard::SpecificityFloor => GraphPlanGuard::SpecificityFloor,
        GraphPlannerGuard::BestFirstThreshold => GraphPlanGuard::BestFirstThreshold,
        GraphPlannerGuard::SloIneligible => GraphPlanGuard::SloIneligible,
        GraphPlannerGuard::ModeIncompatible => GraphPlanGuard::ModeIncompatible,
    }
}

fn public_plan_costs(costs: GraphPlanCosts) -> GraphPlanCostTrace {
    GraphPlanCostTrace {
        p1: costs.p1,
        p2: costs.p2,
        p3: costs.p3,
        p3h: costs.p3h,
        p4: costs.p4,
        p5: costs.p5,
    }
}

fn mark_exact_fallback(trace: &mut GraphDispatchTrace) {
    trace.graph_plan.exact_fallback = true;
    if !trace.warnings.contains(&GraphQueryWarning::ExactFallback) {
        trace.warnings.push(GraphQueryWarning::ExactFallback);
    }
}

fn finalize_graph_response(
    mut response: SearchResponse,
    mut trace: GraphDispatchTrace,
    telemetry: crate::observability::GraphExecutionTelemetry,
) -> SearchResponse {
    trace.graph_epoch = telemetry.graph_epoch;
    trace.graph_expand = telemetry.expand;
    trace.fuse = telemetry.fuse;
    response.degraded |= trace.graph_plan.degraded;
    crate::observability::observe_graph_dispatch(&trace);
    response.graph = Some(trace);
    response
}

pub(super) fn audit_error_code(error: &GaussError) -> &'static str {
    match error {
        GaussError::Graph(error) => error.code.as_str(),
        GaussError::CollectionExists(_) => "chirondb.collection_exists",
        GaussError::CollectionNotFound(_) => "chirondb.collection_not_found",
        GaussError::PointNotFound(_) => "chirondb.point_not_found",
        GaussError::DimensionMismatch { .. } => "chirondb.dimension_mismatch",
        GaussError::InvalidCollectionName(_) => "chirondb.invalid_collection_name",
        GaussError::InvalidRequest(_) => "chirondb.invalid_request",
        GaussError::ResourceExhausted(_) => "chirondb.resource_exhausted",
        GaussError::AuditUnavailable(_) => "chirondb.audit_unavailable",
        GaussError::DataDirLocked { .. } => "chirondb.data_dir_locked",
        GaussError::WalCorruption { .. } => "chirondb.wal_corruption",
        GaussError::WalUnavailable(_) => "chirondb.wal_unavailable",
        GaussError::SegmentCorruption { .. } => "chirondb.segment_corruption",
        GaussError::Io(_) => "chirondb.io",
        GaussError::Json(_) => "chirondb.json",
    }
}

fn complete_allow_degraded_audit(
    audit: Option<crate::audit::AuditOperation>,
    result: Result<SearchResponse>,
) -> Result<SearchResponse> {
    let Some(audit) = audit else {
        return result;
    };
    match result {
        Ok(response) => {
            audit.success(serde_json::json!({
                "allow_degraded": true,
                "served_degraded": response.degraded,
                "dispatch": response.graph,
            }))?;
            Ok(response)
        }
        Err(error) => {
            audit.failure(audit_error_code(&error))?;
            Err(error)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum P5Termination {
    StableTopK,
    FrontierExhausted,
    ExactFallback,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct P5SearchOutcome {
    pub(super) response: SearchResponse,
    pub(super) termination: P5Termination,
    pub(super) frontier_pops: usize,
    pub(super) frontier_expansions: usize,
    pub(super) vector_distances: usize,
    pub(super) unique_nodes_seen: usize,
    pub(super) peak_frontier: usize,
    pub(super) max_depth_popped: u32,
    pub(super) internal_edges_examined: u64,
}

#[derive(Debug)]
struct P5FrontierPoint {
    point_id: String,
    score: Option<f32>,
    depth: u32,
    root: bool,
}

impl P5FrontierPoint {
    fn can_improve(&self, worst: &ScoredPoint) -> bool {
        if self.root {
            return true;
        }
        self.score.is_some_and(|score| {
            score.total_cmp(&worst.score) == Ordering::Greater
                || (score.total_cmp(&worst.score) == Ordering::Equal && self.point_id < worst.id)
        })
    }
}

impl PartialEq for P5FrontierPoint {
    fn eq(&self, other: &Self) -> bool {
        self.point_id == other.point_id
            && self.depth == other.depth
            && self.root == other.root
            && match (self.score, other.score) {
                (Some(left), Some(right)) => left.total_cmp(&right) == Ordering::Equal,
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for P5FrontierPoint {}

impl PartialOrd for P5FrontierPoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for P5FrontierPoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| match (self.score, other.score) {
                (Some(left), Some(right)) => left.total_cmp(&right),
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            })
            // BinaryHeap is max-first. Smaller IDs and shallower depths win
            // deterministic ties, matching ordinary dense ranking where the
            // score permits it.
            .then_with(|| other.point_id.cmp(&self.point_id))
            .then_with(|| other.depth.cmp(&self.depth))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum P3HybridBranch {
    Dense,
    Sparse,
}

#[derive(Debug)]
struct P3HybridCandidate {
    reachable: bool,
    dense_rank: Option<usize>,
    sparse_rank: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum P3ReachabilityDecision {
    Reachable,
    Unreachable,
    ExactFallback,
}

#[derive(Debug)]
struct ProgressiveRankCursor {
    ranked: Vec<RankedPoint>,
    position: usize,
    complete: bool,
}

impl ProgressiveRankCursor {
    fn advance_to(&mut self, target: usize) -> std::ops::Range<usize> {
        let start = self.position;
        self.position = target.min(self.ranked.len());
        start..self.position
    }

    fn exhausted(&self) -> bool {
        self.position >= self.ranked.len()
    }

    fn has_unseen(&self) -> bool {
        !self.exhausted() || !self.complete
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GraphWorkLedger {
    internal_edges_examined: u64,
    nodes_visited: u64,
    cold_fragments_read: u64,
    cold_bytes_read: u64,
}

impl GraphWorkLedger {
    fn record(&mut self, expansion: &PinnedGraphExpansion) {
        self.internal_edges_examined = self
            .internal_edges_examined
            .saturating_add(expansion.internal_edges_examined);
        self.nodes_visited = self
            .nodes_visited
            .saturating_add(expansion.traversal.stats.nodes_visited);
        self.cold_fragments_read = self
            .cold_fragments_read
            .saturating_add(expansion.traversal.stats.cold_fragments_read);
        self.cold_bytes_read = self
            .cold_bytes_read
            .saturating_add(expansion.traversal.stats.cold_bytes_read);
    }

    fn remaining(
        self,
        original: TraversalBudget,
        started: Instant,
        persistent_memory_bytes: u64,
    ) -> Result<TraversalBudget> {
        self.remaining_for("P3", original, started, persistent_memory_bytes)
    }

    fn remaining_for(
        self,
        plan: &str,
        original: TraversalBudget,
        started: Instant,
        persistent_memory_bytes: u64,
    ) -> Result<TraversalBudget> {
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let max_time_ms = original.max_time_ms.saturating_sub(elapsed_ms);
        let max_edges = original
            .max_edges
            .saturating_sub(self.internal_edges_examined);
        let max_visited = original.max_visited.saturating_sub(self.nodes_visited);
        let max_memory_bytes = original
            .max_memory_bytes
            .saturating_sub(persistent_memory_bytes);
        if max_time_ms == 0 || max_edges == 0 || max_visited == 0 || max_memory_bytes == 0 {
            return Err(slo_unavailable(format!(
                "{plan} exhausted its graph retrieval budget before an exact result was available"
            )));
        }
        let cold = original.cold.map(|cold| crate::graph::ColdTraversalBudget {
            max_fragments: cold.max_fragments.saturating_sub(self.cold_fragments_read),
            max_bytes: cold.max_bytes.saturating_sub(self.cold_bytes_read),
        });
        if cold.is_some_and(|cold| cold.max_fragments == 0 || cold.max_bytes == 0) {
            return Err(slo_unavailable(format!(
                "{plan} exhausted its cold graph retrieval budget before an exact result was available"
            )));
        }
        Ok(TraversalBudget {
            max_depth: original.max_depth,
            max_frontier: original.max_frontier,
            max_visited,
            max_edges,
            max_time_ms,
            max_memory_bytes,
            cold,
        })
    }
}

#[derive(Debug)]
struct ScoredPoint {
    id: String,
    score: f32,
}

/// One P2 admitted set: stable ordinals for current sealed stores and the
/// unavoidable ID compatibility leg for mutable, sealing, and legacy stores.
#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))]
struct GraphOrdinalCandidates {
    sealed: SegmentOrdinalSet,
    fallback: HashSet<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GraphOrdinalCandidates {
    fn len(&self) -> usize {
        usize::try_from(self.sealed.len())
            .unwrap_or(usize::MAX)
            .saturating_add(self.fallback.len())
    }

    fn contains(&self, collection: &Collection, point_id: &str) -> bool {
        if self.fallback.contains(point_id) {
            return true;
        }
        let Some(crate::searcher::SegLoc::Searcher(index)) = collection.id_index.get(point_id)
        else {
            return false;
        };
        let Some(searcher) = collection.searchers.get(*index as usize) else {
            return false;
        };
        searcher
            .ordinal(point_id)
            .is_some_and(|ordinal| self.sealed.contains(&searcher.id, ordinal))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphNavigationMode {
    AdmittedOnly,
    LiveSteppingStones,
}

#[derive(Debug, Default)]
struct GraphNavigationTelemetry {
    non_admitted_checks: AtomicUsize,
}

struct GraphStringFilter<'a> {
    candidates: &'a GraphOrdinalCandidates,
    collection: &'a Collection,
    navigation: GraphNavigationMode,
    telemetry: &'a GraphNavigationTelemetry,
}

impl crate::index::FilterPredicate for GraphStringFilter<'_> {
    fn matches(&self, point_id: &str) -> bool {
        self.candidates.contains(self.collection, point_id)
    }

    fn navigable(&self, point_id: &str) -> bool {
        if self.matches(point_id) {
            return true;
        }
        if self.navigation == GraphNavigationMode::LiveSteppingStones {
            self.telemetry
                .non_admitted_checks
                .fetch_add(1, AtomicOrdering::Relaxed);
            true
        } else {
            false
        }
    }
}

struct GraphOrdinalFilter<'a> {
    candidates: &'a SegmentOrdinalSet,
    navigation: GraphNavigationMode,
    telemetry: &'a GraphNavigationTelemetry,
}

impl crate::index::OrdinalFilterPredicate for GraphOrdinalFilter<'_> {
    fn matches_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        self.candidates.contains(segment, ordinal)
    }

    fn navigable_ordinal(&self, segment: &str, ordinal: u32) -> bool {
        if self.matches_ordinal(segment, ordinal) {
            return true;
        }
        if self.navigation == GraphNavigationMode::LiveSteppingStones {
            self.telemetry
                .non_admitted_checks
                .fetch_add(1, AtomicOrdering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl PartialEq for ScoredPoint {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.score.total_cmp(&other.score) == Ordering::Equal
    }
}

impl Eq for ScoredPoint {}

impl PartialOrd for ScoredPoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredPoint {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap keeps the greatest value at the root. Reverse score order
        // so the root is the worst retained hit; for equal scores the larger
        // point ID is worse because final retrieval order is ID-ascending.
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_graph_dispatch(
        &self,
        collection_name: &str,
        graph: GraphConstraint,
        statement_filter: Option<&Filter>,
        vector_name: Option<&str>,
        k: usize,
        recall_target: Option<f32>,
        mode: GraphStatementMode,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<PreparedGraphDispatch> {
        let prepare_started = Instant::now();
        let allow_degraded = graph.allow_degraded;
        if mode == GraphStatementMode::HybridWeighted {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::WeightedUncontracted,
                vec![GraphQueryWarning::UncontractedFusion],
                prepare_started,
            ));
        }
        if graph.budget.max_depth == 0 {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::DepthZero,
                Vec::new(),
                prepare_started,
            ));
        }
        let full_request: crate::graph::GraphTraverseRequest = graph.clone().into();
        super::graph_runtime::validate_traversal_request(&full_request)?;
        let budget = full_request.budget.validate()?;
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let enforcement = self.tenant_enforcement();
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        if collection.graph_backfill_pending() {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::BackfillInProgress,
                Vec::new(),
                prepare_started,
            ));
        }
        if collection.live_points() == 0 {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::EmptyCollection,
                Vec::new(),
                prepare_started,
            ));
        }
        let Some(calibration) = collection.graph_calibration.as_deref() else {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::CalibrationMissing,
                Vec::new(),
                prepare_started,
            ));
        };
        let Some(target_recall_bps) =
            recall_target_bps(recall_target.or(collection.config.recall_sla))?
        else {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::RecallTargetMissing,
                Vec::new(),
                prepare_started,
            ));
        };
        let Some(k) = u32::try_from(k).ok() else {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::CalibrationProfileMiss,
                Vec::new(),
                prepare_started,
            ));
        };
        let dimension = vector_name
            .and_then(|name| collection.config.named_vector_dims.get(name))
            .copied()
            .unwrap_or(collection.config.vector_dim);
        let Some(dimension) = u32::try_from(dimension).ok() else {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::CalibrationProfileMiss,
                Vec::new(),
                prepare_started,
            ));
        };
        let visibility = collection.overlay_read_state();
        let state = graph_planner_state(&collection, &visibility)?;
        let overlay_lsn_lag = state.wal_lsn.saturating_sub(collection.wal_watermark);
        let filters = GraphFilterShape {
            statement: statement_filter.is_some(),
            node: full_request.node_filter.is_some(),
            edge: full_request.edge_filter.is_some(),
        };
        let contract_mode = match mode {
            GraphStatementMode::Dense => GraphContractMode::Dense,
            GraphStatementMode::HybridRrf => GraphContractMode::HybridRrf,
            GraphStatementMode::HybridWeighted => unreachable!("weighted returned exact"),
        };
        let profile_query = GraphProfileQuery {
            mode: contract_mode,
            vector_field: vector_name,
            metric: collection.config.metric,
            dimension,
            graph_epoch: state.graph_epoch,
            schema_epoch: state.schema_epoch,
            manifest_generation: state.manifest_generation,
            overlay_generation: state.overlay_generation,
            direction: full_request.direction,
            typed: !full_request.edge_types.is_empty(),
            hops: full_request.budget.max_depth,
            filters,
            overlay_lsn_lag,
            planner_policy_version: GRAPH_PLANNER_POLICY_VERSION,
            branch_depth_policy_version: GRAPH_BRANCH_DEPTH_POLICY_VERSION,
            k,
            target_recall_bps,
        };
        let Some(profile) = calibration.profile(&profile_query)? else {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::CalibrationProfileMiss,
                Vec::new(),
                prepare_started,
            ));
        };
        if budget.max_edges <= profile.probe_policy.edge_budget {
            return Ok(exact_dispatch(
                graph,
                GraphPlanGuard::ProbeBudgetInsufficient,
                Vec::new(),
                prepare_started,
            ));
        }

        let estimate_started = Instant::now();
        check_execution_budget(cancelled, estimate_started, budget)?;
        let mut probe_request = full_request.clone();
        probe_request.budget.max_depth = 1;
        probe_request.budget.max_edges = profile.probe_policy.edge_budget;
        let expansion = expand_constraint_locked(
            &collection,
            &visibility,
            &probe_request,
            statement_filter,
            scope,
            enforcement,
            cancelled,
        )?;
        let next_nodes = expansion
            .nodes
            .iter()
            .filter(|node| node.depth == 1)
            .count() as u64;
        let observation = BoundedProbeObservation {
            target_hops: full_request.budget.max_depth,
            completed_hops: expansion.traversal.stats.hops_completed,
            visible_nodes_seen: expansion.nodes.len() as u64,
            visible_nodes_expanded: expansion
                .traversal
                .stats
                .nodes_visited
                .saturating_sub(expansion.nodes.len() as u64),
            visible_frontier_nodes: next_nodes,
            visible_next_nodes_discovered: next_nodes,
            visible_edges_examined: expansion.traversal.stats.visible_edges_examined,
            truncation: expansion.traversal.truncation,
        };
        let estimate = estimate_bounded_probe(
            collection.live_points(),
            profile.probe_policy,
            observation,
            profile.boundaries,
        )?;
        let (min_specificity_bps, max_specificity_bps) =
            estimate.specificity_interval_bps(collection.live_points())?;
        let probe_trace = GraphProbeTrace {
            hops_completed: expansion.traversal.stats.hops_completed,
            nodes_visited: expansion.traversal.stats.nodes_visited,
            edges_examined: expansion.traversal.stats.visible_edges_examined,
            cold_fragments_read: expansion.traversal.stats.cold_fragments_read,
            cold_bytes_read: expansion.traversal.stats.cold_bytes_read,
            truncation: expansion.traversal.truncation,
        };
        let estimate_elapsed_us = elapsed_us(estimate_started);
        let envelope = calibration.lookup(&GraphEnvelopeQuery {
            mode: contract_mode,
            vector_field: vector_name,
            metric: collection.config.metric,
            dimension,
            topology_family: &profile.topology_family,
            graph_epoch: state.graph_epoch,
            schema_epoch: state.schema_epoch,
            manifest_generation: state.manifest_generation,
            overlay_generation: state.overlay_generation,
            direction: full_request.direction,
            typed: !full_request.edge_types.is_empty(),
            hops: full_request.budget.max_depth,
            filters,
            min_specificity_bps,
            max_specificity_bps,
            overlay_lsn_lag,
            planner_policy_version: GRAPH_PLANNER_POLICY_VERSION,
            branch_depth_policy_version: GRAPH_BRANCH_DEPTH_POLICY_VERSION,
            k,
            target_recall_bps,
        })?;
        let mut ledger = GraphWorkLedger::default();
        ledger.record(&expansion);
        let mut remaining_graph = graph;
        remaining_graph.budget =
            ledger.remaining_for("planner probe", budget, estimate_started, 0)?;
        remaining_graph.budget.max_depth = full_request.budget.max_depth;
        let Some(envelope) = envelope else {
            return Ok(PreparedGraphDispatch::Exact {
                graph: remaining_graph,
                trace: GraphDispatchTrace {
                    graph_epoch: None,
                    graph_estimate: GraphEstimateTrace {
                        estimator: GraphEstimatorKind::ProbeExpansion,
                        specificity: Some(GraphSpecificityInterval {
                            min_bps: min_specificity_bps,
                            max_bps: max_specificity_bps,
                        }),
                        calibration_version: Some(calibration.calibration_version),
                        envelope_version: None,
                        overlay_lsn_lag: Some(overlay_lsn_lag),
                        probe: Some(probe_trace),
                        elapsed_us: estimate_elapsed_us,
                    },
                    graph_plan: GraphPlanTrace {
                        chosen: GraphRetrievalPlan::P1Exact,
                        guard: Some(GraphPlanGuard::CalibrationEnvelopeMiss),
                        modelled_costs: None,
                        degraded: false,
                        exact_fallback: false,
                        dense_branch_depth: None,
                        sparse_branch_depth: None,
                        elapsed_us: 0,
                    },
                    graph_expand: crate::graph::GraphExpandTrace::default(),
                    fuse: None,
                    warnings: Vec::new(),
                },
            });
        };
        let planner_started = Instant::now();
        let costs = profile.costs.plan_costs(
            profile.execution,
            mode,
            collection.live_points(),
            estimate.planner_estimate.admitted_points(),
            dimension,
            full_request.budget.max_depth,
            k as usize,
        )?;
        let planner_input = GraphPlannerInput {
            statement_mode: mode,
            k: k as usize,
            collection_points: collection.live_points(),
            estimate: estimate.planner_estimate,
            calibration: envelope.calibration,
            p5_degraded_opt_in: allow_degraded,
            costs,
        };
        let shadow_candidates = graph_shadow_candidates(planner_input)?;
        let decision = select_graph_plan(planner_input)?;
        let GraphPlannerDecision::Execute(selection) = decision else {
            return Ok(PreparedGraphDispatch::Exact {
                graph: remaining_graph,
                trace: GraphDispatchTrace {
                    graph_epoch: None,
                    graph_estimate: GraphEstimateTrace {
                        estimator: GraphEstimatorKind::ProbeExpansion,
                        specificity: Some(GraphSpecificityInterval {
                            min_bps: min_specificity_bps,
                            max_bps: max_specificity_bps,
                        }),
                        calibration_version: Some(calibration.calibration_version),
                        envelope_version: Some(envelope.envelope_version),
                        overlay_lsn_lag: Some(overlay_lsn_lag),
                        probe: Some(probe_trace),
                        elapsed_us: estimate_elapsed_us,
                    },
                    graph_plan: GraphPlanTrace {
                        chosen: GraphRetrievalPlan::P1Exact,
                        guard: Some(GraphPlanGuard::ProbeAmbiguous),
                        modelled_costs: None,
                        degraded: false,
                        exact_fallback: false,
                        dense_branch_depth: None,
                        sparse_branch_depth: None,
                        elapsed_us: elapsed_us(planner_started),
                    },
                    graph_expand: crate::graph::GraphExpandTrace::default(),
                    fuse: None,
                    warnings: Vec::new(),
                },
            });
        };
        let expose_costs = !enforcement.blocks() || scope.is_system() || scope.can_cross_read();
        let trace = GraphDispatchTrace {
            graph_epoch: None,
            graph_estimate: GraphEstimateTrace {
                estimator: GraphEstimatorKind::ProbeExpansion,
                specificity: Some(GraphSpecificityInterval {
                    min_bps: min_specificity_bps,
                    max_bps: max_specificity_bps,
                }),
                calibration_version: Some(calibration.calibration_version),
                envelope_version: Some(envelope.envelope_version),
                overlay_lsn_lag: Some(overlay_lsn_lag),
                probe: Some(probe_trace),
                elapsed_us: estimate_elapsed_us,
            },
            graph_plan: GraphPlanTrace {
                chosen: selection.plan,
                guard: selection.guard.map(public_planner_guard),
                modelled_costs: expose_costs.then(|| public_plan_costs(costs)),
                degraded: selection.degraded,
                exact_fallback: false,
                dense_branch_depth: None,
                sparse_branch_depth: None,
                elapsed_us: elapsed_us(planner_started),
            },
            graph_expand: crate::graph::GraphExpandTrace::default(),
            fuse: None,
            warnings: if selection.degraded {
                vec![GraphQueryWarning::DegradedPlan]
            } else {
                Vec::new()
            },
        };
        Ok(PreparedGraphDispatch::Calibrated {
            graph: remaining_graph,
            selection: selection.bind_state(state),
            policies: GraphDispatchPolicies::try_from(profile.execution)?,
            trace,
            shadow: (profile.execution.shadow_sample_bps > 0 && shadow_candidates.len() > 1)
                .then_some(super::graph_shadow::GraphShadowSpec {
                    calibration_version: calibration.calibration_version,
                    envelope_version: envelope.envelope_version,
                    sample_bps: profile.execution.shadow_sample_bps,
                    candidates: shadow_candidates,
                }),
        })
    }

    /// Exact vector ranking over the complete graph-reachable set.
    ///
    /// This is the internal D4a boundary. Protocol façades are deliberately
    /// added only after planner selection is stable in the following slices.
    pub fn exact_graph_search_scoped(
        &self,
        collection_name: &str,
        request: ExactGraphSearchRequest,
        scope: &crate::tenant::TenantScope,
    ) -> Result<ExactGraphSearchResponse> {
        let cancelled = AtomicBool::new(false);
        self.exact_graph_search_cancellable_scoped(collection_name, request, scope, &cancelled)
    }

    /// Cancellable exact P1 execution. Constraint truncation is never exposed
    /// as a partial hit list: it fails with `graph.slo_unavailable`.
    pub fn exact_graph_search_cancellable_scoped(
        &self,
        collection_name: &str,
        request: ExactGraphSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<ExactGraphSearchResponse> {
        self.exact_graph_search_cancellable_scoped_with_state(
            collection_name,
            request,
            scope,
            cancelled,
            None,
        )
    }

    pub(super) fn exact_graph_search_cancellable_scoped_with_state(
        &self,
        collection_name: &str,
        request: ExactGraphSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        expected_state: Option<GraphPlannerState>,
    ) -> Result<ExactGraphSearchResponse> {
        let ExactGraphSearchRequest {
            filter,
            vector,
            vector_name,
            k,
            graph,
            with_payload,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(GaussError::InvalidRequest(
                "dense vector values must be finite".to_string(),
            ));
        }
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }

        self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if let Some(expected) = expected_state
                    && graph_planner_state(collection, visibility)? != expected
                {
                    return Err(slo_unavailable(
                        "P1 calibrated read state changed before execution",
                    ));
                }
                validate_dense_dimension(collection, &vector, vector_name.as_deref())?;
                let (ranked, searched) = score_dense_top_k_locked(
                    collection,
                    visibility,
                    &expansion.nodes,
                    &vector,
                    vector_name.as_deref(),
                    k,
                    cancelled,
                    started,
                    budget,
                )?;
                let hits = hydrate_hits_locked(
                    collection,
                    visibility,
                    ranked,
                    with_payload.unwrap_or_else(|| self.default_with_payload()),
                    cancelled,
                    started,
                    budget,
                )?;
                Ok(ExactGraphSearchResponse {
                    hits,
                    searched,
                    elapsed_ms: started.elapsed().as_millis(),
                    graph_epoch: expansion.graph_epoch,
                    traversal: expansion.traversal.stats,
                    plan: GraphRetrievalPlan::P1Exact,
                })
            },
        )
    }

    pub(super) fn graph_search_scoped_controlled(
        &self,
        collection_name: &str,
        mut request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<SearchResponse> {
        validate_k(request.k, "k")?;
        validate_filter_complexity(request.filter.as_ref())?;
        validate_dense_query(&request.vector, request.recall_target)?;
        if let Some(vector_name) = &request.vector_name {
            validate_vector_name(vector_name)?;
        }
        let mut graph = request.graph.take().ok_or_else(|| {
            GaussError::InvalidRequest("graph-constrained search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, request.budget_ms)?;
        let audit = graph
            .allow_degraded
            .then(|| {
                self.audit_query_operation_with_context(
                    "graph.allow_degraded_search",
                    Some(collection_name),
                    audit_context(scope),
                )
            })
            .transpose()?;
        let result = (|| {
            let prepared = self.prepare_graph_dispatch(
                collection_name,
                graph,
                request.filter.as_ref(),
                request.vector_name.as_deref(),
                request.k,
                request.recall_target,
                GraphStatementMode::Dense,
                scope,
                cancelled,
            )?;
            match prepared {
                PreparedGraphDispatch::Exact { graph, trace } => {
                    let execution = crate::observability::GraphExecutionGuard::start();
                    let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
                    let mut operation_metrics = OperationGuard::start("search");
                    let response = self.exact_graph_search_cancellable_scoped(
                        collection_name,
                        ExactGraphSearchRequest {
                            vector: request.vector,
                            vector_name: request.vector_name,
                            k: request.k,
                            filter: request.filter,
                            graph,
                            with_payload: request.with_payload,
                        },
                        scope,
                        cancelled,
                    )?;
                    operation_metrics.succeed();
                    let telemetry = execution.finish();
                    Ok(finalize_graph_response(
                        SearchResponse {
                            hits: response.hits,
                            degraded: false,
                            searched: response.searched,
                            elapsed_ms: response.elapsed_ms,
                            graph: None,
                        },
                        trace,
                        telemetry,
                    ))
                }
                PreparedGraphDispatch::Calibrated {
                    graph,
                    selection,
                    policies,
                    mut trace,
                    shadow,
                } => {
                    let execution = crate::observability::GraphExecutionGuard::start();
                    request.graph = Some(graph);
                    let shadow_request = shadow.as_ref().map(|_| request.clone());
                    let chosen_started = Instant::now();
                    let response = match selection.plan {
                        GraphRetrievalPlan::P1Exact => {
                            let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
                            let mut operation_metrics = OperationGuard::start("search");
                            let response = self.exact_graph_search_cancellable_scoped_with_state(
                                collection_name,
                                ExactGraphSearchRequest {
                                    vector: request.vector,
                                    vector_name: request.vector_name,
                                    k: request.k,
                                    filter: request.filter,
                                    graph: request.graph.expect("prepared graph"),
                                    with_payload: request.with_payload,
                                },
                                scope,
                                cancelled,
                                selection.expected_state,
                            )?;
                            operation_metrics.succeed();
                            SearchResponse {
                                hits: response.hits,
                                degraded: false,
                                searched: response.searched,
                                elapsed_ms: response.elapsed_ms,
                                graph: None,
                            }
                        }
                        GraphRetrievalPlan::P2PrefilteredCascade => self
                            .p2_graph_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                            )?,
                        GraphRetrievalPlan::P3ProgressiveProbe => {
                            let outcome = self.p3_graph_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                                policies.p3,
                            )?;
                            if outcome.termination == P3Termination::ExactFallback {
                                mark_exact_fallback(&mut trace);
                            }
                            outcome.response
                        }
                        GraphRetrievalPlan::P4ReachabilityAwareBeam => {
                            let outcome = self.p4_graph_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                            )?;
                            if outcome.termination == P4Termination::ExactFallback {
                                mark_exact_fallback(&mut trace);
                            }
                            outcome.response
                        }
                        GraphRetrievalPlan::P5BestFirst => {
                            let outcome = self.p5_graph_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                                policies.p5,
                            )?;
                            if outcome.termination == P5Termination::ExactFallback {
                                mark_exact_fallback(&mut trace);
                            }
                            outcome.response
                        }
                        GraphRetrievalPlan::P3HybridJointWidening => {
                            return Err(slo_unavailable(
                                "dense graph dispatch selected the fused P3H executor",
                            ));
                        }
                    };
                    let chosen_elapsed_us = elapsed_us(chosen_started);
                    let telemetry = execution.finish();
                    let response = finalize_graph_response(response, trace, telemetry);
                    if let (Some(spec), Some(request), Some(state)) =
                        (shadow, shadow_request, selection.expected_state)
                    {
                        self.schedule_dense_graph_shadow(
                            collection_name,
                            request,
                            scope.clone(),
                            super::graph_shadow::GraphShadowExecution {
                                chosen: selection.plan,
                                chosen_elapsed_us,
                                state,
                                policies,
                                spec,
                            },
                        );
                    }
                    Ok(response)
                }
            }
        })();
        complete_allow_degraded_audit(audit, result)
    }

    /// Execute one planner-authorized dense P3 statement.
    ///
    /// The bounded ANN pool is built once. Geometric windows only advance a
    /// cursor through that pool, so widening never restarts ANN or re-probes a
    /// candidate. D6 owns activation and calibrated policy selection.
    #[allow(clippy::too_many_lines)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p3_graph_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
        policy: P3ProgressivePolicy,
    ) -> Result<P3GraphSearchOutcome> {
        validate_p3_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("search");
        let SearchRequest {
            vector,
            vector_name,
            k,
            filter,
            graph,
            budget_ms,
            consistency: _,
            ef_search,
            recall_target,
            with_payload,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        validate_dense_query(&vector, recall_target)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P3 graph search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;
        let full_request: crate::graph::GraphTraverseRequest = graph.into();
        super::graph_runtime::validate_traversal_request(&full_request)?;
        let budget = full_request.budget.validate()?;
        let started = Instant::now();
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let enforcement = self.tenant_enforcement();
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        if collection.graph_backfill_pending() {
            return Err(slo_unavailable(
                "P3 graph retrieval is unavailable while point-handle backfill is pending",
            ));
        }
        if collection.global_backend().is_some() {
            return Err(slo_unavailable(
                "P3 progressive widening requires the segmented LS-VEC backend",
            ));
        }
        validate_dense_dimension(&collection, &vector, vector_name.as_deref())?;
        let (initial_window, candidate_cap) =
            validate_p3_policy(policy, k, collection.live_points())?;
        let visibility = collection.overlay_read_state();
        if !selection_matches_state(selection, &collection, &visibility)? {
            return Err(slo_unavailable(
                "P3 calibrated read state changed before execution",
            ));
        }
        check_execution_budget(cancelled, started, budget)?;

        let mut ledger = GraphWorkLedger::default();
        let anchor_depth = full_request.budget.max_depth.div_ceil(2);
        let reverse_depth = full_request.budget.max_depth / 2;
        let mut anchor_request = full_request.clone();
        anchor_request.budget = ledger.remaining(budget, started, 0)?;
        anchor_request.budget.max_depth = anchor_depth;
        let anchor_expansion = expand_constraint_locked(
            &collection,
            &visibility,
            &anchor_request,
            filter.as_ref(),
            scope,
            enforcement,
            cancelled,
        )?;
        ledger.record(&anchor_expansion);
        if let Some(reason) = anchor_expansion.traversal.truncation {
            return Err(slo_unavailable(format!(
                "P3 anchor frontier exceeded its {reason:?} budget"
            )));
        }
        crate::failpoint::check("graph_retrieval.after_expansion")?;

        let mut anchor_depths = HashMap::with_capacity(anchor_expansion.nodes.len());
        for node in &anchor_expansion.nodes {
            anchor_depths
                .entry(node.point_id.clone())
                .and_modify(|depth: &mut u32| *depth = (*depth).min(node.depth))
                .or_insert(node.depth);
        }
        let anchor_frontier_nodes = anchor_depths.len();
        let persistent_memory = p3_persistent_memory(candidate_cap, k, anchor_frontier_nodes)?;
        if persistent_memory > budget.max_memory_bytes {
            return Err(slo_unavailable(
                "P3 cursor, anchor frontier, and survivor state exceed the graph retrieval memory budget",
            ));
        }
        // Ensure the traversal work already consumed plus the long-lived P3
        // state still leaves a valid budget before starting ANN.
        ledger.remaining(budget, started, persistent_memory)?;
        let mut cursor = materialize_progressive_ann_cursor(
            &collection,
            &visibility,
            &vector,
            vector_name.as_deref(),
            candidate_cap,
            ef_search,
            recall_target,
            cancelled,
            started,
            budget,
        )?;
        let ann_candidates_materialized = cursor.ranked.len();
        let mut cumulative_windows = Vec::new();
        let mut survivors = Vec::with_capacity(k);
        let mut candidates_probed = 0_usize;
        let mut target_probes = 0_usize;
        let mut next_window = initial_window;
        let mut exact_fallback = false;

        while survivors.len() < k && !cursor.exhausted() {
            let cumulative = next_window.min(candidate_cap);
            let range = cursor.advance_to(cumulative);
            cumulative_windows.push(cursor.position);
            for index in range {
                check_execution_budget(cancelled, started, budget)?;
                candidates_probed = candidates_probed.saturating_add(1);
                let candidate = &cursor.ranked[index];
                if !candidate_matches_p3_filters(
                    &collection,
                    &visibility,
                    &candidate.id,
                    full_request.node_filter.as_ref(),
                    filter.as_ref(),
                    scope,
                    enforcement,
                )? {
                    continue;
                }
                let mut reachable = anchor_depths
                    .get(&candidate.id)
                    .is_some_and(|depth| *depth <= full_request.budget.max_depth);
                if !reachable && reverse_depth > 0 {
                    target_probes = target_probes.saturating_add(1);
                    let mut target_request = full_request.clone();
                    target_request.anchors = vec![candidate.id.clone()];
                    target_request.direction = reverse_graph_direction(full_request.direction);
                    target_request.budget = ledger.remaining(budget, started, persistent_memory)?;
                    target_request.budget.max_depth = reverse_depth;
                    let target_expansion = expand_constraint_locked(
                        &collection,
                        &visibility,
                        &target_request,
                        filter.as_ref(),
                        scope,
                        enforcement,
                        cancelled,
                    )?;
                    ledger.record(&target_expansion);
                    if target_expansion.traversal.truncation.is_some() {
                        exact_fallback = true;
                        break;
                    }
                    reachable = target_expansion.nodes.iter().any(|node| {
                        anchor_depths.get(&node.point_id).is_some_and(|anchor| {
                            anchor.saturating_add(node.depth) <= full_request.budget.max_depth
                        })
                    });
                }
                if reachable {
                    survivors.push(ScoredPoint {
                        id: candidate.id.clone(),
                        score: candidate.score,
                    });
                    if survivors.len() == k {
                        break;
                    }
                }
            }
            if exact_fallback || survivors.len() == k || cursor.position >= candidate_cap {
                break;
            }
            let grown = next_window
                .checked_mul(policy.growth_factor)
                .unwrap_or(candidate_cap);
            next_window = grown.min(candidate_cap);
            if next_window <= cursor.position {
                break;
            }
        }

        if survivors.len() == k && !exact_fallback {
            let hits = hydrate_hits_locked(
                &collection,
                &visibility,
                survivors,
                with_payload.unwrap_or_else(|| self.default_with_payload()),
                cancelled,
                started,
                budget,
            )?;
            let response = SearchResponse {
                hits,
                degraded: selection.degraded,
                searched: candidates_probed,
                elapsed_ms: started.elapsed().as_millis(),
                graph: None,
            };
            operation_metrics.succeed();
            return Ok(P3GraphSearchOutcome {
                response,
                termination: P3Termination::KSurvivors,
                cumulative_windows,
                ann_candidates_materialized,
                candidates_probed,
                target_probes,
                anchor_frontier_nodes,
                internal_edges_examined: ledger.internal_edges_examined,
            });
        }

        // Cursor/frontier/survivor memory is released before exact fallback;
        // graph work and wall time already consumed remain charged.
        drop(cursor);
        drop(anchor_depths);
        drop(survivors);
        let response = p3_exact_fallback_locked(
            &collection,
            &visibility,
            &full_request,
            filter.as_ref(),
            &vector,
            vector_name.as_deref(),
            k,
            with_payload.unwrap_or_else(|| self.default_with_payload()),
            scope,
            enforcement,
            cancelled,
            started,
            budget,
            &mut ledger,
            selection.degraded,
        )?;
        operation_metrics.succeed();
        Ok(P3GraphSearchOutcome {
            response,
            termination: P3Termination::ExactFallback,
            cumulative_windows,
            ann_candidates_materialized,
            candidates_probed,
            target_probes,
            anchor_frontier_nodes,
            internal_edges_examined: ledger.internal_edges_examined,
        })
    }

    /// Execute one planner-authorized fused P3H statement.
    ///
    /// Dense and sparse branch pools are built once, then independently
    /// widened. Every unique candidate receives at most one reachability
    /// decision. Success requires the strict RRF unseen-score bound to close;
    /// otherwise the executor takes complete P1 or fails.
    #[allow(clippy::too_many_lines)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p3h_graph_hybrid_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
        policy: P3HybridProgressivePolicy,
    ) -> Result<P3HybridSearchOutcome> {
        validate_p3h_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("hybrid_search");
        let HybridSearchRequest {
            vector,
            vector_name,
            sparse_vector,
            k,
            filter,
            graph,
            budget_ms,
            fusion,
            dense_weight,
            sparse_weight,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        let vector = vector
            .ok_or_else(|| GaussError::InvalidRequest("P3H requires a dense branch".to_string()))?;
        let sparse_vector = sparse_vector.ok_or_else(|| {
            GaussError::InvalidRequest("P3H requires a sparse branch".to_string())
        })?;
        validate_dense_query(&vector, None)?;
        validate_sparse_vector(&sparse_vector)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        if fusion != HybridFusion::Rrf {
            return Err(slo_unavailable(
                "P3H stopping bounds are defined only for RRF fusion",
            ));
        }
        if !dense_weight.is_finite()
            || !sparse_weight.is_finite()
            || dense_weight < 0.0
            || sparse_weight < 0.0
        {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be finite and non-negative".to_string(),
            ));
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P3H graph search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;
        let full_request: crate::graph::GraphTraverseRequest = graph.into();
        super::graph_runtime::validate_traversal_request(&full_request)?;
        let budget = full_request.budget.validate()?;
        let started = Instant::now();
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let enforcement = self.tenant_enforcement();
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        if collection.graph_backfill_pending() {
            return Err(slo_unavailable(
                "P3H graph retrieval is unavailable while point-handle backfill is pending",
            ));
        }
        if collection.global_backend().is_some() {
            return Err(slo_unavailable(
                "P3H joint widening requires the segmented LS-VEC backend",
            ));
        }
        validate_dense_dimension(&collection, &vector, vector_name.as_deref())?;
        let live_points = collection.live_points();
        let (dense_initial, dense_cap) = validate_p3_policy(policy.dense, k, live_points)?;
        let (sparse_initial, sparse_cap) = validate_p3_policy(policy.sparse, k, live_points)?;
        let visibility = collection.overlay_read_state();
        if !selection_matches_state(selection, &collection, &visibility)? {
            return Err(slo_unavailable(
                "P3H calibrated read state changed before execution",
            ));
        }
        check_execution_budget(cancelled, started, budget)?;

        let mut ledger = GraphWorkLedger::default();
        let anchor_depth = full_request.budget.max_depth.div_ceil(2);
        let reverse_depth = full_request.budget.max_depth / 2;
        let mut anchor_request = full_request.clone();
        anchor_request.budget = ledger.remaining(budget, started, 0)?;
        anchor_request.budget.max_depth = anchor_depth;
        let anchor_expansion = expand_constraint_locked(
            &collection,
            &visibility,
            &anchor_request,
            filter.as_ref(),
            scope,
            enforcement,
            cancelled,
        )?;
        ledger.record(&anchor_expansion);
        if let Some(reason) = anchor_expansion.traversal.truncation {
            return Err(slo_unavailable(format!(
                "P3H anchor frontier exceeded its {reason:?} budget"
            )));
        }
        crate::failpoint::check("graph_retrieval.after_expansion")?;
        let mut anchor_depths = HashMap::with_capacity(anchor_expansion.nodes.len());
        for node in &anchor_expansion.nodes {
            anchor_depths
                .entry(node.point_id.clone())
                .and_modify(|depth: &mut u32| *depth = (*depth).min(node.depth))
                .or_insert(node.depth);
        }
        let anchor_frontier_nodes = anchor_depths.len();
        let (persistent_memory, peak_memory) =
            p3h_memory_reservation(dense_cap, sparse_cap, k, anchor_frontier_nodes, live_points)?;
        if peak_memory > budget.max_memory_bytes {
            return Err(slo_unavailable(
                "P3H branch cursors, sparse scoring, fusion, and graph state exceed the graph retrieval memory budget",
            ));
        }
        ledger.remaining(budget, started, peak_memory)?;
        let mut dense_cursor = materialize_progressive_ann_cursor(
            &collection,
            &visibility,
            &vector,
            vector_name.as_deref(),
            dense_cap,
            None,
            None,
            cancelled,
            started,
            budget,
        )?;
        let mut sparse_cursor = materialize_progressive_sparse_cursor(
            &collection,
            &visibility,
            &sparse_vector,
            sparse_cap,
            cancelled,
            started,
            budget,
        )?;

        let mut candidates = HashMap::<String, P3HybridCandidate>::new();
        let mut dense_admitted = Vec::<RankedPoint>::new();
        let mut sparse_admitted = Vec::<RankedPoint>::new();
        let mut dense_windows = Vec::new();
        let mut sparse_windows = Vec::new();
        let mut reachability_decisions = 0_usize;
        let mut target_probes = 0_usize;
        let mut dense_target = dense_initial;
        let mut sparse_target = sparse_initial;
        let mut exact_fallback = false;

        for (branch, cursor, target, windows) in [
            (
                P3HybridBranch::Dense,
                &mut dense_cursor,
                dense_target,
                &mut dense_windows,
            ),
            (
                P3HybridBranch::Sparse,
                &mut sparse_cursor,
                sparse_target,
                &mut sparse_windows,
            ),
        ] {
            let range = cursor.advance_to(target);
            windows.push(cursor.position);
            if process_p3h_range_locked(
                branch,
                &cursor.ranked[range],
                &collection,
                &visibility,
                &full_request,
                filter.as_ref(),
                scope,
                enforcement,
                cancelled,
                started,
                budget,
                persistent_memory,
                reverse_depth,
                &anchor_depths,
                &mut ledger,
                &mut candidates,
                &mut dense_admitted,
                &mut sparse_admitted,
                &mut reachability_decisions,
                &mut target_probes,
            )? {
                exact_fallback = true;
                break;
            }
        }

        let mut fused = Vec::new();
        let mut kth_score = None;
        let mut stopping_bound = f32::INFINITY;
        while !exact_fallback {
            fused = fuse_rankings(
                &dense_admitted,
                &sparse_admitted,
                HybridFusion::Rrf,
                dense_weight,
                sparse_weight,
            );
            kth_score = fused.get(k - 1).map(|point| point.score);
            stopping_bound = p3h_rrf_unseen_bound(
                &candidates,
                dense_admitted.len(),
                sparse_admitted.len(),
                dense_cursor.has_unseen(),
                sparse_cursor.has_unseen(),
                dense_weight,
                sparse_weight,
            );
            if kth_score.is_some_and(|score| score > stopping_bound) {
                break;
            }

            let dense_can_advance = !dense_cursor.exhausted();
            let sparse_can_advance = !sparse_cursor.exhausted();
            if !dense_can_advance && !sparse_can_advance {
                exact_fallback = true;
                break;
            }
            let branch = choose_p3h_branch(
                dense_can_advance,
                sparse_can_advance,
                dense_cursor.position,
                sparse_cursor.position,
                dense_admitted.len(),
                sparse_admitted.len(),
                dense_weight,
                sparse_weight,
            );
            let (cursor, target, windows, branch_policy, branch_cap) = match branch {
                P3HybridBranch::Dense => (
                    &mut dense_cursor,
                    &mut dense_target,
                    &mut dense_windows,
                    policy.dense,
                    dense_cap,
                ),
                P3HybridBranch::Sparse => (
                    &mut sparse_cursor,
                    &mut sparse_target,
                    &mut sparse_windows,
                    policy.sparse,
                    sparse_cap,
                ),
            };
            *target = next_p3h_window(*target, cursor.position, branch_policy, branch_cap);
            let range = cursor.advance_to(*target);
            if range.is_empty() {
                exact_fallback = true;
                break;
            }
            windows.push(cursor.position);
            if process_p3h_range_locked(
                branch,
                &cursor.ranked[range],
                &collection,
                &visibility,
                &full_request,
                filter.as_ref(),
                scope,
                enforcement,
                cancelled,
                started,
                budget,
                persistent_memory,
                reverse_depth,
                &anchor_depths,
                &mut ledger,
                &mut candidates,
                &mut dense_admitted,
                &mut sparse_admitted,
                &mut reachability_decisions,
                &mut target_probes,
            )? {
                exact_fallback = true;
            }
        }

        let dense_depth = dense_cursor.position;
        let sparse_depth = sparse_cursor.position;
        let dense_admitted_count = dense_admitted.len();
        let sparse_admitted_count = sparse_admitted.len();
        let candidates_seen = candidates.len();
        if !exact_fallback {
            crate::observability::record_graph_fuse(
                dense_admitted_count,
                sparse_admitted_count,
                dense_depth,
                sparse_depth,
            );
            let ranked = fused
                .into_iter()
                .take(k)
                .map(|point| ScoredPoint {
                    id: point.id,
                    score: point.score,
                })
                .collect();
            let hits = hydrate_hits_locked(
                &collection,
                &visibility,
                ranked,
                true,
                cancelled,
                started,
                budget,
            )?;
            let response = SearchResponse {
                hits,
                degraded: selection.degraded,
                searched: dense_depth.saturating_add(sparse_depth),
                elapsed_ms: started.elapsed().as_millis(),
                graph: None,
            };
            operation_metrics.succeed();
            return Ok(P3HybridSearchOutcome {
                response,
                termination: P3HybridTermination::RrfBoundClosed,
                dense_windows,
                sparse_windows,
                dense_depth,
                sparse_depth,
                dense_admitted: dense_admitted_count,
                sparse_admitted: sparse_admitted_count,
                candidates_seen,
                reachability_decisions,
                target_probes,
                anchor_frontier_nodes,
                kth_score,
                stopping_bound,
                internal_edges_examined: ledger.internal_edges_examined,
            });
        }

        drop(dense_cursor);
        drop(sparse_cursor);
        drop(anchor_depths);
        drop(candidates);
        drop(dense_admitted);
        drop(sparse_admitted);
        let response = p3h_exact_fallback_locked(
            &collection,
            &visibility,
            &full_request,
            filter.as_ref(),
            &vector,
            vector_name.as_deref(),
            &sparse_vector,
            k,
            dense_weight,
            sparse_weight,
            scope,
            enforcement,
            cancelled,
            started,
            budget,
            &mut ledger,
            selection.degraded,
        )?;
        operation_metrics.succeed();
        Ok(P3HybridSearchOutcome {
            response,
            termination: P3HybridTermination::ExactFallback,
            dense_windows,
            sparse_windows,
            dense_depth,
            sparse_depth,
            dense_admitted: dense_admitted_count,
            sparse_admitted: sparse_admitted_count,
            candidates_seen,
            reachability_decisions,
            target_probes,
            anchor_frontier_nodes,
            kth_score,
            stopping_bound,
            internal_edges_examined: ledger.internal_edges_examined,
        })
    }

    /// Execute one planner-authorized P2 dense statement.
    ///
    /// D6 will supply production estimator/cost inputs. Keeping the selection
    /// explicit here prevents D5b from inventing a temporary public plan knob.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p2_graph_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
    ) -> Result<SearchResponse> {
        validate_p2_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("search");
        let SearchRequest {
            vector,
            vector_name,
            k,
            filter,
            graph,
            budget_ms,
            consistency: _,
            ef_search,
            recall_target,
            with_payload,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        validate_dense_query(&vector, recall_target)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P2 graph search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;

        let response = self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if !selection_matches_state(selection, collection, visibility)? {
                    return Err(slo_unavailable(
                        "P2 calibrated read state changed before execution",
                    ));
                }
                validate_dense_dimension(collection, &vector, vector_name.as_deref())?;
                let candidate_memory =
                    p2_candidate_memory_limit(expansion.nodes.len(), k, 1, false, budget)?;
                let candidates = build_graph_ordinal_candidates(
                    collection,
                    visibility,
                    &expansion.nodes,
                    candidate_memory,
                    "P2",
                )?;
                let (ranked, searched) = score_dense_p2_locked(
                    collection,
                    visibility,
                    &candidates,
                    &vector,
                    vector_name.as_deref(),
                    k,
                    ef_search,
                    recall_target,
                    cancelled,
                    started,
                    budget,
                )?;
                let hits = hydrate_hits_locked(
                    collection,
                    visibility,
                    ranked
                        .into_iter()
                        .map(|point| ScoredPoint {
                            id: point.id,
                            score: point.score,
                        })
                        .collect(),
                    with_payload.unwrap_or_else(|| self.default_with_payload()),
                    cancelled,
                    started,
                    budget,
                )?;
                Ok(SearchResponse {
                    hits,
                    degraded: selection.degraded,
                    searched,
                    elapsed_ms: started.elapsed().as_millis(),
                    graph: None,
                })
            },
        )?;
        operation_metrics.succeed();
        Ok(response)
    }

    pub(super) fn graph_hybrid_search_scoped_controlled(
        &self,
        collection_name: &str,
        mut request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<SearchResponse> {
        validate_k(request.k, "k")?;
        validate_filter_complexity(request.filter.as_ref())?;
        if request.vector.is_none() && request.sparse_vector.is_none() {
            return Err(GaussError::InvalidRequest(
                "hybrid search requires a dense vector, sparse vector, or both".to_string(),
            ));
        }
        if let Some(vector) = &request.vector {
            validate_dense_query(vector, None)?;
        }
        if let Some(vector_name) = &request.vector_name {
            validate_vector_name(vector_name)?;
        }
        if let Some(sparse_vector) = &request.sparse_vector {
            validate_sparse_vector(sparse_vector)?;
        }
        if !request.dense_weight.is_finite()
            || !request.sparse_weight.is_finite()
            || request.dense_weight < 0.0
            || request.sparse_weight < 0.0
        {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be finite and non-negative".to_string(),
            ));
        }
        let mut graph = request.graph.take().ok_or_else(|| {
            GaussError::InvalidRequest("graph-constrained hybrid search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, request.budget_ms)?;
        let both_branches = request.vector.is_some() && request.sparse_vector.is_some();
        let mode = match request.fusion {
            HybridFusion::Rrf => GraphStatementMode::HybridRrf,
            HybridFusion::Weighted => GraphStatementMode::HybridWeighted,
        };
        let audit = graph
            .allow_degraded
            .then(|| {
                self.audit_query_operation_with_context(
                    "graph.allow_degraded_hybrid_search",
                    Some(collection_name),
                    audit_context(scope),
                )
            })
            .transpose()?;
        let result = (|| {
            let prepared = if both_branches {
                self.prepare_graph_dispatch(
                    collection_name,
                    graph,
                    request.filter.as_ref(),
                    request.vector_name.as_deref(),
                    request.k,
                    None,
                    mode,
                    scope,
                    cancelled,
                )?
            } else {
                exact_dispatch(
                    graph,
                    GraphPlanGuard::ModeIncompatible,
                    Vec::new(),
                    Instant::now(),
                )
            };
            match prepared {
                PreparedGraphDispatch::Exact { graph, trace } => {
                    let execution = crate::observability::GraphExecutionGuard::start();
                    request.graph = Some(graph);
                    let response = self.exact_graph_hybrid_search_scoped(
                        collection_name,
                        request,
                        scope,
                        cancelled,
                    )?;
                    let telemetry = execution.finish();
                    Ok(finalize_graph_response(response, trace, telemetry))
                }
                PreparedGraphDispatch::Calibrated {
                    graph,
                    selection,
                    policies,
                    mut trace,
                    shadow,
                } => {
                    let execution = crate::observability::GraphExecutionGuard::start();
                    request.graph = Some(graph);
                    let shadow_request = shadow.as_ref().map(|_| request.clone());
                    let chosen_started = Instant::now();
                    let response = match selection.plan {
                        GraphRetrievalPlan::P1Exact => self
                            .exact_graph_hybrid_search_scoped_with_state(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection.expected_state,
                            )?,
                        GraphRetrievalPlan::P2PrefilteredCascade => self
                            .p2_graph_hybrid_search_scoped(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                            )?,
                        GraphRetrievalPlan::P3HybridJointWidening => {
                            let outcome = self.p3h_graph_hybrid_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                                policies.p3h,
                            )?;
                            trace.graph_plan.dense_branch_depth =
                                Some(u64::try_from(outcome.dense_depth).unwrap_or(u64::MAX));
                            trace.graph_plan.sparse_branch_depth =
                                Some(u64::try_from(outcome.sparse_depth).unwrap_or(u64::MAX));
                            if outcome.termination == P3HybridTermination::ExactFallback {
                                mark_exact_fallback(&mut trace);
                            }
                            outcome.response
                        }
                        GraphRetrievalPlan::P4ReachabilityAwareBeam => {
                            let outcome = self.p4_graph_hybrid_search_scoped_controlled(
                                collection_name,
                                request,
                                scope,
                                cancelled,
                                selection,
                            )?;
                            if outcome.termination == P4Termination::ExactFallback {
                                mark_exact_fallback(&mut trace);
                            }
                            outcome.response
                        }
                        GraphRetrievalPlan::P3ProgressiveProbe
                        | GraphRetrievalPlan::P5BestFirst => {
                            return Err(slo_unavailable(
                                "hybrid graph dispatch selected a dense-only executor",
                            ));
                        }
                    };
                    let chosen_elapsed_us = elapsed_us(chosen_started);
                    let telemetry = execution.finish();
                    let response = finalize_graph_response(response, trace, telemetry);
                    if let (Some(spec), Some(request), Some(state)) =
                        (shadow, shadow_request, selection.expected_state)
                    {
                        self.schedule_hybrid_graph_shadow(
                            collection_name,
                            request,
                            scope.clone(),
                            super::graph_shadow::GraphShadowExecution {
                                chosen: selection.plan,
                                chosen_elapsed_us,
                                state,
                                policies,
                                spec,
                            },
                        );
                    }
                    Ok(response)
                }
            }
        })();
        complete_allow_degraded_audit(audit, result)
    }

    pub(super) fn exact_graph_hybrid_search_scoped(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
    ) -> Result<SearchResponse> {
        self.exact_graph_hybrid_search_scoped_with_state(
            collection_name,
            request,
            scope,
            cancelled,
            None,
        )
    }

    pub(super) fn exact_graph_hybrid_search_scoped_with_state(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        expected_state: Option<GraphPlannerState>,
    ) -> Result<SearchResponse> {
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("hybrid_search");
        let HybridSearchRequest {
            vector,
            vector_name,
            sparse_vector,
            k,
            filter,
            graph,
            budget_ms,
            fusion,
            dense_weight,
            sparse_weight,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        if vector.is_none() && sparse_vector.is_none() {
            return Err(GaussError::InvalidRequest(
                "hybrid search requires a dense vector, sparse vector, or both".to_string(),
            ));
        }
        if vector
            .as_ref()
            .is_some_and(|vector| vector.iter().any(|value| !value.is_finite()))
        {
            return Err(GaussError::InvalidRequest(
                "dense vector values must be finite".to_string(),
            ));
        }
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        if let Some(sparse_vector) = &sparse_vector {
            validate_sparse_vector(sparse_vector)?;
        }
        if !dense_weight.is_finite()
            || !sparse_weight.is_finite()
            || dense_weight < 0.0
            || sparse_weight < 0.0
        {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be finite and non-negative".to_string(),
            ));
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("graph-constrained hybrid search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;

        let response = self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if let Some(expected) = expected_state
                    && graph_planner_state(collection, visibility)? != expected
                {
                    return Err(slo_unavailable(
                        "P1 hybrid calibrated read state changed before execution",
                    ));
                }
                if let Some(vector) = &vector {
                    validate_dense_dimension(collection, vector, vector_name.as_deref())?;
                }
                ensure_hybrid_rank_memory(
                    expansion.nodes.len(),
                    vector.is_some(),
                    sparse_vector.is_some(),
                    budget,
                )?;
                let resolver = CollectionReadResolver {
                    collection,
                    state: visibility,
                };
                let admitted = expansion
                    .nodes
                    .iter()
                    .map(|node| node.point_id.clone())
                    .collect::<HashSet<_>>();
                let mut searched = 0_usize;
                let dense_ranked = if let Some(vector) = &vector {
                    let (ranked, dense_searched) = score_dense_all_locked(
                        collection,
                        visibility,
                        &expansion.nodes,
                        vector,
                        vector_name.as_deref(),
                        cancelled,
                        started,
                        budget,
                    )?;
                    searched += dense_searched;
                    ranked
                } else {
                    Vec::new()
                };
                let sparse_ranked = if let Some(query) = &sparse_vector {
                    let outcome = sparse_search_ranked(
                        &collection.sparse_index,
                        &resolver,
                        crate::search::SparseSearchParams {
                            query,
                            limit: admitted.len(),
                            payload_candidates: Some(&admitted),
                            filter: filter.as_ref(),
                            budget: Some(budget.wall_time()),
                            started,
                            cancelled: Some(cancelled),
                        },
                    );
                    searched += outcome.searched;
                    if outcome.degraded {
                        check_execution_budget(cancelled, started, budget)?;
                        return Err(slo_unavailable(
                            "exact sparse ranking exceeded the graph retrieval budget",
                        ));
                    }
                    outcome.ranked
                } else {
                    Vec::new()
                };
                crate::observability::record_graph_fuse(
                    dense_ranked.len(),
                    sparse_ranked.len(),
                    dense_ranked.len(),
                    sparse_ranked.len(),
                );
                let fused = fuse_rankings(
                    &dense_ranked,
                    &sparse_ranked,
                    fusion,
                    dense_weight,
                    sparse_weight,
                );
                let ranked = fused
                    .into_iter()
                    .take(k)
                    .map(|point| ScoredPoint {
                        id: point.id,
                        score: point.score,
                    })
                    .collect();
                let hits = hydrate_hits_locked(
                    collection, visibility, ranked, true, cancelled, started, budget,
                )?;
                Ok(SearchResponse {
                    hits,
                    degraded: false,
                    searched,
                    elapsed_ms: started.elapsed().as_millis(),
                    graph: None,
                })
            },
        )?;
        operation_metrics.succeed();
        Ok(response)
    }

    /// Execute one planner-authorized P2 fused statement. Dense LS-VEC and
    /// exact sparse retrieval consume the same single expansion.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p2_graph_hybrid_search_scoped(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
    ) -> Result<SearchResponse> {
        validate_p2_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("hybrid_search");
        let HybridSearchRequest {
            vector,
            vector_name,
            sparse_vector,
            k,
            filter,
            graph,
            budget_ms,
            fusion,
            dense_weight,
            sparse_weight,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        if vector.is_none() && sparse_vector.is_none() {
            return Err(GaussError::InvalidRequest(
                "hybrid search requires a dense vector, sparse vector, or both".to_string(),
            ));
        }
        if let Some(vector) = &vector {
            validate_dense_query(vector, None)?;
        }
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        if let Some(sparse_vector) = &sparse_vector {
            validate_sparse_vector(sparse_vector)?;
        }
        if !dense_weight.is_finite()
            || !sparse_weight.is_finite()
            || dense_weight < 0.0
            || sparse_weight < 0.0
        {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be finite and non-negative".to_string(),
            ));
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P2 graph hybrid search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;

        let response = self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if !selection_matches_state(selection, collection, visibility)? {
                    return Err(slo_unavailable(
                        "P2 hybrid calibrated read state changed before execution",
                    ));
                }
                if let Some(vector) = &vector {
                    validate_dense_dimension(collection, vector, vector_name.as_deref())?;
                }
                let max_branch_limit = k.saturating_mul(4).max(k);
                let branch_count =
                    usize::from(vector.is_some()) + usize::from(sparse_vector.is_some());
                let candidate_memory = p2_candidate_memory_limit(
                    expansion.nodes.len(),
                    max_branch_limit,
                    branch_count,
                    sparse_vector.is_some(),
                    budget,
                )?;
                let candidates = build_graph_ordinal_candidates(
                    collection,
                    visibility,
                    &expansion.nodes,
                    candidate_memory,
                    "P2",
                )?;
                let branch_limit = max_branch_limit.min(candidates.len());
                let resolver = CollectionReadResolver {
                    collection,
                    state: visibility,
                };
                let admitted = expansion
                    .nodes
                    .iter()
                    .map(|node| node.point_id.clone())
                    .collect::<HashSet<_>>();
                let mut searched = 0_usize;
                let dense_ranked = if let Some(vector) = &vector {
                    let (ranked, dense_searched) = score_dense_p2_locked(
                        collection,
                        visibility,
                        &candidates,
                        vector,
                        vector_name.as_deref(),
                        branch_limit,
                        None,
                        None,
                        cancelled,
                        started,
                        budget,
                    )?;
                    searched += dense_searched;
                    ranked
                } else {
                    Vec::new()
                };
                let sparse_ranked = if let Some(query) = &sparse_vector {
                    let outcome = sparse_search_ranked(
                        &collection.sparse_index,
                        &resolver,
                        crate::search::SparseSearchParams {
                            query,
                            limit: branch_limit,
                            payload_candidates: Some(&admitted),
                            filter: filter.as_ref(),
                            budget: Some(budget.wall_time()),
                            started,
                            cancelled: Some(cancelled),
                        },
                    );
                    searched += outcome.searched;
                    if outcome.degraded {
                        check_execution_budget(cancelled, started, budget)?;
                        return Err(slo_unavailable(
                            "P2 sparse ranking exceeded the graph retrieval budget",
                        ));
                    }
                    outcome.ranked
                } else {
                    Vec::new()
                };
                crate::observability::record_graph_fuse(
                    dense_ranked.len(),
                    sparse_ranked.len(),
                    dense_ranked.len(),
                    sparse_ranked.len(),
                );
                let ranked = fuse_rankings(
                    &dense_ranked,
                    &sparse_ranked,
                    fusion,
                    dense_weight,
                    sparse_weight,
                )
                .into_iter()
                .take(k)
                .map(|point| ScoredPoint {
                    id: point.id,
                    score: point.score,
                })
                .collect();
                let hits = hydrate_hits_locked(
                    collection, visibility, ranked, true, cancelled, started, budget,
                )?;
                Ok(SearchResponse {
                    hits,
                    degraded: selection.degraded,
                    searched,
                    elapsed_ms: started.elapsed().as_millis(),
                    graph: None,
                })
            },
        )?;
        operation_metrics.succeed();
        Ok(response)
    }

    /// Execute one planner-authorized dense P4 statement.
    ///
    /// Graph-admitted rows may occupy result capacity, while every other live
    /// LS-VEC row remains available as a navigation stepping stone. Underfill
    /// or an incompatible backend takes exact P1 over the pinned expansion.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p4_graph_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
    ) -> Result<P4SearchOutcome> {
        validate_p4_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("search");
        let SearchRequest {
            vector,
            vector_name,
            k,
            filter,
            graph,
            budget_ms,
            consistency: _,
            ef_search,
            recall_target,
            with_payload,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        validate_dense_query(&vector, recall_target)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P4 graph search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;

        let outcome = self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if !selection_matches_state(selection, collection, visibility)? {
                    return Err(slo_unavailable(
                        "P4 calibrated read state changed before execution",
                    ));
                }
                validate_dense_dimension(collection, &vector, vector_name.as_deref())?;
                let admitted_points = expansion.nodes.len();
                let candidate_memory =
                    p4_candidate_memory_limit(admitted_points, k, 1, false, budget)?;
                let candidates = build_graph_ordinal_candidates(
                    collection,
                    visibility,
                    &expansion.nodes,
                    candidate_memory,
                    "P4",
                )?;
                let mut dense_candidates = 0_usize;
                let mut non_admitted_navigation_checks = 0_usize;
                let (ranked, searched, termination) = if collection.global_backend().is_some() {
                    drop(candidates);
                    let (ranked, searched) = score_dense_top_k_locked(
                        collection,
                        visibility,
                        &expansion.nodes,
                        &vector,
                        vector_name.as_deref(),
                        k,
                        cancelled,
                        started,
                        budget,
                    )?;
                    (ranked, searched, P4Termination::ExactFallback)
                } else {
                    let (beam, beam_searched, bridge_checks) = score_dense_p4_locked(
                        collection,
                        visibility,
                        &candidates,
                        &vector,
                        vector_name.as_deref(),
                        k,
                        ef_search,
                        recall_target,
                        cancelled,
                        started,
                        budget,
                    )?;
                    dense_candidates = beam.len();
                    non_admitted_navigation_checks = bridge_checks;
                    if beam.len() < k {
                        drop(beam);
                        drop(candidates);
                        let (ranked, searched) = score_dense_top_k_locked(
                            collection,
                            visibility,
                            &expansion.nodes,
                            &vector,
                            vector_name.as_deref(),
                            k,
                            cancelled,
                            started,
                            budget,
                        )?;
                        (ranked, searched, P4Termination::ExactFallback)
                    } else {
                        (
                            beam.into_iter()
                                .map(|point| ScoredPoint {
                                    id: point.id,
                                    score: point.score,
                                })
                                .collect(),
                            beam_searched,
                            P4Termination::Beam,
                        )
                    }
                };
                let hits = hydrate_hits_locked(
                    collection,
                    visibility,
                    ranked,
                    with_payload.unwrap_or_else(|| self.default_with_payload()),
                    cancelled,
                    started,
                    budget,
                )?;
                Ok(P4SearchOutcome {
                    response: SearchResponse {
                        hits,
                        degraded: selection.degraded,
                        searched,
                        elapsed_ms: started.elapsed().as_millis(),
                        graph: None,
                    },
                    termination,
                    admitted_points,
                    dense_candidates,
                    sparse_candidates: 0,
                    non_admitted_navigation_checks,
                })
            },
        )?;
        operation_metrics.succeed();
        Ok(outcome)
    }

    /// Execute one planner-authorized fused P4 statement. Only the dense
    /// branch changes navigation; sparse BM25 remains an exact admitted-set
    /// intersection and both branches share one pinned expansion.
    #[allow(clippy::too_many_lines)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p4_graph_hybrid_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
    ) -> Result<P4SearchOutcome> {
        validate_p4_selection(selection)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("hybrid_search");
        let HybridSearchRequest {
            vector,
            vector_name,
            sparse_vector,
            k,
            filter,
            graph,
            budget_ms,
            fusion,
            dense_weight,
            sparse_weight,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        let vector = vector
            .ok_or_else(|| GaussError::InvalidRequest("P4 requires a dense branch".to_string()))?;
        let sparse_vector = sparse_vector.ok_or_else(|| {
            GaussError::InvalidRequest("P4 fused retrieval requires a sparse branch".to_string())
        })?;
        validate_dense_query(&vector, None)?;
        validate_sparse_vector(&sparse_vector)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        if !dense_weight.is_finite()
            || !sparse_weight.is_finite()
            || dense_weight < 0.0
            || sparse_weight < 0.0
        {
            return Err(GaussError::InvalidRequest(
                "hybrid search weights must be finite and non-negative".to_string(),
            ));
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P4 graph hybrid search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;

        let outcome = self.with_pinned_graph_expansion(
            collection_name,
            graph,
            filter.as_ref(),
            scope,
            cancelled,
            |collection, visibility, expansion, started, budget| {
                if !selection_matches_state(selection, collection, visibility)? {
                    return Err(slo_unavailable(
                        "P4 hybrid calibrated read state changed before execution",
                    ));
                }
                validate_dense_dimension(collection, &vector, vector_name.as_deref())?;
                let admitted_points = expansion.nodes.len();
                let branch_limit = k.saturating_mul(4).max(k).min(admitted_points);
                let candidate_memory =
                    p4_candidate_memory_limit(admitted_points, branch_limit, 2, true, budget)?;
                let candidates = build_graph_ordinal_candidates(
                    collection,
                    visibility,
                    &expansion.nodes,
                    candidate_memory,
                    "P4",
                )?;
                let mut dense_candidates = 0_usize;
                let mut sparse_candidates = 0_usize;
                let mut non_admitted_navigation_checks = 0_usize;
                let mut exact_fallback = collection.global_backend().is_some();
                let resolver = CollectionReadResolver {
                    collection,
                    state: visibility,
                };
                let admitted = expansion
                    .nodes
                    .iter()
                    .map(|node| node.point_id.clone())
                    .collect::<HashSet<_>>();
                let (dense_ranked, sparse_ranked, approximate_searched) = if exact_fallback {
                    (Vec::new(), Vec::new(), 0)
                } else {
                    let (dense, dense_searched, bridge_checks) = score_dense_p4_locked(
                        collection,
                        visibility,
                        &candidates,
                        &vector,
                        vector_name.as_deref(),
                        branch_limit,
                        None,
                        None,
                        cancelled,
                        started,
                        budget,
                    )?;
                    dense_candidates = dense.len();
                    non_admitted_navigation_checks = bridge_checks;
                    let sparse = sparse_search_ranked(
                        &collection.sparse_index,
                        &resolver,
                        crate::search::SparseSearchParams {
                            query: &sparse_vector,
                            limit: branch_limit,
                            payload_candidates: Some(&admitted),
                            filter: filter.as_ref(),
                            budget: Some(budget.wall_time()),
                            started,
                            cancelled: Some(cancelled),
                        },
                    );
                    if sparse.degraded {
                        check_execution_budget(cancelled, started, budget)?;
                        return Err(slo_unavailable(
                            "P4 sparse ranking exceeded the graph retrieval budget",
                        ));
                    }
                    sparse_candidates = sparse.ranked.len();
                    let searched = dense_searched.saturating_add(sparse.searched);
                    (dense, sparse.ranked, searched)
                };
                let approximate = if exact_fallback {
                    Vec::new()
                } else {
                    crate::observability::record_graph_fuse(
                        dense_ranked.len(),
                        sparse_ranked.len(),
                        dense_candidates,
                        sparse_candidates,
                    );
                    fuse_rankings(
                        &dense_ranked,
                        &sparse_ranked,
                        fusion,
                        dense_weight,
                        sparse_weight,
                    )
                    .into_iter()
                    .take(k)
                    .map(|point| ScoredPoint {
                        id: point.id,
                        score: point.score,
                    })
                    .collect::<Vec<_>>()
                };
                exact_fallback |= approximate.len() < k;
                let (ranked, searched, termination) = if exact_fallback {
                    drop(approximate);
                    drop(dense_ranked);
                    drop(sparse_ranked);
                    drop(candidates);
                    drop(admitted);
                    let (ranked, searched) = p4_exact_hybrid_locked(
                        collection,
                        visibility,
                        &expansion.nodes,
                        filter.as_ref(),
                        &vector,
                        vector_name.as_deref(),
                        &sparse_vector,
                        k,
                        fusion,
                        dense_weight,
                        sparse_weight,
                        cancelled,
                        started,
                        budget,
                    )?;
                    (ranked, searched, P4Termination::ExactFallback)
                } else {
                    (approximate, approximate_searched, P4Termination::Beam)
                };
                let hits = hydrate_hits_locked(
                    collection, visibility, ranked, true, cancelled, started, budget,
                )?;
                Ok(P4SearchOutcome {
                    response: SearchResponse {
                        hits,
                        degraded: selection.degraded,
                        searched,
                        elapsed_ms: started.elapsed().as_millis(),
                        graph: None,
                    },
                    termination,
                    admitted_points,
                    dense_candidates,
                    sparse_candidates,
                    non_admitted_navigation_checks,
                })
            },
        )?;
        operation_metrics.succeed();
        Ok(outcome)
    }

    /// Execute one planner-authorized dense P5 statement.
    ///
    /// The reachable set is never materialized. Every admitted frontier node
    /// is prioritized by its exact vector score; roots are expanded first and
    /// vectorless nodes remain lowest-priority traversal intermediates. The
    /// heuristic stability rule is valid only inside D6's calibrated envelope.
    #[allow(clippy::too_many_lines)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn p5_graph_search_scoped_controlled(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        selection: GraphPlanSelection,
        policy: P5BestFirstPolicy,
    ) -> Result<P5SearchOutcome> {
        validate_p5_selection(selection)?;
        validate_p5_policy(policy)?;
        let _inflight = SearchInflightGuard::new(self.search_inflight.clone());
        let mut operation_metrics = OperationGuard::start("search");
        let SearchRequest {
            vector,
            vector_name,
            k,
            filter,
            graph,
            budget_ms,
            consistency: _,
            ef_search: _,
            recall_target,
            with_payload,
        } = request;
        validate_k(k, "k")?;
        validate_filter_complexity(filter.as_ref())?;
        validate_dense_query(&vector, recall_target)?;
        if let Some(vector_name) = &vector_name {
            validate_vector_name(vector_name)?;
        }
        let mut graph = graph.ok_or_else(|| {
            GaussError::InvalidRequest("P5 graph search requires graph".to_string())
        })?;
        apply_request_time_budget(&mut graph, budget_ms)?;
        let full_request: crate::graph::GraphTraverseRequest = graph.into();
        super::graph_runtime::validate_traversal_request(&full_request)?;
        let budget = full_request.budget.validate()?;
        let started = Instant::now();
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let enforcement = self.tenant_enforcement();
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        if collection.graph_backfill_pending() {
            return Err(slo_unavailable(
                "P5 graph retrieval is unavailable while point-handle backfill is pending",
            ));
        }
        validate_dense_dimension(&collection, &vector, vector_name.as_deref())?;
        let visibility = collection.overlay_read_state();
        if !selection_matches_state(selection, &collection, &visibility)? {
            return Err(slo_unavailable(
                "P5 calibrated read state changed before execution",
            ));
        }
        check_execution_budget(cancelled, started, budget)?;

        let mut ledger = GraphWorkLedger::default();
        let mut frontier_pops = 0_usize;
        let mut frontier_expansions = 0_usize;
        let mut vector_distances = 0_usize;
        let mut peak_frontier = 0_usize;
        let mut max_depth_popped = 0_u32;

        // At depth zero P5 has no graph frontier advantage. Use complete P1
        // rather than inventing special anchor stability semantics.
        if full_request.budget.max_depth == 0 {
            let response = p5_exact_fallback_locked(
                &collection,
                &visibility,
                &full_request,
                filter.as_ref(),
                &vector,
                vector_name.as_deref(),
                k,
                with_payload.unwrap_or_else(|| self.default_with_payload()),
                scope,
                enforcement,
                cancelled,
                started,
                budget,
                &mut ledger,
                selection.degraded,
            )?;
            operation_metrics.succeed();
            return Ok(P5SearchOutcome {
                response,
                termination: P5Termination::ExactFallback,
                frontier_pops,
                frontier_expansions,
                vector_distances,
                unique_nodes_seen: 0,
                peak_frontier,
                max_depth_popped,
                internal_edges_examined: ledger.internal_edges_examined,
            });
        }

        let mut seen = HashSet::with_capacity(full_request.anchors.len());
        let mut frontier = BinaryHeap::with_capacity(full_request.anchors.len());
        for point_id in &full_request.anchors {
            if !seen.insert(point_id.clone()) {
                continue;
            }
            collection
                .resolve_in_read_state(&visibility, point_id)
                .filter(|point| scope.may_read_payload(enforcement, &point.payload))
                .ok_or_else(endpoint_not_found)?;
            frontier.push(P5FrontierPoint {
                point_id: point_id.clone(),
                score: None,
                depth: 0,
                root: true,
            });
        }
        ledger.nodes_visited = u64::try_from(seen.len()).unwrap_or(u64::MAX);
        peak_frontier = frontier.len();
        let mut top = BinaryHeap::with_capacity(k.saturating_add(1));
        let mut exact_fallback = ledger.nodes_visited > budget.max_visited
            || p5_state_memory(seen.len(), frontier.len(), k)? > budget.max_memory_bytes;
        let mut termination = P5Termination::FrontierExhausted;

        while !exact_fallback {
            let Some(best) = frontier.peek() else {
                termination = P5Termination::FrontierExhausted;
                break;
            };
            if top.len() == k && top.peek().is_some_and(|worst| !best.can_improve(worst)) {
                termination = P5Termination::StableTopK;
                break;
            }

            let current = frontier.pop().expect("P5 frontier was checked before pop");
            frontier_pops = frontier_pops.saturating_add(1);
            max_depth_popped = max_depth_popped.max(current.depth);
            if let Some(score) = current.score {
                let scored = ScoredPoint {
                    id: current.point_id.clone(),
                    score,
                };
                if top.len() < k {
                    top.push(scored);
                } else if top
                    .peek()
                    .is_some_and(|worst| ranked_before(&scored, worst))
                {
                    top.pop();
                    top.push(scored);
                }
            }
            if current.depth >= full_request.budget.max_depth {
                continue;
            }
            if frontier_expansions >= policy.max_expansions {
                exact_fallback = true;
                break;
            }

            let persistent_memory = p5_state_memory(seen.len(), frontier.len(), k)?;
            if persistent_memory > budget.max_memory_bytes
                || u64::try_from(frontier.len()).unwrap_or(u64::MAX) >= budget.max_frontier
            {
                exact_fallback = true;
                break;
            }
            let mut step_budget = ledger.remaining_for("P5", budget, started, persistent_memory)?;
            step_budget.max_depth = 1;
            // The current root was already charged globally. Give the
            // isolated one-hop expansion one local root slot.
            step_budget.max_visited = step_budget.max_visited.saturating_add(1);
            step_budget.max_frontier = budget
                .max_frontier
                .saturating_sub(u64::try_from(frontier.len()).unwrap_or(u64::MAX))
                .max(1);
            let mut step_request = full_request.clone();
            step_request.anchors = vec![current.point_id];
            step_request.budget = step_budget;
            let expansion = expand_constraint_locked(
                &collection,
                &visibility,
                &step_request,
                filter.as_ref(),
                scope,
                enforcement,
                cancelled,
            )?;
            frontier_expansions = frontier_expansions.saturating_add(1);
            ledger.internal_edges_examined = ledger
                .internal_edges_examined
                .saturating_add(expansion.internal_edges_examined);
            ledger.nodes_visited = ledger
                .nodes_visited
                .saturating_add(expansion.traversal.stats.nodes_visited.saturating_sub(1));
            ledger.cold_fragments_read = ledger
                .cold_fragments_read
                .saturating_add(expansion.traversal.stats.cold_fragments_read);
            ledger.cold_bytes_read = ledger
                .cold_bytes_read
                .saturating_add(expansion.traversal.stats.cold_bytes_read);
            crate::failpoint::check("graph_retrieval.after_expansion")?;
            if expansion.traversal.truncation.is_some() {
                exact_fallback = true;
                break;
            }

            for node in expansion.nodes {
                if !seen.insert(node.point_id.clone()) {
                    continue;
                }
                let point = resolve_admitted_point(&collection, &visibility, &node.point_id)?;
                let score = point_vector(&point, vector_name.as_deref())
                    .map(|candidate| collection.config.metric.score(&vector, candidate))
                    .transpose()?;
                if score.is_some() {
                    vector_distances = vector_distances.saturating_add(1);
                }
                let next_depth = current.depth.saturating_add(1);
                let next_memory = p5_state_memory(seen.len(), frontier.len().saturating_add(1), k)?;
                if next_memory > budget.max_memory_bytes
                    || u64::try_from(frontier.len().saturating_add(1)).unwrap_or(u64::MAX)
                        > budget.max_frontier
                {
                    exact_fallback = true;
                    break;
                }
                frontier.push(P5FrontierPoint {
                    point_id: node.point_id,
                    score,
                    depth: next_depth,
                    root: false,
                });
                peak_frontier = peak_frontier.max(frontier.len());
            }
        }

        let unique_nodes_seen = seen.len();
        let internal_edges_examined = ledger.internal_edges_examined;
        let response = if exact_fallback {
            drop(frontier);
            drop(seen);
            drop(top);
            let response = p5_exact_fallback_locked(
                &collection,
                &visibility,
                &full_request,
                filter.as_ref(),
                &vector,
                vector_name.as_deref(),
                k,
                with_payload.unwrap_or_else(|| self.default_with_payload()),
                scope,
                enforcement,
                cancelled,
                started,
                budget,
                &mut ledger,
                selection.degraded,
            )?;
            termination = P5Termination::ExactFallback;
            response
        } else {
            let mut ranked = top.into_vec();
            ranked.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.id.cmp(&right.id))
            });
            let hits = hydrate_hits_locked(
                &collection,
                &visibility,
                ranked,
                with_payload.unwrap_or_else(|| self.default_with_payload()),
                cancelled,
                started,
                budget,
            )?;
            SearchResponse {
                hits,
                degraded: selection.degraded,
                searched: vector_distances,
                elapsed_ms: started.elapsed().as_millis(),
                graph: None,
            }
        };
        operation_metrics.succeed();
        Ok(P5SearchOutcome {
            response,
            termination,
            frontier_pops,
            frontier_expansions,
            vector_distances,
            unique_nodes_seen,
            peak_frontier,
            max_depth_popped,
            internal_edges_examined: if termination == P5Termination::ExactFallback {
                ledger.internal_edges_examined
            } else {
                internal_edges_examined
            },
        })
    }

    fn with_pinned_graph_expansion<T>(
        &self,
        collection_name: &str,
        graph: GraphConstraint,
        statement_filter: Option<&Filter>,
        scope: &crate::tenant::TenantScope,
        cancelled: &AtomicBool,
        execute: impl FnOnce(
            &Collection,
            &crate::overlay::OverlayReadState,
            &PinnedGraphExpansion,
            Instant,
            crate::graph::TraversalBudget,
        ) -> Result<T>,
    ) -> Result<T> {
        let traversal_request: crate::graph::GraphTraverseRequest = graph.into();
        super::graph_runtime::validate_traversal_request(&traversal_request)?;
        let budget = traversal_request.budget.validate()?;
        let started = Instant::now();
        let coll = self.get_coll(collection_name)?;
        {
            let collection = coll.read();
            active_mutable_graph(&collection)?;
        }
        let _permit = crate::graph_admission::acquire(collection_name, scope, budget, cancelled)?;
        let enforcement = self.tenant_enforcement();
        let _lifecycle = self.lifecycle_gate.read();
        let collection = coll.read();
        if collection.graph_backfill_pending() {
            return Err(slo_unavailable(
                "exact graph retrieval is unavailable while point-handle backfill is pending",
            ));
        }
        let visibility = collection.overlay_read_state();
        check_execution_budget(cancelled, started, budget)?;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let remaining_ms = budget.max_time_ms.saturating_sub(elapsed_ms);
        if remaining_ms == 0 {
            return Err(slo_unavailable(
                "exact graph retrieval exceeded its wall-time budget",
            ));
        }
        let mut execution_request = traversal_request;
        execution_request.budget.max_time_ms = remaining_ms;
        let expansion = expand_constraint_locked(
            &collection,
            &visibility,
            &execution_request,
            statement_filter,
            scope,
            enforcement,
            cancelled,
        )?;
        crate::observability::record_graph_epoch(expansion.graph_epoch);
        if let Some(reason) = expansion.traversal.truncation {
            return Err(slo_unavailable(format!(
                "exact graph constraint expansion exceeded its {reason:?} budget"
            )));
        }
        crate::failpoint::check("graph_retrieval.after_expansion")?;
        execute(&collection, &visibility, &expansion, started, budget)
    }
}

fn apply_request_time_budget(graph: &mut GraphConstraint, budget_ms: Option<u64>) -> Result<()> {
    if let Some(budget_ms) = budget_ms {
        if budget_ms == 0 {
            return Err(slo_unavailable(
                "exact graph retrieval has no remaining wall-time budget",
            ));
        }
        graph.budget.max_time_ms = graph.budget.max_time_ms.min(budget_ms);
    }
    Ok(())
}

fn recall_target_bps(target: Option<f32>) -> Result<Option<u16>> {
    let Some(target) = target else {
        return Ok(None);
    };
    if !target.is_finite() || !(0.5..=1.0).contains(&target) {
        return Err(GaussError::InvalidRequest(format!(
            "recall_target must be finite and in [0.5, 1.0], got {target}"
        )));
    }
    let bps = (f64::from(target) * 10_000.0)
        .ceil()
        .clamp(5_000.0, 10_000.0);
    Ok(Some(bps as u16))
}

pub(super) fn graph_planner_state(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
) -> Result<GraphPlannerState> {
    Ok(GraphPlannerState {
        graph_epoch: active_mutable_graph(collection)?.epoch().raw(),
        schema_epoch: collection.schema_epoch,
        manifest_generation: collection
            .graph_generation
            .as_ref()
            .map_or(0, |generation| generation.manifest.generation),
        overlay_generation: visibility.generation(),
        overlay_version: visibility.version(),
        wal_lsn: collection.wal.len()?,
    })
}

fn selection_matches_state(
    selection: GraphPlanSelection,
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
) -> Result<bool> {
    match selection.expected_state {
        Some(expected) => Ok(graph_planner_state(collection, visibility)? == expected),
        None => Ok(true),
    }
}

fn validate_dense_dimension(
    collection: &Collection,
    vector: &[f32],
    vector_name: Option<&str>,
) -> Result<()> {
    let expected = vector_name
        .and_then(|name| collection.config.named_vector_dims.get(name))
        .copied()
        .unwrap_or(collection.config.vector_dim);
    if vector.len() != expected {
        return Err(GaussError::DimensionMismatch {
            expected,
            actual: vector.len(),
        });
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_dense_query(vector: &[f32], recall_target: Option<f32>) -> Result<()> {
    if vector.iter().any(|value| !value.is_finite()) {
        return Err(GaussError::InvalidRequest(
            "dense vector values must be finite".to_string(),
        ));
    }
    if let Some(recall_target) = recall_target
        && (!recall_target.is_finite() || !(0.5..=1.0).contains(&recall_target))
    {
        return Err(GaussError::InvalidRequest(format!(
            "recall_target must be finite and in [0.5, 1.0], got {recall_target}"
        )));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p2_selection(selection: GraphPlanSelection) -> Result<()> {
    if selection.plan != GraphRetrievalPlan::P2PrefilteredCascade
        || selection.failure_policy != GraphPlanFailurePolicy::ExactP1OrError
    {
        return Err(slo_unavailable(
            "the selected graph retrieval plan has no P2 executor",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p3_selection(selection: GraphPlanSelection) -> Result<()> {
    if selection.plan != GraphRetrievalPlan::P3ProgressiveProbe
        || selection.failure_policy != GraphPlanFailurePolicy::ExactP1OrError
    {
        return Err(slo_unavailable(
            "the selected graph retrieval plan has no dense P3 executor",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p3h_selection(selection: GraphPlanSelection) -> Result<()> {
    if selection.plan != GraphRetrievalPlan::P3HybridJointWidening
        || selection.failure_policy != GraphPlanFailurePolicy::ExactP1OrError
    {
        return Err(slo_unavailable(
            "the selected graph retrieval plan has no fused P3H executor",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p4_selection(selection: GraphPlanSelection) -> Result<()> {
    if selection.plan != GraphRetrievalPlan::P4ReachabilityAwareBeam
        || selection.failure_policy != GraphPlanFailurePolicy::ExactP1OrError
    {
        return Err(slo_unavailable(
            "the selected graph retrieval plan has no P4 executor",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p5_selection(selection: GraphPlanSelection) -> Result<()> {
    if selection.plan != GraphRetrievalPlan::P5BestFirst
        || selection.failure_policy != GraphPlanFailurePolicy::ExactP1OrError
    {
        return Err(slo_unavailable(
            "the selected graph retrieval plan has no dense P5 executor",
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p5_policy(policy: P5BestFirstPolicy) -> Result<()> {
    if policy.max_expansions == 0 {
        return Err(GaussError::InvalidRequest(
            "P5 max_expansions must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_p3_policy(
    policy: P3ProgressivePolicy,
    k: usize,
    live_points: usize,
) -> Result<(usize, usize)> {
    if policy.initial_factor == 0 {
        return Err(GaussError::InvalidRequest(
            "P3 initial_factor must be greater than zero".to_string(),
        ));
    }
    if policy.growth_factor < 2 {
        return Err(GaussError::InvalidRequest(
            "P3 growth_factor must be at least two".to_string(),
        ));
    }
    if policy.max_candidates < k {
        return Err(GaussError::InvalidRequest(
            "P3 max_candidates must be at least k".to_string(),
        ));
    }
    let initial = k.checked_mul(policy.initial_factor).ok_or_else(|| {
        GaussError::InvalidRequest("P3 initial candidate window overflows usize".to_string())
    })?;
    let candidate_cap = policy.max_candidates.min(live_points);
    Ok((initial.min(candidate_cap), candidate_cap))
}

#[cfg_attr(not(test), allow(dead_code))]
fn p5_state_memory(visited: usize, frontier: usize, k: usize) -> Result<u64> {
    const P5_STATE_ENTRY_BYTES: u64 = 1_216;
    let entries = visited
        .checked_add(frontier)
        .and_then(|entries| entries.checked_add(k))
        .ok_or_else(|| slo_unavailable("P5 best-first state size overflows usize"))?;
    Ok(u64::try_from(entries)
        .unwrap_or(u64::MAX)
        .saturating_mul(P5_STATE_ENTRY_BYTES))
}

#[cfg_attr(not(test), allow(dead_code))]
fn p3_persistent_memory(
    candidate_cap: usize,
    k: usize,
    anchor_frontier_nodes: usize,
) -> Result<u64> {
    let entries = candidate_cap
        .checked_add(k)
        .and_then(|entries| entries.checked_add(anchor_frontier_nodes))
        .ok_or_else(|| slo_unavailable("P3 persistent state cardinality overflows usize"))?;
    Ok(u64::try_from(entries)
        .unwrap_or(u64::MAX)
        .saturating_mul(RANKED_POINT_BUDGET_BYTES))
}

#[cfg_attr(not(test), allow(dead_code))]
fn p3h_memory_reservation(
    dense_cap: usize,
    sparse_cap: usize,
    k: usize,
    anchor_frontier_nodes: usize,
    live_points: usize,
) -> Result<(u64, u64)> {
    let branch_entries = dense_cap
        .checked_add(sparse_cap)
        .ok_or_else(|| slo_unavailable("P3H branch cardinality overflows usize"))?;
    // Two materialized branch pools, one union map, admitted branch rankings,
    // fused ranking, anchor frontier, and final k coexist after materialization.
    let persistent_entries = branch_entries
        .checked_mul(4)
        .and_then(|entries| entries.checked_add(anchor_frontier_nodes))
        .and_then(|entries| entries.checked_add(k))
        .ok_or_else(|| slo_unavailable("P3H persistent state cardinality overflows usize"))?;
    let persistent = u64::try_from(persistent_entries)
        .unwrap_or(u64::MAX)
        .saturating_mul(RANKED_POINT_BUDGET_BYTES);
    // The current sparse primitive aggregates scores by ID before top-k. Until
    // an index-level incremental cursor lands, reserve its worst-case live-ID
    // map concurrently with the persistent P3H state.
    let sparse_transient = u64::try_from(live_points)
        .unwrap_or(u64::MAX)
        .saturating_mul(RANKED_POINT_BUDGET_BYTES);
    Ok((persistent, persistent.saturating_add(sparse_transient)))
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn materialize_progressive_ann_cursor(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    query: &[f32],
    vector_name: Option<&str>,
    candidate_cap: usize,
    ef_search: Option<u32>,
    recall_target: Option<f32>,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
) -> Result<ProgressiveRankCursor> {
    if candidate_cap == 0 {
        return Ok(ProgressiveRankCursor {
            ranked: Vec::new(),
            position: 0,
            complete: collection.live_points() == 0,
        });
    }
    let resolved_recall_target = recall_target
        .or(collection.config.recall_sla)
        .unwrap_or(crate::h2qg::DEFAULT_RECALL_TARGET);
    let resolved_ef_search = ef_search
        .or(collection.config.hnsw_ef_search)
        .map(|ef| (ef as usize).max(candidate_cap))
        .or_else(|| {
            let ef = collection
                .recall_curve
                .as_ref()
                .and_then(|curve| super::ef_search_from_curve(curve, resolved_recall_target))
                .unwrap_or_else(|| {
                    crate::h2qg::ef_search_for_recall_target(
                        candidate_cap,
                        resolved_recall_target,
                        collection.live_points(),
                        collection.config.vector_dim,
                    )
                });
            Some(ef)
        });
    let resolver = CollectionReadResolver {
        collection,
        state: visibility,
    };
    let candidates = crate::search::fan_out_candidates(
        None,
        &collection.streamer,
        collection.sealing.as_deref(),
        &collection.searchers,
        visibility,
        &resolver,
        collection.live_points(),
        query,
        candidate_cap,
        vector_name,
        resolved_ef_search,
        resolved_recall_target,
        None,
        None,
        Some(cancelled),
    );
    check_execution_budget(cancelled, started, budget)?;
    let mut ranked = Vec::with_capacity(candidates.len().min(candidate_cap));
    for point in candidates {
        check_execution_budget(cancelled, started, budget)?;
        let Some(vector) = point_vector(&point, vector_name) else {
            continue;
        };
        ranked.push(RankedPoint {
            id: point.id.clone(),
            score: collection.config.metric.score(query, vector)?,
        });
    }
    ranked.sort_by(rank_order);
    ranked.truncate(candidate_cap);
    Ok(ProgressiveRankCursor {
        ranked,
        position: 0,
        complete: candidate_cap >= collection.live_points(),
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn materialize_progressive_sparse_cursor(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    query: &crate::model::SparseVector,
    candidate_cap: usize,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
) -> Result<ProgressiveRankCursor> {
    if candidate_cap == 0 {
        return Ok(ProgressiveRankCursor {
            ranked: Vec::new(),
            position: 0,
            complete: collection.live_points() == 0,
        });
    }
    let resolver = CollectionReadResolver {
        collection,
        state: visibility,
    };
    let probe_limit = candidate_cap
        .checked_add(1)
        .unwrap_or(candidate_cap)
        .min(collection.live_points());
    let mut outcome = sparse_search_ranked(
        &collection.sparse_index,
        &resolver,
        crate::search::SparseSearchParams {
            query,
            limit: probe_limit,
            payload_candidates: None,
            filter: None,
            budget: Some(budget.wall_time()),
            started,
            cancelled: Some(cancelled),
        },
    );
    if outcome.degraded {
        check_execution_budget(cancelled, started, budget)?;
        return Err(slo_unavailable(
            "P3H sparse cursor materialization exceeded the graph retrieval budget",
        ));
    }
    let complete =
        candidate_cap >= collection.live_points() || outcome.ranked.len() <= candidate_cap;
    outcome.ranked.truncate(candidate_cap);
    Ok(ProgressiveRankCursor {
        ranked: outcome.ranked,
        position: 0,
        complete,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn process_p3h_range_locked(
    branch: P3HybridBranch,
    ranked: &[RankedPoint],
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    full_request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&Filter>,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
    persistent_memory: u64,
    reverse_depth: u32,
    anchor_depths: &HashMap<String, u32>,
    ledger: &mut GraphWorkLedger,
    candidates: &mut HashMap<String, P3HybridCandidate>,
    dense_admitted: &mut Vec<RankedPoint>,
    sparse_admitted: &mut Vec<RankedPoint>,
    reachability_decisions: &mut usize,
    target_probes: &mut usize,
) -> Result<bool> {
    for candidate in ranked {
        check_execution_budget(cancelled, started, budget)?;
        if !candidates.contains_key(&candidate.id) {
            *reachability_decisions = reachability_decisions.saturating_add(1);
            let decision = p3h_candidate_reachability_locked(
                collection,
                visibility,
                &candidate.id,
                full_request,
                statement_filter,
                scope,
                enforcement,
                cancelled,
                started,
                budget,
                persistent_memory,
                reverse_depth,
                anchor_depths,
                ledger,
                target_probes,
            )?;
            if decision == P3ReachabilityDecision::ExactFallback {
                return Ok(true);
            }
            candidates.insert(
                candidate.id.clone(),
                P3HybridCandidate {
                    reachable: decision == P3ReachabilityDecision::Reachable,
                    dense_rank: None,
                    sparse_rank: None,
                },
            );
        }
        let state = candidates
            .get_mut(&candidate.id)
            .expect("P3H candidate inserted before branch admission");
        if !state.reachable {
            continue;
        }
        match branch {
            P3HybridBranch::Dense if state.dense_rank.is_none() => {
                let rank = dense_admitted.len().saturating_add(1);
                state.dense_rank = Some(rank);
                dense_admitted.push(RankedPoint {
                    id: candidate.id.clone(),
                    score: candidate.score,
                });
            }
            P3HybridBranch::Sparse if state.sparse_rank.is_none() => {
                let rank = sparse_admitted.len().saturating_add(1);
                state.sparse_rank = Some(rank);
                sparse_admitted.push(RankedPoint {
                    id: candidate.id.clone(),
                    score: candidate.score,
                });
            }
            P3HybridBranch::Dense | P3HybridBranch::Sparse => {}
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn p3h_candidate_reachability_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    point_id: &str,
    full_request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&Filter>,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
    persistent_memory: u64,
    reverse_depth: u32,
    anchor_depths: &HashMap<String, u32>,
    ledger: &mut GraphWorkLedger,
    target_probes: &mut usize,
) -> Result<P3ReachabilityDecision> {
    if !candidate_matches_p3_filters(
        collection,
        visibility,
        point_id,
        full_request.node_filter.as_ref(),
        statement_filter,
        scope,
        enforcement,
    )? {
        return Ok(P3ReachabilityDecision::Unreachable);
    }
    if anchor_depths
        .get(point_id)
        .is_some_and(|depth| *depth <= full_request.budget.max_depth)
    {
        return Ok(P3ReachabilityDecision::Reachable);
    }
    if reverse_depth == 0 {
        return Ok(P3ReachabilityDecision::Unreachable);
    }
    *target_probes = target_probes.saturating_add(1);
    let mut target_request = full_request.clone();
    target_request.anchors = vec![point_id.to_string()];
    target_request.direction = reverse_graph_direction(full_request.direction);
    target_request.budget = ledger.remaining(budget, started, persistent_memory)?;
    target_request.budget.max_depth = reverse_depth;
    let target_expansion = expand_constraint_locked(
        collection,
        visibility,
        &target_request,
        statement_filter,
        scope,
        enforcement,
        cancelled,
    )?;
    ledger.record(&target_expansion);
    if target_expansion.traversal.truncation.is_some() {
        return Ok(P3ReachabilityDecision::ExactFallback);
    }
    if target_expansion.nodes.iter().any(|node| {
        anchor_depths.get(&node.point_id).is_some_and(|anchor| {
            anchor.saturating_add(node.depth) <= full_request.budget.max_depth
        })
    }) {
        Ok(P3ReachabilityDecision::Reachable)
    } else {
        Ok(P3ReachabilityDecision::Unreachable)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn p3h_rrf_unseen_bound(
    candidates: &HashMap<String, P3HybridCandidate>,
    dense_admitted: usize,
    sparse_admitted: usize,
    dense_has_unseen: bool,
    sparse_has_unseen: bool,
    dense_weight: f32,
    sparse_weight: f32,
) -> f32 {
    let dense_next = if dense_has_unseen {
        rrf_contribution(dense_weight, dense_admitted.saturating_add(1))
    } else {
        0.0
    };
    let sparse_next = if sparse_has_unseen {
        rrf_contribution(sparse_weight, sparse_admitted.saturating_add(1))
    } else {
        0.0
    };
    let mut bound = dense_next + sparse_next;
    for candidate in candidates.values().filter(|candidate| candidate.reachable) {
        let dense_partial = candidate.dense_rank.is_none() && dense_has_unseen;
        let sparse_partial = candidate.sparse_rank.is_none() && sparse_has_unseen;
        if !dense_partial && !sparse_partial {
            continue;
        }
        let dense = candidate
            .dense_rank
            .map(|rank| rrf_contribution(dense_weight, rank))
            .unwrap_or(if dense_partial { dense_next } else { 0.0 });
        let sparse = candidate
            .sparse_rank
            .map(|rank| rrf_contribution(sparse_weight, rank))
            .unwrap_or(if sparse_partial { sparse_next } else { 0.0 });
        bound = bound.max(dense + sparse);
    }
    bound
}

fn rrf_contribution(weight: f32, one_based_rank: usize) -> f32 {
    weight / (60.0 + one_based_rank as f32)
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn choose_p3h_branch(
    dense_can_advance: bool,
    sparse_can_advance: bool,
    dense_depth: usize,
    sparse_depth: usize,
    dense_admitted: usize,
    sparse_admitted: usize,
    dense_weight: f32,
    sparse_weight: f32,
) -> P3HybridBranch {
    match (dense_can_advance, sparse_can_advance) {
        (true, false) => P3HybridBranch::Dense,
        (false, true) => P3HybridBranch::Sparse,
        (false, false) => unreachable!("P3H branch choice requires an advanceable cursor"),
        (true, true) => {
            let dense_bound = rrf_contribution(dense_weight, dense_admitted.saturating_add(1));
            let sparse_bound = rrf_contribution(sparse_weight, sparse_admitted.saturating_add(1));
            match dense_bound.total_cmp(&sparse_bound) {
                Ordering::Greater => P3HybridBranch::Dense,
                Ordering::Less => P3HybridBranch::Sparse,
                Ordering::Equal if sparse_depth < dense_depth => P3HybridBranch::Sparse,
                Ordering::Equal => P3HybridBranch::Dense,
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn next_p3h_window(
    current_target: usize,
    current_depth: usize,
    policy: P3ProgressivePolicy,
    cap: usize,
) -> usize {
    let base = current_target.max(current_depth).max(1);
    let grown = base
        .checked_mul(policy.growth_factor)
        .unwrap_or(cap)
        .min(cap);
    grown.max(current_depth.saturating_add(1).min(cap))
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn candidate_matches_p3_filters(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    point_id: &str,
    graph_filter: Option<&Filter>,
    statement_filter: Option<&Filter>,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
) -> Result<bool> {
    let point = collection
        .resolve_in_read_state(visibility, point_id)
        .ok_or_else(|| slo_unavailable("a P3 candidate disappeared from the pinned read state"))?;
    Ok(scope.may_read_payload(enforcement, &point.payload)
        && graph_filter.is_none_or(|filter| filter.matches(&point.payload))
        && statement_filter.is_none_or(|filter| filter.matches(&point.payload)))
}

const fn reverse_graph_direction(direction: GraphDirection) -> GraphDirection {
    match direction {
        GraphDirection::Outgoing => GraphDirection::Incoming,
        GraphDirection::Incoming => GraphDirection::Outgoing,
        GraphDirection::Both => GraphDirection::Both,
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn p3_exact_fallback_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    full_request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&Filter>,
    query: &[f32],
    vector_name: Option<&str>,
    k: usize,
    with_payload: bool,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
    ledger: &mut GraphWorkLedger,
    degraded: bool,
) -> Result<SearchResponse> {
    let mut request = full_request.clone();
    request.budget = ledger.remaining(budget, started, 0)?;
    request.budget.max_depth = full_request.budget.max_depth;
    let expansion = expand_constraint_locked(
        collection,
        visibility,
        &request,
        statement_filter,
        scope,
        enforcement,
        cancelled,
    )?;
    ledger.record(&expansion);
    if let Some(reason) = expansion.traversal.truncation {
        return Err(slo_unavailable(format!(
            "P3 exact fallback exceeded its {reason:?} budget"
        )));
    }
    let (ranked, searched) = score_dense_top_k_locked(
        collection,
        visibility,
        &expansion.nodes,
        query,
        vector_name,
        k,
        cancelled,
        started,
        budget,
    )?;
    let hits = hydrate_hits_locked(
        collection,
        visibility,
        ranked,
        with_payload,
        cancelled,
        started,
        budget,
    )?;
    Ok(SearchResponse {
        hits,
        degraded,
        searched,
        elapsed_ms: started.elapsed().as_millis(),
        graph: None,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn p5_exact_fallback_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    full_request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&Filter>,
    query: &[f32],
    vector_name: Option<&str>,
    k: usize,
    with_payload: bool,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
    ledger: &mut GraphWorkLedger,
    degraded: bool,
) -> Result<SearchResponse> {
    let mut request = full_request.clone();
    request.budget = ledger.remaining_for("P5", budget, started, 0)?;
    request.budget.max_depth = full_request.budget.max_depth;
    let expansion = expand_constraint_locked(
        collection,
        visibility,
        &request,
        statement_filter,
        scope,
        enforcement,
        cancelled,
    )?;
    ledger.record(&expansion);
    if let Some(reason) = expansion.traversal.truncation {
        return Err(slo_unavailable(format!(
            "P5 exact fallback exceeded its {reason:?} budget"
        )));
    }
    let (ranked, searched) = score_dense_top_k_locked(
        collection,
        visibility,
        &expansion.nodes,
        query,
        vector_name,
        k,
        cancelled,
        started,
        budget,
    )?;
    let hits = hydrate_hits_locked(
        collection,
        visibility,
        ranked,
        with_payload,
        cancelled,
        started,
        budget,
    )?;
    Ok(SearchResponse {
        hits,
        degraded,
        searched,
        elapsed_ms: started.elapsed().as_millis(),
        graph: None,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn p3h_exact_fallback_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    full_request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&Filter>,
    dense_query: &[f32],
    vector_name: Option<&str>,
    sparse_query: &crate::model::SparseVector,
    k: usize,
    dense_weight: f32,
    sparse_weight: f32,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
    ledger: &mut GraphWorkLedger,
    degraded: bool,
) -> Result<SearchResponse> {
    let mut request = full_request.clone();
    request.budget = ledger.remaining(budget, started, 0)?;
    request.budget.max_depth = full_request.budget.max_depth;
    let expansion = expand_constraint_locked(
        collection,
        visibility,
        &request,
        statement_filter,
        scope,
        enforcement,
        cancelled,
    )?;
    ledger.record(&expansion);
    if let Some(reason) = expansion.traversal.truncation {
        return Err(slo_unavailable(format!(
            "P3H exact fallback exceeded its {reason:?} budget"
        )));
    }
    ensure_hybrid_rank_memory(expansion.nodes.len(), true, true, budget)?;
    let resolver = CollectionReadResolver {
        collection,
        state: visibility,
    };
    let admitted = expansion
        .nodes
        .iter()
        .map(|node| node.point_id.clone())
        .collect::<HashSet<_>>();
    let (dense_ranked, dense_searched) = score_dense_all_locked(
        collection,
        visibility,
        &expansion.nodes,
        dense_query,
        vector_name,
        cancelled,
        started,
        budget,
    )?;
    let sparse = sparse_search_ranked(
        &collection.sparse_index,
        &resolver,
        crate::search::SparseSearchParams {
            query: sparse_query,
            limit: admitted.len(),
            payload_candidates: Some(&admitted),
            filter: statement_filter,
            budget: Some(budget.wall_time()),
            started,
            cancelled: Some(cancelled),
        },
    );
    if sparse.degraded {
        check_execution_budget(cancelled, started, budget)?;
        return Err(slo_unavailable(
            "P3H exact sparse fallback exceeded the graph retrieval budget",
        ));
    }
    crate::observability::record_graph_fuse(
        dense_ranked.len(),
        sparse.ranked.len(),
        dense_ranked.len(),
        sparse.ranked.len(),
    );
    let ranked = fuse_rankings(
        &dense_ranked,
        &sparse.ranked,
        HybridFusion::Rrf,
        dense_weight,
        sparse_weight,
    )
    .into_iter()
    .take(k)
    .map(|point| ScoredPoint {
        id: point.id,
        score: point.score,
    })
    .collect();
    let hits = hydrate_hits_locked(
        collection, visibility, ranked, true, cancelled, started, budget,
    )?;
    Ok(SearchResponse {
        hits,
        degraded,
        searched: dense_searched.saturating_add(sparse.searched),
        elapsed_ms: started.elapsed().as_millis(),
        graph: None,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn p4_exact_hybrid_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    nodes: &[GraphTraversalNode],
    statement_filter: Option<&Filter>,
    dense_query: &[f32],
    vector_name: Option<&str>,
    sparse_query: &crate::model::SparseVector,
    k: usize,
    fusion: HybridFusion,
    dense_weight: f32,
    sparse_weight: f32,
    cancelled: &AtomicBool,
    started: Instant,
    budget: TraversalBudget,
) -> Result<(Vec<ScoredPoint>, usize)> {
    ensure_hybrid_rank_memory(nodes.len(), true, true, budget)?;
    let resolver = CollectionReadResolver {
        collection,
        state: visibility,
    };
    let admitted = nodes
        .iter()
        .map(|node| node.point_id.clone())
        .collect::<HashSet<_>>();
    let (dense_ranked, dense_searched) = score_dense_all_locked(
        collection,
        visibility,
        nodes,
        dense_query,
        vector_name,
        cancelled,
        started,
        budget,
    )?;
    let sparse = sparse_search_ranked(
        &collection.sparse_index,
        &resolver,
        crate::search::SparseSearchParams {
            query: sparse_query,
            limit: admitted.len(),
            payload_candidates: Some(&admitted),
            filter: statement_filter,
            budget: Some(budget.wall_time()),
            started,
            cancelled: Some(cancelled),
        },
    );
    if sparse.degraded {
        check_execution_budget(cancelled, started, budget)?;
        return Err(slo_unavailable(
            "P4 exact sparse fallback exceeded the graph retrieval budget",
        ));
    }
    crate::observability::record_graph_fuse(
        dense_ranked.len(),
        sparse.ranked.len(),
        dense_ranked.len(),
        sparse.ranked.len(),
    );
    let ranked = fuse_rankings(
        &dense_ranked,
        &sparse.ranked,
        fusion,
        dense_weight,
        sparse_weight,
    )
    .into_iter()
    .take(k)
    .map(|point| ScoredPoint {
        id: point.id,
        score: point.score,
    })
    .collect();
    Ok((ranked, dense_searched.saturating_add(sparse.searched)))
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_graph_ordinal_candidates(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    nodes: &[GraphTraversalNode],
    max_memory_bytes: u64,
    plan: &str,
) -> Result<GraphOrdinalCandidates> {
    const ORDINAL_BYTES: u64 = 8;
    const FALLBACK_ID_BYTES: u64 = 320;
    let mut candidates = GraphOrdinalCandidates::default();
    let mut estimated_bytes = 0_u64;
    for node in nodes {
        if !collection.contains_in_read_state(visibility, &node.point_id) {
            return Err(slo_unavailable(
                "a graph-admitted point disappeared while building the candidate bitmap",
            ));
        }
        match collection.id_index.get(&node.point_id) {
            Some(crate::searcher::SegLoc::Streamer | crate::searcher::SegLoc::Sealing) => {
                if !candidates.fallback.contains(&node.point_id) {
                    estimated_bytes = estimated_bytes.saturating_add(FALLBACK_ID_BYTES);
                    ensure_candidate_memory(estimated_bytes, max_memory_bytes, plan)?;
                    candidates.fallback.insert(node.point_id.clone());
                }
            }
            Some(crate::searcher::SegLoc::Searcher(index)) => {
                let searcher = collection.searchers.get(*index as usize).ok_or_else(|| {
                    slo_unavailable("a P2 segment location is outside the pinned read state")
                })?;
                if let Some(ordinal) = searcher.ordinal(&node.point_id) {
                    if !candidates.sealed.contains(&searcher.id, ordinal) {
                        estimated_bytes = estimated_bytes.saturating_add(ORDINAL_BYTES);
                        ensure_candidate_memory(estimated_bytes, max_memory_bytes, plan)?;
                        candidates.sealed.insert(searcher.id.clone(), ordinal);
                    }
                } else {
                    // Persisted alpha/legacy stores have no stable ordinal
                    // domain and remain on the permanent ID compatibility leg.
                    if !candidates.fallback.contains(&node.point_id) {
                        estimated_bytes = estimated_bytes.saturating_add(FALLBACK_ID_BYTES);
                        ensure_candidate_memory(estimated_bytes, max_memory_bytes, plan)?;
                        candidates.fallback.insert(node.point_id.clone());
                    }
                }
            }
            None => {
                return Err(slo_unavailable(
                    "a graph-admitted point has no pinned vector location",
                ));
            }
        }
    }
    Ok(candidates)
}

fn ensure_candidate_memory(estimated: u64, limit: u64, plan: &str) -> Result<()> {
    if estimated > limit {
        return Err(slo_unavailable(format!(
            "{plan} candidate bitmap exceeds the graph retrieval memory budget"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn score_dense_p2_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    candidates: &GraphOrdinalCandidates,
    query: &[f32],
    vector_name: Option<&str>,
    limit: usize,
    ef_search: Option<u32>,
    recall_target: Option<f32>,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<(Vec<RankedPoint>, usize)> {
    let (ranked, searched, _) = score_dense_graph_filtered_locked(
        collection,
        visibility,
        candidates,
        query,
        vector_name,
        limit,
        ef_search,
        recall_target,
        GraphNavigationMode::AdmittedOnly,
        cancelled,
        started,
        budget,
    )?;
    Ok((ranked, searched))
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
fn score_dense_p4_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    candidates: &GraphOrdinalCandidates,
    query: &[f32],
    vector_name: Option<&str>,
    limit: usize,
    ef_search: Option<u32>,
    recall_target: Option<f32>,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<(Vec<RankedPoint>, usize, usize)> {
    score_dense_graph_filtered_locked(
        collection,
        visibility,
        candidates,
        query,
        vector_name,
        limit,
        ef_search,
        recall_target,
        GraphNavigationMode::LiveSteppingStones,
        cancelled,
        started,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn score_dense_graph_filtered_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    candidates: &GraphOrdinalCandidates,
    query: &[f32],
    vector_name: Option<&str>,
    limit: usize,
    ef_search: Option<u32>,
    recall_target: Option<f32>,
    navigation: GraphNavigationMode,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<(Vec<RankedPoint>, usize, usize)> {
    if collection.global_backend().is_some() {
        return Err(slo_unavailable(
            "graph-aware ordinal filtering requires the segmented LS-VEC backend",
        ));
    }
    if limit == 0 || candidates.len() == 0 {
        return Ok((Vec::new(), 0, 0));
    }
    let resolved_recall_target = recall_target
        .or(collection.config.recall_sla)
        .unwrap_or(crate::h2qg::DEFAULT_RECALL_TARGET);
    let resolved_ef_search = ef_search
        .or(collection.config.hnsw_ef_search)
        .map(|ef| (ef as usize).max(limit))
        .or_else(|| {
            let ef = collection
                .recall_curve
                .as_ref()
                .and_then(|curve| super::ef_search_from_curve(curve, resolved_recall_target))
                .unwrap_or_else(|| {
                    crate::h2qg::ef_search_for_recall_target(
                        limit,
                        resolved_recall_target,
                        collection.live_points(),
                        collection.config.vector_dim,
                    )
                });
            Some(ef)
        });
    let telemetry = GraphNavigationTelemetry::default();
    let string_filter = GraphStringFilter {
        candidates,
        collection,
        navigation,
        telemetry: &telemetry,
    };
    let ordinal_filter = GraphOrdinalFilter {
        candidates: &candidates.sealed,
        navigation,
        telemetry: &telemetry,
    };
    let resolver = CollectionReadResolver {
        collection,
        state: visibility,
    };
    let dense_candidates = crate::search::fan_out_candidates(
        None,
        &collection.streamer,
        collection.sealing.as_deref(),
        &collection.searchers,
        visibility,
        &resolver,
        collection.live_points(),
        query,
        limit,
        vector_name,
        resolved_ef_search,
        resolved_recall_target,
        Some(&string_filter),
        Some(&ordinal_filter),
        Some(cancelled),
    );
    check_execution_budget(cancelled, started, budget)?;

    let mut ranked = Vec::with_capacity(dense_candidates.len().min(limit));
    for point in dense_candidates {
        check_execution_budget(cancelled, started, budget)?;
        if !candidates.contains(collection, &point.id) {
            continue;
        }
        let Some(vector) = point_vector(&point, vector_name) else {
            continue;
        };
        ranked.push(RankedPoint {
            id: point.id.clone(),
            score: collection.config.metric.score(query, vector)?,
        });
    }
    let searched = ranked.len();
    ranked.sort_by(rank_order);
    ranked.truncate(limit);
    Ok((
        ranked,
        searched,
        telemetry.non_admitted_checks.load(AtomicOrdering::Relaxed),
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
fn p2_candidate_memory_limit(
    admitted: usize,
    branch_limit: usize,
    branches: usize,
    sparse_ids: bool,
    budget: crate::graph::TraversalBudget,
) -> Result<u64> {
    filtered_candidate_memory_limit("P2", admitted, branch_limit, branches, sparse_ids, budget)
}

#[cfg_attr(not(test), allow(dead_code))]
fn p4_candidate_memory_limit(
    admitted: usize,
    branch_limit: usize,
    branches: usize,
    sparse_ids: bool,
    budget: crate::graph::TraversalBudget,
) -> Result<u64> {
    filtered_candidate_memory_limit("P4", admitted, branch_limit, branches, sparse_ids, budget)
}

fn filtered_candidate_memory_limit(
    plan: &str,
    admitted: usize,
    branch_limit: usize,
    branches: usize,
    sparse_ids: bool,
    budget: crate::graph::TraversalBudget,
) -> Result<u64> {
    const FALLBACK_ID_BYTES: u64 = 320;
    let admitted = u64::try_from(admitted).unwrap_or(u64::MAX);
    let expansion_bytes = admitted.saturating_mul(RANKED_POINT_BUDGET_BYTES);
    let sparse_bytes = if sparse_ids {
        admitted.saturating_mul(FALLBACK_ID_BYTES)
    } else {
        0
    };
    let rank_copies = u64::try_from(branches.saturating_add(2)).unwrap_or(u64::MAX);
    let rank_bytes = u64::try_from(branch_limit)
        .unwrap_or(u64::MAX)
        .saturating_mul(rank_copies)
        .saturating_mul(RANKED_POINT_BUDGET_BYTES);
    let reserved = expansion_bytes
        .saturating_add(sparse_bytes)
        .saturating_add(rank_bytes);
    let Some(remaining) = budget.max_memory_bytes.checked_sub(reserved) else {
        return Err(slo_unavailable(format!(
            "{plan} candidate and ranking state exceeds the graph retrieval memory budget"
        )));
    };
    Ok(remaining)
}

#[allow(clippy::too_many_arguments)]
fn score_dense_top_k_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    nodes: &[GraphTraversalNode],
    query: &[f32],
    vector_name: Option<&str>,
    k: usize,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<(Vec<ScoredPoint>, usize)> {
    let mut top = BinaryHeap::with_capacity(k.saturating_add(1));
    let mut searched = 0_usize;
    for node in nodes {
        check_execution_budget(cancelled, started, budget)?;
        let point = resolve_admitted_point(collection, visibility, &node.point_id)?;
        let Some(vector) = point_vector(&point, vector_name) else {
            continue;
        };
        let scored = ScoredPoint {
            id: point.id.clone(),
            score: collection.config.metric.score(query, vector)?,
        };
        searched += 1;
        if top.len() < k {
            top.push(scored);
        } else if top
            .peek()
            .is_some_and(|worst| ranked_before(&scored, worst))
        {
            top.pop();
            top.push(scored);
        }
    }
    let mut ranked = top.into_vec();
    ranked.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok((ranked, searched))
}

#[allow(clippy::too_many_arguments)]
fn score_dense_all_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    nodes: &[GraphTraversalNode],
    query: &[f32],
    vector_name: Option<&str>,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<(Vec<RankedPoint>, usize)> {
    let mut ranked = Vec::with_capacity(nodes.len());
    for node in nodes {
        check_execution_budget(cancelled, started, budget)?;
        let point = resolve_admitted_point(collection, visibility, &node.point_id)?;
        let Some(vector) = point_vector(&point, vector_name) else {
            continue;
        };
        ranked.push(RankedPoint {
            id: point.id.clone(),
            score: collection.config.metric.score(query, vector)?,
        });
    }
    ranked.sort_by(rank_order);
    let searched = ranked.len();
    Ok((ranked, searched))
}

fn hydrate_hits_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    ranked: Vec<ScoredPoint>,
    with_payload: bool,
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<Vec<SearchHit>> {
    let mut hits = Vec::with_capacity(ranked.len());
    for ranked in ranked {
        check_execution_budget(cancelled, started, budget)?;
        let point = collection
            .resolve_in_read_state(visibility, &ranked.id)
            .ok_or_else(|| {
                slo_unavailable("a ranked point disappeared from the pinned read state")
            })?;
        hits.push(SearchHit {
            id: ranked.id,
            score: ranked.score,
            payload: if with_payload {
                point.payload.clone()
            } else {
                Value::Null
            },
        });
    }
    Ok(hits)
}

fn resolve_admitted_point<'a>(
    collection: &'a Collection,
    visibility: &crate::overlay::OverlayReadState,
    point_id: &str,
) -> Result<std::borrow::Cow<'a, crate::model::Point>> {
    collection
        .resolve_in_read_state(visibility, point_id)
        .ok_or_else(|| {
            slo_unavailable("a graph-admitted point disappeared from the pinned read state")
        })
}

fn ensure_hybrid_rank_memory(
    admitted: usize,
    dense: bool,
    sparse: bool,
    budget: crate::graph::TraversalBudget,
) -> Result<()> {
    let branches = u64::from(dense) + u64::from(sparse);
    // Expansion nodes, admitted-set keys, per-branch rankings, fused ranking,
    // and final hit hydration coexist while the read state stays pinned.
    let copies = branches.saturating_add(4);
    let estimated = u64::try_from(admitted)
        .unwrap_or(u64::MAX)
        .saturating_mul(copies)
        .saturating_mul(RANKED_POINT_BUDGET_BYTES);
    if estimated > budget.max_memory_bytes {
        return Err(slo_unavailable(
            "exact fused ranking exceeds the graph retrieval memory budget",
        ));
    }
    Ok(())
}

pub(super) fn expand_constraint_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    request: &crate::graph::GraphTraverseRequest,
    statement_filter: Option<&crate::Filter>,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
) -> Result<PinnedGraphExpansion> {
    let expansion = run_traversal_locked(
        collection,
        visibility,
        request,
        scope,
        enforcement,
        cancelled,
        TraversalRunOptions {
            statement_filter,
            capture: TraversalCapture::Nodes,
        },
    )?;
    let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
        GaussError::InvalidRequest(
            "enabled graph lifecycle has no point incarnation resolver".to_string(),
        )
    })?;
    let internal_edges_examined = expansion.execution.internal_edges_examined;
    let raw = expansion.execution.result;
    crate::observability::observe_graph_traversal(&raw.stats, raw.truncation);

    let mut nodes = raw
        .visits
        .iter()
        .filter_map(|visit| {
            resolver
                .live_point_id(visit.nid)
                .map(|point_id| GraphTraversalNode {
                    point_id: point_id.to_string(),
                    depth: visit.depth,
                })
        })
        .collect::<Vec<_>>();
    if raw.truncation.is_none() && request.budget.max_depth == 0 {
        nodes.extend(
            expansion
                .unassigned_depth_zero
                .into_iter()
                .map(|point_id| GraphTraversalNode { point_id, depth: 0 }),
        );
    }

    Ok(PinnedGraphExpansion {
        nodes,
        traversal: raw,
        graph_epoch: expansion.graph_epoch,
        backfill_pending: expansion.backfill_pending,
        internal_edges_examined,
    })
}

pub(super) fn traverse_query_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    request: &GraphTraversalQueryRequest,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    database_id: uuid::Uuid,
) -> Result<GraphTraversalQueryResult> {
    let capture = match request.returns {
        GraphTraversalReturn::Nodes => TraversalCapture::Nodes,
        GraphTraversalReturn::Edges => TraversalCapture::Edges,
        GraphTraversalReturn::Paths => TraversalCapture::Paths {
            limit: if request.traversal.budget.max_depth == 0 {
                usize::MAX
            } else {
                request.limit.ok_or_else(|| {
                    GaussError::InvalidRequest(
                        "graph path traversal requires an explicit limit".to_string(),
                    )
                })?
            },
        },
    };
    let expansion = run_traversal_locked(
        collection,
        visibility,
        &request.traversal,
        scope,
        enforcement,
        cancelled,
        TraversalRunOptions {
            statement_filter: None,
            capture,
        },
    )?;
    let mutable = active_mutable_graph(collection)?;
    let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
        GaussError::InvalidRequest(
            "enabled graph lifecycle has no point incarnation resolver".to_string(),
        )
    })?;
    let mut truncation = expansion.execution.result.truncation;
    let mut warnings = Vec::new();
    if truncation.is_some() {
        warnings.push(GraphWarning::ResultTruncated);
    }
    if expansion.backfill_pending {
        warnings.push(GraphWarning::HandleBackfillInProgress);
    }

    let result = match request.returns {
        GraphTraversalReturn::Nodes => {
            let mut rows = expansion
                .execution
                .result
                .visits
                .iter()
                .filter_map(|visit| {
                    resolver.live_point_id(visit.nid).map(|point_id| {
                        graph_node_row(
                            collection,
                            visibility,
                            point_id,
                            visit.depth,
                            request.with_payload,
                        )
                    })
                })
                .collect::<Vec<_>>();
            if truncation.is_none() && request.traversal.budget.max_depth == 0 {
                rows.extend(expansion.unassigned_depth_zero.iter().map(|point_id| {
                    graph_node_row(collection, visibility, point_id, 0, request.with_payload)
                }));
            }
            apply_row_limit(&mut rows, request.limit, &mut truncation, &mut warnings);
            GraphTraversalRows::Nodes(rows)
        }
        GraphTraversalReturn::Edges => {
            let mut rows = expansion
                .execution
                .edges
                .iter()
                .map(|edge| {
                    graph_edge_row(
                        collection,
                        visibility,
                        mutable,
                        resolver,
                        *edge,
                        request.with_payload,
                        database_id,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            apply_row_limit(&mut rows, request.limit, &mut truncation, &mut warnings);
            GraphTraversalRows::Edges(rows)
        }
        GraphTraversalReturn::Paths => {
            let mut rows = expansion
                .execution
                .paths
                .iter()
                .map(|path| {
                    let nodes = path
                        .nodes
                        .iter()
                        .enumerate()
                        .map(|(depth, nid)| {
                            let point_id = resolver.live_point_id(*nid).ok_or_else(|| {
                                GaussError::InvalidRequest(
                                    "live graph path endpoint disappeared from the pinned state"
                                        .to_string(),
                                )
                            })?;
                            Ok(graph_node_row(
                                collection,
                                visibility,
                                point_id,
                                depth as u32,
                                request.with_payload,
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let edges = path
                        .edges
                        .iter()
                        .map(|edge| {
                            graph_edge_row(
                                collection,
                                visibility,
                                mutable,
                                resolver,
                                *edge,
                                request.with_payload,
                                database_id,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(GraphTraversalPathRow { nodes, edges })
                })
                .collect::<Result<Vec<_>>>()?;
            if truncation.is_none() && request.traversal.budget.max_depth == 0 {
                rows.extend(expansion.unassigned_depth_zero.iter().map(|point_id| {
                    GraphTraversalPathRow {
                        nodes: vec![graph_node_row(
                            collection,
                            visibility,
                            point_id,
                            0,
                            request.with_payload,
                        )],
                        edges: Vec::new(),
                    }
                }));
            }
            apply_row_limit(&mut rows, request.limit, &mut truncation, &mut warnings);
            GraphTraversalRows::Paths(rows)
        }
    };

    crate::observability::observe_graph_traversal(&expansion.execution.result.stats, truncation);
    Ok(GraphTraversalQueryResult {
        result,
        stats: expansion.execution.result.stats,
        truncation,
        warnings,
        graph_epoch: expansion.graph_epoch,
    })
}

fn run_traversal_locked(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    request: &crate::graph::GraphTraverseRequest,
    scope: &crate::tenant::TenantScope,
    enforcement: crate::tenant::TenantEnforcement,
    cancelled: &AtomicBool,
    options: TraversalRunOptions<'_>,
) -> Result<RawPinnedGraphExpansion> {
    let TraversalRunOptions {
        statement_filter,
        capture,
    } = options;
    let mutable = active_mutable_graph(collection)?;
    let resolver = collection.graph_resolver.as_ref().ok_or_else(|| {
        GaussError::InvalidRequest(
            "enabled graph lifecycle has no point incarnation resolver".to_string(),
        )
    })?;
    let graph_epoch = mutable.epoch();
    let backfill_pending = collection.graph_backfill_pending();

    let selected_types = if request.edge_types.is_empty() {
        None
    } else {
        Some(
            request
                .edge_types
                .iter()
                .map(|name| {
                    mutable.types().resolve_name(name).ok_or_else(|| {
                        GraphError::new(
                            GraphErrorCode::TypeNotFound,
                            "one or more requested edge types are not configured",
                        )
                        .into()
                    })
                })
                .collect::<Result<HashSet<_>>>()?,
        )
    };

    let mut seen_anchors = HashSet::with_capacity(request.anchors.len());
    let mut assigned_anchors = Vec::with_capacity(request.anchors.len());
    let mut unassigned_depth_zero = Vec::new();
    for point_id in &request.anchors {
        if !seen_anchors.insert(point_id.clone()) {
            continue;
        }
        let point = collection
            .resolve_in_read_state(visibility, point_id)
            .filter(|point| scope.may_read_payload(enforcement, &point.payload))
            .ok_or_else(endpoint_not_found)?;
        match resolver.live_nid(point_id) {
            Some(nid) => assigned_anchors.push(nid),
            None if request.budget.max_depth == 0
                && request
                    .node_filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(&point.payload))
                && statement_filter.is_none_or(|filter| filter.matches(&point.payload)) =>
            {
                unassigned_depth_zero.push(point_id.clone());
            }
            None => {}
        }
    }

    let include_admin = scope.is_system() || scope.can_cross_read();
    let graph = RetrievalTraversalGraph {
        graph: mutable,
        collection,
        resolver,
    };
    let traversal = crate::graph_traversal::MutableTraversal {
        graph: &graph,
        anchors: assigned_anchors,
        visible_anchor_count: seen_anchors.len() as u64,
        selected_types,
        direction: request.direction,
        node_filter: request.node_filter.as_ref(),
        statement_filter,
        edge_filter: request.edge_filter.as_ref(),
        budget: request.budget,
        cancelled,
        payload_for_nid: |nid| {
            resolver
                .live_point_id(nid)
                .and_then(|point_id| collection.resolve_in_read_state(visibility, point_id))
                .filter(|point| scope.may_read_payload(enforcement, &point.payload))
                .map(|point| point.payload.clone())
        },
        namespaces_for_payload: |payload| {
            let tenant = payload
                .get(crate::tenant::TENANT_FIELD)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(DEFAULT_GRAPH_NAMESPACE);
            let mut namespaces = vec![GraphNamespace::Tenant(tenant.to_string())];
            if include_admin {
                namespaces.push(GraphNamespace::AdminCrossTenant);
            }
            namespaces
        },
    };
    let execution = match capture {
        TraversalCapture::Nodes => crate::graph_traversal::exact_bfs(traversal)?,
        TraversalCapture::Edges => crate::graph_traversal::exact_bfs_with_edges(traversal)?,
        TraversalCapture::Paths { limit } => {
            crate::graph_traversal::exact_simple_paths(traversal, limit)?
        }
    };
    unassigned_depth_zero.sort_unstable();
    Ok(RawPinnedGraphExpansion {
        execution,
        graph_epoch,
        backfill_pending,
        unassigned_depth_zero,
    })
}

fn graph_node_row(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    point_id: &str,
    depth: u32,
    with_payload: bool,
) -> GraphTraversalNodeRow {
    GraphTraversalNodeRow {
        id: point_id.to_string(),
        depth,
        payload: with_payload
            .then(|| {
                collection
                    .resolve_in_read_state(visibility, point_id)
                    .map(|point| point.payload.clone())
            })
            .flatten(),
    }
}

fn graph_edge_row(
    collection: &Collection,
    visibility: &crate::overlay::OverlayReadState,
    mutable: &crate::mutable_graph::MutableGraphState,
    resolver: &crate::graph_resolver::PointIncarnationResolver,
    edge: crate::graph_traversal::TraversalEdgeVisit,
    with_payload: bool,
    database_id: uuid::Uuid,
) -> Result<GraphTraversalEdgeRow> {
    let source = resolver.live_point_id(edge.source).ok_or_else(|| {
        GaussError::InvalidRequest(
            "live graph edge source disappeared from the pinned state".to_string(),
        )
    })?;
    let target = resolver.live_point_id(edge.target).ok_or_else(|| {
        GaussError::InvalidRequest(
            "live graph edge target disappeared from the pinned state".to_string(),
        )
    })?;
    if collection
        .resolve_in_read_state(visibility, source)
        .is_none()
        || collection
            .resolve_in_read_state(visibility, target)
            .is_none()
    {
        return Err(GaussError::InvalidRequest(
            "live graph edge endpoint disappeared from the pinned state".to_string(),
        ));
    }
    let edge_type = mutable
        .types()
        .get(edge.type_id)
        .ok_or_else(|| {
            GaussError::InvalidRequest("live graph edge has an unknown type id".to_string())
        })?
        .name
        .clone();
    let properties = if with_payload {
        Some(
            mutable
                .edge_properties(edge.edge_id)?
                .ok_or_else(|| {
                    GaussError::InvalidRequest("live graph edge has no properties".to_string())
                })?
                .into_owned(),
        )
    } else {
        None
    };
    Ok(GraphTraversalEdgeRow {
        id: crate::edge_token::encode(database_id, edge.edge_id)?,
        source: source.to_string(),
        target: target.to_string(),
        edge_type,
        properties,
    })
}

fn apply_row_limit<T>(
    rows: &mut Vec<T>,
    limit: Option<usize>,
    truncation: &mut Option<crate::graph::TraversalTruncationReason>,
    warnings: &mut Vec<GraphWarning>,
) {
    let Some(limit) = limit else {
        return;
    };
    if rows.len() <= limit {
        return;
    }
    rows.truncate(limit);
    if truncation.is_none() {
        *truncation = Some(crate::graph::TraversalTruncationReason::Limit);
    }
    if !warnings.contains(&GraphWarning::ResultTruncated) {
        warnings.push(GraphWarning::ResultTruncated);
    }
}

fn ranked_before(left: &ScoredPoint, right: &ScoredPoint) -> bool {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.id.cmp(&right.id))
        == Ordering::Less
}

fn check_execution_budget(
    cancelled: &AtomicBool,
    started: Instant,
    budget: crate::graph::TraversalBudget,
) -> Result<()> {
    if cancelled.load(AtomicOrdering::Acquire) {
        return Err(
            GraphError::new(GraphErrorCode::Cancelled, "graph retrieval was cancelled").into(),
        );
    }
    if started.elapsed() >= budget.wall_time() {
        return Err(slo_unavailable(
            "exact graph retrieval exceeded its wall-time budget",
        ));
    }
    Ok(())
}

fn slo_unavailable(message: impl Into<String>) -> GaussError {
    GraphError::new(GraphErrorCode::SloUnavailable, message).into()
}

fn endpoint_not_found() -> GaussError {
    GraphError::new(
        GraphErrorCode::EndpointNotFound,
        "one or more graph endpoints are unavailable",
    )
    .into()
}

#[cfg(test)]
mod p2_filter_tests {
    use super::*;
    use crate::index::OrdinalFilterPredicate;

    #[test]
    fn p2_rejected_ordinals_are_not_navigation_bridges() {
        let mut admitted = SegmentOrdinalSet::new();
        admitted.insert("segment", 7);
        let telemetry = GraphNavigationTelemetry::default();
        let predicate = GraphOrdinalFilter {
            candidates: &admitted,
            navigation: GraphNavigationMode::AdmittedOnly,
            telemetry: &telemetry,
        };
        assert!(predicate.matches_ordinal("segment", 7));
        assert!(predicate.navigable_ordinal("segment", 7));
        assert!(!predicate.matches_ordinal("segment", 8));
        assert!(!predicate.navigable_ordinal("segment", 8));
        assert_eq!(
            telemetry.non_admitted_checks.load(AtomicOrdering::Relaxed),
            0
        );
    }

    #[test]
    fn p4_rejected_ordinals_remain_navigation_stepping_stones() {
        let mut admitted = SegmentOrdinalSet::new();
        admitted.insert("segment", 7);
        let telemetry = GraphNavigationTelemetry::default();
        let predicate = GraphOrdinalFilter {
            candidates: &admitted,
            navigation: GraphNavigationMode::LiveSteppingStones,
            telemetry: &telemetry,
        };
        assert!(predicate.matches_ordinal("segment", 7));
        assert!(predicate.navigable_ordinal("segment", 7));
        assert!(!predicate.matches_ordinal("segment", 8));
        assert!(predicate.navigable_ordinal("segment", 8));
        assert_eq!(
            telemetry.non_admitted_checks.load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[test]
    fn p3h_rrf_bound_covers_partial_and_wholly_unseen_candidates() {
        let candidates = HashMap::from([
            (
                "partial".to_string(),
                P3HybridCandidate {
                    reachable: true,
                    dense_rank: Some(1),
                    sparse_rank: None,
                },
            ),
            (
                "complete".to_string(),
                P3HybridCandidate {
                    reachable: true,
                    dense_rank: Some(2),
                    sparse_rank: Some(1),
                },
            ),
            (
                "rejected".to_string(),
                P3HybridCandidate {
                    reachable: false,
                    dense_rank: Some(3),
                    sparse_rank: None,
                },
            ),
        ]);
        let bound = p3h_rrf_unseen_bound(&candidates, 3, 1, true, true, 1.0, 1.0);
        let expected_partial = rrf_contribution(1.0, 1) + rrf_contribution(1.0, 2);
        let wholly_unseen = rrf_contribution(1.0, 4) + rrf_contribution(1.0, 2);
        assert!(expected_partial > wholly_unseen);
        assert_eq!(bound, expected_partial);

        let dense_only_bound = p3h_rrf_unseen_bound(&candidates, 3, 1, true, false, 1.0, 1.0);
        assert_eq!(dense_only_bound, rrf_contribution(1.0, 4));
    }
}
