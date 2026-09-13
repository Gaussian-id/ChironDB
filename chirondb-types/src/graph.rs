use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::filter::Filter;

pub const GRAPH_ALLOCATOR_EPOCH_BITS: u32 = 24;
pub const GRAPH_ALLOCATOR_COUNTER_BITS: u32 = 40;
pub const GRAPH_ALLOCATOR_MAX_EPOCH: u32 = (1 << GRAPH_ALLOCATOR_EPOCH_BITS) - 1;
pub const GRAPH_ALLOCATOR_MAX_COUNTER: u64 = (1 << GRAPH_ALLOCATOR_COUNTER_BITS) - 1;

pub const MAX_GRAPH_ANCHORS: usize = 128;
pub const MAX_GRAPH_TYPES_PER_CLAUSE: usize = 64;
pub const MAX_GRAPH_EDGES_PER_BATCH: usize = 4_096;
pub const MAX_GRAPH_DEPTH: u32 = 16;
pub const MAX_GRAPH_CATALOG_NAME_BYTES: usize = 255;
pub const MAX_EDGE_PROPERTY_BYTES: usize = 64 * 1024;
pub const MAX_GRAPH_BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Nid(u64);

impl Nid {
    pub const UNASSIGNED: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn from_parts(epoch: u32, counter: u64) -> Option<Self> {
        if epoch == 0
            || epoch > GRAPH_ALLOCATOR_MAX_EPOCH
            || counter == 0
            || counter > GRAPH_ALLOCATOR_MAX_COUNTER
        {
            return None;
        }
        Some(Self(
            ((epoch as u64) << GRAPH_ALLOCATOR_COUNTER_BITS) | counter,
        ))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn epoch(self) -> u32 {
        (self.0 >> GRAPH_ALLOCATOR_COUNTER_BITS) as u32
    }

    pub const fn counter(self) -> u64 {
        self.0 & GRAPH_ALLOCATOR_MAX_COUNTER
    }

    pub const fn is_assigned(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EdgeId(u64);

impl EdgeId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn from_parts(epoch: u32, counter: u64) -> Option<Self> {
        if epoch == 0
            || epoch > GRAPH_ALLOCATOR_MAX_EPOCH
            || counter == 0
            || counter > GRAPH_ALLOCATOR_MAX_COUNTER
        {
            return None;
        }
        Some(Self(
            ((epoch as u64) << GRAPH_ALLOCATOR_COUNTER_BITS) | counter,
        ))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn epoch(self) -> u32 {
        (self.0 >> GRAPH_ALLOCATOR_COUNTER_BITS) as u32
    }

    pub const fn counter(self) -> u64 {
        self.0 & GRAPH_ALLOCATOR_MAX_COUNTER
    }
}

/// Public, opaque representation of one stable edge identity.
///
/// Clients may store and return this token but must not parse, sort, or infer
/// topology from it. The core validates its version, database incarnation,
/// internal identity, and checksum at every boundary.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EdgeToken(String);

impl EdgeToken {
    pub fn from_encoded(encoded: impl Into<String>) -> Self {
        Self(encoded.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_encoded(self) -> String {
        self.0
    }
}

impl fmt::Display for EdgeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Explicit topology permission. Point roles never imply one of these grants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum GraphCapability {
    #[serde(rename = "graph:read")]
    Read,
    #[serde(rename = "graph:write")]
    Write,
    #[serde(rename = "graph:admin")]
    Admin,
    #[serde(rename = "graph:type_configure")]
    TypeConfigure,
}

impl GraphCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "graph:read",
            Self::Write => "graph:write",
            Self::Admin => "graph:admin",
            Self::TypeConfigure => "graph:type_configure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "graph:read" => Some(Self::Read),
            "graph:write" => Some(Self::Write),
            "graph:admin" => Some(Self::Admin),
            "graph:type_configure" => Some(Self::TypeConfigure),
            _ => None,
        }
    }
}

impl fmt::Display for GraphCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Public relation namespace choice. Tenant names are always derived from
/// authenticated point ownership and are never accepted from a request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphRelationScope {
    #[default]
    Local,
    AdminCrossTenant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphEdgeType {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_property: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigureEdgeTypeRequest {
    pub name: String,
    #[serde(default)]
    pub weight_property: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RelateRequest {
    pub source_point_id: String,
    pub target_point_id: String,
    pub edge_type: String,
    #[serde(default = "empty_property_document")]
    pub properties: Value,
    #[serde(default)]
    pub scope: GraphRelationScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UpdateEdgeRequest {
    pub mode: EdgePropertyMode,
    #[serde(default = "empty_property_document")]
    pub properties: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraverseRequest {
    pub anchors: Vec<String>,
    #[serde(default)]
    pub edge_types: Vec<String>,
    #[serde(default)]
    pub direction: GraphDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_filter: Option<Filter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_filter: Option<Filter>,
    #[serde(default)]
    pub budget: TraversalBudget,
}

/// Materialization requested by a pure graph traversal.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphTraversalReturn {
    #[default]
    Nodes,
    Edges,
    Paths,
}

/// Complete pure-traversal request shared by ChironQL and native protocols.
///
/// `LIMIT` caps returned rows; `traversal.budget` independently caps work.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraversalQueryRequest {
    #[serde(flatten)]
    pub traversal: GraphTraverseRequest,
    #[serde(default)]
    pub returns: GraphTraversalReturn,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub with_payload: bool,
}

/// Statement-level graph membership constraint shared by retrieval modes.
///
/// The constraint determines which live points may be ranked. It carries no
/// scoring fields and exposes no raw graph identities, so dense, sparse, and
/// hybrid executors can consume the same reachable set without topology
/// influencing score order.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphConstraint {
    pub anchors: Vec<String>,
    #[serde(default)]
    pub edge_types: Vec<String>,
    #[serde(default)]
    pub direction: GraphDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_filter: Option<Filter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_filter: Option<Filter>,
    #[serde(default = "default_graph_constraint_budget")]
    pub budget: TraversalBudget,
    /// Explicitly permit an advisory graph-retrieval plan whose measured
    /// recall is below the requested contract. The engine still prefers an
    /// exact or calibrated path; when this flag changes the selected plan the
    /// response is marked and the decision is durably audited.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_degraded: bool,
}

fn default_graph_constraint_budget() -> TraversalBudget {
    TraversalBudget {
        max_depth: 1,
        ..TraversalBudget::default()
    }
}

impl From<GraphConstraint> for GraphTraverseRequest {
    fn from(constraint: GraphConstraint) -> Self {
        Self {
            anchors: constraint.anchors,
            edge_types: constraint.edge_types,
            direction: constraint.direction,
            node_filter: constraint.node_filter,
            edge_filter: constraint.edge_filter,
            budget: constraint.budget,
        }
    }
}

impl From<GraphTraverseRequest> for GraphConstraint {
    fn from(request: GraphTraverseRequest) -> Self {
        Self {
            anchors: request.anchors,
            edge_types: request.edge_types,
            direction: request.direction,
            node_filter: request.node_filter,
            edge_filter: request.edge_filter,
            budget: request.budget,
            allow_degraded: false,
        }
    }
}

/// Dense P1 retrieval over the exact reachable set of one graph constraint.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExactGraphSearchRequest {
    pub vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector_name: Option<String>,
    #[serde(default = "default_graph_search_k")]
    pub k: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
    pub graph: GraphConstraint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_payload: Option<bool>,
}

fn default_graph_search_k() -> usize {
    10
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GraphRetrievalPlan {
    #[serde(rename = "p1_exact")]
    P1Exact,
    #[serde(rename = "p2_prefiltered_cascade")]
    P2PrefilteredCascade,
    #[serde(rename = "p3_progressive_probe")]
    P3ProgressiveProbe,
    #[serde(rename = "p3h_joint_widening")]
    P3HybridJointWidening,
    #[serde(rename = "p4_reachability_aware_beam")]
    P4ReachabilityAwareBeam,
    #[serde(rename = "p5_best_first")]
    P5BestFirst,
}

impl GraphRetrievalPlan {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P1Exact => "p1_exact",
            Self::P2PrefilteredCascade => "p2_prefiltered_cascade",
            Self::P3ProgressiveProbe => "p3_progressive_probe",
            Self::P3HybridJointWidening => "p3h_joint_widening",
            Self::P4ReachabilityAwareBeam => "p4_reachability_aware_beam",
            Self::P5BestFirst => "p5_best_first",
        }
    }
}

/// Estimator actually used for one graph-constrained retrieval statement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEstimatorKind {
    Default,
    ProbeExpansion,
    Sketch,
}

/// Stable low-cardinality reason that constrained planner selection stopped
/// at a guard rather than using only relative modelled cost.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphPlanGuard {
    WeightedUncontracted,
    DepthZero,
    BackfillInProgress,
    EmptyCollection,
    CalibrationMissing,
    RecallTargetMissing,
    CalibrationProfileMiss,
    ProbeBudgetInsufficient,
    CalibrationEnvelopeMiss,
    ProbeAmbiguous,
    SpecificityFloor,
    BestFirstThreshold,
    SloIneligible,
    ModeIncompatible,
}

impl GraphPlanGuard {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeightedUncontracted => "weighted_uncontracted",
            Self::DepthZero => "depth_zero",
            Self::BackfillInProgress => "backfill_in_progress",
            Self::EmptyCollection => "empty_collection",
            Self::CalibrationMissing => "calibration_missing",
            Self::RecallTargetMissing => "recall_target_missing",
            Self::CalibrationProfileMiss => "calibration_profile_miss",
            Self::ProbeBudgetInsufficient => "probe_budget_insufficient",
            Self::CalibrationEnvelopeMiss => "calibration_envelope_miss",
            Self::ProbeAmbiguous => "probe_ambiguous",
            Self::SpecificityFloor => "specificity_floor",
            Self::BestFirstThreshold => "best_first_threshold",
            Self::SloIneligible => "slo_ineligible",
            Self::ModeIncompatible => "mode_incompatible",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphSpecificityInterval {
    pub min_bps: u16,
    pub max_bps: u16,
}

/// Integer work units from one matching calibration profile. These are
/// relative planner inputs, never wall-clock promises. They are omitted for a
/// tenant-scoped caller because global collection work can disclose hidden
/// population size.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphPlanCostTrace {
    pub p1: u64,
    pub p2: u64,
    pub p3: u64,
    pub p3h: u64,
    pub p4: u64,
    pub p5: u64,
}

/// Authorized facts observed by the bounded planner probe. All counters are
/// post-tenant-filter and therefore match the response visibility boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphProbeTrace {
    pub hops_completed: u32,
    pub nodes_visited: u64,
    pub edges_examined: u64,
    pub cold_fragments_read: u64,
    pub cold_bytes_read: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<TraversalTruncationReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphEstimateTrace {
    pub estimator: GraphEstimatorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specificity: Option<GraphSpecificityInterval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_lsn_lag: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<GraphProbeTrace>,
    pub elapsed_us: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphPlanTrace {
    pub chosen: GraphRetrievalPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<GraphPlanGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modelled_costs: Option<GraphPlanCostTrace>,
    pub degraded: bool,
    pub exact_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dense_branch_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse_branch_depth: Option<u64>,
    pub elapsed_us: u64,
}

/// Authorized runtime work for the graph-membership stage. Counts are
/// accumulated only after tenant/statement visibility has been established;
/// internal physical-work counters remain private to budget enforcement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphExpandTrace {
    pub hops_completed: u32,
    pub nodes_visited: u64,
    pub edges_examined: u64,
    pub hop_local: u64,
    pub hop_global: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpha_bps: Option<u16>,
    pub supersession_followed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beta_bps: Option<u16>,
    pub fragments_read: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<TraversalTruncationReason>,
    pub cold_fragments_faulted: u64,
    pub cold_bytes_read: u64,
    pub elapsed_us: u64,
}

/// Per-branch materialization observed by one graph-constrained fused
/// statement. This is omitted for dense-only statements.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphFuseTrace {
    pub dense_admitted: u64,
    pub sparse_admitted: u64,
    pub dense_overfetch: u64,
    pub sparse_overfetch: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GraphQueryWarning {
    #[serde(rename = "graph.degraded_plan")]
    DegradedPlan,
    #[serde(rename = "graph.uncontracted_fusion")]
    UncontractedFusion,
    #[serde(rename = "graph.exact_fallback")]
    ExactFallback,
}

/// Planner evidence returned only for graph-constrained search. Protocol
/// adapters serialize the same object rather than reconstructing decisions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphDispatchTrace {
    /// Graph lifecycle epoch pinned by the executor that produced these hits.
    /// This is recorded by the common execution path, never reconstructed by
    /// a protocol adapter after the collection lock has been released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_epoch: Option<GraphEpoch>,
    pub graph_estimate: GraphEstimateTrace,
    pub graph_plan: GraphPlanTrace,
    pub graph_expand: GraphExpandTrace,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuse: Option<GraphFuseTrace>,
    #[serde(default)]
    pub warnings: Vec<GraphQueryWarning>,
}

/// Complete P1 result. Budget truncation is returned as
/// `graph.slo_unavailable`, never as a partial response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExactGraphSearchResponse {
    pub hits: Vec<crate::model::SearchHit>,
    pub searched: usize,
    pub elapsed_ms: u128,
    pub graph_epoch: GraphEpoch,
    pub traversal: TraversalStats,
    pub plan: GraphRetrievalPlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphTraversalNode {
    pub point_id: String,
    pub depth: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphTraversalResult {
    pub nodes: Vec<GraphTraversalNode>,
    pub stats: TraversalStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<TraversalTruncationReason>,
    #[serde(default)]
    pub warnings: Vec<GraphWarning>,
    pub graph_epoch: GraphEpoch,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraversalNodeRow {
    pub id: String,
    pub depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraversalEdgeRow {
    pub id: EdgeToken,
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraversalPathRow {
    pub nodes: Vec<GraphTraversalNodeRow>,
    pub edges: Vec<GraphTraversalEdgeRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", content = "rows", rename_all = "snake_case")]
pub enum GraphTraversalRows {
    Nodes(Vec<GraphTraversalNodeRow>),
    Edges(Vec<GraphTraversalEdgeRow>),
    Paths(Vec<GraphTraversalPathRow>),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GraphTraversalQueryResult {
    pub result: GraphTraversalRows,
    pub stats: TraversalStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<TraversalTruncationReason>,
    #[serde(default)]
    pub warnings: Vec<GraphWarning>,
    pub graph_epoch: GraphEpoch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphMutationReceipt {
    pub graph_epoch: GraphEpoch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_lsn: Option<u64>,
    pub durable: bool,
    #[serde(default)]
    pub replayed: bool,
}

/// Public receipt for enabling or dropping one collection's graph overlay.
///
/// Lifecycle remains an explicit administrative operation rather than graph
/// DDL. Native protocol adapters reuse this object so epoch/LSN/durability
/// semantics cannot drift by surface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphLifecycleResult {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_epoch: Option<GraphEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_lsn: Option<u64>,
    pub durable: bool,
    pub transitioned: bool,
    pub backfill_in_progress: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelateResult {
    pub edge_id: EdgeToken,
    pub receipt: GraphMutationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigureEdgeTypeResult {
    pub edge_type: GraphEdgeType,
    pub receipt: GraphMutationReceipt,
    pub changed: bool,
}

/// Public opaque identifier for one durable deferred bulk-load window.
///
/// The token is generated by the core. Clients may persist and return it but
/// must not infer graph epoch, WAL position, or endpoint identity from it.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GraphDeferredSessionId(String);

impl GraphDeferredSessionId {
    pub fn from_encoded(encoded: impl Into<String>) -> Self {
        Self(encoded.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GraphDeferredSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphDeferredSessionState {
    Open,
    Committed,
    Aborted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphDeferredSessionResult {
    pub session_id: GraphDeferredSessionId,
    pub state: GraphDeferredSessionState,
    pub receipt: GraphMutationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphDeferredUpsertResult {
    pub total_points: usize,
    pub bound_endpoints: usize,
    pub receipt: GraphMutationReceipt,
}

fn empty_property_document() -> Value {
    Value::Object(serde_json::Map::new())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TypeId(u32);

impl TypeId {
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GraphEpoch(u64);

impl GraphEpoch {
    pub const INITIAL: Self = Self(1);

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNamespace {
    Tenant(String),
    AdminCrossTenant,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphDirection {
    #[default]
    Outgoing,
    Incoming,
    Both,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgePropertyMode {
    Merge,
    Replace,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RelateMutation {
    pub edge_id: EdgeId,
    pub source: Nid,
    pub target: Nid,
    pub type_id: TypeId,
    pub namespace: GraphNamespace,
    #[serde(default)]
    pub properties: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnrelateMutation {
    pub edge_id: EdgeId,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EdgePropertyMutation {
    pub edge_id: EdgeId,
    pub mode: EdgePropertyMode,
    pub properties: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeMutation {
    Relate(RelateMutation),
    Unrelate(UnrelateMutation),
    Properties(EdgePropertyMutation),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalTruncationReason {
    Limit,
    Depth,
    Frontier,
    Visited,
    Edges,
    Time,
    Memory,
    ColdFragments,
    ColdBytes,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphWarning {
    ResultTruncated,
    ConstraintTruncated,
    Degraded,
    ExactFallback,
    HandleBackfillInProgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ColdTraversalBudget {
    pub max_fragments: u64,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraversalBudget {
    pub max_depth: u32,
    pub max_frontier: u64,
    pub max_visited: u64,
    pub max_edges: u64,
    pub max_time_ms: u64,
    pub max_memory_bytes: u64,
    /// Resolved from collection policy before execution. `None` is not an
    /// unlimited allowance and must not reach a cold-fragment reader.
    pub cold: Option<ColdTraversalBudget>,
}

impl Default for TraversalBudget {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_frontier: 1_000_000,
            max_visited: 10_000_000,
            max_edges: 100_000_000,
            max_time_ms: 5_000,
            max_memory_bytes: 512 * 1024 * 1024,
            cold: None,
        }
    }
}

impl TraversalBudget {
    pub const fn wall_time(self) -> Duration {
        Duration::from_millis(self.max_time_ms)
    }

    pub fn validate(self) -> std::result::Result<Self, GraphError> {
        if self.max_depth > MAX_GRAPH_DEPTH {
            return Err(GraphError::new(
                GraphErrorCode::DepthExceeded,
                format!(
                    "depth {} exceeds fixed maximum {MAX_GRAPH_DEPTH}",
                    self.max_depth
                ),
            ));
        }
        if self.max_frontier == 0
            || self.max_visited == 0
            || self.max_edges == 0
            || self.max_time_ms == 0
            || self.max_memory_bytes == 0
        {
            return Err(GraphError::new(
                GraphErrorCode::InvalidBudget,
                "traversal budgets must be positive",
            ));
        }
        if self
            .cold
            .is_some_and(|cold| cold.max_fragments == 0 || cold.max_bytes == 0)
        {
            return Err(GraphError::new(
                GraphErrorCode::InvalidBudget,
                "cold traversal budgets must be positive when present",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraversalStats {
    pub hops_completed: u32,
    pub nodes_visited: u64,
    pub visible_edges_examined: u64,
    #[serde(default)]
    pub hop_local: u64,
    #[serde(default)]
    pub hop_global: u64,
    #[serde(default)]
    pub supersession_followed: u64,
    #[serde(default)]
    pub fragments_read: u64,
    #[serde(default)]
    pub max_frontier_size: u64,
    pub cold_fragments_read: u64,
    pub cold_bytes_read: u64,
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraversalVisit {
    pub nid: Nid,
    pub depth: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraversalResult {
    pub visits: Vec<TraversalVisit>,
    pub stats: TraversalStats,
    pub truncation: Option<TraversalTruncationReason>,
    pub warnings: Vec<GraphWarning>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GraphErrorCode {
    #[serde(rename = "graph.not_enabled")]
    GraphDisabled,
    #[serde(rename = "graph.endpoint_not_found")]
    EndpointNotFound,
    #[serde(rename = "graph.edge_not_found")]
    EdgeNotFound,
    #[serde(rename = "graph.type_unknown")]
    TypeNotFound,
    #[serde(rename = "graph.epoch_mismatch")]
    EpochMismatch,
    #[serde(rename = "graph.too_many_anchors")]
    TooManyAnchors,
    #[serde(rename = "graph.too_many_types")]
    TooManyTypes,
    #[serde(rename = "graph.batch_too_large")]
    BatchTooLarge,
    #[serde(rename = "graph.depth_exceeded")]
    DepthExceeded,
    #[serde(rename = "graph.property_too_large")]
    PropertyTooLarge,
    #[serde(rename = "graph.batch_bytes_exceeded")]
    BatchBytesExceeded,
    #[serde(rename = "graph.invalid_budget")]
    InvalidBudget,
    #[serde(rename = "graph.overloaded")]
    Overloaded,
    #[serde(rename = "graph.cancelled")]
    Cancelled,
    #[serde(rename = "graph.slo_unavailable")]
    SloUnavailable,
    #[serde(rename = "graph.tenant_move_has_edges")]
    TenantMoveHasEdges,
    #[serde(rename = "graph.edges_exist")]
    EdgesExist,
    #[serde(rename = "graph.deferred_session_not_found")]
    DeferredSessionNotFound,
    #[serde(rename = "graph.deferred_endpoints_remain")]
    DeferredEndpointsRemain,
    #[serde(rename = "graph.allocator_exhausted")]
    AllocatorExhausted,
}

impl GraphErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GraphDisabled => "graph.not_enabled",
            Self::EndpointNotFound => "graph.endpoint_not_found",
            Self::EdgeNotFound => "graph.edge_not_found",
            Self::TypeNotFound => "graph.type_unknown",
            Self::EpochMismatch => "graph.epoch_mismatch",
            Self::TooManyAnchors => "graph.too_many_anchors",
            Self::TooManyTypes => "graph.too_many_types",
            Self::BatchTooLarge => "graph.batch_too_large",
            Self::DepthExceeded => "graph.depth_exceeded",
            Self::PropertyTooLarge => "graph.property_too_large",
            Self::BatchBytesExceeded => "graph.batch_bytes_exceeded",
            Self::InvalidBudget => "graph.invalid_budget",
            Self::Overloaded => "graph.overloaded",
            Self::Cancelled => "graph.cancelled",
            Self::SloUnavailable => "graph.slo_unavailable",
            Self::TenantMoveHasEdges => "graph.tenant_move_has_edges",
            Self::EdgesExist => "graph.edges_exist",
            Self::DeferredSessionNotFound => "graph.deferred_session_not_found",
            Self::DeferredEndpointsRemain => "graph.deferred_endpoints_remain",
            Self::AllocatorExhausted => "graph.allocator_exhausted",
        }
    }
}

impl fmt::Display for GraphErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Error, Eq, PartialEq, Serialize)]
#[error("{code}: {message}")]
pub struct GraphError {
    pub code: GraphErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl GraphError {
    pub fn new(code: GraphErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            item_index: None,
            retry_after_ms: None,
        }
    }

    pub const fn with_item_index(mut self, item_index: usize) -> Self {
        self.item_index = Some(item_index);
        self
    }

    pub const fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieval_constraint_defaults_to_one_hop_without_internal_ids() {
        let constraint: GraphConstraint = serde_json::from_value(serde_json::json!({
            "anchors": ["root"]
        }))
        .unwrap();
        assert_eq!(constraint.direction, GraphDirection::Outgoing);
        assert_eq!(constraint.budget.max_depth, 1);
        assert!(!constraint.allow_degraded);

        let encoded = serde_json::to_string(&constraint).unwrap();
        for internal in ["edge_id", "nid", "type_id"] {
            assert!(!encoded.contains(internal));
        }
        assert!(!encoded.contains("allow_degraded"));
    }

    #[test]
    fn degraded_opt_in_and_dispatch_warning_codes_are_stable() {
        let mut constraint: GraphConstraint = serde_json::from_value(serde_json::json!({
            "anchors": ["root"]
        }))
        .unwrap();
        constraint.allow_degraded = true;
        let encoded = serde_json::to_value(&constraint).unwrap();
        assert_eq!(encoded["allow_degraded"], true);
        assert!(
            serde_json::from_value::<GraphConstraint>(encoded)
                .unwrap()
                .allow_degraded
        );

        for (warning, wire) in [
            (GraphQueryWarning::DegradedPlan, "graph.degraded_plan"),
            (
                GraphQueryWarning::UncontractedFusion,
                "graph.uncontracted_fusion",
            ),
            (GraphQueryWarning::ExactFallback, "graph.exact_fallback"),
        ] {
            assert_eq!(serde_json::to_value(warning).unwrap(), wire);
        }
    }

    #[test]
    fn allocator_ids_are_epoch_scoped_and_zero_is_reserved() {
        assert_eq!(Nid::UNASSIGNED.raw(), 0);
        assert!(!Nid::UNASSIGNED.is_assigned());
        assert_eq!(Nid::from_parts(0, 1), None);
        assert_eq!(Nid::from_parts(1, 0), None);
        assert_eq!(
            Nid::from_parts(GRAPH_ALLOCATOR_MAX_EPOCH, 1)
                .unwrap()
                .epoch(),
            GRAPH_ALLOCATOR_MAX_EPOCH
        );
        assert_eq!(
            Nid::from_parts(7, GRAPH_ALLOCATOR_MAX_COUNTER)
                .unwrap()
                .counter(),
            GRAPH_ALLOCATOR_MAX_COUNTER
        );
        assert_eq!(EdgeId::from_parts(7, 91).unwrap().raw(), (7_u64 << 40) | 91);
    }

    #[test]
    fn graph_epoch_never_wraps_or_uses_zero() {
        assert_eq!(GraphEpoch::from_raw(0), None);
        assert_eq!(GraphEpoch::INITIAL.next().unwrap().raw(), 2);
        assert_eq!(GraphEpoch::from_raw(u64::MAX).unwrap().next(), None);
    }

    #[test]
    fn fixed_v1_limits_match_the_paper() {
        assert_eq!(MAX_GRAPH_ANCHORS, 128);
        assert_eq!(MAX_GRAPH_TYPES_PER_CLAUSE, 64);
        assert_eq!(MAX_GRAPH_EDGES_PER_BATCH, 4_096);
        assert_eq!(MAX_GRAPH_DEPTH, 16);
        assert_eq!(MAX_EDGE_PROPERTY_BYTES, 64 * 1024);
        assert_eq!(MAX_GRAPH_BATCH_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn traversal_defaults_and_hard_depth_are_enforced() {
        let budget = TraversalBudget::default().validate().unwrap();
        assert_eq!(budget.max_depth, 5);
        assert_eq!(budget.max_frontier, 1_000_000);
        assert_eq!(budget.max_visited, 10_000_000);
        assert_eq!(budget.max_edges, 100_000_000);
        assert_eq!(budget.wall_time(), Duration::from_secs(5));
        assert_eq!(budget.max_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(budget.cold, None);

        let error = TraversalBudget {
            max_depth: MAX_GRAPH_DEPTH + 1,
            ..budget
        }
        .validate()
        .unwrap_err();
        assert_eq!(error.code, GraphErrorCode::DepthExceeded);
    }

    #[test]
    fn graph_error_codes_are_stable() {
        assert_eq!(
            GraphErrorCode::EndpointNotFound.as_str(),
            "graph.endpoint_not_found"
        );
        assert_eq!(
            GraphErrorCode::BatchTooLarge.as_str(),
            "graph.batch_too_large"
        );
        assert_eq!(
            GraphErrorCode::SloUnavailable.as_str(),
            "graph.slo_unavailable"
        );
        assert_eq!(GraphErrorCode::Overloaded.to_string(), "graph.overloaded");
        assert_eq!(
            serde_json::to_string(&GraphErrorCode::EndpointNotFound).unwrap(),
            "\"graph.endpoint_not_found\""
        );
        assert_eq!(
            serde_json::from_str::<GraphErrorCode>("\"graph.slo_unavailable\"").unwrap(),
            GraphErrorCode::SloUnavailable
        );
    }

    #[test]
    fn graph_capability_names_are_exact_and_stable() {
        for capability in [
            GraphCapability::Read,
            GraphCapability::Write,
            GraphCapability::Admin,
            GraphCapability::TypeConfigure,
        ] {
            assert_eq!(
                GraphCapability::parse(capability.as_str()),
                Some(capability)
            );
            assert_eq!(
                serde_json::from_str::<GraphCapability>(
                    &serde_json::to_string(&capability).unwrap()
                )
                .unwrap(),
                capability
            );
        }
        assert_eq!(GraphCapability::parse("graph:everything"), None);
        assert_eq!(GraphCapability::parse("tenant:cross_read"), None);
    }
}
