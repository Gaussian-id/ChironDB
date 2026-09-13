use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DistanceMetric, Filter};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionConfig {
    pub name: String,
    pub vector_dim: usize,
    #[serde(default)]
    pub metric: DistanceMetric,
    #[serde(default = "default_shards")]
    pub shards: u32,
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    #[serde(default)]
    pub quantization: Option<String>,
    #[serde(default)]
    pub payload_schema: HashMap<String, PayloadType>,
    /// Per-name vector dimensions for named vector fields.  When a name is not
    /// in this map the collection's default `vector_dim` is used.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub named_vector_dims: HashMap<String, usize>,
    /// HNSW graph parameter `m` (neighbour count per node).  None = engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hnsw_m: Option<u32>,
    /// HNSW `ef_construction` (candidate beam during build).  None = engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hnsw_ef_construction: Option<u32>,
    /// HNSW default `ef_search` for queries against this collection.
    /// Per-query `SearchRequest.ef_search` overrides this when set.
    /// None = engine default (scaled from k).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hnsw_ef_search: Option<u32>,
    /// P3 — contracted recall SLA for this collection. When `Some`, the engine
    /// periodically recalibrates and emits a `recall_sla_breach` audit event if
    /// the active `ef_search` no longer hits the SLA on the observed curve.
    /// Range: `0.5..=1.0`. `None` disables monitoring (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_sla: Option<f32>,
    /// P4 — persisted dense index family. LS-VEC is the sole supported value
    /// and the default when omitted. Mini-HNSW remains an internal mutable-tier
    /// implementation detail, not a selectable sealed index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_kind: Option<String>,
    /// Maximum estimated bytes retained in the mutable LS-Vec streamer
    /// before it is frozen for a background seal. Zero normalizes to the
    /// engine default for callers that use the protocol/default value.
    #[serde(default = "default_streamer_max_bytes")]
    pub streamer_max_bytes: usize,
}

pub const DEFAULT_STREAMER_MAX_BYTES: usize = 1024 * 1024 * 1024;

fn default_streamer_max_bytes() -> usize {
    DEFAULT_STREAMER_MAX_BYTES
}

/// Dimension threshold at which `CollectionConfig::normalize` auto-picks SQ8
/// quantization when the caller leaves it unset. Empirically high-dim
/// collections (e.g. OpenAI ada-002 = 1536 dims) win the most from the 4×
/// memory reduction → cache-locality boost — measured on
/// `chirondb-server/src/bench/ann_benchmarks.rs` Pareto sweeps. Below this
/// threshold full f32 is faster (no decode overhead, fits cache anyway).
pub const SQ8_AUTO_DIM_THRESHOLD: usize = 256;

impl CollectionConfig {
    pub fn normalize(mut self) -> Self {
        if self.shards == 0 {
            self.shards = default_shards();
        }
        if self.replicas == 0 {
            self.replicas = default_replicas();
        }
        if self.streamer_max_bytes == 0 {
            self.streamer_max_bytes = DEFAULT_STREAMER_MAX_BYTES;
        }
        if self
            .index_kind
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("lsvec"))
        {
            self.index_kind = Some("lsvec".to_string());
        }
        // PA-3: SQ8 auto-default for high-dim collections. Closes the p99 +
        // memory-footprint gap to Qdrant on 1536-dim workloads (OpenAI ada,
        // VoyageAI-large) without breaking callers who explicitly pick
        // `quantization = Some("none")` or `Some("sq8")`.
        if self.quantization.is_none() && self.vector_dim >= SQ8_AUTO_DIM_THRESHOLD {
            self.quantization = Some("sq8".to_string());
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    String,
    Number,
    Bool,
    Object,
    Array,
    OptionalString,
    OptionalNumber,
    OptionalBool,
    OptionalObject,
    OptionalArray,
    NullableString,
    NullableNumber,
    NullableBool,
    NullableObject,
    NullableArray,
}

impl fmt::Display for PayloadType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Bool => "bool",
            Self::Object => "object",
            Self::Array => "array",
            Self::OptionalString => "optional_string",
            Self::OptionalNumber => "optional_number",
            Self::OptionalBool => "optional_bool",
            Self::OptionalObject => "optional_object",
            Self::OptionalArray => "optional_array",
            Self::NullableString => "nullable_string",
            Self::NullableNumber => "nullable_number",
            Self::NullableBool => "nullable_bool",
            Self::NullableObject => "nullable_object",
            Self::NullableArray => "nullable_array",
        };
        formatter.write_str(value)
    }
}

impl PayloadType {
    pub fn is_optional(self) -> bool {
        matches!(
            self,
            Self::OptionalString
                | Self::OptionalNumber
                | Self::OptionalBool
                | Self::OptionalObject
                | Self::OptionalArray
        )
    }

    pub fn is_nullable(self) -> bool {
        matches!(
            self,
            Self::OptionalString
                | Self::OptionalNumber
                | Self::OptionalBool
                | Self::OptionalObject
                | Self::OptionalArray
                | Self::NullableString
                | Self::NullableNumber
                | Self::NullableBool
                | Self::NullableObject
                | Self::NullableArray
        )
    }

    pub fn base_type(self) -> Self {
        match self {
            Self::OptionalString | Self::NullableString => Self::String,
            Self::OptionalNumber | Self::NullableNumber => Self::Number,
            Self::OptionalBool | Self::NullableBool => Self::Bool,
            Self::OptionalObject | Self::NullableObject => Self::Object,
            Self::OptionalArray | Self::NullableArray => Self::Array,
            value => value,
        }
    }
}

fn default_shards() -> u32 {
    1
}

fn default_replicas() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Point {
    pub id: String,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub vectors: HashMap<String, Vec<f32>>,
    #[serde(default)]
    pub sparse_vector: Option<SparseVector>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SparseVector {
    pub indices: Vec<u32>,
    pub values: Vec<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpsertPoints {
    pub points: Vec<Point>,
    /// When true (default), block until WAL fsync is confirmed.
    /// When false, return immediately after queuing the write.
    #[serde(default = "default_wait")]
    pub wait: bool,
}

fn default_wait() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdatePayloadSchemaRequest {
    pub payload_schema: HashMap<String, PayloadType>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeletePoints {
    pub ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPointsRequest {
    pub ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPointsResponse {
    pub points: Vec<Point>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetPayloadRequest {
    pub id: String,
    pub payload: serde_json::Value,
    /// When true (default), merge fields into existing payload.
    /// When false, replace payload entirely.
    #[serde(default = "default_merge")]
    pub merge: bool,
}

fn default_merge() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeleteByFilterRequest {
    pub filter: Filter,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeleteByFilterResponse {
    pub deleted: usize,
}

/// Read consistency level for search operations.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    /// Read from the leader, confirmed by quorum commit.
    Strong,
    /// Read from any replica, bounded by a maximum staleness LSN delta.
    #[default]
    Bounded,
    /// Read from any local replica (current default behavior).
    Eventual,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchRequest {
    pub vector: Vec<f32>,
    #[serde(default)]
    pub vector_name: Option<String>,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default)]
    pub filter: Option<Filter>,
    /// Statement-level graph membership constraint. The core computes one
    /// admitted set before ranking; protocol parity is completed in G3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<crate::graph::GraphConstraint>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
    #[serde(default)]
    pub consistency: Option<ConsistencyLevel>,
    /// Per-query HNSW `ef_search` override.  Higher = more accurate but slower.
    /// Falls back to `CollectionConfig.hnsw_ef_search`, then engine default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ef_search: Option<u32>,
    /// PA-1: target recall (0.0..=1.0). When set and `ef_search` is None,
    /// the engine picks `ef_search` from a calibration curve so the query
    /// only pays for the precision the caller asked for. Default = None
    /// (use `ef_search` / collection default — full back-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_target: Option<f32>,
    /// PA-2: when `Some(false)`, the search response omits hit `payload`
    /// (returns `Value::Null`). Skips the `serde_json::Value` clone in the
    /// hot scoring loop. Default = `None` (treated as `true` for back-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_payload: Option<bool>,
}

fn default_k() -> usize {
    10
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub score: f32,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub degraded: bool,
    pub searched: usize,
    pub elapsed_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<crate::graph::GraphDispatchTrace>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultiSearchRequest {
    pub searches: Vec<SearchRequest>,
    #[serde(default)]
    pub fusion: Option<HybridFusion>,
    #[serde(default)]
    pub fused_k: Option<usize>,
    #[serde(default)]
    pub weights: Vec<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultiSearchResponse {
    pub results: Vec<SearchResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fused: Option<SearchResponse>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridFusion {
    #[default]
    Rrf,
    Weighted,
}

/// Native text BM25 + default dense vector retrieval with RRF fusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextHybridSearchRequest {
    pub vector: Vec<f32>,
    pub query: String,
    pub text_field: String,
    pub k: usize,
    #[serde(default)]
    pub filter: Option<Filter>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HybridSearchRequest {
    #[serde(default)]
    pub vector: Option<Vec<f32>>,
    #[serde(default)]
    pub vector_name: Option<String>,
    #[serde(default)]
    pub sparse_vector: Option<SparseVector>,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default)]
    pub filter: Option<Filter>,
    /// One statement-level graph constraint shared by dense and sparse
    /// branches and applied before fusion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<crate::graph::GraphConstraint>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
    #[serde(default)]
    pub fusion: HybridFusion,
    #[serde(default = "default_weight")]
    pub dense_weight: f32,
    #[serde(default = "default_weight")]
    pub sparse_weight: f32,
}

fn default_weight() -> f32 {
    1.0
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecommendRequest {
    #[serde(default)]
    pub positive: Vec<String>,
    #[serde(default)]
    pub negative: Vec<String>,
    #[serde(default)]
    pub vector_name: Option<String>,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default)]
    pub filter: Option<Filter>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
}

/// A single score adjustment rule for payload-based reranking.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScoreBoost {
    /// Payload field name to match.
    pub field: String,
    /// Required payload value (equality match).
    pub value: serde_json::Value,
    /// Multiplicative factor applied to the base score when the field matches.
    /// Values > 1.0 boost; values in (0, 1) penalise.
    pub boost: f32,
}

/// Rerank previously-retrieved candidates using payload-based score boosts.
///
/// Internally this runs a wider ANN prefetch (`prefetch_k`) and then
/// adjusts each hit's score with any matching `score_boosts` before
/// returning the top `k` results.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RerankRequest {
    /// Query vector used for the initial ANN prefetch.
    pub vector: Vec<f32>,
    #[serde(default)]
    pub vector_name: Option<String>,
    /// Number of final results to return.
    #[serde(default = "default_k")]
    pub k: usize,
    /// Number of ANN candidates to retrieve before reranking.
    /// Defaults to `3 × k`.
    #[serde(default)]
    pub prefetch_k: Option<usize>,
    #[serde(default)]
    pub filter: Option<Filter>,
    /// Score adjustment rules evaluated per result.
    #[serde(default)]
    pub score_boosts: Vec<ScoreBoost>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CountRequest {
    #[serde(default)]
    pub filter: Option<Filter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CountResponse {
    pub count: usize,
}

/// Index build readiness for a collection. Surfaces the
/// `index_build_in_flight` background-build flag and indexed vs. total
/// point counts so callers (benchmark harnesses, production clients with a
/// `recall_sla` contract) can tell when a collection's ANN index has caught
/// up with ingested points instead of inferring it from search latency.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IndexStatusResponse {
    pub build_in_flight: bool,
    pub indexed_points: usize,
    pub total_points: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScrollRequest {
    /// ID-based continuation token returned by the previous page.
    /// Pass `None` to start from the first page.
    #[serde(default)]
    pub offset: Option<String>,
    #[serde(default = "default_scroll_limit")]
    pub limit: usize,
    #[serde(default)]
    pub filter: Option<Filter>,
}

fn default_scroll_limit() -> usize {
    100
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScrollResponse {
    pub points: Vec<Point>,
    /// ID of the last returned point.  Pass as `offset` to get the next page.
    /// `None` when this is the last page.
    pub next_offset: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnapshotRequest {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RestoreRequest {
    pub path: String,
    #[serde(default)]
    pub target_wal_lsns: HashMap<String, u64>,
    #[serde(default)]
    pub target_wal_unix_ms: HashMap<String, u64>,
    #[serde(default)]
    pub wal_restore_archive_dir: Option<String>,
    #[serde(default)]
    pub wal_restore_object_store_dir: Option<String>,
    #[serde(default)]
    pub wal_restore_object_store_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompactResponse {
    pub collection: String,
    pub segment_id: String,
    pub points: usize,
    pub h2qg_cells: usize,
    pub named_h2qg_fields: usize,
    pub sparse_dimensions: usize,
    pub sparse_postings: usize,
    pub payload_fields: usize,
    pub payload_values: usize,
    pub payload_postings: usize,
    pub tombstones: usize,
    pub wal_archived_segments: usize,
    pub wal_archived_bytes: u64,
    pub wal_external_archived_segments: usize,
    pub wal_external_archived_bytes: u64,
    pub wal_object_archived_segments: usize,
    pub wal_object_archived_bytes: u64,
    pub wal_archive_command_executed: bool,
    pub wal_auto_retained_archives: usize,
    pub wal_auto_pruned_archives: usize,
    pub wal_auto_pruned_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ColdTierResponse {
    pub collection: String,
    pub segments: usize,
    pub files: usize,
    pub bytes: u64,
    pub points: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PruneWalArchiveRequest {
    pub retain_last: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalArchivePruneResponse {
    pub collection: String,
    pub retained_archives: usize,
    pub pruned_archives: usize,
    pub pruned_bytes: u64,
}

#[cfg(test)]
mod sq8_default_tests {
    use super::{
        CollectionConfig, DEFAULT_STREAMER_MAX_BYTES, DistanceMetric, SQ8_AUTO_DIM_THRESHOLD,
    };
    use std::collections::HashMap;

    fn cfg(dim: usize, quantization: Option<String>) -> CollectionConfig {
        CollectionConfig {
            name: "t".to_string(),
            vector_dim: dim,
            metric: DistanceMetric::L2,
            shards: 1,
            replicas: 1,
            quantization,
            payload_schema: HashMap::new(),
            named_vector_dims: HashMap::new(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        }
    }

    #[test]
    fn high_dim_auto_picks_sq8() {
        let normalized = cfg(SQ8_AUTO_DIM_THRESHOLD, None).normalize();
        assert_eq!(normalized.quantization.as_deref(), Some("sq8"));
        let normalized = cfg(1536, None).normalize();
        assert_eq!(normalized.quantization.as_deref(), Some("sq8"));
    }

    #[test]
    fn low_dim_leaves_quantization_unset() {
        let normalized = cfg(128, None).normalize();
        assert_eq!(normalized.quantization, None);
        let normalized = cfg(SQ8_AUTO_DIM_THRESHOLD - 1, None).normalize();
        assert_eq!(normalized.quantization, None);
    }

    #[test]
    fn explicit_quantization_wins() {
        let normalized = cfg(2048, Some("none".into())).normalize();
        assert_eq!(normalized.quantization.as_deref(), Some("none"));
    }

    #[test]
    fn streamer_cap_defaults_and_explicit_value_survives_normalize() {
        assert_eq!(
            cfg(2, None).normalize().streamer_max_bytes,
            DEFAULT_STREAMER_MAX_BYTES
        );
        let mut explicit = cfg(2, None);
        explicit.streamer_max_bytes = 1024;
        assert_eq!(explicit.normalize().streamer_max_bytes, 1024);
    }

    #[test]
    fn missing_and_case_insensitive_index_kind_normalize_to_lsvec() {
        assert_eq!(
            cfg(2, None).normalize().index_kind.as_deref(),
            Some("lsvec")
        );
        let mut explicit = cfg(2, None);
        explicit.index_kind = Some("LSVEC".to_string());
        assert_eq!(explicit.normalize().index_kind.as_deref(), Some("lsvec"));
    }

    #[test]
    fn legacy_json_defaults_streamer_cap() {
        let config: CollectionConfig = serde_json::from_value(serde_json::json!({
            "name": "legacy",
            "vector_dim": 2
        }))
        .unwrap();
        assert_eq!(config.streamer_max_bytes, DEFAULT_STREAMER_MAX_BYTES);
    }

    #[test]
    fn explicit_sq8_below_threshold_kept() {
        let normalized = cfg(64, Some("sq8".into())).normalize();
        assert_eq!(normalized.quantization.as_deref(), Some("sq8"));
    }
}
