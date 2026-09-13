// Re-export types so internal modules can use `use crate::model::X` unchanged
pub mod distance {
    pub use chirondb_types::distance::*;
}
pub mod error {
    pub use chirondb_types::error::*;
}
pub mod filter {
    pub use chirondb_types::filter::*;
}
pub mod graph {
    pub use chirondb_types::graph::*;
}
pub mod model {
    pub use chirondb_types::model::*;
}
pub use chirondb_types::{DistanceMetric, Filter, GaussError, GraphError, GraphErrorCode, Result};
pub use graph::{
    ExactGraphSearchRequest, ExactGraphSearchResponse, GraphConstraint, GraphRetrievalPlan,
};
pub use tenant::{TenantCapability, TenantEnforcement, TenantScope};

// Engine modules (moved from old src/)
pub mod audit;
mod bm25;
pub(crate) mod build_progress;
pub mod checkpoint;
pub mod compaction;
mod data_dir_lock;
pub mod db;
pub mod distance_soa;
pub(crate) mod edge_token;
pub mod encryption;
pub mod failpoint;
pub mod fs_util;
pub(crate) mod graph_admission;
// G1 freezes and validates these formats before the complete graph segment
// group becomes publication-authoritative in the later marker/manifest slice.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_artifact;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_edge;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_edgeid;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_edgeprop;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "D6a estimator and calibration boundary is wired into dispatch in D6b"
    )
)]
pub(crate) mod graph_estimator;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_fragdir;
#[cfg(feature = "fuzzing")]
pub mod graph_fuzz;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_generation;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_group;
pub(crate) mod graph_identity;
pub(crate) mod graph_lifecycle;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_nid;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_planner;
pub(crate) mod graph_resolver;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod graph_tdelta;
pub(crate) mod graph_traversal;
pub mod h2qg;
pub mod index;
pub(crate) mod mutable_graph;
pub mod observability;
pub mod ordinal;
pub(crate) mod overlay;
pub mod payload_index;
pub mod query_arena;
pub(crate) mod restore_journal;
pub mod seal;
pub mod search;
pub mod search_pool;
pub mod searcher;
pub mod segment;
pub mod snapshot;
mod snapshot_journal;
pub mod sparse_index;
pub mod storage_layout;
pub mod streamer;
pub mod structural_embedding;
pub mod tenant;
pub mod wal;
pub mod wal_archive;
pub mod wal_replication;

// Crate-root re-exports (matching the original lib.rs)
pub use db::Db;
pub use index::{IndexBackend, IndexKind, IndexParams};
pub use model::{
    CollectionConfig, CountResponse, DeleteByFilterRequest, DeleteByFilterResponse,
    GetPointsRequest, GetPointsResponse, HybridFusion, HybridSearchRequest, MultiSearchRequest,
    MultiSearchResponse, PayloadType, Point, PruneWalArchiveRequest, RecommendRequest,
    RerankRequest, ScoreBoost, ScrollResponse, SearchHit, SearchRequest, SearchResponse,
    SetPayloadRequest, SparseVector, TextHybridSearchRequest, UpdatePayloadSchemaRequest,
    WalArchivePruneResponse,
};
pub use ordinal::SegmentOrdinalSet;
pub use segment::{SoASegmentCache, SoAVectorStorage};
pub use structural_embedding::StructuralUpsertReceipt;
