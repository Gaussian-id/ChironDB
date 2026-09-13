// Re-export everything from core so internal modules can use `use crate::Db`, `use crate::model::X` unchanged
pub use chirondb_core::*;

// Server modules
pub mod api;
pub mod auth;
pub mod branding;
pub mod chironql_exec;
pub mod chironql_parser;
pub mod chironql_repl;
pub mod cli;
pub mod cluster;
pub mod dispatch;
pub mod events;
pub mod grpc;
pub mod pg_catalog;
pub mod pgvector_exec;
pub mod pgvector_parser;
pub mod placement;
pub mod raft;
pub mod raft_grpc;
pub mod rbac;
pub mod security_paths;
pub mod tls;
pub mod wire;
pub mod wire_postgres;

pub const MAX_UPSERT_POINTS_PER_REQUEST: usize = 10_000;

// Additional re-exports that were in the old lib.rs
pub use model::{
    CollectionConfig, CountResponse, DeleteByFilterRequest, DeleteByFilterResponse,
    GetPointsRequest, GetPointsResponse, HybridFusion, HybridSearchRequest, MultiSearchRequest,
    MultiSearchResponse, PayloadType, Point, PruneWalArchiveRequest, RecommendRequest,
    RerankRequest, ScoreBoost, ScrollResponse, SearchHit, SearchRequest, SearchResponse,
    SetPayloadRequest, SparseVector, UpdatePayloadSchemaRequest, WalArchivePruneResponse,
};

pub mod mcp;
