use thiserror::Error;

use crate::graph::GraphError;

pub type Result<T> = std::result::Result<T, GaussError>;

#[derive(Debug, Error)]
pub enum GaussError {
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error("collection already exists: {0}")]
    CollectionExists(String),
    #[error("collection not found: {0}")]
    CollectionNotFound(String),
    #[error("point not found: {0}")]
    PointNotFound(String),
    #[error("expected vector dimension {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },
    #[error("invalid collection name: {0}")]
    InvalidCollectionName(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),
    #[error("audit unavailable: {0}")]
    AuditUnavailable(String),
    #[error("data directory is already locked: {path}; owner metadata: {owner:?}")]
    DataDirLocked { path: String, owner: Option<String> },
    #[error("wal corruption in {path}: {message}")]
    WalCorruption { path: String, message: String },
    #[error("wal unavailable: {0}")]
    WalUnavailable(String),
    #[error("segment corruption in {path}: {message}")]
    SegmentCorruption { path: String, message: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
