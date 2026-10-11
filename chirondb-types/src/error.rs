use thiserror::Error;

use crate::graph::GraphError;

pub type Result<T> = std::result::Result<T, GaussError>;

#[derive(Debug, Error)]
pub enum GaussError {
    #[error(transparent)]
    Security(#[from] crate::security::SecurityError),
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error("collection already exists: {0}")]
    CollectionExists(String),
    #[error("collection not found: {0}")]
    CollectionNotFound(String),
    #[error("point not found: {0}")]
    PointNotFound(String),
    #[error("duplicate key")]
    DuplicateKey,
    #[error("expected vector dimension {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },
    #[error("invalid collection name: {0}")]
    InvalidCollectionName(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("SQL row precondition failed: expected {expected}, affected {actual}")]
    SqlRowPreconditionFailed { expected: u64, actual: u64 },
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
    #[error("transaction outcome is unknown: {transaction_id}")]
    CommitOutcomeUnknown { transaction_id: String },
    #[error("transaction rejected; key remains consumed: {transaction_id}")]
    CommitRejected { transaction_id: String },
    #[error("segment corruption in {path}: {message}")]
    SegmentCorruption { path: String, message: String },
    #[error(transparent)]
    Io(std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<std::io::Error> for GaussError {
    fn from(error: std::io::Error) -> Self {
        // Read adapters can carry an engine error through the std::io boundary.
        // Preserve its classification and receipt identity without matching text.
        match error.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => Self::Io(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read};

    struct RefusedRead(Option<GaussError>);

    impl Read for RefusedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(self.0.take().unwrap()))
        }
    }

    #[test]
    fn buffered_reader_preserves_resource_refusal() {
        let mut reader = BufReader::new(RefusedRead(Some(GaussError::ResourceExhausted(
            "range budget".into(),
        ))));
        let error: GaussError = reader.read_exact(&mut [0]).unwrap_err().into();
        assert!(
            matches!(error, GaussError::ResourceExhausted(message) if message == "range budget")
        );
    }

    #[test]
    fn io_adapter_preserves_transaction_reconciliation_identity() {
        let error = GaussError::from(std::io::Error::other(GaussError::CommitOutcomeUnknown {
            transaction_id: "stable-transaction".into(),
        }));
        assert!(
            matches!(error, GaussError::CommitOutcomeUnknown { transaction_id } if transaction_id == "stable-transaction")
        );
    }

    #[test]
    fn ordinary_os_errors_keep_their_original_code_and_kind() {
        let original = std::io::Error::from_raw_os_error(28);
        let kind = original.kind();
        let GaussError::Io(error) = GaussError::from(original) else {
            panic!("OS error must remain an IO error");
        };
        assert_eq!(error.raw_os_error(), Some(28));
        assert_eq!(error.kind(), kind);
    }

    #[test]
    fn matching_error_text_does_not_turn_io_into_resource_refusal() {
        let error = GaussError::from(std::io::Error::other("resource exhausted: range budget"));
        assert!(matches!(error, GaussError::Io(_)));
    }
}
