//! Phase 2A — direct-call dispatch for the search hot path.
//!
//! # Why this exists
//!
//! Every `/search` and `/search_batch` request previously ran inside
//! `tokio::task::spawn_blocking`. At c=80, that queues 80 tasks for a
//! small blocking pool; the submit/join overhead is 20–50 µs per
//! request — 2–5% of wall time at low concurrency, worse at high
//! concurrency (2026-06-16 AM bench: the dispatch path was the
//! ceiling at 110–117 QPS across three structurally different
//! backends — HNSW+SQ8, HNSW+full-f32, RaBitQ+SQ8).
//!
//! `Db::search` and `Db::multi_search` are synchronous, in-memory
//! operations on the HNSW / RaBitQ graph. They do no async I/O, never
//! block on a future, never hold a non-`Send` guard, and finish in
//! microseconds to a few milliseconds. Calling them directly on the
//! axum task is therefore safe — and removes a measurable slice of
//! per-request wall time at high concurrency.
//!
//! # Contract
//!
//! [`dispatch_search`] and [`dispatch_multi_search`] accept a closure
//! shaped like `move || db.search(&collection, request)` and invoke it
//! synchronously on the calling tokio task. The closure MUST:
//!
//! * Not block on async I/O (no `.await` on a real future).
//! * Not hold a non-`Send` guard across the call.
//! * Finish in milliseconds (typical: <5 ms; allowed up to 50 ms
//!   under load on a single process).
//!
//! The API layer maps the returned `GaussError` into `ApiError` at
//! the handler boundary.
//!
//! # If the contract breaks
//!
//! If a future change introduces async I/O on the search path (e.g.
//! cold-tier fetch, remote sparse-index lookup), the right move is
//! to switch this module to a dedicated `rayon` pool with a bounded
//! queue — the handler call sites stay identical. The two functions
//! below are the single point of change.

use crate::Result as GaussResult;
use crate::model::{MultiSearchResponse, SearchResponse};

/// Run a synchronous search on the calling tokio task.
///
/// The closure is invoked inline. It MUST satisfy the contract in the
/// module docs. On error, returns the underlying `GaussError`; the
/// API layer converts it to `ApiError` at the handler boundary.
#[inline]
pub fn dispatch_search<F>(f: F) -> GaussResult<SearchResponse>
where
    F: FnOnce() -> GaussResult<SearchResponse>,
{
    f()
}

/// Run a synchronous multi-search on the calling tokio task. Same
/// contract as [`dispatch_search`].
#[inline]
pub fn dispatch_multi_search<F>(f: F) -> GaussResult<MultiSearchResponse>
where
    F: FnOnce() -> GaussResult<MultiSearchResponse>,
{
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GaussError;
    use crate::model::SearchHit;
    use serde_json::json;

    #[test]
    fn dispatch_search_runs_inline_and_propagates_ok() {
        let result = dispatch_search(|| {
            Ok(SearchResponse {
                hits: vec![SearchHit {
                    id: "id-1".to_string(),
                    score: 0.5,
                    payload: json!({ "tag": "unit" }),
                }],
                degraded: false,
                searched: 1,
                elapsed_ms: 0,
                graph: None,
            })
        });
        let response = result.expect("dispatch should propagate Ok");
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "id-1");
        assert!((response.hits[0].score - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn dispatch_search_propagates_err() {
        let result = dispatch_search(|| Err(GaussError::CollectionNotFound("missing".to_string())));
        assert!(matches!(result, Err(GaussError::CollectionNotFound(_))));
    }

    #[test]
    fn dispatch_multi_search_runs_inline() {
        let result = dispatch_multi_search(|| {
            Ok(MultiSearchResponse {
                results: Vec::new(),
                fused: None,
            })
        });
        let response = result.expect("multi dispatch should propagate Ok");
        assert!(response.results.is_empty());
        assert!(response.fused.is_none());
    }
}
