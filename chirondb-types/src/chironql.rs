//! ChironQL wire DTOs — shared by every surface that speaks the language.
//!
//! P0 of the ChironQL plan (§6.2). These types are defined here, in the crate
//! both the server and the SDKs already depend on, so the HTTP endpoint, the
//! gRPC service, the embedded console and the standalone client cannot drift
//! into four slightly different shapes.
//!
//! Nothing in this module executes anything; it is the vocabulary only.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One ChironQL statement submitted for execution.
///
/// One statement per request. Multi-statement bodies would need partial-failure
/// semantics and there are no transactions to make that coherent, so the REPL
/// splits on `;` and sends them one at a time.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ChironQlRequest {
    pub query: String,
    /// Session collection (`USE products`). A collection named in the statement
    /// itself always wins over this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    /// Return the execution trace on success. The trace is always returned on
    /// the failure path regardless of this flag.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trace: bool,
    /// Proceed with a statement that would otherwise stop and ask.
    ///
    /// `DELETE ... WHERE` does not run without this: the server counts what
    /// the filter matches and refuses with `chironql.confirmation_required`,
    /// carrying the count, so the caller can decide with a number in front of
    /// them. This protects every surface, not just the ones with a prompt.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confirm: bool,
}

/// What a statement produced.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChironQlKind {
    /// A result set: `columns` and `rows` are populated.
    Rows,
    /// A mutation: `stats.affected` carries the count.
    Affected,
    /// Session statements (`USE`) — nothing to render.
    Empty,
}

/// Everything the caller learns about how the query ran.
///
/// Every field here is a value the engine actually returned. Nothing is
/// estimated, defaulted, or echoed back from the request while wearing the
/// costume of a measurement — see the plan §7.3.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ChironQlStats {
    /// Wall clock for the whole statement, server-side.
    pub took_ms: f64,
    /// Points the engine scanned, when the statement ran a search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub searched: Option<usize>,
    /// The engine served a degraded answer for this query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    /// Rows affected, for mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected: Option<u64>,
    /// Recall target the caller *asked for*, echoed so a client can label it as
    /// a request. This is never an achieved measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_target_requested: Option<f32>,
    /// Active graph epoch observed by this mutation/traversal, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_epoch: Option<u64>,
    /// WAL position of a graph mutation. `None` is preserved for a replayed
    /// idempotent result rather than manufactured as zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_lsn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replayed: Option<bool>,
    /// Truncation reason for pure traversal, including an explicit row LIMIT
    /// when additional rows existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<crate::graph::TraversalTruncationReason>,
    /// Stable warning codes such as `graph.result_truncated`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Planner/expansion evidence returned by graph-constrained retrieval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<crate::graph::GraphDispatchTrace>,
}

/// A successful ChironQL execution.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChironQlResponse {
    pub kind: ChironQlKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<Value>,
    pub stats: ChironQlStats,
    /// Pagination cursor for `SCROLL`. `None` means this was the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// Correlates this result with the server's own log line for it.
    pub query_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<QueryTrace>,
}

/// A failed ChironQL execution — parse reject, permission denial, or an engine
/// error. Carries the trace up to and including the stage that failed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChironQlError {
    pub error: String,
    /// Stable machine-readable code, e.g. `chironql.no_or_across_fields`.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Byte offset into the submitted query text, for a caret.
    ///
    /// `u32` rather than `usize`: a single statement is never four gigabytes,
    /// and the narrower field keeps this error small enough to travel as the
    /// `Err` half of every executor result without bloating the success path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
    /// How many points the refused statement would have touched. Set only for
    /// `chironql.confirmation_required`, so a prompt can name a real number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_estimate: Option<u32>,
    pub query_id: String,
    /// Boxed so the error stays small: it travels as the `Err` half of every
    /// executor result, and a fat `Err` costs every call on the success path
    /// too. The JSON is identical either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<Box<QueryTrace>>,
}

/// The server's own account of what it did, stage by stage.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct QueryTrace {
    pub query_id: String,
    pub stages: Vec<TraceStage>,
}

/// One stage of execution.
///
/// `name` is a `String` rather than a `&'static str` because these round-trip
/// through the SDKs; the server only ever constructs them from the constants in
/// [`stage`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TraceStage {
    pub name: String,
    pub elapsed_us: u64,
    #[serde(flatten)]
    pub outcome: StageOutcome,
    /// Stage-specific detail, filtered by the caller's role before it is
    /// serialized. Never contains credentials, paths, or environment values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StageOutcome {
    Ok,
    Failed { code: String, message: String },
}

impl StageOutcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Canonical stage names. The set is closed: a stage that did not run is
/// absent from the trace rather than present with a zero duration.
pub mod stage {
    pub const PARSE: &str = "parse";
    pub const AUTHORIZE: &str = "authorize";
    pub const RESOLVE_COLLECTION: &str = "resolve_collection";
    pub const RESOLVE_VECTOR: &str = "resolve_vector";
    pub const COMPILE_FILTER: &str = "compile_filter";
    pub const ENGINE_SEARCH: &str = "engine_search";
    pub const COUNT_MATCHES: &str = "count_matches";
    pub const CONFIRM: &str = "confirm";
    pub const ENGINE_WRITE: &str = "engine_write";
    pub const GRAPH_ESTIMATE: &str = "graph_estimate";
    pub const GRAPH_PLAN: &str = "graph_plan";
    pub const GRAPH_EXPAND: &str = "graph_expand";
    pub const FUSE: &str = "fuse";
    pub const RENDER: &str = "render";
}

impl QueryTrace {
    pub fn new(query_id: impl Into<String>) -> Self {
        Self {
            query_id: query_id.into(),
            stages: Vec::new(),
        }
    }

    pub fn push_ok(&mut self, name: &str, elapsed_us: u64, detail: Option<Value>) {
        self.stages.push(TraceStage {
            name: name.to_string(),
            elapsed_us,
            outcome: StageOutcome::Ok,
            detail,
        });
    }

    pub fn push_failed(
        &mut self,
        name: &str,
        elapsed_us: u64,
        code: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.stages.push(TraceStage {
            name: name.to_string(),
            elapsed_us,
            outcome: StageOutcome::Failed {
                code: code.into(),
                message: message.into(),
            },
            detail: None,
        });
    }

    /// The stage that failed, if any.
    pub fn failed_stage(&self) -> Option<&TraceStage> {
        self.stages.iter().find(|stage| !stage.outcome.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_records_failure_at_the_stage_that_failed() {
        let mut trace = QueryTrace::new("q_test");
        trace.push_ok(stage::PARSE, 40, None);
        trace.push_failed(
            stage::RESOLVE_VECTOR,
            310,
            "chironql.point_not_found",
            "point 'missing' not found",
        );

        assert_eq!(trace.stages.len(), 2);
        assert_eq!(
            trace.failed_stage().map(|s| s.name.as_str()),
            Some("resolve_vector")
        );
    }

    #[test]
    fn graph_trace_stage_names_are_closed_and_stable() {
        assert_eq!(stage::GRAPH_ESTIMATE, "graph_estimate");
        assert_eq!(stage::GRAPH_PLAN, "graph_plan");
        assert_eq!(stage::GRAPH_EXPAND, "graph_expand");
        assert_eq!(stage::FUSE, "fuse");
    }

    #[test]
    fn stats_omit_fields_the_engine_did_not_report() {
        let json = serde_json::to_value(ChironQlStats {
            took_ms: 3.1,
            searched: Some(1412),
            degraded: Some(false),
            ..Default::default()
        })
        .expect("serialize");

        let object = json.as_object().expect("object");
        assert!(object.contains_key("searched"));
        // No affected count and no recall figure were produced, so neither
        // appears at all — absent, not zero.
        assert!(!object.contains_key("affected"));
        assert!(!object.contains_key("recall_target_requested"));
    }

    #[test]
    fn request_round_trips() {
        let request: ChironQlRequest =
            serde_json::from_str(r#"{"query":"COUNT products;","collection":"products"}"#)
                .expect("deserialize");
        assert_eq!(request.query, "COUNT products;");
        assert_eq!(request.collection.as_deref(), Some("products"));
        assert!(!request.trace);
    }
}
