use std::{
    cell::{Cell, RefCell},
    env,
    sync::OnceLock,
    time::Instant,
};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use tracing_subscriber::{
    EnvFilter,
    fmt::writer::BoxMakeWriter,
    layer::SubscriberExt,
    util::{SubscriberInitExt, TryInitError},
};

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

thread_local! {
    static GRAPH_EXECUTION: RefCell<Option<GraphExecutionTelemetry>> = const { RefCell::new(None) };
    static GRAPH_SHADOW_DEPTH: Cell<u32> = const { Cell::new(0) };
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GraphExecutionTelemetry {
    pub(crate) graph_epoch: Option<crate::graph::GraphEpoch>,
    pub(crate) expand: crate::graph::GraphExpandTrace,
    pub(crate) fuse: Option<crate::graph::GraphFuseTrace>,
}

pub(crate) struct GraphExecutionGuard {
    finished: bool,
}

impl GraphExecutionGuard {
    pub(crate) fn start() -> Self {
        GRAPH_EXECUTION.with(|active| {
            debug_assert!(active.borrow().is_none());
            *active.borrow_mut() = Some(GraphExecutionTelemetry::default());
        });
        Self { finished: false }
    }

    pub(crate) fn finish(mut self) -> GraphExecutionTelemetry {
        self.finished = true;
        GRAPH_EXECUTION.with(|active| active.borrow_mut().take().unwrap_or_default())
    }
}

impl Drop for GraphExecutionGuard {
    fn drop(&mut self) {
        if !self.finished {
            GRAPH_EXECUTION.with(|active| {
                active.borrow_mut().take();
            });
        }
    }
}

/// Marks an executor invocation as timing-only shadow work. Normal operation
/// and traversal metrics are redirected so sampled alternatives cannot be
/// mistaken for client-visible query outcomes.
pub(crate) struct GraphShadowExecutionGuard;

impl GraphShadowExecutionGuard {
    pub(crate) fn enter() -> Self {
        GRAPH_SHADOW_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for GraphShadowExecutionGuard {
    fn drop(&mut self) {
        GRAPH_SHADOW_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

fn graph_shadow_active() -> bool {
    GRAPH_SHADOW_DEPTH.with(|depth| depth.get() > 0)
}

pub(crate) fn record_graph_fuse(
    dense_admitted: usize,
    sparse_admitted: usize,
    dense_overfetch: usize,
    sparse_overfetch: usize,
) {
    GRAPH_EXECUTION.with(|active| {
        let mut active = active.borrow_mut();
        let Some(telemetry) = active.as_mut() else {
            return;
        };
        telemetry.fuse = Some(crate::graph::GraphFuseTrace {
            dense_admitted: dense_admitted as u64,
            sparse_admitted: sparse_admitted as u64,
            dense_overfetch: dense_overfetch as u64,
            sparse_overfetch: sparse_overfetch as u64,
        });
    });
}

pub(crate) fn record_graph_epoch(graph_epoch: crate::graph::GraphEpoch) {
    GRAPH_EXECUTION.with(|active| {
        let mut active = active.borrow_mut();
        let Some(telemetry) = active.as_mut() else {
            return;
        };
        telemetry.graph_epoch = Some(graph_epoch);
    });
}

fn record_graph_expansion(
    stats: &crate::graph::TraversalStats,
    truncation: Option<crate::graph::TraversalTruncationReason>,
) {
    GRAPH_EXECUTION.with(|active| {
        let mut active = active.borrow_mut();
        let Some(telemetry) = active.as_mut() else {
            return;
        };
        let expand = &mut telemetry.expand;
        expand.hops_completed = expand.hops_completed.saturating_add(stats.hops_completed);
        expand.nodes_visited = expand.nodes_visited.saturating_add(stats.nodes_visited);
        expand.edges_examined = expand
            .edges_examined
            .saturating_add(stats.visible_edges_examined);
        expand.hop_local = expand.hop_local.saturating_add(stats.hop_local);
        expand.hop_global = expand.hop_global.saturating_add(stats.hop_global);
        expand.supersession_followed = expand
            .supersession_followed
            .saturating_add(stats.supersession_followed);
        expand.fragments_read = expand.fragments_read.saturating_add(stats.fragments_read);
        expand.cold_fragments_faulted = expand
            .cold_fragments_faulted
            .saturating_add(stats.cold_fragments_read);
        expand.cold_bytes_read = expand.cold_bytes_read.saturating_add(stats.cold_bytes_read);
        expand.elapsed_us = expand
            .elapsed_us
            .saturating_add(stats.elapsed_ms.saturating_mul(1_000));
        if expand.truncation.is_none() {
            expand.truncation = truncation;
        }
        let hops = u128::from(expand.hop_local).saturating_add(u128::from(expand.hop_global));
        if hops > 0 {
            expand.alpha_bps = Some(
                u16::try_from(u128::from(expand.hop_local).saturating_mul(10_000) / hops)
                    .unwrap_or(10_000),
            );
            expand.beta_bps = Some(
                u16::try_from(
                    u128::from(expand.supersession_followed).saturating_mul(10_000) / hops,
                )
                .unwrap_or(10_000),
            );
        }
    });
}

pub fn init_metrics() -> PrometheusHandle {
    PROMETHEUS_HANDLE
        .get_or_init(|| {
            describe_metrics();
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus metrics recorder")
        })
        .clone()
}

#[derive(Debug)]
pub struct FlamegraphCapture;

pub fn spawn_flamegraph_capture_from_env() -> std::io::Result<Option<FlamegraphCapture>> {
    if env::var_os("CHIRONDB_FLAMEGRAPH_DIR")
        .or_else(|| env::var_os("GAUSSDB_FLAMEGRAPH_DIR"))
        .is_none()
    {
        return Ok(None);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "in-process flamegraph capture is disabled because its profiler dependency does not satisfy the release security policy; use an OS profiler instead",
    ))
}

#[derive(Debug)]
pub struct TracingGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl TracingGuard {
    pub fn otel_enabled(&self) -> bool {
        self.tracer_provider.is_some()
    }
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(tracer_provider) = self.tracer_provider.take() {
            let _ = tracer_provider.shutdown();
        }
    }
}

/// Where formatted log lines go.
///
/// Stdout is the default and what every existing deployment gets. The embedded
/// ChironQL console needs stdout for its prompt and results, so it starts the
/// server with [`LogTarget::Stderr`]; interleaving log lines with a prompt
/// makes both unreadable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogTarget {
    #[default]
    Stdout,
    Stderr,
}

pub fn init_tracing() -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    init_tracing_to(LogTarget::default())
}

pub fn init_tracing_to(
    target: LogTarget,
) -> Result<TracingGuard, Box<dyn std::error::Error + Send + Sync>> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let writer = match target {
        LogTarget::Stdout => BoxMakeWriter::new(std::io::stdout),
        LogTarget::Stderr => BoxMakeWriter::new(std::io::stderr),
    };
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(writer);

    if otel_enabled_from_env() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_service_name("chirondb")
                    .with_attribute(opentelemetry::KeyValue::new(
                        "service.version",
                        env!("CARGO_PKG_VERSION"),
                    ))
                    .build(),
            )
            .with_batch_exporter(exporter)
            .build();
        let tracer = tracer_provider.tracer("chirondb");
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .map_err(init_error)?;
        Ok(TracingGuard {
            tracer_provider: Some(tracer_provider),
        })
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()
            .map_err(init_error)?;
        Ok(TracingGuard {
            tracer_provider: None,
        })
    }
}

fn init_error(error: TryInitError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(error)
}

fn otel_enabled_from_env() -> bool {
    matches!(
        env::var("CHIRONDB_OTEL")
            .or_else(|_| env::var("GAUSSDB_OTEL"))
            .as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("on") | Ok("ON")
    ) || env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
        || env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
}

pub fn observe_operation(operation: &'static str, started: Instant, status: &'static str) {
    metrics::counter!(
        "gaussdb_operations_total",
        "operation" => operation,
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "gaussdb_operation_duration_seconds",
        "operation" => operation,
        "status" => status
    )
    .record(started.elapsed().as_secs_f64());
}

pub fn observe_degraded(operation: &'static str) {
    metrics::counter!("gaussdb_degraded_queries_total", "operation" => operation).increment(1);
}

/// Fired when `search::search_point_candidates`'s safety-net backfill scan
/// (the `O(N)` fallback for points the ANN index hasn't caught up to yet,
/// e.g. while a background `spawn_index_build` is in flight) actually finds
/// and includes a point. Distinct from `observe_degraded`, which marks a
/// budget/partial-result condition -- this counter exists so an operator can
/// tell "the index is behind ingestion and queries are paying O(N) scans"
/// apart from "this single query hit its latency budget."
pub fn observe_index_backfill_scan(backfilled_points: usize) {
    metrics::counter!("gaussdb_search_index_backfill_points_total")
        .increment(backfilled_points as u64);
}

pub fn observe_points_upserted(count: usize) {
    metrics::counter!("gaussdb_points_upserted_total").increment(count as u64);
}

pub fn observe_points_deleted(count: usize) {
    metrics::counter!("gaussdb_points_deleted_total").increment(count as u64);
}

pub fn observe_graph_edges_orphaned_by_delete(count: usize) {
    metrics::counter!("graph_edges_orphaned_by_delete_total").increment(count as u64);
}

pub fn observe_graph_traversal(
    stats: &crate::graph::TraversalStats,
    truncation: Option<crate::graph::TraversalTruncationReason>,
) {
    record_graph_expansion(stats, truncation);
    if graph_shadow_active() {
        metrics::counter!("graph_shadow_edges_examined_total")
            .increment(stats.visible_edges_examined);
        return;
    }
    metrics::counter!("graph_edges_examined_total").increment(stats.visible_edges_examined);
    metrics::counter!("graph_hop_local_total").increment(stats.hop_local);
    metrics::counter!("graph_hop_global_total").increment(stats.hop_global);
    metrics::counter!("graph_supersession_followed_total").increment(stats.supersession_followed);
    metrics::histogram!("graph_fragments_per_query").record(stats.fragments_read as f64);
    metrics::histogram!("graph_frontier_size").record(stats.max_frontier_size as f64);
    if let Some(reason) = truncation {
        metrics::counter!(
            "graph_truncation_total",
            "reason" => graph_truncation_reason(reason)
        )
        .increment(1);
    }
}

/// Record one completed graph planner decision. The trace has already been
/// reduced to tenant-safe, low-cardinality fields by the retrieval layer.
pub fn observe_graph_dispatch(trace: &crate::graph::GraphDispatchTrace) {
    metrics::counter!(
        "graph_plan_chosen_total",
        "plan" => trace.graph_plan.chosen.as_str()
    )
    .increment(1);
    if let Some(guard) = trace.graph_plan.guard {
        metrics::counter!("graph_plan_guard_total", "guard" => guard.as_str()).increment(1);
    }
    if let Some(specificity) = trace.graph_estimate.specificity {
        let midpoint =
            u32::from(specificity.min_bps).saturating_add(u32::from(specificity.max_bps)) / 2;
        metrics::histogram!("graph_sigma_estimated_bps").record(f64::from(midpoint));
        if specificity.min_bps == specificity.max_bps {
            metrics::histogram!("graph_sigma_realized_bps").record(f64::from(specificity.min_bps));
        }
    }
    if trace.graph_estimate.estimator == crate::graph::GraphEstimatorKind::Sketch
        && let Some(lag) = trace.graph_estimate.overlay_lsn_lag
    {
        metrics::histogram!("graph_sketch_staleness_lsn").record(lag as f64);
    }
    if trace.graph_plan.degraded {
        metrics::counter!("graph_degraded_plan_total").increment(1);
    }
    if trace.graph_plan.exact_fallback {
        metrics::counter!("graph_exact_fallback_total", "plan" => trace.graph_plan.chosen.as_str())
            .increment(1);
    }
}

fn graph_truncation_reason(reason: crate::graph::TraversalTruncationReason) -> &'static str {
    use crate::graph::TraversalTruncationReason;
    match reason {
        TraversalTruncationReason::Limit => "limit",
        TraversalTruncationReason::Depth => "depth",
        TraversalTruncationReason::Frontier => "frontier",
        TraversalTruncationReason::Visited => "visited",
        TraversalTruncationReason::Edges => "edges",
        TraversalTruncationReason::Time => "time",
        TraversalTruncationReason::Memory => "memory",
        TraversalTruncationReason::ColdFragments => "cold_fragments",
        TraversalTruncationReason::ColdBytes => "cold_bytes",
        TraversalTruncationReason::Cancelled => "cancelled",
    }
}

pub fn set_storage_gauges(collections: usize, points: usize, sparse_postings: usize) {
    metrics::gauge!("gaussdb_collections").set(collections as f64);
    metrics::gauge!("gaussdb_points").set(points as f64);
    metrics::gauge!("gaussdb_sparse_postings").set(sparse_postings as f64);
}

fn describe_metrics() {
    metrics::describe_counter!(
        "gaussdb_operations_total",
        "Total GaussDB operations by operation and status."
    );
    metrics::describe_histogram!(
        "gaussdb_operation_duration_seconds",
        metrics::Unit::Seconds,
        "GaussDB operation latency in seconds."
    );
    metrics::describe_counter!(
        "gaussdb_degraded_queries_total",
        "Total query operations that returned degraded=true."
    );
    metrics::describe_counter!(
        "gaussdb_rate_limited_requests_total",
        "Total ingress requests rejected by the optional rate limiter."
    );
    metrics::describe_counter!(
        "gaussdb_points_upserted_total",
        "Total points accepted by upsert requests."
    );
    metrics::describe_counter!(
        "gaussdb_points_deleted_total",
        "Total points deleted from collections."
    );
    metrics::describe_counter!(
        "graph_edges_orphaned_by_delete_total",
        "Total visible graph edges made permanently invisible by point deletion."
    );
    metrics::describe_gauge!(
        "graph_pool_bytes_reserved",
        metrics::Unit::Bytes,
        "Process-wide graph traversal memory reserved by admitted queries."
    );
    metrics::describe_gauge!(
        "graph_cold_pool_bytes_reserved",
        metrics::Unit::Bytes,
        "Process-wide cold-fragment bytes reserved by admitted graph traversals."
    );
    metrics::describe_histogram!(
        "graph_admission_wait_seconds",
        metrics::Unit::Seconds,
        "Time spent awaiting process-wide graph traversal admission."
    );
    metrics::describe_counter!(
        "graph_admission_rejected_total",
        "Graph traversals refused before expansion, by low-cardinality reason."
    );
    metrics::describe_counter!(
        "graph_admission_cancelled_total",
        "Graph traversals cancelled while awaiting process-wide admission."
    );
    metrics::describe_counter!(
        "graph_edges_examined_total",
        "Authorised visible edges examined by exact graph traversal."
    );
    metrics::describe_counter!(
        "graph_hop_local_total",
        "Authorised graph edges resolved through a tagged local reference."
    );
    metrics::describe_counter!(
        "graph_hop_global_total",
        "Authorised graph edges resolved through a global Nid reference."
    );
    metrics::describe_counter!(
        "graph_supersession_followed_total",
        "Authorised local references whose live point moved to another vector location."
    );
    metrics::describe_histogram!(
        "graph_fragments_per_query",
        "Authorised sealed adjacency fragments read per graph expansion."
    );
    metrics::describe_histogram!(
        "graph_frontier_size",
        "Maximum authorised BFS frontier size per graph traversal."
    );
    metrics::describe_counter!(
        "graph_truncation_total",
        "Graph traversal results truncated by low-cardinality budget reason."
    );
    metrics::describe_counter!(
        "graph_plan_chosen_total",
        "Completed graph-constrained retrievals by selected planner plan."
    );
    metrics::describe_counter!(
        "graph_plan_guard_total",
        "Completed graph-constrained retrievals by stable planner guard."
    );
    metrics::describe_histogram!(
        "graph_sigma_estimated_bps",
        "Tenant-authorized graph specificity estimate in basis points."
    );
    metrics::describe_histogram!(
        "graph_sigma_realized_bps",
        "Exact tenant-authorized graph specificity in basis points."
    );
    metrics::describe_histogram!(
        "graph_sketch_staleness_lsn",
        "Planner sketch freshness lag in WAL LSNs."
    );
    metrics::describe_counter!(
        "graph_degraded_plan_total",
        "Graph queries served by an explicitly allowed advisory plan."
    );
    metrics::describe_counter!(
        "graph_exact_fallback_total",
        "Approximate graph plan executions that completed through exact P1 fallback."
    );
    metrics::describe_counter!(
        "graph_shadow_sample_total",
        "Sampled graph-plan shadow jobs by bounded-queue/completion status."
    );
    metrics::describe_histogram!(
        "graph_shadow_plan_duration_seconds",
        metrics::Unit::Seconds,
        "Timing-only sampled graph plan duration by plan and stable outcome."
    );
    metrics::describe_histogram!(
        "graph_shadow_regret_ratio",
        "Chosen-plan duration divided by the fastest successful sampled eligible plan."
    );
    metrics::describe_counter!(
        "graph_shadow_edges_examined_total",
        "Authorised visible edges examined by timing-only shadow alternatives."
    );
    metrics::describe_counter!(
        "graph_shadow_operation_total",
        "Timing-only shadow executor operations by stable operation and status."
    );
    metrics::describe_counter!(
        "graph_shadow_worker_panic_total",
        "Panics isolated by the bounded graph shadow worker."
    );
    metrics::describe_gauge!("gaussdb_collections", "Current number of collections.");
    metrics::describe_gauge!("gaussdb_points", "Current number of stored points.");
    metrics::describe_gauge!(
        "gaussdb_sparse_postings",
        "Current number of sparse vector postings in memory."
    );
    metrics::describe_counter!(
        "chirondb_wal_append_records_total",
        "Total CRC-framed WAL records appended."
    );
    metrics::describe_counter!(
        "chirondb_wal_append_bytes_total",
        metrics::Unit::Bytes,
        "Total CRC-framed WAL bytes appended."
    );
    metrics::describe_histogram!(
        "chirondb_wal_fsync_duration_seconds",
        metrics::Unit::Seconds,
        "WAL filesystem synchronization latency in seconds."
    );
    metrics::describe_gauge!(
        "chirondb_wal_unsynced_bytes",
        metrics::Unit::Bytes,
        "Current WAL bytes not yet synchronized to stable storage."
    );
    metrics::describe_gauge!(
        "chirondb_wal_oldest_unsynced_seconds",
        metrics::Unit::Seconds,
        "Age in seconds of the oldest WAL bytes not yet synchronized."
    );
    metrics::describe_counter!(
        "chirondb_wal_recovery_records_total",
        "Total WAL records replayed during recovery."
    );
    metrics::describe_histogram!(
        "chirondb_wal_recovery_duration_seconds",
        metrics::Unit::Seconds,
        "WAL recovery scan latency in seconds."
    );
    metrics::describe_counter!(
        "chirondb_wal_corruption_total",
        "Total WAL scans that failed closed on corruption."
    );
    metrics::describe_counter!(
        "chirondb_wal_tail_repairs_total",
        "Total safe torn tails repaired on final active WAL segments."
    );
}

pub struct OperationGuard {
    operation: &'static str,
    started: Instant,
    status: &'static str,
    span: tracing::span::EnteredSpan,
    shadow: bool,
}

impl OperationGuard {
    pub fn start(operation: &'static str) -> Self {
        let span = tracing::info_span!(
            "gaussdb.operation",
            operation,
            status = tracing::field::Empty,
            elapsed_ms = tracing::field::Empty
        )
        .entered();
        Self {
            operation,
            started: Instant::now(),
            status: "error",
            span,
            shadow: graph_shadow_active(),
        }
    }

    pub fn succeed(&mut self) {
        self.status = "ok";
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.span.record("status", self.status);
        self.span
            .record("elapsed_ms", self.started.elapsed().as_millis() as u64);
        if self.shadow {
            metrics::counter!(
                "graph_shadow_operation_total",
                "operation" => self.operation,
                "status" => self.status
            )
            .increment(1);
        } else {
            observe_operation(self.operation, self.started, self.status);
        }
    }
}
