//! Bounded timing-only execution of sampled graph-plan alternatives.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    time::Instant,
};

#[cfg(test)]
use std::{
    sync::{Condvar, Mutex},
    time::Duration,
};

use crate::{
    Result,
    graph::{ExactGraphSearchRequest, GraphError, GraphErrorCode, GraphRetrievalPlan},
    graph_planner::{GraphPlanFailurePolicy, GraphPlanSelection, GraphPlannerState},
    model::{HybridSearchRequest, SearchRequest},
};

use super::{Db, graph_retrieval::GraphDispatchPolicies};

const SHADOW_QUEUE_CAPACITY: usize = 16;
type ShadowJob = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Debug)]
pub(super) struct GraphShadowSpec {
    pub(super) calibration_version: u64,
    pub(super) envelope_version: u64,
    pub(super) sample_bps: u16,
    pub(super) candidates: Vec<GraphRetrievalPlan>,
}

#[derive(Clone, Debug)]
pub(super) struct GraphShadowExecution {
    pub(super) chosen: GraphRetrievalPlan,
    pub(super) chosen_elapsed_us: u64,
    pub(super) state: GraphPlannerState,
    pub(super) policies: GraphDispatchPolicies,
    pub(super) spec: GraphShadowSpec,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphShadowPlanTiming {
    pub(crate) plan: GraphRetrievalPlan,
    pub(crate) elapsed_us: u64,
    pub(crate) error_code: Option<&'static str>,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "identity retained for sampled-regret evidence")
)]
pub(crate) struct GraphShadowReport {
    pub(crate) collection: String,
    pub(crate) calibration_version: u64,
    pub(crate) envelope_version: u64,
    pub(crate) chosen: GraphRetrievalPlan,
    pub(crate) chosen_elapsed_us: u64,
    pub(crate) alternatives: Vec<GraphShadowPlanTiming>,
}

#[derive(Debug)]
pub(crate) struct GraphShadowRuntime {
    sender: SyncSender<ShadowJob>,
    sequence: AtomicU64,
    #[cfg(test)]
    reports: Arc<(Mutex<Vec<GraphShadowReport>>, Condvar)>,
}

impl GraphShadowRuntime {
    pub(crate) fn new() -> Arc<Self> {
        let (sender, receiver) = mpsc::sync_channel::<ShadowJob>(SHADOW_QUEUE_CAPACITY);
        #[cfg(test)]
        let reports = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let runtime = Arc::new(Self {
            sender,
            sequence: AtomicU64::new(0),
            #[cfg(test)]
            reports: Arc::clone(&reports),
        });
        std::thread::Builder::new()
            .name("chirondb-graph-shadow".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                        metrics::counter!("graph_shadow_worker_panic_total").increment(1);
                    }
                }
            })
            .expect("graph shadow worker thread");
        runtime
    }

    pub(super) fn should_sample(&self, sample_bps: u16) -> bool {
        if sample_bps == 0 {
            return false;
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        // Coprime with 10_000, so each full window visits every basis-point
        // bucket exactly once without concentrating samples at the start.
        let bucket = (sequence % 10_000) * 7_919 % 10_000;
        bucket < u64::from(sample_bps)
    }

    pub(super) fn submit(&self, task: impl FnOnce() -> GraphShadowReport + Send + 'static) {
        #[cfg(test)]
        let reports = Arc::clone(&self.reports);
        let job = Box::new(move || {
            let report = task();
            observe_report(&report);
            #[cfg(test)]
            {
                let (lock, ready) = &*reports;
                lock.lock().expect("shadow report lock").push(report);
                ready.notify_all();
            }
        });
        match self.sender.try_send(job) {
            Ok(()) => {
                metrics::counter!("graph_shadow_sample_total", "status" => "queued").increment(1)
            }
            Err(TrySendError::Full(_)) => {
                metrics::counter!("graph_shadow_sample_total", "status" => "queue_full")
                    .increment(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                metrics::counter!("graph_shadow_sample_total", "status" => "unavailable")
                    .increment(1);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn wait_for_report(
        &self,
        collection: &str,
        calibration_version: u64,
        timeout: Duration,
    ) -> Option<GraphShadowReport> {
        let deadline = Instant::now() + timeout;
        let (lock, ready) = &*self.reports;
        let mut reports = lock.lock().expect("shadow report lock");
        loop {
            if let Some(index) = reports.iter().position(|report| {
                report.collection == collection && report.calibration_version == calibration_version
            }) {
                return Some(reports.remove(index));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, timed) = ready
                .wait_timeout(reports, remaining)
                .expect("shadow report wait");
            reports = next;
            if timed.timed_out() {
                return None;
            }
        }
    }
}

fn observe_report(report: &GraphShadowReport) {
    let mut best = report.chosen_elapsed_us.max(1);
    let mut complete = true;
    metrics::histogram!(
        "graph_shadow_plan_duration_seconds",
        "plan" => report.chosen.as_str(),
        "status" => "chosen"
    )
    .record(report.chosen_elapsed_us as f64 / 1_000_000.0);
    for timing in &report.alternatives {
        let status = timing.error_code.unwrap_or("ok");
        metrics::histogram!(
            "graph_shadow_plan_duration_seconds",
            "plan" => timing.plan.as_str(),
            "status" => status
        )
        .record(timing.elapsed_us as f64 / 1_000_000.0);
        if timing.error_code.is_some() {
            complete = false;
        } else {
            best = best.min(timing.elapsed_us.max(1));
        }
    }
    if complete {
        metrics::histogram!("graph_shadow_regret_ratio")
            .record(report.chosen_elapsed_us.max(1) as f64 / best as f64);
        metrics::counter!("graph_shadow_sample_total", "status" => "complete").increment(1);
    } else {
        metrics::counter!("graph_shadow_sample_total", "status" => "incomplete").increment(1);
    }
}

fn shadow_selection(plan: GraphRetrievalPlan, state: GraphPlannerState) -> GraphPlanSelection {
    GraphPlanSelection {
        plan,
        guard: None,
        fallback_from: None,
        fallback_reason: None,
        degraded: false,
        failure_policy: if plan == GraphRetrievalPlan::P1Exact {
            GraphPlanFailurePolicy::Error
        } else {
            GraphPlanFailurePolicy::ExactP1OrError
        },
        expected_state: Some(state),
    }
}

impl Db {
    pub(super) fn schedule_dense_graph_shadow(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: crate::tenant::TenantScope,
        execution: GraphShadowExecution,
    ) {
        let GraphShadowExecution {
            chosen,
            chosen_elapsed_us,
            state,
            policies,
            spec,
        } = execution;
        if !self.graph_shadow_runtime.should_sample(spec.sample_bps) {
            return;
        }
        let db = self.clone();
        let collection = collection_name.to_string();
        self.graph_shadow_runtime.submit(move || {
            let alternatives = spec
                .candidates
                .iter()
                .copied()
                .filter(|plan| *plan != chosen)
                .map(|plan| {
                    let started = Instant::now();
                    let result = db.execute_dense_shadow_plan(
                        &collection,
                        request.clone(),
                        &scope,
                        plan,
                        state,
                        policies,
                    );
                    GraphShadowPlanTiming {
                        plan,
                        elapsed_us: elapsed_us(started),
                        error_code: result
                            .as_ref()
                            .err()
                            .map(super::graph_retrieval::audit_error_code),
                    }
                })
                .collect();
            GraphShadowReport {
                collection,
                calibration_version: spec.calibration_version,
                envelope_version: spec.envelope_version,
                chosen,
                chosen_elapsed_us,
                alternatives,
            }
        });
    }

    pub(super) fn schedule_hybrid_graph_shadow(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: crate::tenant::TenantScope,
        execution: GraphShadowExecution,
    ) {
        let GraphShadowExecution {
            chosen,
            chosen_elapsed_us,
            state,
            policies,
            spec,
        } = execution;
        if !self.graph_shadow_runtime.should_sample(spec.sample_bps) {
            return;
        }
        let db = self.clone();
        let collection = collection_name.to_string();
        self.graph_shadow_runtime.submit(move || {
            let alternatives = spec
                .candidates
                .iter()
                .copied()
                .filter(|plan| *plan != chosen)
                .map(|plan| {
                    let started = Instant::now();
                    let result = db.execute_hybrid_shadow_plan(
                        &collection,
                        request.clone(),
                        &scope,
                        plan,
                        state,
                        policies,
                    );
                    GraphShadowPlanTiming {
                        plan,
                        elapsed_us: elapsed_us(started),
                        error_code: result
                            .as_ref()
                            .err()
                            .map(super::graph_retrieval::audit_error_code),
                    }
                })
                .collect();
            GraphShadowReport {
                collection,
                calibration_version: spec.calibration_version,
                envelope_version: spec.envelope_version,
                chosen,
                chosen_elapsed_us,
                alternatives,
            }
        });
    }

    fn execute_dense_shadow_plan(
        &self,
        collection_name: &str,
        request: SearchRequest,
        scope: &crate::tenant::TenantScope,
        plan: GraphRetrievalPlan,
        state: GraphPlannerState,
        policies: GraphDispatchPolicies,
    ) -> Result<()> {
        let _shadow = crate::observability::GraphShadowExecutionGuard::enter();
        self.ensure_shadow_state(collection_name, state)?;
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let selection = shadow_selection(plan, state);
        match plan {
            GraphRetrievalPlan::P1Exact => {
                let graph = request.graph.clone().ok_or_else(|| {
                    crate::GaussError::InvalidRequest("shadow P1 requires graph".into())
                })?;
                self.exact_graph_search_cancellable_scoped_with_state(
                    collection_name,
                    ExactGraphSearchRequest {
                        vector: request.vector,
                        vector_name: request.vector_name,
                        k: request.k,
                        filter: request.filter,
                        graph,
                        with_payload: Some(false),
                    },
                    scope,
                    &cancelled,
                    Some(state),
                )?;
            }
            GraphRetrievalPlan::P2PrefilteredCascade => {
                self.p2_graph_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                )?;
            }
            GraphRetrievalPlan::P3ProgressiveProbe => {
                self.p3_graph_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                    policies.p3,
                )?;
            }
            GraphRetrievalPlan::P4ReachabilityAwareBeam => {
                self.p4_graph_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                )?;
            }
            GraphRetrievalPlan::P5BestFirst => {
                self.p5_graph_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                    policies.p5,
                )?;
            }
            GraphRetrievalPlan::P3HybridJointWidening => {
                return Err(crate::GaussError::InvalidRequest(
                    "dense shadow cannot execute P3H".into(),
                ));
            }
        }
        Ok(())
    }

    fn execute_hybrid_shadow_plan(
        &self,
        collection_name: &str,
        request: HybridSearchRequest,
        scope: &crate::tenant::TenantScope,
        plan: GraphRetrievalPlan,
        state: GraphPlannerState,
        policies: GraphDispatchPolicies,
    ) -> Result<()> {
        let _shadow = crate::observability::GraphShadowExecutionGuard::enter();
        self.ensure_shadow_state(collection_name, state)?;
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let selection = shadow_selection(plan, state);
        match plan {
            GraphRetrievalPlan::P1Exact => {
                self.exact_graph_hybrid_search_scoped_with_state(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    Some(state),
                )?;
            }
            GraphRetrievalPlan::P2PrefilteredCascade => {
                self.p2_graph_hybrid_search_scoped(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                )?;
            }
            GraphRetrievalPlan::P3HybridJointWidening => {
                self.p3h_graph_hybrid_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                    policies.p3h,
                )?;
            }
            GraphRetrievalPlan::P4ReachabilityAwareBeam => {
                self.p4_graph_hybrid_search_scoped_controlled(
                    collection_name,
                    request,
                    scope,
                    &cancelled,
                    selection,
                )?;
            }
            GraphRetrievalPlan::P3ProgressiveProbe | GraphRetrievalPlan::P5BestFirst => {
                return Err(crate::GaussError::InvalidRequest(
                    "hybrid shadow selected a dense-only plan".into(),
                ));
            }
        }
        Ok(())
    }

    fn ensure_shadow_state(
        &self,
        collection_name: &str,
        expected: GraphPlannerState,
    ) -> Result<()> {
        let coll = self.get_coll(collection_name)?;
        let collection = coll.read();
        let visibility = collection.overlay_read_state();
        if super::graph_retrieval::graph_planner_state(&collection, &visibility)? != expected {
            return Err(GraphError::new(
                GraphErrorCode::SloUnavailable,
                "sampled shadow state changed before alternative execution",
            )
            .into());
        }
        Ok(())
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::GraphShadowRuntime;

    #[test]
    fn deterministic_sampler_covers_each_basis_point_bucket_once_per_window() {
        let runtime = GraphShadowRuntime::new();
        let sampled = (0..10_000).filter(|_| runtime.should_sample(237)).count();
        assert_eq!(sampled, 237);
        assert!(!runtime.should_sample(0));
    }
}
