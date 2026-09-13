//! Deterministic graph retrieval plan eligibility.
//!
//! This module freezes the D5 planner vocabulary and guard order. Executors
//! consume its decisions in later D5 slices; until then, existing public graph
//! retrieval remains on exact P1.

use crate::{GaussError, Result, graph::GraphRetrievalPlan};

const BASIS_POINTS: u128 = 10_000;
const EXACT_SCAN_PERCENT: u128 = 5;
const EXACT_SCAN_MAX_CANDIDATES: usize = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphStatementMode {
    Dense,
    HybridRrf,
    HybridWeighted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphEstimate {
    Exact {
        admitted_points: usize,
    },
    Sketch {
        admitted_points: usize,
        competent: bool,
    },
    Probe {
        admitted_points: usize,
        conclusive: bool,
    },
}

impl GraphEstimate {
    pub(crate) fn admitted_points(self) -> usize {
        match self {
            Self::Exact { admitted_points }
            | Self::Sketch {
                admitted_points, ..
            }
            | Self::Probe {
                admitted_points, ..
            } => admitted_points,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum P5RecallEligibility {
    CalibratedMeetsTarget,
    CalibratedBelowTarget,
    Uncalibrated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct P5Calibration {
    /// Minimum measured specificity at which P5 becomes a candidate.
    pub(crate) min_specificity_bps: u16,
    /// Largest `k` covered by the same calibration envelope.
    pub(crate) max_k: usize,
    pub(crate) recall: P5RecallEligibility,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GraphPlannerCalibration {
    /// Calibrated floor below which P4 is mandatory. `None` means no claim.
    pub(crate) specificity_floor_bps: Option<u16>,
    /// Collection metric/topology-specific P5 envelope. `None` disables P5.
    pub(crate) p5: Option<P5Calibration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphPlanCosts {
    pub(crate) p1: u64,
    pub(crate) p2: u64,
    pub(crate) p3: u64,
    pub(crate) p3h: u64,
    pub(crate) p4: u64,
    pub(crate) p5: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphPlannerInput {
    pub(crate) statement_mode: GraphStatementMode,
    pub(crate) k: usize,
    pub(crate) collection_points: usize,
    pub(crate) estimate: GraphEstimate,
    pub(crate) calibration: GraphPlannerCalibration,
    pub(crate) p5_degraded_opt_in: bool,
    pub(crate) costs: GraphPlanCosts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphPlanFallbackReason {
    ProbeAmbiguous,
    P5RecallContract,
    P5HybridIncompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphPlannerGuard {
    ProbeAmbiguous,
    SpecificityFloor,
    BestFirstThreshold,
    SloIneligible,
    ModeIncompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphPlanFailurePolicy {
    Error,
    ExactP1OrError,
}

/// Exact collection cut for which one calibrated plan was selected.
/// Executors compare this ticket after acquiring their own pinned read state;
/// a publication race therefore falls back to P1 instead of using stale
/// calibration against a new graph/vector cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphPlannerState {
    pub(crate) graph_epoch: u64,
    pub(crate) schema_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) overlay_version: u64,
    pub(crate) wal_lsn: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphPlanSelection {
    pub(crate) plan: GraphRetrievalPlan,
    pub(crate) guard: Option<GraphPlannerGuard>,
    pub(crate) fallback_from: Option<GraphRetrievalPlan>,
    pub(crate) fallback_reason: Option<GraphPlanFallbackReason>,
    pub(crate) degraded: bool,
    pub(crate) failure_policy: GraphPlanFailurePolicy,
    pub(crate) expected_state: Option<GraphPlannerState>,
}

impl GraphPlanSelection {
    pub(crate) fn bind_state(mut self, state: GraphPlannerState) -> Self {
        self.expected_state = Some(state);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphPlannerDecision {
    ProbeRequired,
    Execute(GraphPlanSelection),
}

/// Select a graph retrieval plan using the normative Rev 3.4 guard order.
pub(crate) fn select_graph_plan(input: GraphPlannerInput) -> Result<GraphPlannerDecision> {
    validate_input(input)?;

    match input.estimate {
        GraphEstimate::Sketch {
            competent: false, ..
        } => return Ok(GraphPlannerDecision::ProbeRequired),
        GraphEstimate::Probe {
            conclusive: false, ..
        } => {
            return Ok(GraphPlannerDecision::Execute(selection(
                GraphRetrievalPlan::P2PrefilteredCascade,
                Some(GraphPlannerGuard::ProbeAmbiguous),
                None,
                Some(GraphPlanFallbackReason::ProbeAmbiguous),
                false,
            )));
        }
        GraphEstimate::Exact { .. }
        | GraphEstimate::Sketch {
            competent: true, ..
        }
        | GraphEstimate::Probe {
            conclusive: true, ..
        } => {}
    }

    let admitted_points = input.estimate.admitted_points();
    if input
        .calibration
        .specificity_floor_bps
        .is_some_and(|floor| ratio_is_below(admitted_points, input.collection_points, floor))
    {
        return Ok(GraphPlannerDecision::Execute(selection(
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
            Some(GraphPlannerGuard::SpecificityFloor),
            None,
            None,
            false,
        )));
    }

    if let Some(p5) = input.calibration.p5
        && ratio_is_at_least(
            admitted_points,
            input.collection_points,
            p5.min_specificity_bps,
        )
        && input.k <= p5.max_k
    {
        let degraded = p5.recall != P5RecallEligibility::CalibratedMeetsTarget;
        if degraded && !input.p5_degraded_opt_in {
            return Ok(GraphPlannerDecision::Execute(p5_fallback(
                input,
                GraphPlanFallbackReason::P5RecallContract,
            )));
        }
        if input.statement_mode != GraphStatementMode::Dense {
            return Ok(GraphPlannerDecision::Execute(p5_fallback(
                input,
                GraphPlanFallbackReason::P5HybridIncompatible,
            )));
        }
        return Ok(GraphPlannerDecision::Execute(selection(
            GraphRetrievalPlan::P5BestFirst,
            Some(GraphPlannerGuard::BestFirstThreshold),
            None,
            None,
            degraded,
        )));
    }

    let plan = cheapest_plan(
        ordinary_candidates(
            input.statement_mode,
            admitted_points,
            input.collection_points,
        ),
        input.costs,
    );
    Ok(GraphPlannerDecision::Execute(selection(
        plan, None, None, None, false,
    )))
}

/// Recall-eligible alternatives for sampled production timing. P1 is always
/// retained as the exact reference even when the dispatch seed would not
/// normally consider it. Guard-ineligible approximate plans are excluded so
/// shadow regret never rewards a fast result outside the active contract.
pub(crate) fn graph_shadow_candidates(input: GraphPlannerInput) -> Result<Vec<GraphRetrievalPlan>> {
    validate_input(input)?;
    if matches!(
        input.estimate,
        GraphEstimate::Sketch {
            competent: false,
            ..
        } | GraphEstimate::Probe {
            conclusive: false,
            ..
        }
    ) {
        return Ok(Vec::new());
    }
    let admitted = input.estimate.admitted_points();
    if input
        .calibration
        .specificity_floor_bps
        .is_some_and(|floor| ratio_is_below(admitted, input.collection_points, floor))
    {
        return Ok(vec![
            GraphRetrievalPlan::P1Exact,
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
        ]);
    }

    let mut candidates = match input.statement_mode {
        GraphStatementMode::Dense => vec![
            GraphRetrievalPlan::P1Exact,
            GraphRetrievalPlan::P2PrefilteredCascade,
            GraphRetrievalPlan::P3ProgressiveProbe,
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
        ],
        GraphStatementMode::HybridRrf => vec![
            GraphRetrievalPlan::P1Exact,
            GraphRetrievalPlan::P2PrefilteredCascade,
            GraphRetrievalPlan::P3HybridJointWidening,
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
        ],
        GraphStatementMode::HybridWeighted => return Ok(Vec::new()),
    };
    if input.statement_mode == GraphStatementMode::Dense
        && input.calibration.p5.is_some_and(|p5| {
            ratio_is_at_least(admitted, input.collection_points, p5.min_specificity_bps)
                && input.k <= p5.max_k
                && (p5.recall == P5RecallEligibility::CalibratedMeetsTarget
                    || input.p5_degraded_opt_in)
        })
    {
        candidates.push(GraphRetrievalPlan::P5BestFirst);
    }
    Ok(candidates)
}

fn validate_input(input: GraphPlannerInput) -> Result<()> {
    if input.collection_points == 0 {
        return Err(GaussError::InvalidRequest(
            "graph planner requires a non-empty collection".to_string(),
        ));
    }
    if input.k == 0 {
        return Err(GaussError::InvalidRequest(
            "graph planner k must be greater than zero".to_string(),
        ));
    }
    if input.estimate.admitted_points() > input.collection_points {
        return Err(GaussError::InvalidRequest(
            "graph estimate exceeds collection cardinality".to_string(),
        ));
    }
    if input
        .calibration
        .specificity_floor_bps
        .is_some_and(|floor| u128::from(floor) > BASIS_POINTS)
    {
        return Err(GaussError::InvalidRequest(
            "graph specificity floor exceeds 10000 basis points".to_string(),
        ));
    }
    if let Some(p5) = input.calibration.p5 {
        if u128::from(p5.min_specificity_bps) > BASIS_POINTS {
            return Err(GaussError::InvalidRequest(
                "graph P5 threshold exceeds 10000 basis points".to_string(),
            ));
        }
        if p5.max_k == 0 {
            return Err(GaussError::InvalidRequest(
                "graph P5 calibration max_k must be greater than zero".to_string(),
            ));
        }
    }
    Ok(())
}

fn ordinary_candidates(
    mode: GraphStatementMode,
    admitted_points: usize,
    collection_points: usize,
) -> &'static [GraphRetrievalPlan] {
    const DENSE_EXACT: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P1Exact,
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P3ProgressiveProbe,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const DENSE_APPROXIMATE: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P3ProgressiveProbe,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const HYBRID_EXACT: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P1Exact,
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P3HybridJointWidening,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const HYBRID_APPROXIMATE: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P3HybridJointWidening,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const WEIGHTED_EXACT: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P1Exact,
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const WEIGHTED_APPROXIMATE: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];

    match (mode, exact_scan_seed(admitted_points, collection_points)) {
        (GraphStatementMode::Dense, true) => DENSE_EXACT,
        (GraphStatementMode::Dense, false) => DENSE_APPROXIMATE,
        (GraphStatementMode::HybridRrf, true) => HYBRID_EXACT,
        (GraphStatementMode::HybridRrf, false) => HYBRID_APPROXIMATE,
        (GraphStatementMode::HybridWeighted, true) => WEIGHTED_EXACT,
        (GraphStatementMode::HybridWeighted, false) => WEIGHTED_APPROXIMATE,
    }
}

fn p5_fallback(input: GraphPlannerInput, reason: GraphPlanFallbackReason) -> GraphPlanSelection {
    const DENSE: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const HYBRID_RRF: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P3HybridJointWidening,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    const HYBRID_WEIGHTED: &[GraphRetrievalPlan] = &[
        GraphRetrievalPlan::P2PrefilteredCascade,
        GraphRetrievalPlan::P4ReachabilityAwareBeam,
    ];
    let candidates = match input.statement_mode {
        GraphStatementMode::Dense => DENSE,
        GraphStatementMode::HybridRrf => HYBRID_RRF,
        GraphStatementMode::HybridWeighted => HYBRID_WEIGHTED,
    };
    selection(
        cheapest_plan(candidates, input.costs),
        Some(match reason {
            GraphPlanFallbackReason::P5RecallContract => GraphPlannerGuard::SloIneligible,
            GraphPlanFallbackReason::P5HybridIncompatible => GraphPlannerGuard::ModeIncompatible,
            GraphPlanFallbackReason::ProbeAmbiguous => GraphPlannerGuard::ProbeAmbiguous,
        }),
        Some(GraphRetrievalPlan::P5BestFirst),
        Some(reason),
        false,
    )
}

fn cheapest_plan(candidates: &[GraphRetrievalPlan], costs: GraphPlanCosts) -> GraphRetrievalPlan {
    candidates
        .iter()
        .copied()
        .min_by_key(|plan| plan_cost(*plan, costs))
        .expect("planner candidate sets are non-empty")
}

fn plan_cost(plan: GraphRetrievalPlan, costs: GraphPlanCosts) -> u64 {
    match plan {
        GraphRetrievalPlan::P1Exact => costs.p1,
        GraphRetrievalPlan::P2PrefilteredCascade => costs.p2,
        GraphRetrievalPlan::P3ProgressiveProbe => costs.p3,
        GraphRetrievalPlan::P3HybridJointWidening => costs.p3h,
        GraphRetrievalPlan::P4ReachabilityAwareBeam => costs.p4,
        GraphRetrievalPlan::P5BestFirst => costs.p5,
    }
}

fn selection(
    plan: GraphRetrievalPlan,
    guard: Option<GraphPlannerGuard>,
    fallback_from: Option<GraphRetrievalPlan>,
    fallback_reason: Option<GraphPlanFallbackReason>,
    degraded: bool,
) -> GraphPlanSelection {
    let failure_policy = if plan == GraphRetrievalPlan::P1Exact {
        GraphPlanFailurePolicy::Error
    } else {
        GraphPlanFailurePolicy::ExactP1OrError
    };
    GraphPlanSelection {
        plan,
        guard,
        fallback_from,
        fallback_reason,
        degraded,
        failure_policy,
        expected_state: None,
    }
}

pub(super) fn exact_scan_seed(admitted_points: usize, collection_points: usize) -> bool {
    admitted_points <= EXACT_SCAN_MAX_CANDIDATES
        && (admitted_points as u128) * 100 <= (collection_points as u128) * EXACT_SCAN_PERCENT
}

pub(super) fn ratio_is_below(
    admitted_points: usize,
    collection_points: usize,
    threshold_bps: u16,
) -> bool {
    (admitted_points as u128) * BASIS_POINTS
        < (collection_points as u128) * u128::from(threshold_bps)
}

pub(super) fn ratio_is_at_least(
    admitted_points: usize,
    collection_points: usize,
    threshold_bps: u16,
) -> bool {
    !ratio_is_below(admitted_points, collection_points, threshold_bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn costs() -> GraphPlanCosts {
        GraphPlanCosts {
            p1: 1,
            p2: 20,
            p3: 30,
            p3h: 10,
            p4: 40,
            p5: 0,
        }
    }

    fn input(mode: GraphStatementMode) -> GraphPlannerInput {
        GraphPlannerInput {
            statement_mode: mode,
            k: 10,
            collection_points: 100_000,
            estimate: GraphEstimate::Sketch {
                admitted_points: 20_000,
                competent: true,
            },
            calibration: GraphPlannerCalibration::default(),
            p5_degraded_opt_in: false,
            costs: costs(),
        }
    }

    fn executed(decision: GraphPlannerDecision) -> GraphPlanSelection {
        match decision {
            GraphPlannerDecision::Execute(selection) => selection,
            GraphPlannerDecision::ProbeRequired => panic!("expected executable plan"),
        }
    }

    #[test]
    fn vocabulary_has_stable_wire_names() {
        let plans = [
            (GraphRetrievalPlan::P1Exact, "\"p1_exact\""),
            (
                GraphRetrievalPlan::P2PrefilteredCascade,
                "\"p2_prefiltered_cascade\"",
            ),
            (
                GraphRetrievalPlan::P3ProgressiveProbe,
                "\"p3_progressive_probe\"",
            ),
            (
                GraphRetrievalPlan::P3HybridJointWidening,
                "\"p3h_joint_widening\"",
            ),
            (
                GraphRetrievalPlan::P4ReachabilityAwareBeam,
                "\"p4_reachability_aware_beam\"",
            ),
            (GraphRetrievalPlan::P5BestFirst, "\"p5_best_first\""),
        ];
        for (plan, encoded) in plans {
            assert_eq!(serde_json::to_string(&plan).unwrap(), encoded);
            assert_eq!(
                serde_json::from_str::<GraphRetrievalPlan>(encoded).unwrap(),
                plan
            );
        }
    }

    #[test]
    fn estimator_outside_competence_requires_probe() {
        let mut request = input(GraphStatementMode::Dense);
        request.estimate = GraphEstimate::Sketch {
            admitted_points: 20_000,
            competent: false,
        };
        assert_eq!(
            select_graph_plan(request).unwrap(),
            GraphPlannerDecision::ProbeRequired
        );
    }

    #[test]
    fn ambiguous_probe_falls_back_to_p2() {
        let mut request = input(GraphStatementMode::HybridRrf);
        request.estimate = GraphEstimate::Probe {
            admitted_points: 20_000,
            conclusive: false,
        };
        let selection = executed(select_graph_plan(request).unwrap());
        assert_eq!(selection.plan, GraphRetrievalPlan::P2PrefilteredCascade);
        assert_eq!(selection.guard, Some(GraphPlannerGuard::ProbeAmbiguous));
        assert_eq!(
            selection.fallback_reason,
            Some(GraphPlanFallbackReason::ProbeAmbiguous)
        );
        assert_eq!(
            selection.failure_policy,
            GraphPlanFailurePolicy::ExactP1OrError
        );
    }

    #[test]
    fn specificity_floor_precedes_p5_and_costs() {
        let mut request = input(GraphStatementMode::Dense);
        request.estimate = GraphEstimate::Exact {
            admitted_points: 99,
        };
        request.collection_points = 10_000;
        request.calibration = GraphPlannerCalibration {
            specificity_floor_bps: Some(100),
            p5: Some(P5Calibration {
                min_specificity_bps: 0,
                max_k: 100,
                recall: P5RecallEligibility::CalibratedMeetsTarget,
            }),
        };
        let selection = executed(select_graph_plan(request).unwrap());
        assert_eq!(selection.plan, GraphRetrievalPlan::P4ReachabilityAwareBeam);
        assert_eq!(selection.guard, Some(GraphPlannerGuard::SpecificityFloor));
        assert_eq!(
            selection.failure_policy,
            GraphPlanFailurePolicy::ExactP1OrError
        );
    }

    #[test]
    fn p5_requires_recall_eligibility_or_degraded_opt_in() {
        for recall in [
            P5RecallEligibility::Uncalibrated,
            P5RecallEligibility::CalibratedBelowTarget,
        ] {
            let mut request = input(GraphStatementMode::Dense);
            request.calibration.p5 = Some(P5Calibration {
                min_specificity_bps: 1_000,
                max_k: 10,
                recall,
            });
            let fallback = executed(select_graph_plan(request).unwrap());
            assert_eq!(fallback.plan, GraphRetrievalPlan::P2PrefilteredCascade);
            assert_eq!(
                fallback.fallback_from,
                Some(GraphRetrievalPlan::P5BestFirst)
            );
            assert_eq!(
                fallback.fallback_reason,
                Some(GraphPlanFallbackReason::P5RecallContract)
            );
            assert_eq!(fallback.guard, Some(GraphPlannerGuard::SloIneligible));
            assert!(!fallback.degraded);

            request.p5_degraded_opt_in = true;
            let degraded = executed(select_graph_plan(request).unwrap());
            assert_eq!(degraded.plan, GraphRetrievalPlan::P5BestFirst);
            assert_eq!(degraded.guard, Some(GraphPlannerGuard::BestFirstThreshold));
            assert!(degraded.degraded);
        }
    }

    #[test]
    fn calibrated_dense_p5_is_selected_inside_envelope() {
        let mut request = input(GraphStatementMode::Dense);
        request.calibration.p5 = Some(P5Calibration {
            min_specificity_bps: 1_000,
            max_k: 10,
            recall: P5RecallEligibility::CalibratedMeetsTarget,
        });
        let selection = executed(select_graph_plan(request).unwrap());
        assert_eq!(selection.plan, GraphRetrievalPlan::P5BestFirst);
        assert_eq!(selection.guard, Some(GraphPlannerGuard::BestFirstThreshold));
        assert!(!selection.degraded);
    }

    #[test]
    fn hybrid_excludes_p5_after_recall_guard_and_uses_lowest_cost() {
        let mut request = input(GraphStatementMode::HybridRrf);
        request.calibration.p5 = Some(P5Calibration {
            min_specificity_bps: 1_000,
            max_k: 10,
            recall: P5RecallEligibility::CalibratedMeetsTarget,
        });
        let selection = executed(select_graph_plan(request).unwrap());
        assert_eq!(selection.plan, GraphRetrievalPlan::P3HybridJointWidening);
        assert_eq!(
            selection.fallback_from,
            Some(GraphRetrievalPlan::P5BestFirst)
        );
        assert_eq!(
            selection.fallback_reason,
            Some(GraphPlanFallbackReason::P5HybridIncompatible)
        );
        assert_eq!(selection.guard, Some(GraphPlannerGuard::ModeIncompatible));
    }

    #[test]
    fn weighted_hybrid_excludes_p3h_unseen_bound_and_p5() {
        let mut request = input(GraphStatementMode::HybridWeighted);
        let ordinary = executed(select_graph_plan(request).unwrap());
        assert_eq!(ordinary.plan, GraphRetrievalPlan::P2PrefilteredCascade);

        request.calibration.p5 = Some(P5Calibration {
            min_specificity_bps: 1_000,
            max_k: 10,
            recall: P5RecallEligibility::CalibratedMeetsTarget,
        });
        let p5_fallback = executed(select_graph_plan(request).unwrap());
        assert_eq!(p5_fallback.plan, GraphRetrievalPlan::P2PrefilteredCascade);
        assert_eq!(
            p5_fallback.fallback_from,
            Some(GraphRetrievalPlan::P5BestFirst)
        );
        assert_eq!(
            p5_fallback.fallback_reason,
            Some(GraphPlanFallbackReason::P5HybridIncompatible)
        );
    }

    #[test]
    fn p1_is_eligible_only_inside_engine_exact_scan_seed() {
        let mut request = input(GraphStatementMode::Dense);
        request.estimate = GraphEstimate::Exact {
            admitted_points: 5_000,
        };
        let exact = executed(select_graph_plan(request).unwrap());
        assert_eq!(exact.plan, GraphRetrievalPlan::P1Exact);
        assert_eq!(exact.failure_policy, GraphPlanFailurePolicy::Error);

        request.estimate = GraphEstimate::Exact {
            admitted_points: 5_001,
        };
        let approximate = executed(select_graph_plan(request).unwrap());
        assert_eq!(approximate.plan, GraphRetrievalPlan::P2PrefilteredCascade);
    }

    #[test]
    fn shadow_candidates_keep_exact_reference_and_exclude_ineligible_plans() {
        let dense = input(GraphStatementMode::Dense);
        assert_eq!(
            graph_shadow_candidates(dense).unwrap(),
            vec![
                GraphRetrievalPlan::P1Exact,
                GraphRetrievalPlan::P2PrefilteredCascade,
                GraphRetrievalPlan::P3ProgressiveProbe,
                GraphRetrievalPlan::P4ReachabilityAwareBeam,
            ]
        );

        let mut p5 = dense;
        p5.calibration.p5 = Some(P5Calibration {
            min_specificity_bps: 1_000,
            max_k: 10,
            recall: P5RecallEligibility::CalibratedMeetsTarget,
        });
        assert_eq!(
            graph_shadow_candidates(p5).unwrap().last(),
            Some(&GraphRetrievalPlan::P5BestFirst)
        );

        let mut floor = dense;
        floor.estimate = GraphEstimate::Exact { admitted_points: 1 };
        floor.calibration.specificity_floor_bps = Some(100);
        assert_eq!(
            graph_shadow_candidates(floor).unwrap(),
            vec![
                GraphRetrievalPlan::P1Exact,
                GraphRetrievalPlan::P4ReachabilityAwareBeam,
            ]
        );
        assert!(
            graph_shadow_candidates(input(GraphStatementMode::HybridWeighted))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invalid_planner_facts_fail_closed() {
        let mut request = input(GraphStatementMode::Dense);
        request.estimate = GraphEstimate::Exact {
            admitted_points: 100_001,
        };
        assert!(select_graph_plan(request).is_err());

        request.estimate = GraphEstimate::Exact { admitted_points: 1 };
        request.calibration.p5 = Some(P5Calibration {
            min_specificity_bps: 1,
            max_k: 0,
            recall: P5RecallEligibility::CalibratedMeetsTarget,
        });
        assert!(select_graph_plan(request).is_err());
    }
}
