//! Bounded graph selectivity estimation and versioned recall envelopes.
//!
//! D6a freezes checked estimator inputs, fail-closed envelope matching, and
//! the encrypted atomic store. D6b extends each envelope with the measured
//! probe, cost, and executor controls needed for production dispatch.

use std::{collections::HashSet, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    DistanceMetric, GaussError, Result,
    encryption::{FileType, atomic_write_persistent, read_persistent},
    graph::{GraphDirection, MAX_GRAPH_DEPTH, TraversalTruncationReason},
    graph_planner::{
        GraphEstimate, GraphPlanCosts, GraphPlannerCalibration, GraphStatementMode, P5Calibration,
        P5RecallEligibility, exact_scan_seed, ratio_is_at_least, ratio_is_below,
    },
};

pub(crate) const GRAPH_CALIBRATION_FILE: &str = "graph_calibration.gdx";

const MAGIC: &[u8; 8] = b"CHRGCL02";
const FORMAT_VERSION: u16 = 2;
const HEADER_BYTES: usize = 32;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENCODED_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ENVELOPES: usize = 4_096;
const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphContractMode {
    Dense,
    HybridRrf,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphFilterShape {
    pub(crate) statement: bool,
    pub(crate) node: bool,
    pub(crate) edge: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphExecutionCalibration {
    pub(crate) p3_initial_factor: u32,
    pub(crate) p3_growth_factor: u32,
    pub(crate) p3_max_candidates: u32,
    pub(crate) p3h_dense_initial_factor: u32,
    pub(crate) p3h_dense_growth_factor: u32,
    pub(crate) p3h_dense_max_candidates: u32,
    pub(crate) p3h_sparse_initial_factor: u32,
    pub(crate) p3h_sparse_growth_factor: u32,
    pub(crate) p3h_sparse_max_candidates: u32,
    pub(crate) p5_max_expansions: u32,
    /// Deterministic sampled-shadow rate in basis points. Zero disables
    /// production shadows for legacy calibration artifacts; the rate is
    /// calibration-owned and is never a request or collection knob.
    #[serde(default)]
    pub(crate) shadow_sample_bps: u16,
}

/// Integer work coefficients produced by the calibration harness.
///
/// Units are deliberately opaque and comparable only inside one envelope.
/// No wall-clock promise is inferred from them; the planner only uses their
/// relative order after every structural and recall guard has passed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphCostCalibration {
    pub(crate) mean_visible_degree_milli: u32,
    pub(crate) edge_visit_units: u32,
    pub(crate) translation_units: u32,
    pub(crate) distance_component_units: u32,
    pub(crate) dense_candidate_units: u32,
    pub(crate) sparse_candidate_units: u32,
    pub(crate) fusion_candidate_units: u32,
    pub(crate) p4_navigation_units: u32,
}

impl GraphCostCalibration {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_costs(
        self,
        execution: GraphExecutionCalibration,
        mode: GraphStatementMode,
        collection_points: usize,
        admitted_points: usize,
        dimension: u32,
        hops: u32,
        k: usize,
    ) -> Result<GraphPlanCosts> {
        if collection_points == 0
            || admitted_points > collection_points
            || dimension == 0
            || hops == 0
            || k == 0
        {
            return Err(invalid("invalid graph cost-model inputs"));
        }
        validate_cost_calibration(self).map_err(invalid)?;
        validate_execution_calibration(execution).map_err(invalid)?;

        let admitted = admitted_points as u128;
        let collection = collection_points as u128;
        let dimension = u128::from(dimension);
        let k = k as u128;
        let mean_edges = admitted
            .saturating_mul(u128::from(self.mean_visible_degree_milli))
            .div_ceil(1_000);
        let expansion = mean_edges.saturating_mul(u128::from(self.edge_visit_units));
        let exact_distance = admitted
            .saturating_mul(dimension)
            .saturating_mul(u128::from(self.distance_component_units));
        let translation = admitted.saturating_mul(u128::from(self.translation_units));
        let branch_limit = admitted.min(k.saturating_mul(4).max(k));
        let dense_branch = branch_limit.saturating_mul(u128::from(self.dense_candidate_units));
        let sparse_branch = branch_limit.saturating_mul(u128::from(self.sparse_candidate_units));
        let fusion = branch_limit.saturating_mul(u128::from(self.fusion_candidate_units));
        let hybrid_extra = match mode {
            GraphStatementMode::Dense => 0,
            GraphStatementMode::HybridRrf | GraphStatementMode::HybridWeighted => {
                sparse_branch.saturating_add(fusion)
            }
        };

        let p3_candidates = collection.min(u128::from(execution.p3_max_candidates));
        let p3h_dense = collection.min(u128::from(execution.p3h_dense_max_candidates));
        let p3h_sparse = collection.min(u128::from(execution.p3h_sparse_max_candidates));
        let mean_degree = u128::from(self.mean_visible_degree_milli).div_ceil(1_000);
        let mut probe_edges = 1_u128;
        for _ in 0..hops.div_ceil(2) {
            probe_edges = probe_edges.saturating_mul(mean_degree);
        }
        let probe_unit = probe_edges.saturating_mul(u128::from(self.edge_visit_units));
        let p3 = p3_candidates
            .saturating_mul(u128::from(self.dense_candidate_units))
            .saturating_add(p3_candidates.saturating_mul(probe_unit));
        let p3h = p3h_dense
            .saturating_mul(u128::from(self.dense_candidate_units))
            .saturating_add(p3h_sparse.saturating_mul(u128::from(self.sparse_candidate_units)))
            .saturating_add(
                p3h_dense
                    .saturating_add(p3h_sparse)
                    .saturating_mul(probe_unit),
            )
            .saturating_add(
                p3h_dense
                    .saturating_add(p3h_sparse)
                    .saturating_mul(u128::from(self.fusion_candidate_units)),
            );
        let p4 = expansion
            .saturating_add(translation)
            .saturating_add(branch_limit.saturating_mul(u128::from(self.p4_navigation_units)))
            .saturating_add(dense_branch)
            .saturating_add(hybrid_extra);
        let p5_expansions = admitted.min(u128::from(execution.p5_max_expansions));
        let p5 = p5_expansions
            .saturating_mul(mean_degree)
            .saturating_mul(u128::from(self.edge_visit_units))
            .saturating_add(
                p5_expansions
                    .saturating_mul(dimension)
                    .saturating_mul(u128::from(self.distance_component_units)),
            );

        Ok(GraphPlanCosts {
            p1: units(expansion.saturating_add(exact_distance)),
            p2: units(
                expansion
                    .saturating_add(translation)
                    .saturating_add(dense_branch)
                    .saturating_add(hybrid_extra),
            ),
            p3: units(p3),
            p3h: units(p3h),
            p4: units(p4),
            p5: units(p5),
        })
    }
}

fn units(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl GraphFilterShape {
    const fn is_unfiltered(self) -> bool {
        !self.statement && !self.node && !self.edge
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphCalibrationEnvelope {
    pub(crate) envelope_version: u64,
    pub(crate) mode: GraphContractMode,
    pub(crate) vector_field: Option<String>,
    pub(crate) metric: DistanceMetric,
    pub(crate) dimension: u32,
    pub(crate) topology_family: String,
    pub(crate) graph_epoch: u64,
    pub(crate) schema_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) direction: GraphDirection,
    pub(crate) typed: bool,
    pub(crate) min_hops: u32,
    pub(crate) max_hops: u32,
    pub(crate) filters: GraphFilterShape,
    pub(crate) min_specificity_bps: u16,
    pub(crate) max_specificity_bps: u16,
    pub(crate) max_overlay_lsn_lag: u64,
    pub(crate) planner_policy_version: u32,
    pub(crate) branch_depth_policy_version: u32,
    pub(crate) max_k: u32,
    pub(crate) target_recall_bps: u16,
    pub(crate) specificity_floor_bps: Option<u16>,
    pub(crate) p5_min_specificity_bps: Option<u16>,
    pub(crate) p5_max_k: Option<u32>,
    pub(crate) p5_observed_recall_bps: Option<u16>,
    pub(crate) probe_policy: BoundedProbePolicy,
    pub(crate) costs: GraphCostCalibration,
    pub(crate) execution: GraphExecutionCalibration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphProfileQuery<'a> {
    pub(crate) mode: GraphContractMode,
    pub(crate) vector_field: Option<&'a str>,
    pub(crate) metric: DistanceMetric,
    pub(crate) dimension: u32,
    pub(crate) graph_epoch: u64,
    pub(crate) schema_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) direction: GraphDirection,
    pub(crate) typed: bool,
    pub(crate) hops: u32,
    pub(crate) filters: GraphFilterShape,
    pub(crate) overlay_lsn_lag: u64,
    pub(crate) planner_policy_version: u32,
    pub(crate) branch_depth_policy_version: u32,
    pub(crate) k: u32,
    pub(crate) target_recall_bps: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphCalibrationProfile {
    pub(crate) topology_family: String,
    pub(crate) probe_policy: BoundedProbePolicy,
    pub(crate) costs: GraphCostCalibration,
    pub(crate) execution: GraphExecutionCalibration,
    pub(crate) boundaries: ProbeDecisionBoundaries,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphEnvelopeQuery<'a> {
    pub(crate) mode: GraphContractMode,
    pub(crate) vector_field: Option<&'a str>,
    pub(crate) metric: DistanceMetric,
    pub(crate) dimension: u32,
    pub(crate) topology_family: &'a str,
    pub(crate) graph_epoch: u64,
    pub(crate) schema_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) direction: GraphDirection,
    pub(crate) typed: bool,
    pub(crate) hops: u32,
    pub(crate) filters: GraphFilterShape,
    pub(crate) min_specificity_bps: u16,
    pub(crate) max_specificity_bps: u16,
    pub(crate) overlay_lsn_lag: u64,
    pub(crate) planner_policy_version: u32,
    pub(crate) branch_depth_policy_version: u32,
    pub(crate) k: u32,
    pub(crate) target_recall_bps: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphEnvelopeMatch {
    pub(crate) envelope_version: u64,
    pub(crate) calibration: GraphPlannerCalibration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphCalibrationStore {
    pub(crate) calibration_version: u64,
    pub(crate) envelopes: Vec<GraphCalibrationEnvelope>,
}

impl GraphCalibrationStore {
    #[allow(dead_code, reason = "called by the controlled Db publication boundary")]
    pub(crate) fn validate(&self) -> Result<()> {
        validate_store(self).map_err(invalid)
    }

    pub(crate) fn open(collection_dir: &Path) -> Result<Option<Self>> {
        let path = calibration_path(collection_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(corrupt(&path, "calibration path is not a regular file"));
        }
        if metadata.len() > MAX_ENCODED_FILE_BYTES {
            return Err(corrupt(&path, "calibration file exceeds fixed size cap"));
        }
        decode(&path, &read_persistent(&path)?).map(Some)
    }

    pub(crate) fn publish(&self, collection_dir: &Path) -> Result<()> {
        validate_store(self).map_err(invalid)?;
        let encoded = encode(self)?;
        if encoded.len() as u64 > MAX_FILE_BYTES {
            return Err(invalid("graph calibration file exceeds fixed size cap"));
        }
        atomic_write_persistent(
            &calibration_path(collection_dir),
            FileType::Metadata,
            &encoded,
        )
    }

    /// Return calibration only for one exact versioned envelope. Missing,
    /// stale, or ambiguous calibration never becomes a positive SLO claim.
    pub(crate) fn lookup(
        &self,
        query: &GraphEnvelopeQuery<'_>,
    ) -> Result<Option<GraphEnvelopeMatch>> {
        validate_query(query).map_err(invalid)?;
        let mut matches = self
            .envelopes
            .iter()
            .filter(|envelope| envelope.matches(query));
        let Some(envelope) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(invalid(
                "graph calibration contains overlapping eligibility envelopes",
            ));
        }
        Ok(Some(GraphEnvelopeMatch {
            envelope_version: envelope.envelope_version,
            calibration: envelope.planner_calibration(),
        }))
    }

    /// Resolve the calibration-owned controls available before selectivity is
    /// known. Multiple specificity buckets may match, but they must agree on
    /// topology, probe policy, cost coefficients, executor controls, and the
    /// decision boundaries used by the probe. Disagreement is corrupt
    /// calibration, never a reason to guess.
    pub(crate) fn profile(
        &self,
        query: &GraphProfileQuery<'_>,
    ) -> Result<Option<GraphCalibrationProfile>> {
        validate_profile_query(query).map_err(invalid)?;
        let mut candidates = self
            .envelopes
            .iter()
            .filter(|envelope| envelope.matches_profile(query));
        let Some(first) = candidates.next() else {
            return Ok(None);
        };
        let profile = first.profile();
        if candidates.any(|candidate| candidate.profile() != profile) {
            return Err(invalid(
                "graph calibration specificity buckets disagree on dispatch controls",
            ));
        }
        Ok(Some(profile))
    }
}

impl GraphCalibrationEnvelope {
    fn matches(&self, query: &GraphEnvelopeQuery<'_>) -> bool {
        self.mode == query.mode
            && self.vector_field.as_deref() == query.vector_field
            && self.metric == query.metric
            && self.dimension == query.dimension
            && self.topology_family == query.topology_family
            && self.graph_epoch == query.graph_epoch
            && self.schema_epoch == query.schema_epoch
            && self.manifest_generation == query.manifest_generation
            && self.overlay_generation == query.overlay_generation
            && self.direction == query.direction
            && self.typed == query.typed
            && (self.min_hops..=self.max_hops).contains(&query.hops)
            && self.filters == query.filters
            && self.min_specificity_bps <= query.min_specificity_bps
            && query.max_specificity_bps <= self.max_specificity_bps
            && query.overlay_lsn_lag <= self.max_overlay_lsn_lag
            && self.planner_policy_version == query.planner_policy_version
            && self.branch_depth_policy_version == query.branch_depth_policy_version
            && query.k <= self.max_k
            && self.target_recall_bps == query.target_recall_bps
    }

    fn matches_profile(&self, query: &GraphProfileQuery<'_>) -> bool {
        self.mode == query.mode
            && self.vector_field.as_deref() == query.vector_field
            && self.metric == query.metric
            && self.dimension == query.dimension
            && self.graph_epoch == query.graph_epoch
            && self.schema_epoch == query.schema_epoch
            && self.manifest_generation == query.manifest_generation
            && self.overlay_generation == query.overlay_generation
            && self.direction == query.direction
            && self.typed == query.typed
            && (self.min_hops..=self.max_hops).contains(&query.hops)
            && self.filters == query.filters
            && query.overlay_lsn_lag <= self.max_overlay_lsn_lag
            && self.planner_policy_version == query.planner_policy_version
            && self.branch_depth_policy_version == query.branch_depth_policy_version
            && query.k <= self.max_k
            && self.target_recall_bps == query.target_recall_bps
    }

    fn profile(&self) -> GraphCalibrationProfile {
        GraphCalibrationProfile {
            topology_family: self.topology_family.clone(),
            probe_policy: self.probe_policy,
            costs: self.costs,
            execution: self.execution,
            boundaries: ProbeDecisionBoundaries {
                specificity_floor_bps: self.specificity_floor_bps,
                p5_min_specificity_bps: self.p5_min_specificity_bps,
            },
        }
    }

    fn planner_calibration(&self) -> GraphPlannerCalibration {
        let p5 = self.p5_min_specificity_bps.map(|min_specificity_bps| {
            let recall = match self.p5_observed_recall_bps {
                Some(observed) if observed >= self.target_recall_bps => {
                    P5RecallEligibility::CalibratedMeetsTarget
                }
                Some(_) => P5RecallEligibility::CalibratedBelowTarget,
                None => P5RecallEligibility::Uncalibrated,
            };
            P5Calibration {
                min_specificity_bps,
                max_k: self.p5_max_k.expect("validated P5 max_k") as usize,
                recall,
            }
        });
        GraphPlannerCalibration {
            specificity_floor_bps: self.specificity_floor_bps,
            p5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphEstimatorShape {
    pub(crate) direction: GraphDirection,
    pub(crate) typed: bool,
    pub(crate) hops: u32,
    pub(crate) filters: GraphFilterShape,
    pub(crate) graph_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) deletion_lsn: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphSketchEvidence {
    pub(crate) graph_epoch: u64,
    pub(crate) manifest_generation: u64,
    pub(crate) overlay_generation: u64,
    pub(crate) built_at_deletion_lsn: u64,
    pub(crate) max_hops: u32,
    pub(crate) anchor_eligible: bool,
    pub(crate) admitted_points: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphEstimatorRoute {
    Sketch(GraphEstimate),
    Probe,
}

/// Admit an optional sketch only inside its structural competence boundary.
/// There is intentionally no default estimate and no sketch builder in D6a.
pub(crate) fn choose_estimator(
    shape: GraphEstimatorShape,
    sketch: Option<GraphSketchEvidence>,
) -> GraphEstimatorRoute {
    let Some(sketch) = sketch else {
        return GraphEstimatorRoute::Probe;
    };
    let competent = shape.direction == GraphDirection::Both
        && !shape.typed
        && shape.filters.is_unfiltered()
        && shape.hops > 0
        && shape.hops <= sketch.max_hops
        && shape.graph_epoch == sketch.graph_epoch
        && shape.manifest_generation == sketch.manifest_generation
        && shape.overlay_generation == sketch.overlay_generation
        && shape.deletion_lsn == sketch.built_at_deletion_lsn
        && sketch.anchor_eligible;
    if competent {
        GraphEstimatorRoute::Sketch(GraphEstimate::Sketch {
            admitted_points: sketch.admitted_points,
            competent: true,
        })
    } else {
        GraphEstimatorRoute::Probe
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundedProbePolicy {
    pub(crate) edge_budget: u64,
    pub(crate) min_expanded_nodes: u64,
    pub(crate) relative_uncertainty_bps: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundedProbeObservation {
    pub(crate) target_hops: u32,
    pub(crate) completed_hops: u32,
    pub(crate) visible_nodes_seen: u64,
    pub(crate) visible_nodes_expanded: u64,
    pub(crate) visible_frontier_nodes: u64,
    pub(crate) visible_next_nodes_discovered: u64,
    pub(crate) visible_edges_examined: u64,
    pub(crate) truncation: Option<TraversalTruncationReason>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProbeDecisionBoundaries {
    pub(crate) specificity_floor_bps: Option<u16>,
    pub(crate) p5_min_specificity_bps: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundedProbeEstimate {
    pub(crate) planner_estimate: GraphEstimate,
    pub(crate) lower_admitted_points: usize,
    pub(crate) upper_admitted_points: usize,
}

impl BoundedProbeEstimate {
    pub(crate) fn specificity_interval_bps(self, collection_points: usize) -> Result<(u16, u16)> {
        if collection_points == 0
            || self.lower_admitted_points > self.upper_admitted_points
            || self.upper_admitted_points > collection_points
        {
            return Err(invalid("invalid bounded probe specificity interval"));
        }
        let points = collection_points as u128;
        let lower = (self.lower_admitted_points as u128).saturating_mul(BASIS_POINTS) / points;
        let upper = (self.upper_admitted_points as u128)
            .saturating_mul(BASIS_POINTS)
            .div_ceil(points);
        Ok((lower as u16, upper as u16))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecisionRegion {
    exact_scan: bool,
    below_specificity_floor: bool,
    p5_candidate: bool,
}

/// Extrapolate one authorized bounded probe. A complete probe becomes exact;
/// an incomplete one is conclusive only when its whole uncertainty interval
/// stays in one planner region. Non-edge truncation always fails closed.
pub(crate) fn estimate_bounded_probe(
    collection_points: usize,
    policy: BoundedProbePolicy,
    observation: BoundedProbeObservation,
    boundaries: ProbeDecisionBoundaries,
) -> Result<BoundedProbeEstimate> {
    validate_probe(collection_points, policy, observation, boundaries)?;
    let seen = usize::try_from(observation.visible_nodes_seen)
        .unwrap_or(usize::MAX)
        .min(collection_points);
    if observation.completed_hops == observation.target_hops && observation.truncation.is_none() {
        return Ok(BoundedProbeEstimate {
            planner_estimate: GraphEstimate::Exact {
                admitted_points: seen,
            },
            lower_admitted_points: seen,
            upper_admitted_points: seen,
        });
    }

    let allowed_stop = observation.truncation.is_none()
        || (observation.truncation == Some(TraversalTruncationReason::Edges)
            && observation.visible_edges_examined == policy.edge_budget);
    if !allowed_stop || observation.visible_nodes_expanded < policy.min_expanded_nodes {
        return Ok(BoundedProbeEstimate {
            planner_estimate: GraphEstimate::Probe {
                admitted_points: seen,
                conclusive: false,
            },
            lower_admitted_points: seen,
            upper_admitted_points: collection_points,
        });
    }

    let branch_bps = u128::from(observation.visible_next_nodes_discovered)
        .saturating_mul(BASIS_POINTS)
        / u128::from(observation.visible_nodes_expanded);
    let uncertainty = u128::from(policy.relative_uncertainty_bps);
    let lower_branch_bps = branch_bps.saturating_mul(BASIS_POINTS - uncertainty) / BASIS_POINTS;
    let upper_branch_bps = branch_bps
        .saturating_mul(BASIS_POINTS + uncertainty)
        .div_ceil(BASIS_POINTS);
    let remaining_hops = observation.target_hops - observation.completed_hops;
    let lower = extrapolate(
        collection_points,
        observation.visible_nodes_seen,
        observation.visible_frontier_nodes,
        lower_branch_bps,
        remaining_hops,
    );
    let upper = extrapolate(
        collection_points,
        observation.visible_nodes_seen,
        observation.visible_frontier_nodes,
        upper_branch_bps,
        remaining_hops,
    );
    let midpoint = lower + (upper - lower) / 2;
    let conclusive = decision_region(lower, collection_points, boundaries)
        == decision_region(upper, collection_points, boundaries);
    Ok(BoundedProbeEstimate {
        planner_estimate: GraphEstimate::Probe {
            admitted_points: midpoint,
            conclusive,
        },
        lower_admitted_points: lower,
        upper_admitted_points: upper,
    })
}

fn extrapolate(
    collection_points: usize,
    seen: u64,
    frontier: u64,
    branch_bps: u128,
    remaining_hops: u32,
) -> usize {
    let cap = collection_points as u128;
    let mut total = u128::from(seen).min(cap);
    let mut next = u128::from(frontier).min(cap);
    for _ in 0..remaining_hops {
        next = next
            .saturating_mul(branch_bps)
            .div_ceil(BASIS_POINTS)
            .min(cap);
        total = total.saturating_add(next).min(cap);
        if total == cap {
            break;
        }
    }
    total as usize
}

fn decision_region(
    admitted_points: usize,
    collection_points: usize,
    boundaries: ProbeDecisionBoundaries,
) -> DecisionRegion {
    DecisionRegion {
        exact_scan: exact_scan_seed(admitted_points, collection_points),
        below_specificity_floor: boundaries
            .specificity_floor_bps
            .is_some_and(|floor| ratio_is_below(admitted_points, collection_points, floor)),
        p5_candidate: boundaries.p5_min_specificity_bps.is_some_and(|threshold| {
            ratio_is_at_least(admitted_points, collection_points, threshold)
        }),
    }
}

fn validate_probe(
    collection_points: usize,
    policy: BoundedProbePolicy,
    observation: BoundedProbeObservation,
    boundaries: ProbeDecisionBoundaries,
) -> Result<()> {
    if collection_points == 0
        || policy.edge_budget == 0
        || policy.min_expanded_nodes == 0
        || policy.relative_uncertainty_bps > 10_000
        || observation.target_hops == 0
        || observation.target_hops > MAX_GRAPH_DEPTH
        || observation.completed_hops > observation.target_hops
        || observation.visible_edges_examined > policy.edge_budget
        || observation.visible_nodes_seen as u128 > collection_points as u128
        || observation.visible_nodes_expanded as u128 > collection_points as u128
        || observation.visible_frontier_nodes > observation.visible_nodes_seen
        || observation.visible_next_nodes_discovered > observation.visible_edges_examined
        || boundaries
            .specificity_floor_bps
            .is_some_and(|value| value > 10_000)
        || boundaries
            .p5_min_specificity_bps
            .is_some_and(|value| value > 10_000)
    {
        return Err(invalid("invalid bounded graph probe facts or policy"));
    }
    if observation.completed_hops < observation.target_hops
        && observation.visible_nodes_expanded == 0
        && observation.truncation == Some(TraversalTruncationReason::Edges)
    {
        return Err(invalid(
            "bounded graph probe cannot extrapolate without expanded nodes",
        ));
    }
    Ok(())
}

fn calibration_path(collection_dir: &Path) -> std::path::PathBuf {
    collection_dir.join("graph").join(GRAPH_CALIBRATION_FILE)
}

fn encode(store: &GraphCalibrationStore) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&store.envelopes)?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| invalid("graph calibration payload exceeds format length"))?;
    let envelope_count = u32::try_from(store.envelopes.len())
        .map_err(|_| invalid("graph calibration envelope count exceeds format length"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    bytes.extend_from_slice(&envelope_count.to_le_bytes());
    bytes.extend_from_slice(&store.calibration_version.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&crc_fast::crc32_iscsi(&payload).to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode(path: &Path, bytes: &[u8]) -> Result<GraphCalibrationStore> {
    if bytes.len() < HEADER_BYTES || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(corrupt(path, "calibration plaintext length is invalid"));
    }
    if &bytes[..8] != MAGIC {
        return Err(corrupt(path, "bad graph calibration magic"));
    }
    if u16::from_le_bytes(bytes[8..10].try_into().expect("version")) != FORMAT_VERSION {
        return Err(corrupt(path, "unsupported graph calibration version"));
    }
    if usize::from(u16::from_le_bytes(
        bytes[10..12].try_into().expect("header length"),
    )) != HEADER_BYTES
    {
        return Err(corrupt(path, "graph calibration header length mismatch"));
    }
    let envelope_count =
        u32::from_le_bytes(bytes[12..16].try_into().expect("envelope count")) as usize;
    let calibration_version =
        u64::from_le_bytes(bytes[16..24].try_into().expect("calibration version"));
    let payload_len =
        u32::from_le_bytes(bytes[24..28].try_into().expect("payload length")) as usize;
    let expected_crc = u32::from_le_bytes(bytes[28..32].try_into().expect("payload CRC"));
    if envelope_count > MAX_ENVELOPES || HEADER_BYTES.checked_add(payload_len) != Some(bytes.len())
    {
        return Err(corrupt(
            path,
            "graph calibration length or count exceeds cap",
        ));
    }
    let payload = &bytes[HEADER_BYTES..];
    if crc_fast::crc32_iscsi(payload) != expected_crc {
        return Err(corrupt(path, "graph calibration CRC32C mismatch"));
    }
    let envelopes: Vec<GraphCalibrationEnvelope> = serde_json::from_slice(payload)
        .map_err(|error| corrupt(path, format!("invalid graph calibration payload: {error}")))?;
    if envelopes.len() != envelope_count {
        return Err(corrupt(path, "graph calibration envelope count mismatch"));
    }
    let store = GraphCalibrationStore {
        calibration_version,
        envelopes,
    };
    validate_store(&store).map_err(|message| corrupt(path, message))?;
    Ok(store)
}

fn validate_store(store: &GraphCalibrationStore) -> std::result::Result<(), &'static str> {
    if store.calibration_version == 0 {
        return Err("graph calibration version must be non-zero");
    }
    if store.envelopes.len() > MAX_ENVELOPES {
        return Err("graph calibration envelope count exceeds cap");
    }
    let mut versions = HashSet::with_capacity(store.envelopes.len());
    for envelope in &store.envelopes {
        validate_envelope(envelope)?;
        if !versions.insert(envelope.envelope_version) {
            return Err("graph calibration envelope versions must be unique");
        }
    }
    for (index, left) in store.envelopes.iter().enumerate() {
        for right in &store.envelopes[index + 1..] {
            if left.profile_domain_overlaps(right) && left.profile() != right.profile() {
                return Err("graph calibration contains ambiguous dispatch profiles");
            }
            if left.overlaps(right) {
                return Err("graph calibration contains overlapping eligibility envelopes");
            }
        }
    }
    Ok(())
}

impl GraphCalibrationEnvelope {
    fn profile_domain_overlaps(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.vector_field == other.vector_field
            && self.metric == other.metric
            && self.dimension == other.dimension
            && self.graph_epoch == other.graph_epoch
            && self.schema_epoch == other.schema_epoch
            && self.manifest_generation == other.manifest_generation
            && self.overlay_generation == other.overlay_generation
            && self.direction == other.direction
            && self.typed == other.typed
            && self.filters == other.filters
            && self.planner_policy_version == other.planner_policy_version
            && self.branch_depth_policy_version == other.branch_depth_policy_version
            && self.target_recall_bps == other.target_recall_bps
            && ranges_overlap(self.min_hops, self.max_hops, other.min_hops, other.max_hops)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.vector_field == other.vector_field
            && self.metric == other.metric
            && self.dimension == other.dimension
            && self.topology_family == other.topology_family
            && self.graph_epoch == other.graph_epoch
            && self.schema_epoch == other.schema_epoch
            && self.manifest_generation == other.manifest_generation
            && self.overlay_generation == other.overlay_generation
            && self.direction == other.direction
            && self.typed == other.typed
            && self.filters == other.filters
            && self.planner_policy_version == other.planner_policy_version
            && self.branch_depth_policy_version == other.branch_depth_policy_version
            && self.target_recall_bps == other.target_recall_bps
            && ranges_overlap(self.min_hops, self.max_hops, other.min_hops, other.max_hops)
            && ranges_overlap(
                self.min_specificity_bps,
                self.max_specificity_bps,
                other.min_specificity_bps,
                other.max_specificity_bps,
            )
    }
}

fn ranges_overlap<T: Ord>(left_min: T, left_max: T, right_min: T, right_max: T) -> bool {
    left_min <= right_max && right_min <= left_max
}

fn validate_envelope(envelope: &GraphCalibrationEnvelope) -> std::result::Result<(), &'static str> {
    let name_valid = |value: &str| !value.is_empty() && value.len() <= 255 && !value.contains('\0');
    if envelope.envelope_version == 0
        || envelope.dimension == 0
        || !name_valid(&envelope.topology_family)
        || envelope
            .vector_field
            .as_deref()
            .is_some_and(|field| !name_valid(field))
        || envelope.graph_epoch == 0
        || envelope.schema_epoch == 0
        || envelope.min_hops == 0
        || envelope.min_hops > envelope.max_hops
        || envelope.max_hops > MAX_GRAPH_DEPTH
        || envelope.min_specificity_bps > envelope.max_specificity_bps
        || envelope.max_specificity_bps > 10_000
        || envelope.planner_policy_version == 0
        || envelope.branch_depth_policy_version == 0
        || envelope.max_k == 0
        || !(5_000..=10_000).contains(&envelope.target_recall_bps)
        || envelope
            .specificity_floor_bps
            .is_some_and(|value| value > 10_000)
        || envelope
            .p5_min_specificity_bps
            .is_some_and(|value| value > 10_000)
        || envelope
            .p5_observed_recall_bps
            .is_some_and(|value| value > 10_000)
        || envelope.p5_min_specificity_bps.is_some() != envelope.p5_max_k.is_some()
        || envelope.p5_max_k.is_some_and(|value| value == 0)
        || (envelope.p5_min_specificity_bps.is_none() && envelope.p5_observed_recall_bps.is_some())
        || validate_probe_policy(envelope.probe_policy).is_err()
        || validate_cost_calibration(envelope.costs).is_err()
        || validate_execution_calibration(envelope.execution).is_err()
        || envelope.execution.p3_max_candidates < envelope.max_k
        || envelope.execution.p3h_dense_max_candidates < envelope.max_k
        || envelope.execution.p3h_sparse_max_candidates < envelope.max_k
    {
        return Err("invalid graph calibration envelope");
    }
    Ok(())
}

fn validate_query(query: &GraphEnvelopeQuery<'_>) -> std::result::Result<(), &'static str> {
    let name_valid = |value: &str| !value.is_empty() && value.len() <= 255 && !value.contains('\0');
    if query.dimension == 0
        || !name_valid(query.topology_family)
        || query.vector_field.is_some_and(|field| !name_valid(field))
        || query.graph_epoch == 0
        || query.schema_epoch == 0
        || query.hops == 0
        || query.hops > MAX_GRAPH_DEPTH
        || query.min_specificity_bps > query.max_specificity_bps
        || query.max_specificity_bps > 10_000
        || query.planner_policy_version == 0
        || query.branch_depth_policy_version == 0
        || query.k == 0
        || !(5_000..=10_000).contains(&query.target_recall_bps)
    {
        return Err("invalid graph envelope lookup facts");
    }
    Ok(())
}

fn validate_profile_query(query: &GraphProfileQuery<'_>) -> std::result::Result<(), &'static str> {
    let name_valid = |value: &str| !value.is_empty() && value.len() <= 255 && !value.contains('\0');
    if query.dimension == 0
        || query.vector_field.is_some_and(|field| !name_valid(field))
        || query.graph_epoch == 0
        || query.schema_epoch == 0
        || query.hops == 0
        || query.hops > MAX_GRAPH_DEPTH
        || query.planner_policy_version == 0
        || query.branch_depth_policy_version == 0
        || query.k == 0
        || !(5_000..=10_000).contains(&query.target_recall_bps)
    {
        return Err("invalid graph calibration profile lookup facts");
    }
    Ok(())
}

fn validate_probe_policy(policy: BoundedProbePolicy) -> std::result::Result<(), &'static str> {
    if policy.edge_budget == 0
        || policy.min_expanded_nodes == 0
        || policy.relative_uncertainty_bps > 10_000
    {
        return Err("invalid graph bounded probe policy");
    }
    Ok(())
}

fn validate_cost_calibration(costs: GraphCostCalibration) -> std::result::Result<(), &'static str> {
    if costs.mean_visible_degree_milli == 0
        || costs.edge_visit_units == 0
        || costs.translation_units == 0
        || costs.distance_component_units == 0
        || costs.dense_candidate_units == 0
        || costs.sparse_candidate_units == 0
        || costs.fusion_candidate_units == 0
        || costs.p4_navigation_units == 0
    {
        return Err("graph cost calibration units must be positive");
    }
    Ok(())
}

fn validate_execution_calibration(
    execution: GraphExecutionCalibration,
) -> std::result::Result<(), &'static str> {
    if execution.p3_initial_factor == 0
        || execution.p3_growth_factor < 2
        || execution.p3_max_candidates == 0
        || execution.p3h_dense_initial_factor == 0
        || execution.p3h_dense_growth_factor < 2
        || execution.p3h_dense_max_candidates == 0
        || execution.p3h_sparse_initial_factor == 0
        || execution.p3h_sparse_growth_factor < 2
        || execution.p3h_sparse_max_candidates == 0
        || execution.p5_max_expansions == 0
        || execution.shadow_sample_bps > 10_000
    {
        return Err("invalid graph executor calibration");
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn corrupt(path: &Path, message: impl Into<String>) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf, process::Command};

    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;
    use crate::{
        graph::GraphRetrievalPlan,
        graph_planner::{
            GraphPlanCosts, GraphPlannerDecision, GraphPlannerInput, GraphStatementMode,
            select_graph_plan,
        },
    };

    fn envelope() -> GraphCalibrationEnvelope {
        GraphCalibrationEnvelope {
            envelope_version: 7,
            mode: GraphContractMode::Dense,
            vector_field: None,
            metric: DistanceMetric::Cosine,
            dimension: 128,
            topology_family: "scale_free".to_string(),
            graph_epoch: 3,
            schema_epoch: 5,
            manifest_generation: 11,
            overlay_generation: 11,
            direction: GraphDirection::Outgoing,
            typed: true,
            min_hops: 1,
            max_hops: 3,
            filters: GraphFilterShape {
                statement: true,
                node: false,
                edge: false,
            },
            min_specificity_bps: 500,
            max_specificity_bps: 5_000,
            max_overlay_lsn_lag: 32,
            planner_policy_version: 2,
            branch_depth_policy_version: 4,
            max_k: 100,
            target_recall_bps: 9_500,
            specificity_floor_bps: Some(700),
            p5_min_specificity_bps: Some(2_000),
            p5_max_k: Some(20),
            p5_observed_recall_bps: Some(9_600),
            probe_policy: policy(),
            costs: GraphCostCalibration {
                mean_visible_degree_milli: 4_000,
                edge_visit_units: 2,
                translation_units: 1,
                distance_component_units: 3,
                dense_candidate_units: 11,
                sparse_candidate_units: 7,
                fusion_candidate_units: 5,
                p4_navigation_units: 13,
            },
            execution: GraphExecutionCalibration {
                p3_initial_factor: 4,
                p3_growth_factor: 2,
                p3_max_candidates: 1_000,
                p3h_dense_initial_factor: 4,
                p3h_dense_growth_factor: 2,
                p3h_dense_max_candidates: 1_000,
                p3h_sparse_initial_factor: 8,
                p3h_sparse_growth_factor: 2,
                p3h_sparse_max_candidates: 2_000,
                p5_max_expansions: 500,
                shadow_sample_bps: 0,
            },
        }
    }

    fn query<'a>() -> GraphEnvelopeQuery<'a> {
        GraphEnvelopeQuery {
            mode: GraphContractMode::Dense,
            vector_field: None,
            metric: DistanceMetric::Cosine,
            dimension: 128,
            topology_family: "scale_free",
            graph_epoch: 3,
            schema_epoch: 5,
            manifest_generation: 11,
            overlay_generation: 11,
            direction: GraphDirection::Outgoing,
            typed: true,
            hops: 2,
            filters: GraphFilterShape {
                statement: true,
                node: false,
                edge: false,
            },
            min_specificity_bps: 2_500,
            max_specificity_bps: 2_500,
            overlay_lsn_lag: 8,
            planner_policy_version: 2,
            branch_depth_policy_version: 4,
            k: 10,
            target_recall_bps: 9_500,
        }
    }

    fn profile_query<'a>() -> GraphProfileQuery<'a> {
        let query = query();
        GraphProfileQuery {
            mode: query.mode,
            vector_field: query.vector_field,
            metric: query.metric,
            dimension: query.dimension,
            graph_epoch: query.graph_epoch,
            schema_epoch: query.schema_epoch,
            manifest_generation: query.manifest_generation,
            overlay_generation: query.overlay_generation,
            direction: query.direction,
            typed: query.typed,
            hops: query.hops,
            filters: query.filters,
            overlay_lsn_lag: query.overlay_lsn_lag,
            planner_policy_version: query.planner_policy_version,
            branch_depth_policy_version: query.branch_depth_policy_version,
            k: query.k,
            target_recall_bps: query.target_recall_bps,
        }
    }

    fn store() -> GraphCalibrationStore {
        GraphCalibrationStore {
            calibration_version: 9,
            envelopes: vec![envelope()],
        }
    }

    #[test]
    fn exact_envelope_match_exposes_only_calibrated_thresholds() {
        let matched = store().lookup(&query()).unwrap().unwrap();
        assert_eq!(matched.envelope_version, 7);
        assert_eq!(matched.calibration.specificity_floor_bps, Some(700));
        assert_eq!(
            matched.calibration.p5.unwrap().recall,
            P5RecallEligibility::CalibratedMeetsTarget
        );
    }

    #[test]
    fn profile_binds_probe_cost_and_executor_controls_before_estimation() {
        let profile = store().profile(&profile_query()).unwrap().unwrap();
        assert_eq!(profile.topology_family, "scale_free");
        assert_eq!(profile.probe_policy, policy());
        assert_eq!(profile.execution.p5_max_expansions, 500);
        assert_eq!(profile.boundaries.specificity_floor_bps, Some(700));

        let mut inconsistent = store();
        let mut second = envelope();
        second.envelope_version = 8;
        second.min_specificity_bps = 5_001;
        second.max_specificity_bps = 10_000;
        second.costs.edge_visit_units += 1;
        inconsistent.envelopes.push(second);
        assert!(inconsistent.profile(&profile_query()).is_err());
    }

    #[test]
    fn legacy_v2_execution_policy_defaults_shadow_off() {
        let mut value = serde_json::to_value(envelope().execution).unwrap();
        value.as_object_mut().unwrap().remove("shadow_sample_bps");
        let execution: GraphExecutionCalibration = serde_json::from_value(value).unwrap();
        assert_eq!(execution.shadow_sample_bps, 0);
    }

    #[test]
    fn calibrated_costs_change_with_work_shape_without_wall_clock_defaults() {
        let envelope = envelope();
        let dense = envelope
            .costs
            .plan_costs(
                envelope.execution,
                GraphStatementMode::Dense,
                100_000,
                10_000,
                128,
                3,
                10,
            )
            .unwrap();
        let hybrid = envelope
            .costs
            .plan_costs(
                envelope.execution,
                GraphStatementMode::HybridRrf,
                100_000,
                10_000,
                128,
                3,
                10,
            )
            .unwrap();
        let larger = envelope
            .costs
            .plan_costs(
                envelope.execution,
                GraphStatementMode::Dense,
                100_000,
                20_000,
                128,
                3,
                10,
            )
            .unwrap();
        assert!(hybrid.p2 > dense.p2);
        assert!(larger.p1 > dense.p1);
    }

    #[test]
    fn generation_policy_filter_and_freshness_mismatches_invalidate_envelope() {
        let store = store();
        let mut mismatches = Vec::new();
        let mut stale_generation = query();
        stale_generation.manifest_generation += 1;
        mismatches.push(stale_generation);
        let mut stale_schema = query();
        stale_schema.schema_epoch += 1;
        mismatches.push(stale_schema);
        let mut stale_overlay = query();
        stale_overlay.overlay_lsn_lag = 33;
        mismatches.push(stale_overlay);
        let mut wrong_policy = query();
        wrong_policy.planner_policy_version += 1;
        mismatches.push(wrong_policy);
        let mut wrong_filter = query();
        wrong_filter.filters.edge = true;
        mismatches.push(wrong_filter);
        let mut crosses_specificity_bucket = query();
        crosses_specificity_bucket.min_specificity_bps = 400;
        mismatches.push(crosses_specificity_bucket);
        for mismatch in mismatches {
            assert_eq!(store.lookup(&mismatch).unwrap(), None);
        }
    }

    #[test]
    fn missing_or_overlapping_envelope_never_enables_p5() {
        let empty = GraphCalibrationStore {
            calibration_version: 1,
            envelopes: Vec::new(),
        };
        assert_eq!(empty.lookup(&query()).unwrap(), None);

        let mut overlap = store();
        let mut second = envelope();
        second.envelope_version = 8;
        overlap.envelopes.push(second);
        assert!(overlap.lookup(&query()).is_err());
        assert!(overlap.validate().is_err());
    }

    #[test]
    fn calibration_round_trip_is_checked_and_atomic() {
        const MODE: &str = "CHIRONDB_GRAPH_CALIBRATION_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_CALIBRATION_TEST_ROOT";
        const TEST: &str = "graph_estimator::tests::calibration_round_trip_is_checked_and_atomic";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = tempfile::tempdir().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, root.path())
                        .env("RUST_TEST_THREADS", "1")
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        let encrypted = mode == "encrypted";
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(
                &keyring,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "graph-calibration-test",
                    "keys": [{
                        "id": "graph-calibration-test",
                        "key_base64": STANDARD.encode([71_u8; 32]),
                    }],
                })
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(&keyring).unwrap(),
                true,
            )
            .unwrap();
        }

        store().publish(&root).unwrap();
        assert_eq!(GraphCalibrationStore::open(&root).unwrap(), Some(store()));

        let path = calibration_path(&root);
        assert_eq!(
            fs::read(&path)
                .unwrap()
                .starts_with(crate::encryption::MAGIC),
            encrypted
        );
        let mut bytes = read_persistent(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        atomic_write_persistent(&path, FileType::Metadata, &bytes).unwrap();
        assert!(GraphCalibrationStore::open(&root).is_err());
    }

    #[test]
    fn sketch_is_rejected_outside_every_competence_dimension() {
        let base = GraphEstimatorShape {
            direction: GraphDirection::Both,
            typed: false,
            hops: 2,
            filters: GraphFilterShape::default(),
            graph_epoch: 3,
            manifest_generation: 11,
            overlay_generation: 11,
            deletion_lsn: 40,
        };
        let evidence = GraphSketchEvidence {
            graph_epoch: 3,
            manifest_generation: 11,
            overlay_generation: 11,
            built_at_deletion_lsn: 40,
            max_hops: 3,
            anchor_eligible: true,
            admitted_points: 100,
        };
        assert!(matches!(
            choose_estimator(base, Some(evidence)),
            GraphEstimatorRoute::Sketch(_)
        ));

        let rejected = [
            GraphEstimatorShape {
                direction: GraphDirection::Incoming,
                ..base
            },
            GraphEstimatorShape {
                typed: true,
                ..base
            },
            GraphEstimatorShape { hops: 4, ..base },
            GraphEstimatorShape {
                filters: GraphFilterShape {
                    node: true,
                    ..GraphFilterShape::default()
                },
                ..base
            },
            GraphEstimatorShape {
                deletion_lsn: 41,
                ..base
            },
        ];
        for shape in rejected {
            assert_eq!(
                choose_estimator(shape, Some(evidence)),
                GraphEstimatorRoute::Probe
            );
        }
    }

    #[test]
    fn complete_probe_is_exact_and_uses_visible_counts_only() {
        let estimate = estimate_bounded_probe(
            100_000,
            policy(),
            BoundedProbeObservation {
                target_hops: 2,
                completed_hops: 2,
                visible_nodes_seen: 123,
                visible_nodes_expanded: 70,
                visible_frontier_nodes: 20,
                visible_next_nodes_discovered: 50,
                visible_edges_examined: 900,
                truncation: None,
            },
            ProbeDecisionBoundaries::default(),
        )
        .unwrap();
        assert_eq!(
            estimate,
            BoundedProbeEstimate {
                planner_estimate: GraphEstimate::Exact {
                    admitted_points: 123
                },
                lower_admitted_points: 123,
                upper_admitted_points: 123,
            }
        );
    }

    #[test]
    fn bounded_probe_is_conclusive_only_inside_one_planner_region() {
        let mut hop_boundary = observation(1_000, 100, 100);
        hop_boundary.visible_edges_examined = 600;
        hop_boundary.truncation = None;
        let decisive = estimate_bounded_probe(
            100_000,
            policy(),
            hop_boundary,
            ProbeDecisionBoundaries {
                specificity_floor_bps: Some(100),
                p5_min_specificity_bps: Some(5_000),
            },
        )
        .unwrap();
        assert!(matches!(
            decisive.planner_estimate,
            GraphEstimate::Probe {
                conclusive: true,
                ..
            }
        ));

        let mut ambiguous_observation = observation(4_800, 100, 50);
        ambiguous_observation.visible_frontier_nodes = 500;
        let ambiguous = estimate_bounded_probe(
            100_000,
            BoundedProbePolicy {
                relative_uncertainty_bps: 5_000,
                ..policy()
            },
            ambiguous_observation,
            ProbeDecisionBoundaries::default(),
        )
        .unwrap();
        let (lower_bps, upper_bps) = ambiguous.specificity_interval_bps(100_000).unwrap();
        assert!(lower_bps <= 500 && upper_bps > 500);
        let decision = select_graph_plan(GraphPlannerInput {
            statement_mode: GraphStatementMode::Dense,
            k: 10,
            collection_points: 100_000,
            estimate: ambiguous.planner_estimate,
            calibration: GraphPlannerCalibration::default(),
            p5_degraded_opt_in: false,
            costs: GraphPlanCosts {
                p1: 1,
                p2: 2,
                p3: 3,
                p3h: 4,
                p4: 5,
                p5: 0,
            },
        })
        .unwrap();
        let GraphPlannerDecision::Execute(selection) = decision else {
            panic!("probe estimate must be executable");
        };
        assert_eq!(selection.plan, GraphRetrievalPlan::P2PrefilteredCascade);
    }

    #[test]
    fn unsafe_or_inconsistent_probe_stops_fail_closed() {
        for reason in [
            TraversalTruncationReason::Time,
            TraversalTruncationReason::Memory,
            TraversalTruncationReason::Cancelled,
            TraversalTruncationReason::ColdFragments,
        ] {
            let mut facts = observation(1_000, 100, 100);
            facts.truncation = Some(reason);
            assert!(matches!(
                estimate_bounded_probe(
                    100_000,
                    policy(),
                    facts,
                    ProbeDecisionBoundaries::default()
                )
                .unwrap()
                .planner_estimate,
                GraphEstimate::Probe {
                    conclusive: false,
                    ..
                }
            ));
        }
        let mut over_budget = observation(1_000, 100, 100);
        over_budget.visible_edges_examined += 1;
        assert!(
            estimate_bounded_probe(
                100_000,
                policy(),
                over_budget,
                ProbeDecisionBoundaries::default()
            )
            .is_err()
        );
    }

    fn policy() -> BoundedProbePolicy {
        BoundedProbePolicy {
            edge_budget: 1_000,
            min_expanded_nodes: 50,
            relative_uncertainty_bps: 1_000,
        }
    }

    fn observation(seen: u64, expanded: u64, next_discovered: u64) -> BoundedProbeObservation {
        BoundedProbeObservation {
            target_hops: 3,
            completed_hops: 1,
            visible_nodes_seen: seen,
            visible_nodes_expanded: expanded,
            visible_frontier_nodes: 100,
            visible_next_nodes_discovered: next_discovered,
            visible_edges_examined: 1_000,
            truncation: Some(TraversalTruncationReason::Edges),
        }
    }
}
