use std::{collections::HashMap, fs, sync::atomic::AtomicBool, time::Duration};

use serde_json::json;

use super::*;
use crate::db::collection_dir;
use crate::db::graph_retrieval::{
    P3HybridProgressivePolicy, P3HybridTermination, P3ProgressivePolicy, P3Termination,
    P4Termination, P5BestFirstPolicy, P5Termination,
};
#[cfg(feature = "fault-injection")]
use crate::failpoint::TEST_ENV as RETRIEVAL_FAILPOINT_ENV;
use crate::{
    Filter,
    graph::{
        ConfigureEdgeTypeRequest, ExactGraphSearchRequest, GraphConstraint, GraphDirection,
        GraphEstimatorKind, GraphPlanGuard, GraphQueryWarning, GraphRelationScope,
        GraphRetrievalPlan, RelateRequest, TraversalBudget,
    },
    graph_estimator::{
        BoundedProbePolicy, GraphCalibrationEnvelope, GraphCalibrationStore, GraphContractMode,
        GraphCostCalibration, GraphExecutionCalibration, GraphFilterShape,
    },
    graph_planner::{
        GraphEstimate, GraphPlanCosts, GraphPlannerCalibration, GraphPlannerDecision,
        GraphPlannerInput, GraphStatementMode, P5Calibration, P5RecallEligibility,
        select_graph_plan,
    },
    model::{HybridFusion, HybridSearchRequest, SearchRequest, SparseVector},
    tenant::TenantScope,
};

fn dispatch_envelope(db: &Db) -> GraphCalibrationEnvelope {
    let coll = db.get_coll("docs").unwrap();
    let collection = coll.read();
    let visibility = collection.overlay_read_state();
    GraphCalibrationEnvelope {
        envelope_version: 1,
        mode: GraphContractMode::Dense,
        vector_field: None,
        metric: collection.config.metric,
        dimension: 2,
        topology_family: "retrieval-fixture".to_string(),
        graph_epoch: collection.graph_mutable.as_ref().unwrap().epoch().raw(),
        schema_epoch: collection.schema_epoch,
        manifest_generation: collection
            .graph_generation
            .as_ref()
            .map_or(0, |generation| generation.manifest.generation),
        overlay_generation: visibility.generation(),
        direction: GraphDirection::Outgoing,
        typed: true,
        min_hops: 1,
        max_hops: 1,
        filters: GraphFilterShape {
            statement: true,
            node: false,
            edge: false,
        },
        min_specificity_bps: 0,
        max_specificity_bps: 10_000,
        max_overlay_lsn_lag: u64::MAX,
        planner_policy_version: 1,
        branch_depth_policy_version: 1,
        max_k: 10,
        target_recall_bps: 9_500,
        specificity_floor_bps: None,
        p5_min_specificity_bps: None,
        p5_max_k: None,
        p5_observed_recall_bps: None,
        probe_policy: BoundedProbePolicy {
            edge_budget: 100,
            min_expanded_nodes: 1,
            relative_uncertainty_bps: 1_000,
        },
        costs: GraphCostCalibration {
            mean_visible_degree_milli: 2_000,
            edge_visit_units: 1,
            translation_units: 1,
            distance_component_units: 10,
            dense_candidate_units: 1,
            sparse_candidate_units: 1,
            fusion_candidate_units: 1,
            p4_navigation_units: 100,
        },
        execution: GraphExecutionCalibration {
            p3_initial_factor: 1,
            p3_growth_factor: 2,
            p3_max_candidates: 10,
            p3h_dense_initial_factor: 1,
            p3h_dense_growth_factor: 2,
            p3h_dense_max_candidates: 10,
            p3h_sparse_initial_factor: 1,
            p3h_sparse_growth_factor: 2,
            p3h_sparse_max_candidates: 10,
            p5_max_expansions: 5,
            shadow_sample_bps: 0,
        },
    }
}

fn retrieval_point(id: &str, x: f32, allowed: bool) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![x, 0.0],
        vectors: HashMap::new(),
        sparse_vector: match id {
            "b" => Some(SparseVector {
                indices: vec![7],
                values: vec![2.0],
            }),
            "c" => Some(SparseVector {
                indices: vec![7],
                values: vec![1.0],
            }),
            _ => None,
        },
        payload: json!({
            "tenant_id": "acme",
            "allowed": allowed,
            "label": id,
        }),
    }
}

fn graph_constraint(anchor: &str, max_depth: u32) -> GraphConstraint {
    GraphConstraint {
        anchors: vec![anchor.to_string()],
        edge_types: vec!["links".to_string()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth,
            ..TraversalBudget::default()
        },
        allow_degraded: false,
    }
}

fn relate(db: &Db, scope: &TenantScope, source: &str, target: &str, edge_type: &str, live: bool) {
    db.relate_scoped(
        "docs",
        RelateRequest {
            source_point_id: source.to_string(),
            target_point_id: target.to_string(),
            edge_type: edge_type.to_string(),
            properties: json!({"live": live}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        },
        true,
        scope,
    )
    .unwrap();
}

fn retrieval_fixture() -> (TempDir, Db, TenantScope) {
    retrieval_fixture_with_recall(None)
}

fn retrieval_fixture_with_recall(recall_sla: Option<f32>) -> (TempDir, Db, TenantScope) {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::tenant("retrieval-test", "acme");
    let mut config = ls_vec_config("docs");
    config.recall_sla = recall_sla;
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert(
        "docs",
        vec![
            retrieval_point("a", 9.0, true),
            retrieval_point("b", 1.0, false),
            retrieval_point("c", 0.5, true),
            retrieval_point("d", 0.25, true),
            retrieval_point("e", 0.1, true),
        ],
    )
    .unwrap();
    for edge_type in ["links", "references"] {
        db.configure_edge_type_scoped(
            "docs",
            ConfigureEdgeTypeRequest {
                name: edge_type.to_string(),
                weight_property: None,
            },
            true,
            &scope,
        )
        .unwrap();
    }
    relate(&db, &scope, "a", "b", "links", true);
    relate(&db, &scope, "a", "c", "links", false);
    relate(&db, &scope, "a", "d", "references", true);
    relate(&db, &scope, "b", "e", "links", true);
    (temp, db, scope)
}

fn p2_selection(
    mode: GraphStatementMode,
    admitted_points: usize,
) -> crate::graph_planner::GraphPlanSelection {
    let decision = select_graph_plan(GraphPlannerInput {
        statement_mode: mode,
        k: 2,
        collection_points: 100,
        estimate: GraphEstimate::Exact { admitted_points },
        calibration: GraphPlannerCalibration::default(),
        p5_degraded_opt_in: false,
        costs: GraphPlanCosts {
            p1: 10,
            p2: 1,
            p3: 20,
            p3h: 20,
            p4: 30,
            p5: 40,
        },
    })
    .unwrap();
    let GraphPlannerDecision::Execute(selection) = decision else {
        panic!("exact estimate must produce an executable plan");
    };
    assert_eq!(selection.plan, GraphRetrievalPlan::P2PrefilteredCascade);
    selection
}

fn p3_selection() -> crate::graph_planner::GraphPlanSelection {
    let mut selection = p2_selection(GraphStatementMode::Dense, 2);
    selection.plan = GraphRetrievalPlan::P3ProgressiveProbe;
    selection
}

fn p3_policy(max_candidates: usize) -> P3ProgressivePolicy {
    P3ProgressivePolicy {
        initial_factor: 1,
        growth_factor: 2,
        max_candidates,
    }
}

fn p3h_selection() -> crate::graph_planner::GraphPlanSelection {
    let mut selection = p2_selection(GraphStatementMode::HybridRrf, 2);
    selection.plan = GraphRetrievalPlan::P3HybridJointWidening;
    selection
}

fn p3h_policy(dense_cap: usize, sparse_cap: usize) -> P3HybridProgressivePolicy {
    P3HybridProgressivePolicy {
        dense: p3_policy(dense_cap),
        sparse: p3_policy(sparse_cap),
    }
}

fn p3h_request(k: usize, max_depth: u32) -> HybridSearchRequest {
    HybridSearchRequest {
        vector: Some(vec![0.0, 0.0]),
        vector_name: None,
        sparse_vector: Some(SparseVector {
            indices: vec![7],
            values: vec![1.0],
        }),
        k,
        filter: None,
        graph: Some(graph_constraint("a", max_depth)),
        budget_ms: None,
        fusion: HybridFusion::Rrf,
        dense_weight: 1.0,
        sparse_weight: 1.0,
    }
}

fn p4_selection(
    mode: GraphStatementMode,
    admitted_points: usize,
) -> crate::graph_planner::GraphPlanSelection {
    let mut selection = p2_selection(mode, admitted_points);
    selection.plan = GraphRetrievalPlan::P4ReachabilityAwareBeam;
    selection
}

fn p4_dense_request(k: usize) -> SearchRequest {
    SearchRequest {
        vector: vec![0.0, 0.0],
        vector_name: None,
        k,
        filter: None,
        graph: Some(graph_constraint("a", 1)),
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: None,
        with_payload: Some(false),
    }
}

fn p4_hybrid_request(k: usize, fusion: HybridFusion) -> HybridSearchRequest {
    let mut request = p3h_request(k, 1);
    request.fusion = fusion;
    request
}

fn p5_selection(degraded: bool) -> crate::graph_planner::GraphPlanSelection {
    let decision = select_graph_plan(GraphPlannerInput {
        statement_mode: GraphStatementMode::Dense,
        k: 1,
        collection_points: 100,
        estimate: GraphEstimate::Exact {
            admitted_points: 80,
        },
        calibration: GraphPlannerCalibration {
            specificity_floor_bps: None,
            p5: Some(P5Calibration {
                min_specificity_bps: 5_000,
                max_k: 10,
                recall: if degraded {
                    P5RecallEligibility::Uncalibrated
                } else {
                    P5RecallEligibility::CalibratedMeetsTarget
                },
            }),
        },
        p5_degraded_opt_in: degraded,
        costs: GraphPlanCosts {
            p1: 50,
            p2: 20,
            p3: 20,
            p3h: 20,
            p4: 30,
            p5: 1,
        },
    })
    .unwrap();
    let GraphPlannerDecision::Execute(selection) = decision else {
        panic!("exact estimate must produce a P5 selection");
    };
    assert_eq!(selection.plan, GraphRetrievalPlan::P5BestFirst);
    assert_eq!(selection.degraded, degraded);
    selection
}

fn p5_policy(max_expansions: usize) -> P5BestFirstPolicy {
    P5BestFirstPolicy { max_expansions }
}

fn p5_request(k: usize) -> SearchRequest {
    SearchRequest {
        vector: vec![0.0, 0.0],
        vector_name: None,
        k,
        filter: None,
        graph: Some(graph_constraint("a", 2)),
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: None,
        with_payload: Some(false),
    }
}

fn p5_fixture() -> (TempDir, Db, TenantScope) {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::tenant("p5-test", "acme");
    db.create_collection(ls_vec_config("docs")).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.upsert(
        "docs",
        vec![
            retrieval_point("a", 9.0, true),
            retrieval_point("near", 1.0, true),
            retrieval_point("far", 10.0, true),
            retrieval_point("winner", 0.1, true),
            retrieval_point("hidden", 0.0, true),
        ],
    )
    .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "links".to_string(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    relate(&db, &scope, "a", "near", "links", true);
    relate(&db, &scope, "a", "far", "links", true);
    relate(&db, &scope, "near", "winner", "links", true);
    relate(&db, &scope, "far", "hidden", "links", true);
    (temp, db, scope)
}

#[test]
fn public_dense_route_uses_checked_calibration_and_authorized_probe() {
    let (temp, db, scope) = retrieval_fixture();
    drop(db);

    let reopened = Db::open(temp.path()).unwrap();
    let envelope = dispatch_envelope(&reopened);
    drop(reopened);
    GraphCalibrationStore {
        calibration_version: 1,
        envelopes: vec![envelope],
    }
    .publish(&collection_dir(temp.path(), "docs"))
    .unwrap();

    let reopened = Db::open(temp.path()).unwrap();
    reopened.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
    let scoped_filter = scope
        .scope_filter(crate::tenant::TenantEnforcement::Enforced, None)
        .unwrap();
    let prepared = reopened
        .prepare_graph_dispatch(
            "docs",
            graph_constraint("a", 1),
            scoped_filter.as_ref(),
            None,
            1,
            Some(0.95),
            GraphStatementMode::Dense,
            &scope,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(
        matches!(
            &prepared,
            crate::db::graph_retrieval::PreparedGraphDispatch::Calibrated {
                selection: crate::graph_planner::GraphPlanSelection {
                    plan: GraphRetrievalPlan::P2PrefilteredCascade,
                    ..
                },
                ..
            }
        ),
        "unexpected prepared dispatch: {prepared:?}"
    );
    let crate::db::graph_retrieval::PreparedGraphDispatch::Calibrated { trace, .. } = &prepared
    else {
        unreachable!("calibrated dispatch asserted above")
    };
    assert_eq!(
        trace.graph_estimate.estimator,
        GraphEstimatorKind::ProbeExpansion
    );
    assert_eq!(trace.graph_estimate.calibration_version, Some(1));
    assert_eq!(trace.graph_estimate.envelope_version, Some(1));
    assert!(trace.graph_estimate.probe.is_some());
    assert!(trace.graph_plan.modelled_costs.is_none());

    reopened.set_tenant_enforcement(crate::tenant::TenantEnforcement::Disabled);
    let privileged = reopened
        .prepare_graph_dispatch(
            "docs",
            graph_constraint("a", 1),
            scoped_filter.as_ref(),
            None,
            1,
            Some(0.95),
            GraphStatementMode::Dense,
            &scope,
            &AtomicBool::new(false),
        )
        .unwrap();
    let crate::db::graph_retrieval::PreparedGraphDispatch::Calibrated { trace, .. } = privileged
    else {
        panic!("privileged request should match calibration")
    };
    assert!(trace.graph_plan.modelled_costs.is_some());
    reopened.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);

    let response = reopened
        .search_scoped(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(0.95),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].id, "c");
    assert!(response.searched >= 1);
    let trace = response.graph.expect("graph dispatch trace");
    assert_eq!(
        trace.graph_plan.chosen,
        GraphRetrievalPlan::P2PrefilteredCascade
    );
    assert!(trace.graph_plan.modelled_costs.is_none());
    assert!(trace.graph_estimate.probe.is_some());
}

#[test]
fn calibration_publication_is_cas_bound_atomic_and_immediately_visible() {
    let (temp, db, tenant) = retrieval_fixture_with_recall(Some(0.95));
    let envelope = dispatch_envelope(&db);
    let candidate = GraphCalibrationStore {
        calibration_version: 1,
        envelopes: vec![envelope],
    };

    let error = db
        .publish_graph_calibration_candidate_scoped("docs", None, candidate.clone(), &tenant)
        .unwrap_err();
    assert!(error.to_string().contains("administrative writer"));
    assert_eq!(
        GraphCalibrationStore::open(&collection_dir(temp.path(), "docs")).unwrap(),
        None
    );

    let admin = TenantScope::system();
    let receipt = db
        .publish_graph_calibration_candidate_scoped("docs", None, candidate.clone(), &admin)
        .unwrap();
    assert_eq!(receipt.previous_version, None);
    assert_eq!(receipt.published_version, 1);
    assert_eq!(receipt.envelope_count, 1);
    assert_eq!(
        db.get_coll("docs")
            .unwrap()
            .read()
            .graph_calibration
            .as_ref()
            .unwrap()
            .calibration_version,
        1
    );
    assert_eq!(
        GraphCalibrationStore::open(&collection_dir(temp.path(), "docs")).unwrap(),
        Some(candidate.clone())
    );

    let mut replacement = candidate.clone();
    replacement.calibration_version = 2;
    assert!(
        db.publish_graph_calibration_candidate_scoped("docs", None, replacement.clone(), &admin,)
            .unwrap_err()
            .to_string()
            .contains("compare-and-swap")
    );
    replacement.envelopes[0].graph_epoch += 1;
    assert!(
        db.publish_graph_calibration_candidate_scoped("docs", Some(1), replacement, &admin,)
            .unwrap_err()
            .to_string()
            .contains("active graph/vector state")
    );
    assert_eq!(
        GraphCalibrationStore::open(&collection_dir(temp.path(), "docs"))
            .unwrap()
            .unwrap()
            .calibration_version,
        1
    );

    let mut replacement = candidate;
    replacement.calibration_version = 2;
    let receipt = db
        .publish_graph_calibration_candidate_scoped("docs", Some(1), replacement, &admin)
        .unwrap();
    assert_eq!(receipt.previous_version, Some(1));
    assert_eq!(receipt.published_version, 2);

    let records = fs::read_to_string(crate::audit::audit_log_path(temp.path())).unwrap();
    assert!(records.lines().any(|line| {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        record["operation"] == "graph_calibration_publish"
            && record["outcome"] == "success"
            && record["details"]["published_version"] == 2
    }));
}

#[test]
fn sampled_dense_and_rrf_shadows_time_every_eligible_alternative_only() {
    let (_temp, db, scope) = retrieval_fixture_with_recall(Some(0.95));
    let mut dense = dispatch_envelope(&db);
    dense.execution.shadow_sample_bps = 10_000;
    let mut rrf = dense.clone();
    rrf.envelope_version = 2;
    rrf.mode = GraphContractMode::HybridRrf;
    db.publish_graph_calibration_candidate_scoped(
        "docs",
        None,
        GraphCalibrationStore {
            calibration_version: 77,
            envelopes: vec![dense, rrf],
        },
        &TenantScope::system(),
    )
    .unwrap();
    db.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);

    let response = db
        .search_scoped(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(0.95),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();
    assert_eq!(response.hits[0].id, "c");
    let trace = response.graph.expect("dense graph trace");
    assert_eq!(
        trace.graph_plan.chosen,
        GraphRetrievalPlan::P2PrefilteredCascade
    );
    assert!(trace.graph_expand.edges_examined > 0);
    assert!(trace.graph_expand.hop_global > 0);
    assert_eq!(trace.graph_expand.alpha_bps, Some(0));
    assert_eq!(trace.graph_expand.beta_bps, Some(0));
    assert!(trace.fuse.is_none());

    let dense_report = db
        .graph_shadow_runtime
        .wait_for_report("docs", 77, Duration::from_secs(5))
        .expect("dense shadow report");
    assert_eq!(dense_report.envelope_version, 1);
    assert_eq!(
        dense_report.chosen,
        GraphRetrievalPlan::P2PrefilteredCascade
    );
    let dense_plans = dense_report
        .alternatives
        .iter()
        .map(|timing| timing.plan)
        .collect::<Vec<_>>();
    assert_eq!(
        dense_plans,
        vec![
            GraphRetrievalPlan::P1Exact,
            GraphRetrievalPlan::P3ProgressiveProbe,
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
        ]
    );
    assert!(
        dense_report
            .alternatives
            .iter()
            .all(|timing| timing.error_code.is_none())
    );

    let response = db
        .hybrid_search_scoped(
            "docs",
            HybridSearchRequest {
                vector: Some(vec![0.0, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                fusion: HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
            &scope,
        )
        .unwrap();
    let trace = response.graph.expect("RRF graph trace");
    let fuse = trace.fuse.expect("RRF branch detail");
    assert!(fuse.dense_admitted > 0);
    assert!(fuse.sparse_admitted > 0);

    let hybrid_report = db
        .graph_shadow_runtime
        .wait_for_report("docs", 77, Duration::from_secs(5))
        .expect("hybrid shadow report");
    assert_eq!(hybrid_report.envelope_version, 2);
    assert_eq!(
        hybrid_report.chosen,
        GraphRetrievalPlan::P2PrefilteredCascade
    );
    let hybrid_plans = hybrid_report
        .alternatives
        .iter()
        .map(|timing| timing.plan)
        .collect::<Vec<_>>();
    assert_eq!(
        hybrid_plans,
        vec![
            GraphRetrievalPlan::P1Exact,
            GraphRetrievalPlan::P3HybridJointWidening,
            GraphRetrievalPlan::P4ReachabilityAwareBeam,
        ]
    );
    assert!(
        hybrid_report
            .alternatives
            .iter()
            .all(|timing| timing.error_code.is_none())
    );
}

#[test]
fn graph_expand_reports_locality_and_live_supersession_after_authorization() {
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();

    let query = || SearchRequest {
        vector: vec![0.0, 0.0],
        vector_name: None,
        k: 1,
        filter: None,
        graph: Some(graph_constraint("a", 1)),
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: Some(0.95),
        with_payload: Some(false),
    };
    let first = db.search_scoped("docs", query(), &scope).unwrap();
    let first = first.graph.expect("sealed graph trace").graph_expand;
    assert!(first.hop_local > 0);
    assert_eq!(first.hop_global, 0);
    assert_eq!(first.alpha_bps, Some(10_000));
    assert_eq!(first.supersession_followed, 0);
    assert_eq!(first.beta_bps, Some(0));
    assert!(first.fragments_read > 0);

    db.upsert("docs", vec![retrieval_point("c", 0.125, true)])
        .unwrap();
    let response = db.search_scoped("docs", query(), &scope).unwrap();
    assert_eq!(response.hits[0].id, "c");
    let followed = response.graph.expect("supersession trace").graph_expand;
    assert!(followed.hop_local > 0);
    assert!(followed.supersession_followed > 0);
    assert!(followed.beta_bps.is_some_and(|beta| beta > 0));
}

#[test]
fn public_dense_route_reports_exact_guard_without_calibration() {
    let (_temp, db, scope) = retrieval_fixture();
    let response = db
        .search_scoped(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(0.95),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();

    let trace = response.graph.expect("graph dispatch trace");
    assert_eq!(trace.graph_estimate.estimator, GraphEstimatorKind::Default);
    assert_eq!(trace.graph_plan.chosen, GraphRetrievalPlan::P1Exact);
    assert_eq!(
        trace.graph_plan.guard,
        Some(GraphPlanGuard::CalibrationMissing)
    );
    assert!(trace.graph_plan.modelled_costs.is_none());
    assert!(trace.warnings.is_empty());
}

#[test]
fn degraded_p5_opt_in_is_marked_and_durably_audited() {
    let (temp, db, scope) = retrieval_fixture();
    drop(db);

    let reopened = Db::open(temp.path()).unwrap();
    let mut envelope = dispatch_envelope(&reopened);
    envelope.p5_min_specificity_bps = Some(0);
    envelope.p5_max_k = Some(10);
    envelope.p5_observed_recall_bps = Some(9_000);
    drop(reopened);
    GraphCalibrationStore {
        calibration_version: 1,
        envelopes: vec![envelope],
    }
    .publish(&collection_dir(temp.path(), "docs"))
    .unwrap();

    let reopened = Db::open(temp.path()).unwrap();
    reopened.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
    let mut graph = graph_constraint("a", 1);
    graph.allow_degraded = true;
    let response = reopened
        .search_scoped(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(0.95),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();

    assert!(response.degraded);
    let trace = response.graph.expect("graph dispatch trace");
    assert_eq!(trace.graph_plan.chosen, GraphRetrievalPlan::P5BestFirst);
    assert_eq!(
        trace.graph_plan.guard,
        Some(GraphPlanGuard::BestFirstThreshold)
    );
    assert!(trace.graph_plan.degraded);
    assert!(trace.warnings.contains(&GraphQueryWarning::DegradedPlan));
    assert!(trace.graph_plan.modelled_costs.is_none());

    let records = fs::read_to_string(crate::audit::audit_log_path(temp.path())).unwrap();
    let success = records
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|record| {
            record["category"] == "query"
                && record["operation"] == "graph.allow_degraded_search"
                && record["outcome"] == "success"
        })
        .expect("durable ALLOW DEGRADED audit outcome");
    assert_eq!(success["principal_id"], "retrieval-test");
    assert_eq!(success["tenant_id"], "acme");
    assert_eq!(success["details"]["allow_degraded"], true);
    assert_eq!(success["details"]["served_degraded"], true);
    assert_eq!(
        success["details"]["dispatch"]["graph_plan"]["chosen"],
        "p5_best_first"
    );
    assert!(success["details"].get("hits").is_none());
}

#[test]
fn public_rrf_route_uses_hybrid_calibration_and_shared_probe() {
    let (temp, db, scope) = retrieval_fixture_with_recall(Some(0.95));
    drop(db);

    let reopened = Db::open(temp.path()).unwrap();
    let mut envelope = dispatch_envelope(&reopened);
    envelope.mode = GraphContractMode::HybridRrf;
    drop(reopened);
    GraphCalibrationStore {
        calibration_version: 1,
        envelopes: vec![envelope],
    }
    .publish(&collection_dir(temp.path(), "docs"))
    .unwrap();

    let reopened = Db::open(temp.path()).unwrap();
    reopened.set_tenant_enforcement(crate::tenant::TenantEnforcement::Enforced);
    let scoped_filter = scope
        .scope_filter(crate::tenant::TenantEnforcement::Enforced, None)
        .unwrap();
    let prepared = reopened
        .prepare_graph_dispatch(
            "docs",
            graph_constraint("a", 1),
            scoped_filter.as_ref(),
            None,
            1,
            None,
            GraphStatementMode::HybridRrf,
            &scope,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(
        matches!(
            &prepared,
            crate::db::graph_retrieval::PreparedGraphDispatch::Calibrated {
                selection: crate::graph_planner::GraphPlanSelection {
                    plan: GraphRetrievalPlan::P2PrefilteredCascade,
                    ..
                },
                ..
            }
        ),
        "unexpected prepared dispatch: {prepared:?}"
    );

    let response = reopened
        .hybrid_search_scoped(
            "docs",
            HybridSearchRequest {
                vector: Some(vec![0.0, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                fusion: HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
            &scope,
        )
        .unwrap();
    assert_eq!(response.hits.len(), 1);
    assert!(["b", "c"].contains(&response.hits[0].id.as_str()));
}

#[test]
fn stale_planner_ticket_refuses_approximate_execution() {
    let (_temp, db, scope) = retrieval_fixture();
    let coll = db.get_coll("docs").unwrap();
    let collection = coll.read();
    let visibility = collection.overlay_read_state();
    let mut state =
        crate::db::graph_retrieval::graph_planner_state(&collection, &visibility).unwrap();
    state.schema_epoch += 1;
    drop(collection);

    let selection = p2_selection(GraphStatementMode::Dense, 2).bind_state(state);
    let error = db
        .p2_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(0.95),
                with_payload: Some(false),
            },
            &scope,
            &AtomicBool::new(false),
            selection,
        )
        .unwrap_err();
    assert!(error.to_string().contains("calibrated read state changed"));
}

#[test]
fn p3_progressively_widens_one_ann_cursor_until_k_survivors() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();
    let outcome = db
        .p3_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(false),
            },
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            p3_policy(4),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3Termination::KSurvivors);
    assert_eq!(outcome.cumulative_windows, vec![1, 2, 4]);
    assert_eq!(outcome.ann_candidates_materialized, 4);
    assert_eq!(outcome.candidates_probed, 3);
    assert_eq!(outcome.target_probes, 0);
    assert_eq!(outcome.response.searched, 3);
    assert_eq!(outcome.response.hits[0].id, "c");
    assert!(outcome.response.hits[0].payload.is_null());
}

#[test]
fn p3_bidirectional_probe_meets_the_shared_anchor_frontier() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let outcome = db
        .p3_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.1, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 2)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            p3_policy(2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3Termination::KSurvivors);
    assert_eq!(outcome.cumulative_windows, vec![1]);
    assert_eq!(outcome.anchor_frontier_nodes, 2);
    assert_eq!(outcome.target_probes, 1);
    assert!(outcome.internal_edges_examined >= 4);
    assert_eq!(outcome.response.hits[0].id, "e");

    let mut incoming = graph_constraint("e", 2);
    incoming.direction = GraphDirection::Incoming;
    let reverse_outcome = db
        .p3_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![9.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(incoming),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            p3_policy(2),
        )
        .unwrap();
    assert_eq!(reverse_outcome.response.hits[0].id, "a");
    assert_eq!(reverse_outcome.target_probes, 1);
}

#[test]
fn p3_candidate_cap_finishes_with_exact_p1_fallback() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let outcome = db
        .p3_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 2,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            p3_policy(2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3Termination::ExactFallback);
    assert_eq!(outcome.cumulative_windows, vec![2]);
    assert_eq!(outcome.candidates_probed, 2);
    assert_eq!(outcome.response.searched, 2);
    assert_eq!(
        outcome
            .response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );
}

#[test]
fn p3_rejects_uncalibrated_policy_plan_and_partial_budget_results() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let request = || SearchRequest {
        vector: vec![0.0, 0.0],
        vector_name: None,
        k: 1,
        filter: None,
        graph: Some(graph_constraint("a", 1)),
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: None,
        with_payload: None,
    };
    let error = db
        .p3_graph_search_scoped_controlled(
            "docs",
            request(),
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            P3ProgressivePolicy {
                initial_factor: 0,
                growth_factor: 2,
                max_candidates: 4,
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("initial_factor"), "{error}");

    let error = db
        .p3_graph_search_scoped_controlled(
            "docs",
            request(),
            &scope,
            &AtomicBool::new(false),
            p2_selection(GraphStatementMode::Dense, 2),
            p3_policy(4),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("no dense P3 executor"),
        "{error}"
    );

    let cancelled = AtomicBool::new(true);
    let error = db
        .p3_graph_search_scoped_controlled(
            "docs",
            request(),
            &scope,
            &cancelled,
            p3_selection(),
            p3_policy(4),
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.cancelled"), "{error}");

    let mut constrained = request();
    constrained.graph.as_mut().unwrap().budget.max_memory_bytes = 4 * 1024;
    let error = db
        .p3_graph_search_scoped_controlled(
            "docs",
            constrained,
            &scope,
            &AtomicBool::new(false),
            p3_selection(),
            p3_policy(4),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("P3 cursor, anchor frontier"),
        "{error}"
    );
}

#[test]
fn p3h_jointly_widens_unequal_branch_depths_until_rrf_bound_closes() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();
    let exact = db
        .exact_graph_hybrid_search_scoped(
            "docs",
            p3h_request(1, 1),
            &scope,
            &AtomicBool::new(false),
        )
        .unwrap();
    let outcome = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            p3h_request(1, 1),
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(4, 2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3HybridTermination::RrfBoundClosed);
    assert_eq!(outcome.dense_windows, vec![1, 2, 4]);
    assert_eq!(outcome.sparse_windows, vec![1, 2]);
    assert_eq!(outcome.dense_depth, 4);
    assert_eq!(outcome.sparse_depth, 2);
    assert_eq!(outcome.dense_admitted, 2);
    assert_eq!(outcome.sparse_admitted, 2);
    assert_eq!(outcome.candidates_seen, 4);
    assert_eq!(outcome.reachability_decisions, 4);
    assert_eq!(outcome.target_probes, 0);
    assert!(outcome.kth_score.unwrap() > outcome.stopping_bound);
    assert_eq!(outcome.response.hits[0].id, "c");
    assert_eq!(outcome.response.hits[0].id, exact.hits[0].id);
    assert_eq!(outcome.response.hits[0].score, exact.hits[0].score);
}

#[test]
fn p3h_probes_each_cross_branch_candidate_once() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let outcome = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            p3h_request(1, 2),
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(4, 2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3HybridTermination::RrfBoundClosed);
    assert_eq!(outcome.candidates_seen, outcome.reachability_decisions);
    assert_eq!(outcome.candidates_seen, 4);
    assert_eq!(outcome.target_probes, 2);
    assert_eq!(outcome.anchor_frontier_nodes, 2);
    assert!(outcome.internal_edges_examined >= 4);
    assert_eq!(outcome.response.hits[0].id, "b");
}

#[test]
fn p3h_conjoins_statement_filter_and_tenant_scope_before_admission() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut hidden = retrieval_point("hidden", 0.0, true);
    hidden.payload["tenant_id"] = json!("other");
    hidden.sparse_vector = Some(SparseVector {
        indices: vec![7],
        values: vec![100.0],
    });
    db.upsert("docs", vec![hidden]).unwrap();
    let mut request = p3h_request(1, 1);
    request.filter = Some(Filter(json!({"allowed": true})));
    let outcome = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            request,
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(6, 3),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3HybridTermination::RrfBoundClosed);
    assert_eq!(outcome.response.hits.len(), 1);
    assert_eq!(outcome.response.hits[0].id, "c");
    assert_eq!(outcome.response.hits[0].payload["tenant_id"], "acme");
    assert!(outcome.candidates_seen >= 3);
}

#[test]
fn p3h_cursor_caps_finish_with_complete_fused_p1_fallback() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let outcome = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            p3h_request(2, 1),
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(2, 2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P3HybridTermination::ExactFallback);
    assert_eq!(outcome.dense_depth, 2);
    assert_eq!(outcome.sparse_depth, 2);
    assert_eq!(
        outcome
            .response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );
}

#[test]
fn p3h_rejects_weighted_missing_branches_wrong_plan_and_unbounded_state() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut weighted = p3h_request(1, 1);
    weighted.fusion = HybridFusion::Weighted;
    let error = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            weighted,
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(4, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("only for RRF"), "{error}");

    let mut missing_sparse = p3h_request(1, 1);
    missing_sparse.sparse_vector = None;
    let error = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            missing_sparse,
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(4, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("sparse branch"), "{error}");

    let error = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            p3h_request(1, 1),
            &scope,
            &AtomicBool::new(false),
            p2_selection(GraphStatementMode::HybridRrf, 2),
            p3h_policy(4, 2),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("no fused P3H executor"),
        "{error}"
    );

    let mut constrained = p3h_request(1, 1);
    constrained.graph.as_mut().unwrap().budget.max_memory_bytes = 16 * 1024;
    let error = db
        .p3h_graph_hybrid_search_scoped_controlled(
            "docs",
            constrained,
            &scope,
            &AtomicBool::new(false),
            p3h_selection(),
            p3h_policy(4, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("P3H branch cursors"), "{error}");
}

#[test]
fn p4_dense_ranks_only_admitted_rows_on_segmented_lsvec() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();
    let outcome = db
        .p4_graph_search_scoped_controlled(
            "docs",
            p4_dense_request(2),
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P4Termination::Beam);
    assert_eq!(outcome.admitted_points, 2);
    assert_eq!(outcome.dense_candidates, 2);
    assert_eq!(outcome.sparse_candidates, 0);
    // This five-row sealed segment takes LS-VEC's exact small-segment leg;
    // the predicate-level test covers the compressed-beam bridge contract.
    assert_eq!(outcome.non_admitted_navigation_checks, 0);
    assert_eq!(outcome.response.searched, 2);
    assert_eq!(
        outcome
            .response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );
    assert!(
        outcome
            .response
            .hits
            .iter()
            .all(|hit| hit.payload.is_null())
    );
}

#[test]
fn p4_hybrid_changes_only_dense_navigation_for_rrf_and_weighted() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();

    for (mode, fusion) in [
        (GraphStatementMode::HybridRrf, HybridFusion::Rrf),
        (GraphStatementMode::HybridWeighted, HybridFusion::Weighted),
    ] {
        let exact = db
            .exact_graph_hybrid_search_scoped(
                "docs",
                p4_hybrid_request(1, fusion),
                &scope,
                &AtomicBool::new(false),
            )
            .unwrap();
        let outcome = db
            .p4_graph_hybrid_search_scoped_controlled(
                "docs",
                p4_hybrid_request(1, fusion),
                &scope,
                &AtomicBool::new(false),
                p4_selection(mode, 2),
            )
            .unwrap();

        assert_eq!(outcome.termination, P4Termination::Beam);
        assert_eq!(outcome.admitted_points, 2);
        assert_eq!(outcome.dense_candidates, 2);
        assert_eq!(outcome.sparse_candidates, 2);
        assert_eq!(outcome.non_admitted_navigation_checks, 0);
        assert_eq!(outcome.response.hits[0].id, "c");
        assert_eq!(outcome.response.hits[0].id, exact.hits[0].id);
        assert_eq!(outcome.response.hits[0].score, exact.hits[0].score);
    }
}

#[test]
fn p4_underfill_finishes_with_complete_exact_p1_fallback() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();
    let outcome = db
        .p4_graph_search_scoped_controlled(
            "docs",
            p4_dense_request(3),
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap();

    assert_eq!(outcome.termination, P4Termination::ExactFallback);
    assert_eq!(outcome.admitted_points, 2);
    assert_eq!(outcome.dense_candidates, 2);
    assert_eq!(outcome.response.searched, 2);
    assert_eq!(
        outcome
            .response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );

    let hybrid = db
        .p4_graph_hybrid_search_scoped_controlled(
            "docs",
            p4_hybrid_request(3, HybridFusion::Rrf),
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::HybridRrf, 2),
        )
        .unwrap();
    assert_eq!(hybrid.termination, P4Termination::ExactFallback);
    assert_eq!(
        hybrid
            .response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );
}

#[test]
fn p4_conjoins_statement_filter_and_tenant_scope_before_result_admission() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut hidden = retrieval_point("hidden", 0.0, true);
    hidden.payload["tenant_id"] = json!("other");
    db.upsert("docs", vec![hidden]).unwrap();
    let mut request = p4_dense_request(2);
    request.filter = Some(Filter(json!({"allowed": true})));
    request.with_payload = Some(true);
    let outcome = db
        .p4_graph_search_scoped_controlled(
            "docs",
            request,
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::Dense, 1),
        )
        .unwrap();

    assert_eq!(outcome.admitted_points, 1);
    assert_eq!(outcome.termination, P4Termination::ExactFallback);
    assert_eq!(outcome.response.hits.len(), 1);
    assert_eq!(outcome.response.hits[0].id, "c");
    assert_eq!(outcome.response.hits[0].payload["tenant_id"], "acme");
}

#[test]
fn p4_rejects_wrong_plan_missing_branch_cancellation_and_unbounded_state() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();

    let error = db
        .p4_graph_search_scoped_controlled(
            "docs",
            p4_dense_request(1),
            &scope,
            &AtomicBool::new(false),
            p2_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("no P4 executor"), "{error}");

    let mut missing_sparse = p4_hybrid_request(1, HybridFusion::Rrf);
    missing_sparse.sparse_vector = None;
    let error = db
        .p4_graph_hybrid_search_scoped_controlled(
            "docs",
            missing_sparse,
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::HybridRrf, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("sparse branch"), "{error}");

    let error = db
        .p4_graph_search_scoped_controlled(
            "docs",
            p4_dense_request(1),
            &scope,
            &AtomicBool::new(true),
            p4_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.cancelled"), "{error}");

    let mut constrained = p4_dense_request(2);
    constrained.graph.as_mut().unwrap().budget.max_memory_bytes = 8 * 1024;
    let error = db
        .p4_graph_search_scoped_controlled(
            "docs",
            constrained,
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("P4 candidate and ranking state"),
        "{error}"
    );
}

#[test]
fn p5_best_first_stops_on_a_stable_dense_frontier_without_materializing_reachability() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = p5_fixture();
    let outcome = db
        .p5_graph_search_scoped_controlled(
            "docs",
            p5_request(1),
            &scope,
            &AtomicBool::new(false),
            p5_selection(false),
            p5_policy(16),
        )
        .unwrap();

    assert_eq!(outcome.termination, P5Termination::StableTopK);
    assert_eq!(outcome.response.hits.len(), 1);
    assert_eq!(outcome.response.hits[0].id, "winner");
    assert!(!outcome.response.degraded);
    assert_eq!(outcome.frontier_pops, 3);
    assert_eq!(outcome.frontier_expansions, 2);
    assert_eq!(outcome.vector_distances, 3);
    assert_eq!(outcome.unique_nodes_seen, 4);
    assert_eq!(outcome.peak_frontier, 2);
    assert_eq!(outcome.max_depth_popped, 2);
    assert_eq!(outcome.internal_edges_examined, 3);

    let exact = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                graph: graph_constraint("a", 2),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();
    assert_eq!(exact.hits[0].id, "hidden");
    assert_ne!(outcome.response.hits[0].id, exact.hits[0].id);
}

#[test]
fn p5_work_ceiling_releases_frontier_and_runs_complete_p1() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = p5_fixture();
    let outcome = db
        .p5_graph_search_scoped_controlled(
            "docs",
            p5_request(1),
            &scope,
            &AtomicBool::new(false),
            p5_selection(false),
            p5_policy(1),
        )
        .unwrap();

    assert_eq!(outcome.termination, P5Termination::ExactFallback);
    assert_eq!(outcome.response.hits.len(), 1);
    assert_eq!(outcome.response.hits[0].id, "hidden");
    assert_eq!(outcome.frontier_expansions, 1);
    assert_eq!(outcome.vector_distances, 2);
    assert!(outcome.internal_edges_examined >= 6);
}

#[test]
fn p5_conjoins_statement_filter_before_frontier_admission() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut request = p5_request(1);
    request.filter = Some(Filter(json!({"allowed": true})));
    request.with_payload = Some(true);
    let outcome = db
        .p5_graph_search_scoped_controlled(
            "docs",
            request,
            &scope,
            &AtomicBool::new(false),
            p5_selection(true),
            p5_policy(16),
        )
        .unwrap();

    assert_eq!(outcome.termination, P5Termination::FrontierExhausted);
    assert_eq!(outcome.response.hits.len(), 1);
    assert_eq!(outcome.response.hits[0].id, "c");
    assert_eq!(outcome.response.hits[0].payload["tenant_id"], "acme");
    assert!(outcome.response.degraded);
    assert_eq!(outcome.unique_nodes_seen, 2);
}

#[test]
fn p5_keeps_vectorless_nodes_as_low_priority_graph_intermediates() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::tenant("p5-vectorless", "acme");
    let mut config = ls_vec_config("docs");
    config.named_vector_dims.insert("semantic".to_string(), 2);
    db.create_collection(config).unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    let mut target = retrieval_point("target", 5.0, true);
    target
        .vectors
        .insert("semantic".to_string(), vec![0.0, 0.0]);
    db.upsert(
        "docs",
        vec![
            retrieval_point("a", 9.0, true),
            retrieval_point("bridge", 4.0, true),
            target,
        ],
    )
    .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "links".to_string(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    relate(&db, &scope, "a", "bridge", "links", true);
    relate(&db, &scope, "bridge", "target", "links", true);
    let mut request = p5_request(1);
    request.vector_name = Some("semantic".to_string());
    let outcome = db
        .p5_graph_search_scoped_controlled(
            "docs",
            request,
            &scope,
            &AtomicBool::new(false),
            p5_selection(false),
            p5_policy(16),
        )
        .unwrap();

    assert_eq!(outcome.termination, P5Termination::FrontierExhausted);
    assert_eq!(outcome.response.hits[0].id, "target");
    assert_eq!(outcome.vector_distances, 1);
    assert_eq!(outcome.frontier_expansions, 2);
    assert_eq!(outcome.unique_nodes_seen, 3);
}

#[test]
fn p5_rejects_wrong_plan_zero_policy_and_cancellation() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = p5_fixture();

    let error = db
        .p5_graph_search_scoped_controlled(
            "docs",
            p5_request(1),
            &scope,
            &AtomicBool::new(false),
            p4_selection(GraphStatementMode::Dense, 4),
            p5_policy(16),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("no dense P5 executor"),
        "{error}"
    );

    let error = db
        .p5_graph_search_scoped_controlled(
            "docs",
            p5_request(1),
            &scope,
            &AtomicBool::new(false),
            p5_selection(false),
            p5_policy(0),
        )
        .unwrap_err();
    assert!(error.to_string().contains("max_expansions"), "{error}");

    let error = db
        .p5_graph_search_scoped_controlled(
            "docs",
            p5_request(1),
            &scope,
            &AtomicBool::new(true),
            p5_selection(false),
            p5_policy(16),
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.cancelled"), "{error}");
}

#[test]
fn p2_dense_and_hybrid_consume_one_prefusion_admitted_set() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let cancelled = AtomicBool::new(false);
    let dense = db
        .p2_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 2,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(false),
            },
            &scope,
            &cancelled,
            p2_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap();
    assert_eq!(dense.searched, 2);
    assert_eq!(
        dense
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "b"]
    );
    assert!(dense.hits.iter().all(|hit| hit.payload.is_null()));

    let hybrid = db
        .p2_graph_hybrid_search_scoped(
            "docs",
            HybridSearchRequest {
                vector: Some(vec![0.0, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                fusion: HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
            &scope,
            &cancelled,
            p2_selection(GraphStatementMode::HybridRrf, 2),
        )
        .unwrap();
    assert_eq!(hybrid.hits.len(), 1);
    assert_eq!(hybrid.hits[0].id, "c");
    assert!(!hybrid.degraded);
}

#[test]
fn p2_uses_sealed_ordinals_and_mutable_id_fallback() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    db.compact_collection("docs").unwrap();
    {
        let collection = db.get_coll("docs").unwrap();
        let collection = collection.read();
        assert!(collection.streamer.points.is_empty());
        assert!(collection.searchers.iter().any(|searcher| {
            searcher.ordinal("b").is_some()
                && searcher.ordinal("c").is_some()
                && searcher
                    .backend_for(None)
                    .is_some_and(|backend| backend.kind() == crate::index::IndexKind::Ivf)
        }));
    }

    db.upsert("docs", vec![retrieval_point("f", 0.2, true)])
        .unwrap();
    relate(&db, &scope, "a", "f", "links", true);
    let response = db
        .p2_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 3,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            p2_selection(GraphStatementMode::Dense, 3),
        )
        .unwrap();
    assert_eq!(response.searched, 3);
    assert_eq!(
        response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["f", "c", "b"]
    );
}

#[test]
fn p2_executor_rejects_a_different_selected_plan() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut selection = p2_selection(GraphStatementMode::Dense, 2);
    selection.plan = GraphRetrievalPlan::P3ProgressiveProbe;
    let error = db
        .p2_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                filter: None,
                graph: Some(graph_constraint("a", 1)),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            selection,
        )
        .unwrap_err();
    assert!(error.to_string().contains("no P2 executor"), "{error}");
}

#[test]
fn p2_candidate_and_rank_memory_fail_before_partial_results() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut graph = graph_constraint("a", 1);
    graph.budget.max_memory_bytes = 8 * 1024;
    let error = db
        .p2_graph_search_scoped_controlled(
            "docs",
            SearchRequest {
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 2,
                filter: None,
                graph: Some(graph),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
            &scope,
            &AtomicBool::new(false),
            p2_selection(GraphStatementMode::Dense, 2),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("P2 candidate and ranking state"),
        "{error}"
    );
}

#[test]
fn p1_exact_ranks_only_reachable_members_by_vector_distance() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let response = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                graph: graph_constraint("a", 1),
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();

    assert_eq!(response.plan, GraphRetrievalPlan::P1Exact);
    assert_eq!(response.searched, 2);
    assert_eq!(
        response
            .hits
            .iter()
            .map(|hit| hit.id.as_str())
            .collect::<Vec<_>>(),
        vec!["c"]
    );
    assert!(response.hits.iter().all(|hit| hit.payload.is_null()));
    assert_eq!(response.traversal.hops_completed, 1);
}

#[test]
fn p1_exact_applies_direction_type_node_edge_budget_and_cancellation_fail_closed() {
    #[cfg(feature = "fault-injection")]
    let _failpoint_guard = RETRIEVAL_FAILPOINT_ENV.lock().unwrap();
    let (_temp, db, scope) = retrieval_fixture();
    let mut graph = graph_constraint("a", 2);
    graph.node_filter = Some(Filter(json!({"allowed": true})));
    graph.edge_filter = Some(Filter(json!({"live": true})));
    let filtered = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 10,
                graph,
                with_payload: None,
            },
            &scope,
        )
        .unwrap();
    assert!(filtered.hits.is_empty());
    assert_eq!(filtered.searched, 0);

    let mut incoming = graph_constraint("b", 1);
    incoming.direction = GraphDirection::Incoming;
    let incoming = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![9.0, 0.0],
                vector_name: None,
                k: 1,
                graph: incoming,
                with_payload: None,
            },
            &scope,
        )
        .unwrap();
    assert_eq!(incoming.hits[0].id, "a");

    let mut bounded = graph_constraint("a", 1);
    bounded.budget.max_edges = 1;
    let error = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 10,
                graph: bounded,
                with_payload: None,
            },
            &scope,
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.slo_unavailable"));

    let cancelled = AtomicBool::new(true);
    let error = db
        .exact_graph_search_cancellable_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 10,
                graph: graph_constraint("a", 1),
                with_payload: None,
            },
            &scope,
            &cancelled,
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.cancelled"));
}

#[test]
fn scoped_dense_route_conjoins_statement_filter_before_graph_expansion() {
    let (_temp, db, scope) = retrieval_fixture();
    let filter = Filter(json!({"allowed": true}));
    let graph = graph_constraint("a", 2);
    let routed = db
        .search_scoped(
            "docs",
            SearchRequest {
                graph: Some(graph.clone()),
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 10,
                filter: Some(filter.clone()),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();
    let exact = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: Some(filter),
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 10,
                graph,
                with_payload: Some(false),
            },
            &scope,
        )
        .unwrap();

    let routed_ids = routed
        .hits
        .iter()
        .map(|hit| hit.id.as_str())
        .collect::<Vec<_>>();
    let exact_ids = exact
        .hits
        .iter()
        .map(|hit| hit.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(routed_ids, vec!["c"]);
    assert_eq!(routed_ids, exact_ids);
    assert_eq!(routed.searched, 1);
    assert!(routed.hits[0].payload.is_null());
}

#[test]
fn hybrid_rrf_uses_complete_dense_and_sparse_ranks_inside_one_admitted_set() {
    let (_temp, db, scope) = retrieval_fixture();
    let response = db
        .hybrid_search_scoped(
            "docs",
            HybridSearchRequest {
                graph: Some(graph_constraint("a", 1)),
                vector: Some(vec![0.0, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 2,
                filter: None,
                budget_ms: None,
                fusion: HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
            &scope,
        )
        .unwrap();

    assert_eq!(response.hits.len(), 2);
    assert!(response.searched >= 4);
    let admitted_score = 1.0 / 61.0 + 1.0 / 62.0;
    for (actual, expected_id) in response.hits.iter().zip(["c", "b"]) {
        assert_eq!(actual.id, expected_id);
        assert!((actual.score - admitted_score).abs() < 1e-6);
    }

    // A post-fusion filter would first assign dense ranks to graph-excluded
    // points e and d, corrupting the scores retained for b and c.
    let post_fusion_b = 1.0 / 64.0 + 1.0 / 61.0;
    let post_fusion_c = 1.0 / 63.0 + 1.0 / 62.0;
    assert!((response.hits[0].score - post_fusion_c).abs() > 1e-6);
    assert!((response.hits[1].score - post_fusion_b).abs() > 1e-6);

    let mut memory_bounded = graph_constraint("a", 1);
    memory_bounded.budget.max_memory_bytes = 12_000;
    let error = db
        .hybrid_search_scoped(
            "docs",
            HybridSearchRequest {
                graph: Some(memory_bounded),
                vector: Some(vec![0.0, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: vec![7],
                    values: vec![1.0],
                }),
                k: 2,
                filter: None,
                budget_ms: None,
                fusion: HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
            &scope,
        )
        .unwrap_err();
    assert!(error.to_string().contains("fused ranking"));
}

#[cfg(feature = "fault-injection")]
#[test]
fn p1_exact_pins_vector_and_graph_state_until_scoring_finishes() {
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    let (temp, db, scope) = retrieval_fixture();
    let marker = temp.path().join("retrieval-paused");
    let release = temp.path().join("retrieval-release");
    let _failpoint_guard =
        crate::failpoint::test_env("pause:graph_retrieval.after_expansion", &marker, &release);

    let query_db = db.clone();
    let query_scope = scope.clone();
    let query = thread::spawn(move || {
        query_db.exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                graph: graph_constraint("a", 1),
                with_payload: None,
            },
            &query_scope,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "retrieval did not reach its pinned-state pause"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let writer_db = db.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = writer_db.upsert("docs", vec![retrieval_point("c", 20.0, true)]);
        finished_tx.send(result).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        finished_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "point mutation crossed the pinned collection read state"
    );

    std::fs::write(&release, b"continue").unwrap();
    let before = query.join().unwrap().unwrap();
    assert_eq!(before.hits[0].id, "c");
    finished_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    writer.join().unwrap();
    drop(_failpoint_guard);

    let after = db
        .exact_graph_search_scoped(
            "docs",
            ExactGraphSearchRequest {
                filter: None,
                vector: vec![0.0, 0.0],
                vector_name: None,
                k: 1,
                graph: graph_constraint("a", 1),
                with_payload: None,
            },
            &scope,
        )
        .unwrap();
    assert_eq!(after.hits[0].id, "b");
}
