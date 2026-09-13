//! C11 G0 tenant-isolation gate.
//!
//! These tests deliberately live outside the general graph tests so the gate
//! cannot be mistaken for ordinary RBAC coverage. They exercise physical
//! namespace selection, authorized-vs-internal accounting, adversarial timing
//! classes, high tenant cardinality, redacted existence probes, and the
//! immutable-tenant rule through production mutation paths.

use std::{collections::HashMap, sync::atomic::AtomicBool, time::Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::Db;
use crate::{
    CollectionConfig, DistanceMetric, Point,
    graph::{
        ConfigureEdgeTypeRequest, EdgeId, EdgeMutation, GraphDirection, GraphEpoch, GraphNamespace,
        GraphRelationScope, GraphTraverseRequest, Nid, RelateMutation, RelateRequest,
        TraversalBudget, TypeId,
    },
    graph_traversal::{MutableTraversal, TraversalExecution, exact_bfs},
    mutable_graph::MutableGraphState,
    tenant::{TenantCapability, TenantEnforcement, TenantScope},
};

const EPOCH: u32 = 23;

fn nid(counter: u64) -> Nid {
    Nid::from_parts(EPOCH, counter).unwrap()
}

fn edge_id(counter: u64) -> EdgeId {
    EdgeId::from_parts(EPOCH, counter).unwrap()
}

fn relation(
    counter: u64,
    source: Nid,
    target: Nid,
    type_id: u32,
    namespace: GraphNamespace,
) -> EdgeMutation {
    EdgeMutation::Relate(RelateMutation {
        edge_id: edge_id(counter),
        source,
        target,
        type_id: TypeId::from_raw(type_id),
        namespace,
        properties: json!({"position": counter}),
    })
}

fn execute<'a>(
    graph: &'a MutableGraphState,
    payloads: &'a HashMap<Nid, Value>,
    anchor: Nid,
    selected_types: Option<std::collections::HashSet<TypeId>>,
    include_admin: bool,
) -> TraversalExecution {
    exact_bfs(MutableTraversal {
        graph,
        anchors: vec![anchor],
        visible_anchor_count: 1,
        selected_types,
        direction: GraphDirection::Outgoing,
        node_filter: None,
        statement_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: 1,
            ..TraversalBudget::default()
        },
        cancelled: &AtomicBool::new(false),
        payload_for_nid: |candidate| {
            payloads.get(&candidate).and_then(|payload| {
                let visible = include_admin
                    || payload.get("tenant_id").and_then(Value::as_str) == Some("acme");
                visible.then(|| payload.clone())
            })
        },
        namespaces_for_payload: |payload| {
            let tenant = payload["tenant_id"].as_str().unwrap();
            let mut namespaces = vec![GraphNamespace::Tenant(tenant.to_string())];
            if include_admin {
                namespaces.push(GraphNamespace::AdminCrossTenant);
            }
            namespaces
        },
    })
    .unwrap()
}

fn assert_authorized_stats_equal(left: &TraversalExecution, right: &TraversalExecution) {
    assert_eq!(
        left.result.stats.hops_completed,
        right.result.stats.hops_completed
    );
    assert_eq!(
        left.result.stats.nodes_visited,
        right.result.stats.nodes_visited
    );
    assert_eq!(
        left.result.stats.visible_edges_examined,
        right.result.stats.visible_edges_examined
    );
    assert_eq!(
        left.result.stats.max_frontier_size,
        right.result.stats.max_frontier_size
    );
    assert_eq!(
        left.result.stats.cold_fragments_read,
        right.result.stats.cold_fragments_read
    );
    assert_eq!(
        left.result.stats.cold_bytes_read,
        right.result.stats.cold_bytes_read
    );
    assert_eq!(left.result.truncation, right.result.truncation);
}

fn timing_class(nanos: u64) -> u8 {
    match nanos {
        0..10_000 => 0,
        10_000..100_000 => 1,
        100_000..1_000_000 => 2,
        1_000_000..10_000_000 => 3,
        _ => 4,
    }
}

#[test]
fn c11_high_cardinality_tenant_adjacency_is_selected_without_enumeration() {
    const TENANTS: u64 = 4_096;
    let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
    graph
        .types_mut()
        .configure(TypeId::from_raw(1), "LINK".to_string(), None)
        .unwrap();
    let mut payloads = HashMap::with_capacity((TENANTS * 2) as usize);
    let mut edges = Vec::with_capacity(TENANTS as usize);
    for tenant_index in 0..TENANTS {
        let tenant = format!("tenant-{tenant_index:04}");
        let source = nid(tenant_index * 2 + 1);
        let target = nid(tenant_index * 2 + 2);
        payloads.insert(source, json!({"tenant_id": tenant}));
        payloads.insert(target, json!({"tenant_id": tenant}));
        edges.push(relation(
            tenant_index + 1,
            source,
            target,
            1,
            GraphNamespace::Tenant(tenant),
        ));
    }
    graph.apply_validated_edge_mutations(&edges);

    for tenant_index in [0, TENANTS / 2, TENANTS - 1] {
        let source = nid(tenant_index * 2 + 1);
        let target = nid(tenant_index * 2 + 2);
        let tenant = format!("tenant-{tenant_index:04}");
        let execution = exact_bfs(MutableTraversal {
            graph: &graph,
            anchors: vec![source],
            visible_anchor_count: 1,
            selected_types: None,
            direction: GraphDirection::Outgoing,
            node_filter: None,
            statement_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 1,
                ..TraversalBudget::default()
            },
            cancelled: &AtomicBool::new(false),
            payload_for_nid: |candidate| payloads.get(&candidate).cloned(),
            namespaces_for_payload: |_| vec![GraphNamespace::Tenant(tenant.clone())],
        })
        .unwrap();

        assert_eq!(execution.internal_edges_examined, 1);
        assert_eq!(execution.result.stats.visible_edges_examined, 1);
        assert_eq!(execution.result.visits.len(), 1);
        assert_eq!(execution.result.visits[0].nid, target);
        assert!(
            graph
                .outgoing(
                    &GraphNamespace::Tenant(format!("tenant-{:04}", (tenant_index + 1) % TENANTS)),
                    source,
                )
                .is_empty(),
            "a scoped lookup must not enumerate another tenant's directory"
        );
        assert!(
            graph
                .outgoing(&GraphNamespace::AdminCrossTenant, source)
                .is_empty(),
            "tenant-local edges must not enter the admin directory"
        );
    }
}

#[test]
fn c11_hidden_degree_type_position_counters_and_timing_do_not_leak() {
    const HIDDEN_EDGES: u64 = 65_536;
    let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
    for (type_id, name) in [(1, "VISIBLE"), (2, "HIDDEN_A"), (3, "HIDDEN_B")] {
        graph
            .types_mut()
            .configure(TypeId::from_raw(type_id), name.to_string(), None)
            .unwrap();
    }
    let control_source = nid(1);
    let control_target = nid(2);
    let probe_source = nid(3);
    let probe_target = nid(4);
    let hidden_target = nid(5);
    let mut edges = Vec::with_capacity((HIDDEN_EDGES + 2) as usize);
    edges.push(relation(
        1,
        control_source,
        control_target,
        1,
        GraphNamespace::Tenant("acme".to_string()),
    ));
    edges.push(relation(
        2,
        probe_source,
        probe_target,
        1,
        GraphNamespace::Tenant("acme".to_string()),
    ));
    edges.extend((0..HIDDEN_EDGES).map(|index| {
        relation(
            index + 3,
            probe_source,
            hidden_target,
            if index.is_multiple_of(2) { 2 } else { 3 },
            GraphNamespace::AdminCrossTenant,
        )
    }));
    graph.apply_validated_edge_mutations(&edges);
    let payloads = HashMap::from([
        (control_source, json!({"tenant_id": "acme"})),
        (control_target, json!({"tenant_id": "acme"})),
        (probe_source, json!({"tenant_id": "acme"})),
        (probe_target, json!({"tenant_id": "acme"})),
        (hidden_target, json!({"tenant_id": "globex"})),
    ]);

    let control = execute(&graph, &payloads, control_source, None, false);
    let probe = execute(&graph, &payloads, probe_source, None, false);
    assert_eq!(control.internal_edges_examined, 1);
    assert_eq!(probe.internal_edges_examined, 1);
    assert_authorized_stats_equal(&control, &probe);
    assert_eq!(control.result.visits.len(), probe.result.visits.len());
    assert_eq!(probe.result.visits[0].nid, probe_target);

    let hidden_type = std::collections::HashSet::from([TypeId::from_raw(2)]);
    let control_type = execute(
        &graph,
        &payloads,
        control_source,
        Some(hidden_type.clone()),
        false,
    );
    let probe_type = execute(&graph, &payloads, probe_source, Some(hidden_type), false);
    assert!(control_type.result.visits.is_empty());
    assert!(probe_type.result.visits.is_empty());
    assert_eq!(control_type.internal_edges_examined, 1);
    assert_eq!(probe_type.internal_edges_examined, 1);
    assert_authorized_stats_equal(&control_type, &probe_type);

    let authorized = execute(&graph, &payloads, probe_source, None, true);
    assert_eq!(authorized.internal_edges_examined, HIDDEN_EDGES + 1);
    assert_eq!(
        authorized.result.stats.visible_edges_examined,
        HIDDEN_EDGES + 1
    );
    assert_eq!(authorized.result.visits.len(), 2);

    let mut control_times = Vec::with_capacity(129);
    let mut probe_times = Vec::with_capacity(129);
    for _ in 0..129 {
        let started = Instant::now();
        std::hint::black_box(execute(&graph, &payloads, control_source, None, false));
        control_times.push(started.elapsed().as_nanos() as u64);
        let started = Instant::now();
        std::hint::black_box(execute(&graph, &payloads, probe_source, None, false));
        probe_times.push(started.elapsed().as_nanos() as u64);
    }
    control_times.sort_unstable();
    probe_times.sort_unstable();
    let control_median = control_times[control_times.len() / 2];
    let probe_median = probe_times[probe_times.len() / 2];
    let upper = control_median
        .saturating_mul(12)
        .max(control_median.saturating_add(100_000));
    assert!(
        probe_median <= upper,
        "hidden admin namespace changed timing class: control={control_median}ns probe={probe_median}ns upper={upper}ns"
    );
    assert!(
        timing_class(probe_median) <= timing_class(control_median).saturating_add(1),
        "hidden admin namespace crossed timing classes: control={control_median}ns probe={probe_median}ns"
    );
    eprintln!(
        "C11 timing: control_median={control_median}ns class={} probe_median={probe_median}ns class={} upper={upper}ns",
        timing_class(control_median),
        timing_class(probe_median),
    );
}

fn collection_config(name: &str) -> CollectionConfig {
    CollectionConfig {
        name: name.to_string(),
        vector_dim: 2,
        metric: DistanceMetric::L2,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: usize::MAX,
    }
}

fn point(id: &str, x: f32, tenant: &str) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![x, 0.0],
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"tenant_id": tenant, "secret": format!("{id}-payload")}),
    }
}

#[test]
fn c11_scoped_runtime_redacts_existence_and_refuses_incident_tenant_moves() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(collection_config("docs")).unwrap();
    let acme = TenantScope::tenant("acme-reader", "acme");
    db.set_graph_lifecycle_scoped("docs", true, true, &acme)
        .unwrap();
    db.upsert(
        "docs",
        vec![
            point("source-private", 1.0, "acme"),
            point("target-private", 2.0, "acme"),
            point("hidden-private", 3.0, "globex"),
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
        &acme,
    )
    .unwrap();
    let local = RelateRequest {
        source_point_id: "source-private".to_string(),
        target_point_id: "target-private".to_string(),
        edge_type: "links".to_string(),
        properties: json!({"visible": true}),
        scope: GraphRelationScope::Local,
        idempotency_key: None,
    };
    db.relate_scoped("docs", local, true, &acme).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let cross = TenantScope::tenant("cross-admin", "acme")
        .with_capabilities([TenantCapability::CrossRead, TenantCapability::CrossWrite]);
    db.relate_scoped(
        "docs",
        RelateRequest {
            source_point_id: "source-private".to_string(),
            target_point_id: "hidden-private".to_string(),
            edge_type: "links".to_string(),
            properties: json!({"hidden": true}),
            scope: GraphRelationScope::AdminCrossTenant,
            idempotency_key: None,
        },
        true,
        &cross,
    )
    .unwrap();

    let request = GraphTraverseRequest {
        anchors: vec!["source-private".to_string()],
        edge_types: vec!["links".to_string()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: 1,
            ..TraversalBudget::default()
        },
    };
    let scoped = db.traverse_scoped("docs", request.clone(), &acme).unwrap();
    assert_eq!(scoped.nodes.len(), 1);
    assert_eq!(scoped.nodes[0].point_id, "target-private");
    assert_eq!(scoped.stats.visible_edges_examined, 1);
    let public_json = serde_json::to_string(&scoped).unwrap();
    assert!(!public_json.contains("hidden-private"));
    assert!(!public_json.contains("internal_edges"));
    assert!(!public_json.contains("nid"));

    let authorized = db.traverse_scoped("docs", request.clone(), &cross).unwrap();
    assert_eq!(authorized.nodes.len(), 2);
    assert_eq!(authorized.stats.visible_edges_examined, 2);
    assert!(
        authorized
            .nodes
            .iter()
            .any(|node| node.point_id == "hidden-private")
    );

    let hidden_error = db
        .traverse_scoped(
            "docs",
            GraphTraverseRequest {
                anchors: vec!["hidden-private".to_string()],
                ..request.clone()
            },
            &acme,
        )
        .unwrap_err();
    let missing_error = db
        .traverse_scoped(
            "docs",
            GraphTraverseRequest {
                anchors: vec!["does-not-exist-private".to_string()],
                ..request
            },
            &acme,
        )
        .unwrap_err();
    assert_eq!(hidden_error.to_string(), missing_error.to_string());
    assert_eq!(
        hidden_error.to_string(),
        "graph.endpoint_not_found: one or more graph endpoints are unavailable"
    );

    let coll = db.get_coll("docs").unwrap();
    let wal_before = coll.read().wal.len().unwrap();
    let identity_before = db.graph_identity.snapshot();
    let edge_count_before = coll
        .read()
        .graph_mutable
        .as_ref()
        .unwrap()
        .live_edge_count();
    let error = db
        .upsert_scoped(
            "docs",
            vec![point("source-private", 9.0, "globex")],
            true,
            &cross,
        )
        .unwrap_err();
    assert!(error.to_string().contains("graph.tenant_move_has_edges"));
    assert_eq!(coll.read().wal.len().unwrap(), wal_before);
    assert_eq!(db.graph_identity.snapshot(), identity_before);
    assert_eq!(
        coll.read()
            .graph_mutable
            .as_ref()
            .unwrap()
            .live_edge_count(),
        edge_count_before
    );
    let retained = db
        .get_points_scoped("docs", &["source-private".to_string()], &acme)
        .unwrap();
    assert_eq!(retained[0].payload["tenant_id"], "acme");
}
