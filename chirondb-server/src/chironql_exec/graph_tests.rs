use super::*;

use chirondb_core::{CollectionConfig, DistanceMetric, Point};
use chirondb_types::graph::{
    ConfigureEdgeTypeRequest, GraphDirection, GraphTraversalQueryRequest, GraphTraversalReturn,
    GraphTraversalRows, GraphTraverseRequest, GraphWarning, TraversalTruncationReason,
};
use chirondb_types::model::SparseVector;
use serde_json::{Value, json};
use tempfile::TempDir;

const COLLECTION: &str = "docs";

fn fixture(graph_enabled: bool) -> (TempDir, Db) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(CollectionConfig {
        name: COLLECTION.to_string(),
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
        streamer_max_bytes: 0,
    })
    .expect("create collection");
    if graph_enabled {
        let lifecycle = db
            .set_graph_lifecycle_scoped(COLLECTION, true, true, &TenantScope::system())
            .expect("enable graph");
        assert!(lifecycle.enabled);
        db.configure_edge_type_scoped(
            COLLECTION,
            ConfigureEdgeTypeRequest {
                name: "CITES".to_string(),
                weight_property: None,
            },
            true,
            &TenantScope::system(),
        )
        .expect("configure edge type");
    }
    db.upsert(
        COLLECTION,
        vec![
            point("root", vec![9.0, 9.0], 7),
            point("child", vec![1.0, 0.0], 11),
            point("leaf", vec![1.1, 0.0], 13),
            point("outsider", vec![0.0, 0.0], 11),
        ],
    )
    .expect("upsert points");
    (dir, db)
}

fn point(id: &str, vector: Vec<f32>, sparse_index: u32) -> Point {
    Point {
        id: id.to_string(),
        vector,
        vectors: Default::default(),
        sparse_vector: Some(SparseVector {
            indices: vec![sparse_index],
            values: vec![1.0],
        }),
        payload: json!({"kind": id}),
    }
}

fn candidate(
    db: &Db,
    session: &mut Session,
    tenant: TenantScope,
    role: Role,
    query: &str,
) -> ExecResult {
    let mut ctx = ExecContext {
        db,
        session,
        role,
        allowed_collections: None,
        want_trace: true,
        confirm: false,
        tenant,
    };
    execute(&mut ctx, query)
}

fn relate(db: &Db, source: &str, target: &str) -> String {
    relate_with_properties(db, source, target, json!({}))
}

fn relate_with_properties(db: &Db, source: &str, target: &str, properties: Value) -> String {
    let properties = properties
        .as_object()
        .expect("edge properties object")
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    let properties = format!("{{{properties}}}");
    let mut session = Session::default();
    let response = candidate(
        db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        &format!("RELATE {COLLECTION} {source} -> CITES -> {target} SET {properties};"),
    )
    .expect("relate");
    assert_eq!(response.stats.affected, Some(1));
    assert!(response.stats.graph_epoch.is_some());
    assert_eq!(response.stats.durable, Some(true));
    response.rows[0]["edge_id"]
        .as_str()
        .expect("opaque edge token")
        .to_string()
}

fn seed_traversal_topology(db: &Db) -> Vec<String> {
    vec![
        relate_with_properties(db, "root", "child", json!({"enabled": true, "rank": 1})),
        relate_with_properties(db, "root", "child", json!({"enabled": false, "rank": 2})),
        relate_with_properties(db, "root", "leaf", json!({"enabled": true, "rank": 3})),
        relate_with_properties(db, "child", "leaf", json!({"enabled": true, "rank": 4})),
        relate_with_properties(db, "leaf", "root", json!({"enabled": true, "rank": 5})),
        relate_with_properties(db, "child", "child", json!({"enabled": true, "rank": 6})),
    ]
}

#[test]
fn candidate_executes_graph_mutations_and_unrelate_is_atomic() {
    let (dir, db) = fixture(true);
    let first = relate(&db, "root", "child");
    let second = relate(&db, "root", "leaf");

    let mut session = Session::default();
    let updated = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        &format!("UPDATE {COLLECTION} EDGE '{first}' SET PROPERTIES {{reviewed: true}} REPLACE;"),
    )
    .expect("update edge");
    assert_eq!(updated.stats.affected, Some(1));
    assert!(updated.stats.operation_lsn.is_some());

    let failed = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        &format!("UNRELATE {COLLECTION} EDGE '{first}', 'not-a-token';"),
    )
    .expect_err("invalid second token refuses whole statement");
    assert_eq!(failed.code, "graph.edge_not_found");
    let still_present = db
        .traverse_scoped(
            COLLECTION,
            GraphTraverseRequest {
                anchors: vec!["root".to_string()],
                edge_types: vec!["CITES".to_string()],
                direction: GraphDirection::Outgoing,
                node_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 1,
                    ..TraversalBudget::default()
                },
            },
            &TenantScope::system(),
        )
        .expect("traverse after refused batch");
    assert_eq!(still_present.nodes.len(), 2);

    let removed = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        &format!("UNRELATE {COLLECTION} EDGE '{first}', '{second}';"),
    )
    .expect("atomic unrelate");
    assert_eq!(removed.stats.affected, Some(2));
    assert!(removed.stats.operation_lsn.is_some());

    let no_edges = db
        .traverse_scoped(
            COLLECTION,
            GraphTraverseRequest {
                anchors: vec!["root".to_string()],
                edge_types: vec!["CITES".to_string()],
                direction: GraphDirection::Outgoing,
                node_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 1,
                    ..TraversalBudget::default()
                },
            },
            &TenantScope::system(),
        )
        .expect("traverse after unrelate");
    assert!(no_edges.nodes.is_empty());
    drop(db);

    let reopened = Db::open(dir.path()).expect("reopen after atomic unrelate");
    let recovered = reopened
        .traverse_scoped(
            COLLECTION,
            GraphTraverseRequest {
                anchors: vec!["root".to_string()],
                edge_types: vec!["CITES".to_string()],
                direction: GraphDirection::Outgoing,
                node_filter: None,
                edge_filter: None,
                budget: TraversalBudget {
                    max_depth: 1,
                    ..TraversalBudget::default()
                },
            },
            &TenantScope::system(),
        )
        .expect("traverse recovered graph");
    assert!(recovered.nodes.is_empty());
}

#[test]
fn graph_constraint_reaches_dense_and_hybrid_engine_paths_with_trace() {
    let (_dir, db) = fixture(true);
    relate(&db, "root", "child");
    let mut session = Session::default();

    let dense = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "SEARCH docs NEAR [0,0] CONNECTED TO root VIA CITES WITHIN 1 HOPS LIMIT 10;",
    )
    .expect("graph-constrained dense search");
    assert_eq!(dense.rows.len(), 1);
    assert_eq!(dense.rows[0]["id"], "child");
    assert!(dense.stats.graph.is_some());
    let dense_stages = dense
        .trace
        .as_ref()
        .expect("trace")
        .stages
        .iter()
        .map(|stage| stage.name.as_str())
        .collect::<Vec<_>>();
    assert!(dense_stages.contains(&stage::GRAPH_ESTIMATE));
    assert!(dense_stages.contains(&stage::GRAPH_PLAN));
    assert!(dense_stages.contains(&stage::GRAPH_EXPAND));

    let hybrid = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "HYBRID docs NEAR [0,0] TEXT {11:1.0} CONNECTED TO root VIA CITES WITHIN 1 HOPS LIMIT 10;",
    )
    .expect("graph-constrained hybrid search");
    assert_eq!(hybrid.rows.len(), 1);
    assert_eq!(hybrid.rows[0]["id"], "child");
    assert!(
        hybrid
            .stats
            .graph
            .as_ref()
            .expect("graph trace")
            .fuse
            .is_some()
    );
}

#[test]
fn traversal_materializes_exact_nodes_edges_and_simple_paths() {
    let (_dir, db) = fixture(true);
    let edge_tokens = seed_traversal_topology(&db);
    let mut session = Session::default();

    let nodes = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DEPTH 2 WITH PAYLOAD RETURN NODES;",
    )
    .expect("node traversal");
    assert_eq!(nodes.columns, vec!["id", "depth", "payload"]);
    assert_eq!(
        nodes
            .rows
            .iter()
            .map(|row| (row["id"].as_str().unwrap(), row["depth"].as_u64().unwrap()))
            .collect::<Vec<_>>(),
        vec![("child", 1), ("leaf", 1)]
    );
    assert_eq!(nodes.rows[0]["payload"]["kind"], "child");
    assert!(
        nodes
            .trace
            .as_ref()
            .unwrap()
            .stages
            .iter()
            .any(|stage| stage.name == stage::GRAPH_EXPAND)
    );

    let pruned = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DEPTH 3 WHERE kind = 'child' RETURN NODES;",
    )
    .expect("node predicate prunes output and expansion");
    assert_eq!(pruned.rows.len(), 1);
    assert_eq!(pruned.rows[0]["id"], "child");

    let depth_zero = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root DEPTH 0 WHERE kind = 'root' WITH PAYLOAD RETURN NODES;",
    )
    .expect("depth-zero anchors are filtered output");
    assert_eq!(depth_zero.rows.len(), 1);
    assert_eq!(depth_zero.rows[0]["id"], "root");
    assert_eq!(depth_zero.rows[0]["depth"], 0);

    let edges = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DIRECTION ANY DEPTH 2 WITH PAYLOAD RETURN EDGES;",
    )
    .expect("edge traversal");
    assert_eq!(edges.rows.len(), 6);
    let returned_tokens = edges
        .rows
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(returned_tokens.len(), 6, "self-loop is returned once");
    assert_eq!(
        returned_tokens,
        edge_tokens.iter().cloned().collect(),
        "parallel edges remain separate opaque tokens"
    );
    assert!(edges.rows.iter().all(|row| row["type"] == "CITES"));
    assert!(edges.rows.iter().all(|row| row["properties"].is_object()));

    let filtered_edges = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DEPTH 1 EDGE WHERE enabled = true RETURN EDGES;",
    )
    .expect("edge predicate");
    assert_eq!(filtered_edges.rows.len(), 2);
    assert!(
        filtered_edges
            .rows
            .iter()
            .all(|row| row["id"] != edge_tokens[1])
    );

    let paths = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DEPTH 2 WITH PAYLOAD RETURN PATHS LIMIT 100;",
    )
    .expect("simple paths");
    assert_eq!(paths.columns, vec!["nodes", "edges"]);
    assert_eq!(paths.rows.len(), 5);
    assert_eq!(
        paths
            .rows
            .iter()
            .map(|row| {
                row["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|node| node["id"].as_str().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        vec![
            vec!["root", "child"],
            vec!["root", "child"],
            vec!["root", "leaf"],
            vec!["root", "child", "leaf"],
            vec!["root", "child", "leaf"],
        ]
    );
    assert!(paths.rows.iter().all(|row| {
        let nodes = row["nodes"].as_array().unwrap();
        let unique = nodes
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect::<std::collections::HashSet<_>>();
        unique.len() == nodes.len()
    }));
}

#[test]
fn traversal_limit_and_work_budget_report_distinct_truncation() {
    let (_dir, db) = fixture(true);
    seed_traversal_topology(&db);
    let limited = candidate(
        &db,
        &mut Session::default(),
        TenantScope::system(),
        Role::ReadOnly,
        "TRAVERSE docs FROM root VIA CITES DEPTH 2 RETURN EDGES LIMIT 2;",
    )
    .expect("row limit returns a bounded partial result");
    assert_eq!(limited.rows.len(), 2);
    assert_eq!(
        limited.stats.truncation,
        Some(TraversalTruncationReason::Limit)
    );
    assert_eq!(limited.stats.warnings, vec!["graph.result_truncated"]);

    let budgeted = db
        .traverse_query_scoped(
            COLLECTION,
            GraphTraversalQueryRequest {
                traversal: GraphTraverseRequest {
                    anchors: vec!["root".to_string()],
                    edge_types: vec!["CITES".to_string()],
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 2,
                        max_edges: 1,
                        ..TraversalBudget::default()
                    },
                },
                returns: GraphTraversalReturn::Edges,
                limit: None,
                with_payload: false,
            },
            &TenantScope::system(),
        )
        .expect("work budget returns explicit truncation");
    assert_eq!(budgeted.truncation, Some(TraversalTruncationReason::Edges));
    assert_eq!(budgeted.warnings, vec![GraphWarning::ResultTruncated]);
    assert!(matches!(budgeted.result, GraphTraversalRows::Edges(_)));
}

#[test]
fn graph_capability_and_runtime_error_codes_fail_closed() {
    let (_dir, db) = fixture(true);
    let mut session = Session::default();
    let denied = candidate(
        &db,
        &mut session,
        TenantScope::untenanted("missing-graph-capability"),
        Role::ReadOnly,
        "SEARCH docs NEAR [0,0] CONNECTED TO root WITHIN 1 HOPS;",
    )
    .expect_err("graph read capability required");
    assert_eq!(denied.code, "chironql.permission_denied");

    let unknown_type = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        "RELATE docs root -> UNKNOWN -> child;",
    )
    .expect_err("unknown edge type");
    assert_eq!(unknown_type.code, "graph.type_unknown");

    let (_disabled_dir, disabled_db) = fixture(false);
    let disabled = candidate(
        &disabled_db,
        &mut Session::default(),
        TenantScope::system(),
        Role::ReadOnly,
        "SEARCH docs NEAR [0,0] CONNECTED TO root WITHIN 1 HOPS;",
    )
    .expect_err("disabled graph");
    assert_eq!(disabled.code, "graph.not_enabled");
}

#[test]
fn deferred_relate_requires_and_uses_bound_session_in_v1_1() {
    let (_dir, db) = fixture(true);
    let query = "RELATE docs missing-source -> CITES -> missing-target WITH DEFERRED ENDPOINTS;";
    let mut session = Session::default();
    let missing = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        query,
    )
    .expect_err("deferred session is explicit");
    assert_eq!(missing.code, "chironql.deferred_session_required");

    let opened = db
        .open_deferred_graph_session_scoped(COLLECTION, true, &TenantScope::system())
        .expect("open deferred graph session");
    session.graph_deferred_session = Some(opened.session_id);
    let related = candidate(
        &db,
        &mut session,
        TenantScope::system(),
        Role::ReadWrite,
        query,
    )
    .expect("deferred relate");
    assert_eq!(related.stats.affected, Some(1));

    let mut production_session = Session::default();
    let mut production_ctx = ExecContext {
        db: &db,
        session: &mut production_session,
        role: Role::ReadWrite,
        allowed_collections: None,
        want_trace: true,
        confirm: false,
        tenant: TenantScope::system(),
    };
    let related = execute(&mut production_ctx, "RELATE docs root -> CITES -> child;")
        .expect("production parser and executor are 1.1");
    assert_eq!(related.stats.affected, Some(1));
}
