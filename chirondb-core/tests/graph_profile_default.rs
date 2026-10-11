use chirondb_core::{
    Db, Point,
    graph::{
        ConfigureEdgeTypeRequest, GraphDirection, GraphRelationScope, GraphTraverseRequest,
        RelateRequest, TraversalBudget,
    },
    resource_profile::{self, ResourceProfile},
    tenant::TenantScope,
};

#[test]
fn default_graph_traversal_is_admitted_on_two_gib_profile() {
    resource_profile::install(ResourceProfile::from_limits(2 * 1024 * 1024 * 1024, 2));
    let temp = tempfile::tempdir().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let scope = TenantScope::system();
    db.create_collection(
        serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
    )
    .unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &scope)
        .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "cites".into(),
            weight_property: None,
        },
        true,
        &scope,
    )
    .unwrap();
    db.upsert_scoped(
        "docs",
        ["source", "target"]
            .into_iter()
            .map(|id| Point {
                id: id.into(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::json!({}),
            })
            .collect(),
        true,
        &scope,
    )
    .unwrap();
    db.relate_scoped(
        "docs",
        RelateRequest {
            source_point_id: "source".into(),
            target_point_id: "target".into(),
            edge_type: "cites".into(),
            properties: serde_json::json!({}),
            scope: GraphRelationScope::Local,
            idempotency_key: None,
        },
        true,
        &scope,
    )
    .unwrap();

    let request = GraphTraverseRequest {
        anchors: vec!["source".into()],
        edge_types: vec!["cites".into()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget::default(),
    };
    let result = db.traverse_scoped("docs", request, &scope).unwrap();
    assert!(result.nodes.iter().any(|node| node.point_id == "target"));
}
