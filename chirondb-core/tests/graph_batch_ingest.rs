use chirondb_core::{
    CollectionConfig, Db, DistanceMetric, Point,
    graph::{
        ConfigureEdgeTypeRequest, GraphDirection, GraphRelationScope, GraphTraverseRequest,
        RelateBatchRequest, RelateRequest, TraversalBudget,
    },
    tenant::{TenantCapability, TenantEnforcement, TenantScope},
};
use serde_json::json;

fn seed(root: &std::path::Path) -> Db {
    let db = Db::open(root).unwrap();
    db.create_collection(CollectionConfig {
        name: "docs".into(),
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
    .unwrap();
    db.set_graph_lifecycle_scoped("docs", true, true, &TenantScope::system())
        .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        ConfigureEdgeTypeRequest {
            name: "cites".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .unwrap();
    db.upsert(
        "docs",
        ["a", "b", "foreign"]
            .into_iter()
            .map(|id| Point {
                id: id.into(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant_id": if id == "foreign" {"other"} else {"acme"}}),
            })
            .collect(),
    )
    .unwrap();
    db
}

fn edge(target: &str, ordinal: usize) -> RelateRequest {
    RelateRequest {
        source_point_id: "a".into(),
        target_point_id: target.into(),
        edge_type: "cites".into(),
        properties: json!({"ordinal": ordinal}),
        scope: GraphRelationScope::Local,
        idempotency_key: None,
    }
}

fn examined(db: &Db) -> u64 {
    db.traverse_scoped(
        "docs",
        GraphTraverseRequest {
            anchors: vec!["a".into()],
            edge_types: vec!["cites".into()],
            direction: GraphDirection::Outgoing,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget {
                max_depth: 1,
                ..Default::default()
            },
        },
        &TenantScope::tenant("reader", "acme"),
    )
    .unwrap()
    .stats
    .visible_edges_examined
}

#[test]
fn atomic_batch_retries_and_restart_preserve_ordered_edge_ids() {
    let root = tempfile::tempdir().unwrap();
    let scope = TenantScope::tenant("writer", "acme");
    let request = RelateBatchRequest {
        edges: (0..50).map(|i| edge("b", i)).collect(),
        idempotency_key: Some("batch-1".into()),
    };
    let ids = {
        let db = seed(root.path());
        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        let first = db
            .relate_batch_scoped("docs", request.clone(), true, &scope)
            .unwrap();
        assert_eq!(first.edge_ids.len(), 50);
        assert!(first.receipt.durable);
        assert!(!first.receipt.replayed);
        assert_eq!(examined(&db), 50);
        let replay = db
            .relate_batch_scoped("docs", request.clone(), true, &scope)
            .unwrap();
        assert!(replay.receipt.replayed);
        assert_eq!(first.edge_ids, replay.edge_ids);
        let mut changed = request.clone();
        changed.edges[0].properties = json!({"ordinal": 999});
        assert!(
            db.relate_batch_scoped("docs", changed, true, &scope)
                .is_err()
        );
        assert_eq!(examined(&db), 50);
        first.edge_ids
    };
    let db = Db::open(root.path()).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let replay = db
        .relate_batch_scoped("docs", request.clone(), true, &scope)
        .unwrap();
    assert_eq!(replay.edge_ids, ids);
    assert!(replay.receipt.replayed);
    assert_eq!(examined(&db), 50);
    db.unrelate_scoped("docs", &ids[0], true, &scope).unwrap();
    let replay = db
        .relate_batch_scoped("docs", request.clone(), true, &scope)
        .unwrap();
    assert_eq!(replay.edge_ids, ids);
    assert!(replay.receipt.replayed);
    db.compact_collection("docs").unwrap();
    drop(db);
    let db = Db::open(root.path()).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let replay = db
        .relate_batch_scoped("docs", request, true, &scope)
        .unwrap();
    assert_eq!(replay.edge_ids, ids);
    assert!(replay.receipt.replayed);
    assert_eq!(examined(&db), 49, "retry resurrected a removed edge");
}

#[test]
fn replay_rechecks_namespace_permissions_after_compaction() {
    let root = tempfile::tempdir().unwrap();
    let scope = TenantScope::tenant("writer", "acme");
    let privileged = scope.clone().with_capability(TenantCapability::CrossWrite);
    let request = RelateBatchRequest {
        edges: vec![RelateRequest {
            scope: GraphRelationScope::AdminCrossTenant,
            ..edge("foreign", 0)
        }],
        idempotency_key: Some("cross-tenant-batch".into()),
    };
    let ids = {
        let db = seed(root.path());
        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        let first = db
            .relate_batch_scoped("docs", request.clone(), true, &privileged)
            .unwrap();
        db.unrelate_scoped("docs", &first.edge_ids[0], true, &privileged)
            .unwrap();
        db.compact_collection("docs").unwrap();
        first.edge_ids
    };
    let db = Db::open(root.path()).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    assert!(
        db.relate_batch_scoped("docs", request.clone(), true, &scope)
            .is_err()
    );
    let replay = db
        .relate_batch_scoped("docs", request, true, &privileged)
        .unwrap();
    assert_eq!(replay.edge_ids, ids);
    assert!(replay.receipt.replayed);
}

#[test]
fn invalid_or_unauthorized_batch_publishes_no_edges() {
    let root = tempfile::tempdir().unwrap();
    let db = seed(root.path());
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let scope = TenantScope::tenant("writer", "acme");
    let mut wrong_type = edge("b", 1);
    wrong_type.edge_type = "unknown".into();
    let mut item_key = edge("b", 1);
    item_key.idempotency_key = Some("per-edge".into());
    for edges in [
        vec![],
        vec![edge("b", 0); 4097],
        vec![edge("b", 0), edge("missing", 1)],
        vec![edge("b", 0), edge("foreign", 1)],
        vec![edge("b", 0), wrong_type],
        vec![item_key],
    ] {
        assert!(
            db.relate_batch_scoped(
                "docs",
                RelateBatchRequest {
                    edges,
                    idempotency_key: None
                },
                true,
                &scope
            )
            .is_err()
        );
        assert_eq!(examined(&db), 0);
    }
}

#[test]
fn byte_limit_is_atomic_and_maximum_operation_count_is_accepted() {
    let root = tempfile::tempdir().unwrap();
    let db = seed(root.path());
    let scope = TenantScope::tenant("writer", "acme");
    let mut oversized = edge("b", 0);
    oversized.properties = json!({"text": "x".repeat(60 * 1024)});
    assert!(
        db.relate_batch_scoped(
            "docs",
            RelateBatchRequest {
                edges: vec![oversized; 300],
                idempotency_key: None,
            },
            true,
            &scope,
        )
        .is_err()
    );
    assert_eq!(examined(&db), 0);
    let result = db
        .relate_batch_scoped(
            "docs",
            RelateBatchRequest {
                edges: (0..4096).map(|i| edge("b", i)).collect(),
                idempotency_key: Some("maximum-batch".into()),
            },
            true,
            &scope,
        )
        .unwrap();
    assert_eq!(result.edge_ids.len(), 4096);
    assert!(result.receipt.durable);
}

#[cfg(feature = "fault-injection")]
#[test]
fn failure_after_preparation_publishes_nothing_and_can_be_retried() {
    const TEST: &str = "failure_after_preparation_publishes_nothing_and_can_be_retried";
    let request = || RelateBatchRequest {
        edges: (0..50).map(|i| edge("b", i)).collect(),
        idempotency_key: Some("failed-before-commit".into()),
    };
    let scope = TenantScope::tenant("writer", "acme");
    if let Some(root) = std::env::var_os("CHIRONDB_BATCH_FAILURE_ROOT") {
        let db = Db::open(root).unwrap();
        assert!(
            db.relate_batch_scoped("docs", request(), true, &scope)
                .is_err()
        );
        assert_eq!(examined(&db), 0);
        return;
    }
    let root = tempfile::tempdir().unwrap();
    drop(seed(root.path()));
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("CHIRONDB_BATCH_FAILURE_ROOT", root.path())
            .env("CHIRONDB_FAILPOINT", "error:graph_batch.after_prepare")
            .status()
            .unwrap()
            .success()
    );
    let db = Db::open(root.path()).unwrap();
    assert_eq!(examined(&db), 0);
    let committed = db
        .relate_batch_scoped("docs", request(), true, &scope)
        .unwrap();
    assert_eq!(committed.edge_ids.len(), 50);
    assert_eq!(examined(&db), 50);
}
