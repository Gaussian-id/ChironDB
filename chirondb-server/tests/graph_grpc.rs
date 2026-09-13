//! D8b native gRPC graph conformance.
//!
//! Graph RPCs are exposed only by `chirondb.v1.ChironDb`; shared search
//! messages retain their `gaussdb.v1` package and gain additive graph fields.

use std::path::Path;

use chiron_pb::chiron_db_client::ChironDbClient;
use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point,
    auth::AuthConfig,
    grpc::{self, chiron_pb, pb},
    rbac::{ApiKeyEntry, RbacConfig, Role},
    tenant::TenantEnforcement,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tonic::Request;

const COLLECTION: &str = "docs";

fn create_db(path: &Path, seed: bool) -> Db {
    let db = Db::open(path).expect("open db");
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
    if seed {
        db.upsert(
            COLLECTION,
            vec![point("a", [1.0, 0.0]), point("b", [0.0, 1.0])],
        )
        .expect("seed points");
    }
    db
}

fn point(id: &str, vector: [f32; 2]) -> Point {
    Point {
        id: id.to_string(),
        vector: vector.to_vec(),
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({"id": id}),
    }
}

fn proto_point(id: &str, vector: [f32; 2]) -> pb::Point {
    pb::Point {
        id: id.to_string(),
        vector: vector.to_vec(),
        payload_json: json!({"id": id}).to_string(),
        sparse_vector: None,
        vectors: Default::default(),
    }
}

struct Harness {
    data: TempDir,
    db: Db,
    url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(seed: bool, auth: AuthConfig) -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = create_db(data.path(), seed);
        let addr = {
            let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            probe.local_addr().expect("addr")
        };
        let served = db.clone();
        let server = tokio::spawn(async move {
            grpc::serve_with_auth(served, auth, addr)
                .await
                .expect("serve");
        });
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Self {
            data,
            db,
            url: format!("http://{addr}"),
            server,
        }
    }

    async fn client(&self) -> ChironDbClient<tonic::transport::Channel> {
        ChironDbClient::connect(self.url.clone())
            .await
            .expect("connect")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn bearer<T>(message: T, key: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {key}").parse().expect("metadata"),
    );
    request
}

fn lifecycle(no_wait: bool) -> chiron_pb::GraphLifecycleRequest {
    chiron_pb::GraphLifecycleRequest {
        collection: COLLECTION.to_string(),
        no_wait,
    }
}

fn relate(source: &str, target: &str, edge_type: &str) -> chiron_pb::GraphRelateRequest {
    chiron_pb::GraphRelateRequest {
        collection: COLLECTION.to_string(),
        source_point_id: source.to_string(),
        target_point_id: target.to_string(),
        edge_type: edge_type.to_string(),
        properties_json: json!({"first": 1}).to_string(),
        scope: "local".to_string(),
        idempotency_key: None,
        no_wait: false,
    }
}

#[tokio::test]
async fn lifecycle_crud_traversal_search_errors_and_audit_share_the_core_contract() {
    let harness = Harness::start(true, AuthConfig::disabled()).await;
    let mut client = harness.client().await;

    let enabled = client
        .enable_graph(lifecycle(true))
        .await
        .expect("enable")
        .into_inner();
    assert!(enabled.enabled);
    assert!(!enabled.durable);
    let epoch = enabled.graph_epoch.expect("graph epoch");

    let configured = client
        .configure_edge_type(chiron_pb::ConfigureEdgeTypeRequest {
            collection: COLLECTION.to_string(),
            name: "knows".to_string(),
            weight_property: Some("strength".to_string()),
            no_wait: false,
        })
        .await
        .expect("configure")
        .into_inner();
    assert!(configured.changed);
    assert_eq!(configured.edge_type.expect("type").name, "knows");
    assert_eq!(configured.receipt.expect("receipt").graph_epoch, epoch);

    let catalog = client
        .list_edge_types(chiron_pb::ListEdgeTypesRequest {
            collection: COLLECTION.to_string(),
        })
        .await
        .expect("list types")
        .into_inner();
    assert_eq!(catalog.edge_types.len(), 1);

    let related = client
        .relate(relate("a", "b", "knows"))
        .await
        .expect("relate")
        .into_inner();
    assert_eq!(related.edge_id.len(), 39);
    assert!(!related.edge_id.contains('='));
    assert!(related.receipt.as_ref().unwrap().operation_lsn.is_some());

    let updated = client
        .update_edge(chiron_pb::GraphUpdateEdgeRequest {
            collection: COLLECTION.to_string(),
            edge_id: related.edge_id.clone(),
            mode: "merge".to_string(),
            properties_json: json!({"second": 2}).to_string(),
            no_wait: false,
        })
        .await
        .expect("update edge")
        .into_inner();
    assert_eq!(updated.graph_epoch, epoch);

    let traversed = client
        .traverse(chiron_pb::GraphTraverseRequest {
            collection: COLLECTION.to_string(),
            request_json: json!({
                "anchors": ["a"],
                "edge_types": ["knows"],
                "returns": "edges",
                "limit": 10,
                "with_payload": true,
            })
            .to_string(),
        })
        .await
        .expect("traverse")
        .into_inner();
    assert_eq!(traversed.graph_epoch, epoch);
    let traversal: Value = serde_json::from_str(&traversed.result_json).expect("traversal json");
    assert_eq!(traversal["result"]["kind"], json!("edges"));
    assert_eq!(traversal["result"]["rows"][0]["id"], json!(related.edge_id));
    assert_eq!(
        traversal["result"]["rows"][0]["properties"],
        json!({"first": 1, "second": 2})
    );

    let search = client
        .search(pb::SearchRequest {
            collection: COLLECTION.to_string(),
            query: Some(pb::SearchQuery {
                vector: vec![0.0, 1.0],
                k: 1,
                filter_json: String::new(),
                budget_ms: None,
                vector_name: String::new(),
                ef_search: None,
                recall_target: None,
                graph_json: Some(json!({"anchors": ["a"], "edge_types": ["knows"]}).to_string()),
            }),
        })
        .await
        .expect("graph search")
        .into_inner();
    assert_eq!(search.hits[0].id, "b");
    let trace: Value =
        serde_json::from_str(&search.graph_json.expect("graph trace")).expect("trace json");
    assert_eq!(trace["graph_epoch"], json!(epoch));

    let hybrid = client
        .hybrid_search(pb::HybridSearchRequest {
            collection: COLLECTION.to_string(),
            vector: vec![0.0, 1.0],
            sparse_vector: None,
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
            fusion: "rrf".to_string(),
            dense_weight: 1.0,
            sparse_weight: 1.0,
            use_dense_vector: true,
            vector_name: String::new(),
            graph_json: Some(json!({"anchors": ["a"], "edge_types": ["knows"]}).to_string()),
        })
        .await
        .expect("graph hybrid search")
        .into_inner();
    assert_eq!(hybrid.hits[0].id, "b");
    assert!(hybrid.graph_json.is_some());

    let deleted = client
        .unrelate(chiron_pb::GraphUnrelateRequest {
            collection: COLLECTION.to_string(),
            edge_id: related.edge_id,
            no_wait: true,
        })
        .await
        .expect("unrelate")
        .into_inner();
    assert_eq!(deleted.deleted, 1);
    assert!(!deleted.receipt.expect("receipt").durable);

    let dropped = client
        .drop_graph(lifecycle(false))
        .await
        .expect("drop")
        .into_inner();
    assert!(!dropped.enabled);

    let error = client
        .traverse(chiron_pb::GraphTraverseRequest {
            collection: COLLECTION.to_string(),
            request_json: json!({"anchors": ["a"]}).to_string(),
        })
        .await
        .expect_err("disabled graph");
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    let details: Value = serde_json::from_slice(error.details()).expect("graph error details");
    assert_eq!(details["code"], json!("graph.not_enabled"));

    let audit =
        std::fs::read_to_string(harness.data.path().join("audit/audit.jsonl")).expect("audit log");
    for operation in [
        "graph_enable",
        "graph_type_configure",
        "graph_relate",
        "graph_edge_update",
        "graph_unrelate",
        "graph_drop",
    ] {
        assert!(
            audit.contains(operation),
            "missing {operation} in audit log"
        );
    }
}

#[tokio::test]
async fn deferred_sessions_bind_absent_endpoints_over_grpc() {
    let harness = Harness::start(true, AuthConfig::disabled()).await;
    let mut client = harness.client().await;
    client.enable_graph(lifecycle(false)).await.expect("enable");
    client
        .configure_edge_type(chiron_pb::ConfigureEdgeTypeRequest {
            collection: COLLECTION.to_string(),
            name: "references".to_string(),
            weight_property: None,
            no_wait: false,
        })
        .await
        .expect("configure");

    let opened = client
        .open_deferred_graph_session(chiron_pb::GraphDeferredSessionRequest {
            collection: COLLECTION.to_string(),
            session_id: None,
            no_wait: true,
        })
        .await
        .expect("open")
        .into_inner();
    assert_eq!(opened.state, "open");
    assert_eq!(opened.session_id.len(), 32);

    let deferred_edge = client
        .deferred_relate(chiron_pb::GraphDeferredRelateRequest {
            collection: COLLECTION.to_string(),
            session_id: opened.session_id.clone(),
            relate: Some(chiron_pb::GraphRelateRequest {
                collection: String::new(),
                source_point_id: "late-a".to_string(),
                target_point_id: "late-b".to_string(),
                edge_type: "references".to_string(),
                properties_json: String::new(),
                scope: String::new(),
                idempotency_key: Some("grpc-deferred-1".to_string()),
                no_wait: false,
            }),
        })
        .await
        .expect("deferred relate")
        .into_inner();

    let upserted = client
        .deferred_upsert(chiron_pb::GraphDeferredUpsertRequest {
            collection: COLLECTION.to_string(),
            session_id: opened.session_id.clone(),
            points: vec![
                proto_point("late-a", [0.2, 0.8]),
                proto_point("late-b", [0.1, 0.9]),
            ],
            no_wait: true,
        })
        .await
        .expect("deferred upsert")
        .into_inner();
    assert_eq!(upserted.bound_endpoints, 2);
    assert!(!upserted.receipt.expect("receipt").durable);

    let committed = client
        .commit_deferred_graph_session(chiron_pb::GraphDeferredSessionRequest {
            collection: COLLECTION.to_string(),
            session_id: Some(opened.session_id.clone()),
            no_wait: false,
        })
        .await
        .expect("commit")
        .into_inner();
    assert_eq!(committed.session_id, opened.session_id);
    assert_eq!(committed.state, "committed");

    let traversed = client
        .traverse(chiron_pb::GraphTraverseRequest {
            collection: COLLECTION.to_string(),
            request_json: json!({
                "anchors": ["late-a"],
                "edge_types": ["references"],
                "returns": "edges",
                "limit": 10,
            })
            .to_string(),
        })
        .await
        .expect("traverse")
        .into_inner();
    let traversal: Value = serde_json::from_str(&traversed.result_json).expect("json");
    assert_eq!(
        traversal["result"]["rows"][0]["id"],
        json!(deferred_edge.edge_id)
    );
}

fn graph_rbac() -> AuthConfig {
    let entry =
        |id: &str, tenant: Option<&str>, role: Role, capabilities: &[&str]| -> ApiKeyEntry {
            ApiKeyEntry {
                id: Some(id.to_string()),
                key: format!("{id}-key"),
                tenant_id: tenant.map(ToString::to_string),
                role,
                allowed_collections: vec![COLLECTION.to_string()],
                max_collections: None,
                capabilities: capabilities
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            }
        };
    AuthConfig::disabled().with_rbac(RbacConfig {
        keys: vec![
            entry("point-admin", None, Role::Admin, &[]),
            entry(
                "graph-admin",
                None,
                Role::Admin,
                &["graph:admin", "graph:type_configure"],
            ),
            entry(
                "acme",
                Some("acme"),
                Role::Admin,
                &[
                    "graph:read",
                    "graph:write",
                    "graph:admin",
                    "graph:type_configure",
                ],
            ),
            entry(
                "globex",
                Some("globex"),
                Role::ReadWrite,
                &["graph:read", "graph:write"],
            ),
        ],
    })
}

#[tokio::test]
async fn graph_capabilities_tenant_scope_and_denial_audit_are_enforced() {
    let harness = Harness::start(false, graph_rbac()).await;
    harness
        .db
        .set_tenant_enforcement(TenantEnforcement::Enforced);
    let mut client = harness.client().await;

    let denied = client
        .enable_graph(bearer(lifecycle(false), "point-admin-key"))
        .await
        .expect_err("point admin has no graph admin grant");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let details: Value = serde_json::from_slice(denied.details()).expect("denial details");
    assert_eq!(details["code"], json!("graph.permission_denied"));

    client
        .enable_graph(bearer(lifecycle(false), "acme-key"))
        .await
        .expect("enable");
    client
        .configure_edge_type(bearer(
            chiron_pb::ConfigureEdgeTypeRequest {
                collection: COLLECTION.to_string(),
                name: "knows".to_string(),
                weight_property: None,
                no_wait: false,
            },
            "acme-key",
        ))
        .await
        .expect("configure");

    client
        .upsert(bearer(
            pb::UpsertRequest {
                collection: COLLECTION.to_string(),
                points: vec![proto_point("a", [1.0, 0.0]), proto_point("b", [0.0, 1.0])],
                no_wait: false,
            },
            "acme-key",
        ))
        .await
        .expect("acme upsert");
    client
        .upsert(bearer(
            pb::UpsertRequest {
                collection: COLLECTION.to_string(),
                points: vec![proto_point("g", [0.5, 0.5])],
                no_wait: false,
            },
            "globex-key",
        ))
        .await
        .expect("globex upsert");

    let related = client
        .relate(bearer(relate("a", "b", "knows"), "acme-key"))
        .await
        .expect("same tenant relate")
        .into_inner();
    assert_eq!(related.edge_id.len(), 39);

    let cross = client
        .relate(bearer(relate("a", "g", "knows"), "acme-key"))
        .await
        .expect_err("cross-tenant endpoint must stay hidden");
    assert_eq!(cross.code(), tonic::Code::NotFound);
    let details: Value = serde_json::from_slice(cross.details()).expect("graph details");
    assert_eq!(details["code"], json!("graph.endpoint_not_found"));

    let traversed = client
        .traverse(bearer(
            chiron_pb::GraphTraverseRequest {
                collection: COLLECTION.to_string(),
                request_json: json!({
                    "anchors": ["a"],
                    "edge_types": ["knows"],
                    "returns": "nodes",
                })
                .to_string(),
            },
            "acme-key",
        ))
        .await
        .expect("acme traversal")
        .into_inner();
    let result: Value = serde_json::from_str(&traversed.result_json).expect("json");
    let ids: Vec<&str> = result["result"]["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(ids.contains(&"b"));
    assert!(!ids.contains(&"g"));

    let denied_search = client
        .search(bearer(
            pb::SearchRequest {
                collection: COLLECTION.to_string(),
                query: Some(pb::SearchQuery {
                    vector: vec![0.0, 1.0],
                    k: 1,
                    filter_json: String::new(),
                    budget_ms: None,
                    vector_name: String::new(),
                    ef_search: None,
                    recall_target: None,
                    graph_json: Some(json!({"anchors": ["a"]}).to_string()),
                }),
            },
            "point-admin-key",
        ))
        .await
        .expect_err("search graph field requires graph read");
    assert_eq!(denied_search.code(), tonic::Code::PermissionDenied);

    let audit =
        std::fs::read_to_string(harness.data.path().join("audit/audit.jsonl")).expect("audit log");
    assert!(audit.contains("grpc_graph_authorize"));
    assert!(audit.contains("graph.permission_denied"));
}
