//! D8a native HTTP graph conformance.
//!
//! These tests exercise the real legacy and `/v1` routers. They intentionally
//! use only public JSON and opaque edge/session tokens, so a passing test does
//! not depend on internal Nid, EdgeId, TypeId, or WAL representations.

use std::path::Path;

use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, api,
    auth::AuthConfig,
    graph::ConfigureEdgeTypeRequest,
    rbac::{ApiKeyEntry, RbacConfig, Role},
    tenant::{TenantEnforcement, TenantScope},
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const COLLECTION: &str = "docs";

fn seeded_db(path: &Path) -> Db {
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
    db.upsert(
        COLLECTION,
        vec![
            Point {
                id: "a".to_string(),
                vector: vec![1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"kind": "anchor"}),
            },
            Point {
                id: "b".to_string(),
                vector: vec![0.0, 1.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"kind": "target"}),
            },
        ],
    )
    .expect("seed points");
    db
}

struct Harness {
    data: TempDir,
    db: Db,
    base: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(auth: AuthConfig) -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = seeded_db(data.path());
        Self::start_with(data, db, auth).await
    }

    async fn start_with(data: TempDir, db: Db, auth: AuthConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = db.clone();
        let server = tokio::spawn(async move {
            api::serve_listener_with_auth(served, auth, listener)
                .await
                .expect("serve");
        });
        Self {
            data,
            db,
            base: format!("http://{addr}"),
            client: reqwest::Client::new(),
            server,
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(key) = key {
            request = request.bearer_auth(key);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("send");
        let status = response.status();
        let bytes = response.bytes().await.expect("body");
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text": String::from_utf8_lossy(&bytes).into_owned()}));
        (status, value)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn legacy_and_v1_share_graph_lifecycle_crud_traversal_and_search() {
    let harness = Harness::start(AuthConfig::disabled()).await;

    let (status, lifecycle) = harness
        .send(
            Method::PUT,
            "/collections/docs/graph?wait=false",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{lifecycle}");
    assert_eq!(lifecycle["enabled"], json!(true));
    assert_eq!(lifecycle["durable"], json!(false));
    assert!(lifecycle["graph_epoch"].is_number(), "{lifecycle}");

    let (status, configured) = harness
        .send(
            Method::PUT,
            "/v1/collections/docs/graph/types/knows",
            None,
            Some(json!({"weight_property": "strength", "wait": false})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{configured}");
    assert_eq!(configured["edge_type"]["name"], json!("knows"));
    assert_eq!(configured["receipt"]["durable"], json!(false));

    let (status, catalog) = harness
        .send(Method::GET, "/collections/docs/graph/types", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert_eq!(catalog["edge_types"][0]["name"], json!("knows"));

    let (status, related) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/edges",
            None,
            Some(json!({
                "source_point_id": "a",
                "target_point_id": "b",
                "edge_type": "knows",
                "properties": {"first": 1},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{related}");
    let edge_id = related["edge_id"].as_str().expect("opaque edge token");
    assert_eq!(edge_id.len(), 39, "token is an opaque fixed envelope");
    assert!(!edge_id.contains('='), "token is URL-safe without padding");
    assert!(related["receipt"]["operation_lsn"].is_number());

    let (status, merged) = harness
        .send(
            Method::PATCH,
            &format!("/collections/docs/edges/{edge_id}"),
            None,
            Some(json!({"properties": {"second": 2}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{merged}");
    assert!(merged["operation_lsn"].is_number(), "{merged}");

    let (_, traversed) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/graph/traverse",
            None,
            Some(json!({
                "anchors": ["a"],
                "edge_types": ["knows"],
                "returns": "edges",
                "limit": 10,
                "with_payload": true,
            })),
        )
        .await;
    assert_eq!(traversed["result"]["kind"], json!("edges"), "{traversed}");
    assert_eq!(traversed["result"]["rows"][0]["id"], json!(edge_id));
    assert_eq!(
        traversed["result"]["rows"][0]["properties"],
        json!({"first": 1, "second": 2})
    );

    let (status, replaced) = harness
        .send(
            Method::PUT,
            &format!("/v1/collections/docs/edges/{edge_id}"),
            None,
            Some(json!({"properties": {"only": 3}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");

    let (status, search) = harness
        .send(
            Method::POST,
            "/collections/docs/search",
            None,
            Some(json!({
                "vector": [0.0, 1.0],
                "k": 1,
                "graph": {"anchors": ["a"], "edge_types": ["knows"]},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{search}");
    assert_eq!(search["hits"][0]["id"], json!("b"), "{search}");
    assert!(search["graph"]["graph_epoch"].is_number(), "{search}");

    let (status, deleted) = harness
        .send(
            Method::DELETE,
            &format!("/collections/docs/edges/{edge_id}?wait=false"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{deleted}");
    assert_eq!(deleted["deleted"], json!(1));
    assert_eq!(deleted["receipt"]["durable"], json!(false));

    let (status, dropped) = harness
        .send(Method::DELETE, "/v1/collections/docs/graph", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{dropped}");
    assert_eq!(dropped["enabled"], json!(false));

    let (status, error) = harness
        .send(
            Method::POST,
            "/collections/docs/graph/traverse",
            None,
            Some(json!({"anchors": ["a"]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["code"], json!("graph.not_enabled"), "{error}");
    assert!(error["message"].is_string(), "{error}");

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
async fn deferred_sessions_bind_absent_endpoints_and_round_trip_tokens() {
    let harness = Harness::start(AuthConfig::disabled()).await;
    let system = TenantScope::system();
    harness
        .db
        .set_graph_lifecycle_scoped(COLLECTION, true, true, &system)
        .expect("enable graph");
    harness
        .db
        .configure_edge_type_scoped(
            COLLECTION,
            ConfigureEdgeTypeRequest {
                name: "references".to_string(),
                weight_property: None,
            },
            true,
            &system,
        )
        .expect("configure type");

    let (status, opened) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/graph/deferred-sessions?wait=false",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{opened}");
    let session = opened["session_id"].as_str().expect("session token");
    assert_eq!(session.len(), 32);

    let (status, related) = harness
        .send(
            Method::POST,
            &format!("/collections/docs/graph/deferred-sessions/{session}/edges"),
            None,
            Some(json!({
                "source_point_id": "late-a",
                "target_point_id": "late-b",
                "edge_type": "references",
                "idempotency_key": "deferred-http-1",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{related}");
    let edge_id = related["edge_id"].as_str().expect("edge token");

    let (status, upserted) = harness
        .send(
            Method::POST,
            &format!("/v1/collections/docs/graph/deferred-sessions/{session}/points"),
            None,
            Some(json!({
                "points": [
                    {"id": "late-a", "vector": [0.2, 0.8]},
                    {"id": "late-b", "vector": [0.1, 0.9]}
                ],
                "wait": false,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{upserted}");
    assert_eq!(upserted["bound_endpoints"], json!(2));

    let (status, committed) = harness
        .send(
            Method::POST,
            &format!("/collections/docs/graph/deferred-sessions/{session}/commit"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{committed}");
    assert_eq!(committed["session_id"], json!(session));
    assert_eq!(committed["state"], json!("committed"));

    let (status, traversed) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/graph/traverse",
            None,
            Some(json!({
                "anchors": ["late-a"],
                "edge_types": ["references"],
                "returns": "edges",
                "limit": 10,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{traversed}");
    assert_eq!(traversed["result"]["rows"][0]["id"], json!(edge_id));
}

fn graph_rbac() -> AuthConfig {
    let entry =
        |id: &str, role: Role, collections: &[&str], capabilities: &[&str]| -> ApiKeyEntry {
            ApiKeyEntry {
                id: Some(id.to_string()),
                key: format!("{id}-key"),
                tenant_id: None,
                role,
                allowed_collections: collections
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                max_collections: None,
                capabilities: capabilities
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            }
        };
    AuthConfig::disabled().with_rbac(RbacConfig {
        keys: vec![
            entry("point-admin", Role::Admin, &[COLLECTION], &[]),
            entry(
                "graph-admin",
                Role::Admin,
                &[COLLECTION],
                &["graph:admin", "graph:type_configure"],
            ),
            entry(
                "graph-reader",
                Role::ReadOnly,
                &[COLLECTION],
                &["graph:read"],
            ),
            entry(
                "graph-writer",
                Role::ReadWrite,
                &[COLLECTION],
                &["graph:read", "graph:write"],
            ),
            entry(
                "wrong-collection",
                Role::ReadOnly,
                &["other"],
                &["graph:read"],
            ),
        ],
    })
}

#[tokio::test]
async fn graph_capabilities_roles_and_collection_allowlists_are_independent() {
    let harness = Harness::start(graph_rbac()).await;

    let (status, denied) = harness
        .send(
            Method::PUT,
            "/collections/docs/graph",
            Some("point-admin-key"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["code"], json!("graph.permission_denied"));

    let (status, enabled) = harness
        .send(
            Method::PUT,
            "/v1/collections/docs/graph",
            Some("graph-admin-key"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");

    let (status, configured) = harness
        .send(
            Method::PUT,
            "/collections/docs/graph/types/knows",
            Some("graph-admin-key"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{configured}");

    let (status, denied) = harness
        .send(
            Method::GET,
            "/collections/docs/graph/types",
            Some("point-admin-key"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["code"], json!("graph.permission_denied"));

    let (status, catalog) = harness
        .send(
            Method::GET,
            "/v1/collections/docs/graph/types",
            Some("graph-reader-key"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{catalog}");

    let (status, denied) = harness
        .send(
            Method::POST,
            "/collections/docs/edges",
            Some("graph-reader-key"),
            Some(json!({
                "source_point_id": "a",
                "target_point_id": "b",
                "edge_type": "knows",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["code"], json!("graph.permission_denied"));

    let (status, denied) = harness
        .send(
            Method::GET,
            "/collections/docs/graph/types",
            Some("wrong-collection-key"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(denied["code"], json!("graph.permission_denied"));

    let (status, related) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/edges",
            Some("graph-writer-key"),
            Some(json!({
                "source_point_id": "a",
                "target_point_id": "b",
                "edge_type": "knows",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{related}");

    for path in [
        "/collections/docs/search",
        "/v1/collections/docs/hybrid_search",
    ] {
        let body = json!({
            "vector": [0.0, 1.0],
            "k": 1,
            "graph": {"anchors": ["a"], "edge_types": ["knows"]},
        });
        let (status, denied) = harness
            .send(Method::POST, path, Some("point-admin-key"), Some(body))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {denied}");
        assert_eq!(denied["code"], json!("graph.permission_denied"));
    }

    let (status, search) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/search",
            Some("graph-reader-key"),
            Some(json!({
                "vector": [0.0, 1.0],
                "k": 1,
                "graph": {"anchors": ["a"], "edge_types": ["knows"]},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{search}");
    assert_eq!(search["hits"][0]["id"], json!("b"));

    let audit =
        std::fs::read_to_string(harness.data.path().join("audit/audit.jsonl")).expect("audit log");
    assert!(audit.contains("http_graph_authorize"), "{audit}");
    assert!(audit.contains("graph.permission_denied"), "{audit}");
    assert!(audit.contains("point-admin"), "{audit}");
}

#[tokio::test]
async fn tenant_scope_rejects_cross_tenant_edges_without_explicit_cross_write() {
    let data = TempDir::new().expect("tempdir");
    let db = Db::open(data.path()).expect("open db");
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
    db.set_tenant_enforcement(TenantEnforcement::Enforced);

    let entry = |id: &str, tenant: Option<&str>, capabilities: &[&str]| ApiKeyEntry {
        id: Some(id.to_string()),
        key: format!("{id}-key"),
        tenant_id: tenant.map(str::to_string),
        role: Role::Admin,
        allowed_collections: vec![COLLECTION.to_string()],
        max_collections: None,
        capabilities: capabilities
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    };
    let auth = AuthConfig::disabled().with_rbac(RbacConfig {
        keys: vec![
            entry(
                "setup",
                None,
                &[
                    "tenant:cross_read",
                    "tenant:cross_write",
                    "graph:admin",
                    "graph:type_configure",
                    "graph:read",
                    "graph:write",
                ],
            ),
            entry("tenant-a", Some("a"), &["graph:read", "graph:write"]),
            entry("tenant-b", Some("b"), &["graph:read", "graph:write"]),
        ],
    });
    let harness = Harness::start_with(data, db, auth).await;

    for (method, path, key, body) in [
        (Method::PUT, "/collections/docs/graph", "setup-key", None),
        (
            Method::PUT,
            "/collections/docs/graph/types/shared",
            "setup-key",
            Some(json!({})),
        ),
        (
            Method::PUT,
            "/collections/docs/points",
            "tenant-a-key",
            Some(json!({"points": [{"id": "a-node", "vector": [1, 0]}]})),
        ),
        (
            Method::PUT,
            "/collections/docs/points",
            "tenant-b-key",
            Some(json!({"points": [{"id": "b-node", "vector": [0, 1]}]})),
        ),
    ] {
        let (status, response) = harness.send(method, path, Some(key), body).await;
        assert!(status.is_success(), "{path}: {status} {response}");
    }

    let (status, denied) = harness
        .send(
            Method::POST,
            "/collections/docs/edges",
            Some("tenant-a-key"),
            Some(json!({
                "source_point_id": "a-node",
                "target_point_id": "b-node",
                "edge_type": "shared",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
    assert_eq!(denied["code"], json!("graph.endpoint_not_found"));
    assert!(
        !denied.to_string().contains("tenant"),
        "the scoped rejection must not disclose the hidden owner: {denied}"
    );

    let (status, related) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/edges",
            Some("setup-key"),
            Some(json!({
                "source_point_id": "a-node",
                "target_point_id": "b-node",
                "edge_type": "shared",
                "scope": "admin_cross_tenant",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{related}");
    assert!(related["edge_id"].is_string());

    let (status, tenant_view) = harness
        .send(
            Method::POST,
            "/collections/docs/graph/traverse",
            Some("tenant-a-key"),
            Some(json!({"anchors": ["a-node"], "edge_types": ["shared"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tenant_view}");
    assert_eq!(tenant_view["result"]["rows"].as_array().unwrap().len(), 0);

    let (status, admin_view) = harness
        .send(
            Method::POST,
            "/v1/collections/docs/graph/traverse",
            Some("setup-key"),
            Some(json!({"anchors": ["a-node"], "edge_types": ["shared"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{admin_view}");
    assert_eq!(admin_view["result"]["rows"].as_array().unwrap().len(), 1);
}
