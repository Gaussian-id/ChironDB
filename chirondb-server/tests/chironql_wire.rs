//! D8c ChironWire graph/ChironQL conformance.
//!
//! The native protobuf frame carries one ChironQL statement and must preserve
//! the same rows, graph receipts, stable error details, tenant scope and graph
//! capability checks as HTTP and gRPC.

#[allow(dead_code)]
mod common;

use std::path::Path;

use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point,
    auth::AuthConfig,
    graph::ConfigureEdgeTypeRequest,
    grpc::pb::{
        HybridSearchRequest, Point as ProtoPoint, SearchQuery, SearchRequest, UpsertRequest,
        WireChironQlRequest, wire_request, wire_response,
    },
    rbac::{ApiKeyEntry, RbacConfig, Role},
    tenant::{TenantEnforcement, TenantScope},
    wire,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const COLLECTION: &str = "docs";
const POINT_ADMIN_KEY: &str = "point-admin-key-000000000000000000";
const ACME_KEY: &str = "acme-key-00000000000000000000000000";
const GLOBEX_KEY: &str = "globex-key-000000000000000000000000";

struct Harness {
    data: TempDir,
    db: Db,
    endpoint: String,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(seed: bool, auth: AuthConfig) -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = graph_db(data.path(), seed);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = listener.local_addr().expect("addr").to_string();
        let served = db.clone();
        let server = tokio::spawn(async move {
            wire::serve_listener_with_auth(served, auth, listener)
                .await
                .expect("serve");
        });
        Self {
            data,
            db,
            endpoint,
            server,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn graph_db(path: &Path, seed: bool) -> Db {
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
    db.set_graph_lifecycle_scoped(COLLECTION, true, true, &TenantScope::system())
        .expect("enable graph");
    db.configure_edge_type_scoped(
        COLLECTION,
        ConfigureEdgeTypeRequest {
            name: "CITES".to_string(),
            weight_property: Some("rank".to_string()),
        },
        true,
        &TenantScope::system(),
    )
    .expect("configure type");
    if seed {
        db.upsert(
            COLLECTION,
            vec![
                point("root", [9.0, 9.0]),
                point("child", [1.0, 0.0]),
                point("outsider", [0.0, 0.0]),
            ],
        )
        .expect("seed");
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

fn proto_point(id: &str, vector: [f32; 2]) -> ProtoPoint {
    ProtoPoint {
        id: id.to_string(),
        vector: vector.to_vec(),
        payload_json: json!({"id": id}).to_string(),
        sparse_vector: None,
        vectors: Default::default(),
    }
}

fn query(statement: impl Into<String>) -> wire_request::Operation {
    wire_request::Operation::Chironql(WireChironQlRequest {
        query: statement.into(),
        collection: None,
        trace: true,
        confirm: false,
        deferred_session_id: None,
    })
}

fn chironql_payload(
    response: chirondb::grpc::pb::WireResponse,
) -> chirondb::grpc::pb::WireChironQlResponse {
    let wire_response::Payload::Chironql(response) = response.payload.expect("payload") else {
        panic!("expected ChironQL payload");
    };
    response
}

fn row(response: &chirondb::grpc::pb::WireChironQlResponse, index: usize) -> Value {
    serde_json::from_str(&response.rows_json[index]).expect("row json")
}

fn stats(response: &chirondb::grpc::pb::WireChironQlResponse) -> Value {
    serde_json::from_str(&response.stats_json).expect("stats json")
}

#[tokio::test]
async fn graph_chironql_round_trip_preserves_receipts_tokens_trace_and_errors() {
    let harness = Harness::start(true, AuthConfig::disabled()).await;

    let related = chironql_payload(
        common::send_wire(
            &harness.endpoint,
            1,
            query("RELATE docs root -> CITES -> child SET {rank: 1};"),
        )
        .await,
    );
    assert_eq!(related.kind, "rows");
    let edge_id = row(&related, 0)["edge_id"]
        .as_str()
        .expect("edge token")
        .to_string();
    assert_eq!(edge_id.len(), 39);
    assert!(!edge_id.contains('='));
    let receipt = stats(&related);
    assert!(receipt["graph_epoch"].is_number(), "{receipt}");
    assert!(receipt["operation_lsn"].is_number(), "{receipt}");
    assert_eq!(receipt["durable"], json!(true));
    assert!(related.query_id.starts_with("q_"));
    assert!(related.trace_json.is_some());

    let updated = chironql_payload(
        common::send_wire(
            &harness.endpoint,
            2,
            query(format!(
                "UPDATE docs EDGE '{edge_id}' SET PROPERTIES {{rank: 2}} REPLACE;"
            )),
        )
        .await,
    );
    assert_eq!(stats(&updated)["affected"], json!(1));

    let traversed = chironql_payload(
        common::send_wire(
            &harness.endpoint,
            3,
            query("TRAVERSE docs FROM root VIA CITES DEPTH 1 WITH PAYLOAD RETURN EDGES;"),
        )
        .await,
    );
    assert_eq!(row(&traversed, 0)["id"], json!(edge_id));
    assert_eq!(row(&traversed, 0)["properties"], json!({"rank": 2}));

    let searched = chironql_payload(
        common::send_wire(
            &harness.endpoint,
            4,
            query("SEARCH docs NEAR [1,0] CONNECTED TO root VIA CITES WITHIN 1 HOPS LIMIT 1;"),
        )
        .await,
    );
    assert_eq!(row(&searched, 0)["id"], json!("child"));
    assert!(stats(&searched)["graph"]["graph_epoch"].is_number());

    let unrelate = chironql_payload(
        common::send_wire(
            &harness.endpoint,
            5,
            query(format!("UNRELATE docs EDGE '{edge_id}';")),
        )
        .await,
    );
    assert_eq!(stats(&unrelate)["affected"], json!(1));

    let rejected =
        common::send_wire_with_key(&harness.endpoint, 6, "", query("SELECT * FROM docs;")).await;
    assert_eq!(rejected.error_code, "INVALID_ARGUMENT");
    let details: Value = serde_json::from_str(
        rejected
            .error_details_json
            .as_deref()
            .expect("stable error details"),
    )
    .expect("details json");
    assert_eq!(details["code"], json!("chironql.not_sql"));
    assert_eq!(details["position"], json!(0));
    assert!(details["trace"].is_object());
}

#[tokio::test]
async fn deferred_session_token_is_bound_outside_the_language() {
    let harness = Harness::start(true, AuthConfig::disabled()).await;
    let opened = harness
        .db
        .open_deferred_graph_session_scoped(COLLECTION, true, &TenantScope::system())
        .expect("open deferred session");
    let statement = "RELATE docs late-source -> CITES -> late-target WITH DEFERRED ENDPOINTS;";

    let missing = common::send_wire_with_key(&harness.endpoint, 10, "", query(statement)).await;
    assert_eq!(missing.error_code, "INVALID_ARGUMENT");
    let missing_details: Value = serde_json::from_str(
        missing
            .error_details_json
            .as_deref()
            .expect("missing-session details"),
    )
    .expect("details json");
    assert_eq!(
        missing_details["code"],
        json!("chironql.deferred_session_required")
    );

    let accepted = common::send_wire(
        &harness.endpoint,
        11,
        wire_request::Operation::Chironql(WireChironQlRequest {
            query: statement.to_string(),
            collection: None,
            trace: false,
            confirm: false,
            deferred_session_id: Some(opened.session_id.as_str().to_string()),
        }),
    )
    .await;
    assert_eq!(stats(&chironql_payload(accepted))["affected"], json!(1));
}

fn graph_rbac() -> AuthConfig {
    let entry = |id: &str, key: &str, tenant: Option<&str>, capabilities: &[&str]| -> ApiKeyEntry {
        ApiKeyEntry {
            id: Some(id.to_string()),
            key: key.to_string(),
            tenant_id: tenant.map(ToString::to_string),
            role: Role::Admin,
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
            entry("point-admin", POINT_ADMIN_KEY, None, &[]),
            entry(
                "acme",
                ACME_KEY,
                Some("acme"),
                &["graph:read", "graph:write"],
            ),
            entry(
                "globex",
                GLOBEX_KEY,
                Some("globex"),
                &["graph:read", "graph:write"],
            ),
        ],
    })
}

#[tokio::test]
async fn capabilities_tenant_scope_and_denial_audit_apply_to_wire_graph_paths() {
    let harness = Harness::start(false, graph_rbac()).await;
    harness
        .db
        .set_tenant_enforcement(TenantEnforcement::Enforced);

    let upsert = |id: &str, vector: [f32; 2]| {
        wire_request::Operation::Upsert(UpsertRequest {
            collection: COLLECTION.to_string(),
            points: vec![proto_point(id, vector)],
            no_wait: false,
        })
    };
    common::send_wire_with_key(&harness.endpoint, 20, ACME_KEY, upsert("a", [1.0, 0.0])).await;
    common::send_wire_with_key(&harness.endpoint, 21, ACME_KEY, upsert("b", [0.0, 1.0])).await;
    common::send_wire_with_key(&harness.endpoint, 22, GLOBEX_KEY, upsert("g", [0.5, 0.5])).await;

    let denied = common::send_wire_with_key(
        &harness.endpoint,
        23,
        POINT_ADMIN_KEY,
        query("RELATE docs a -> CITES -> b;"),
    )
    .await;
    assert_eq!(denied.error_code, "PERMISSION_DENIED");
    let denied_details: Value = serde_json::from_str(
        denied
            .error_details_json
            .as_deref()
            .expect("permission details"),
    )
    .expect("details json");
    assert_eq!(denied_details["code"], json!("chironql.permission_denied"));

    let related = common::send_wire_with_key(
        &harness.endpoint,
        24,
        ACME_KEY,
        query("RELATE docs a -> CITES -> b;"),
    )
    .await;
    assert_eq!(related.error_code, "", "{}", related.error_message);

    let cross_tenant = common::send_wire_with_key(
        &harness.endpoint,
        25,
        ACME_KEY,
        query("RELATE docs a -> CITES -> g;"),
    )
    .await;
    assert_eq!(cross_tenant.error_code, "NOT_FOUND");
    let cross_details: Value = serde_json::from_str(
        cross_tenant
            .error_details_json
            .as_deref()
            .expect("cross-tenant details"),
    )
    .expect("details json");
    assert_eq!(cross_details["code"], json!("graph.endpoint_not_found"));

    let graph_search = wire_request::Operation::Search(SearchRequest {
        collection: COLLECTION.to_string(),
        query: Some(SearchQuery {
            vector: vec![0.0, 1.0],
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
            vector_name: String::new(),
            ef_search: None,
            recall_target: None,
            graph_json: Some(json!({"anchors": ["a"], "edge_types": ["CITES"]}).to_string()),
        }),
    });
    let denied_search =
        common::send_wire_with_key(&harness.endpoint, 26, POINT_ADMIN_KEY, graph_search.clone())
            .await;
    assert_eq!(denied_search.error_code, "PERMISSION_DENIED");
    let search_details: Value = serde_json::from_str(
        denied_search
            .error_details_json
            .as_deref()
            .expect("graph search details"),
    )
    .expect("details json");
    assert_eq!(search_details["code"], json!("graph.permission_denied"));

    let accepted_search =
        common::send_wire_with_key(&harness.endpoint, 27, ACME_KEY, graph_search).await;
    assert_eq!(accepted_search.error_code, "");
    let wire_response::Payload::Search(search) = accepted_search.payload.expect("search") else {
        panic!("expected search payload");
    };
    assert_eq!(search.hits[0].id, "b");
    assert!(search.graph_json.is_some());

    let hybrid = common::send_wire_with_key(
        &harness.endpoint,
        28,
        ACME_KEY,
        wire_request::Operation::HybridSearch(HybridSearchRequest {
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
            graph_json: Some(json!({"anchors": ["a"], "edge_types": ["CITES"]}).to_string()),
        }),
    )
    .await;
    assert_eq!(hybrid.error_code, "");
    let wire_response::Payload::Search(hybrid) = hybrid.payload.expect("hybrid search") else {
        panic!("expected search payload");
    };
    assert_eq!(hybrid.hits[0].id, "b");
    assert!(hybrid.graph_json.is_some());

    let audit =
        std::fs::read_to_string(harness.data.path().join("audit/audit.jsonl")).expect("audit log");
    assert!(audit.contains("chironwire_chironql"), "{audit}");
    assert!(audit.contains("chironwire_graph_authorize"), "{audit}");
    assert!(audit.contains("graph.permission_denied"), "{audit}");
}
