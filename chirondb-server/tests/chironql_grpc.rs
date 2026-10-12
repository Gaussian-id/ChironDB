//! ChironQL P5 gate — the gRPC surface.
//!
//! The rpc lives on `chirondb.v1.ChironDb` only. The legacy `gaussdb.v1`
//! service is frozen at the surface it shipped with, and this test exists in
//! part to keep that true.

use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, graph::ConfigureEdgeTypeRequest, grpc,
    tenant::TenantScope,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

// The generated code is re-exported by the server crate; regenerating it here
// would land it at the wrong module depth for its own `super::` paths.
use chirondb::grpc::chiron_pb as pb;
use pb::chiron_db_client::ChironDbClient;

const COLLECTION: &str = "products";

async fn start() -> (TempDir, String, tokio::task::JoinHandle<()>) {
    let data = TempDir::new().expect("tempdir");
    let db = Db::open(data.path()).expect("open db");
    db.create_collection(CollectionConfig {
        name: COLLECTION.to_string(),
        vector_dim: 3,
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
                id: "phone".to_string(),
                vector: vec![1.0, 0.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "electronics"}),
            },
            Point {
                id: "book".to_string(),
                vector: vec![0.0, 1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "media"}),
            },
        ],
    )
    .expect("upsert");

    // `grpc::serve` takes an address, so borrow a free port from the OS and
    // release it before handing the address over.
    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        probe.local_addr().expect("addr")
    };
    let handle = tokio::spawn(async move {
        grpc::serve(db, addr).await.expect("serve");
    });
    // The server needs a moment before the first connection attempt.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    (data, format!("http://{addr}"), handle)
}

fn request(query: &str) -> pb::ChironQlRequest {
    pb::ChironQlRequest {
        query: query.to_string(),
        collection: None,
        trace: false,
        confirm: false,
        parameters: Vec::new(),
        idempotency_key: None,
        retry_id: None,
    }
}

#[tokio::test]
async fn executes_a_search_over_grpc() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let response = client
        .execute_query(request("SEARCH products NEAR [1,0,0] LIMIT 1;"))
        .await
        .expect("execute")
        .into_inner();

    assert_eq!(response.kind, "rows");
    assert_eq!(response.columns, vec!["id", "score", "payload"]);
    assert_eq!(response.rows_json.len(), 1);

    let row: Value = serde_json::from_str(&response.rows_json[0]).expect("row json");
    assert_eq!(row["id"], json!("phone"));
    assert!(response.query_id.starts_with("q_"));

    handle.abort();
}

#[tokio::test]
async fn stats_travel_as_json_and_report_what_the_engine_measured() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let response = client
        .execute_query(request("SEARCH products NEAR [1,0,0] LIMIT 2;"))
        .await
        .expect("execute")
        .into_inner();

    let stats: Value = serde_json::from_str(&response.stats_json).expect("stats json");
    assert!(stats["searched"].is_number(), "{stats}");
    assert_eq!(stats["degraded"], json!(false));
    // No recall figure and no ef_search anywhere, same rule as every surface.
    assert!(stats.get("recall").is_none(), "{stats}");
    assert!(
        !response.stats_json.contains("ef_search"),
        "{}",
        response.stats_json
    );

    handle.abort();
}

#[tokio::test]
async fn the_trace_is_returned_when_asked_for() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let response = client
        .execute_query(pb::ChironQlRequest {
            trace: true,
            ..request("COUNT products;")
        })
        .await
        .expect("execute")
        .into_inner();

    let trace: Value = serde_json::from_str(&response.trace_json.expect("trace")).expect("json");
    let stages: Vec<&str> = trace["stages"]
        .as_array()
        .expect("stages")
        .iter()
        .map(|stage| stage["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        stages,
        vec![
            "parse",
            "classify",
            "authorize",
            "resolve_collection",
            "engine_search",
            "render"
        ]
    );

    handle.abort();
}

#[tokio::test]
async fn sql_wrapper_preserves_typed_parameters_and_metadata_over_grpc() {
    use pb::sql_value::Value as SqlValueKind;

    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");
    client
        .execute_query(request(
            "SQL CREATE TABLE notes (id TEXT PRIMARY KEY, title TEXT NOT NULL);",
        ))
        .await
        .expect("create table");

    let inserted = client
        .execute_query(pb::ChironQlRequest {
            parameters: vec![
                pb::SqlValue {
                    value: Some(SqlValueKind::Text("n-1".into())),
                },
                pb::SqlValue {
                    value: Some(SqlValueKind::Text("gRPC".into())),
                },
            ],
            idempotency_key: None,
            retry_id: Some("grpc-cql-relational-1".into()),
            ..request("SQL INSERT INTO notes VALUES ($1, $2);")
        })
        .await
        .expect("insert")
        .into_inner();
    assert_eq!(inserted.domains, ["relational"]);
    assert_eq!(inserted.committed, Some(true));
    assert!(inserted.transaction_id.is_some());

    let selected = client
        .execute_query(pb::ChironQlRequest {
            parameters: vec![pb::SqlValue {
                value: Some(SqlValueKind::Text("n-1".into())),
            }],
            ..request("SQL SELECT id, title FROM notes WHERE id = $1;")
        })
        .await
        .expect("select")
        .into_inner();
    assert_eq!(selected.domains, ["relational"]);
    assert_eq!(
        selected.column_types_json,
        ["{\"kind\":\"text\"}", "{\"kind\":\"text\"}"]
    );
    assert!(selected.snapshot_id.is_some());
    let row: Value = serde_json::from_str(&selected.rows_json[0]).expect("row");
    assert_eq!(row, json!({"id": "n-1", "title": "gRPC"}));

    handle.abort();
}

#[tokio::test]
async fn atomic_multimodel_transaction_runs_over_grpc() {
    use pb::sql_value::Value as SqlValueKind;

    let data = TempDir::new().expect("tempdir");
    let db = Db::open(data.path()).expect("open");
    db.create_collection(CollectionConfig {
        name: "chunks".into(),
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
    .expect("collection");
    db.set_graph_lifecycle_scoped("chunks", true, true, &TenantScope::system())
        .expect("graph");
    db.configure_edge_type_scoped(
        "chunks",
        ConfigureEdgeTypeRequest {
            name: "CITES".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .expect("edge type");
    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        probe.local_addr().expect("addr")
    };
    let handle = tokio::spawn(async move {
        grpc::serve(db, addr).await.expect("serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut client = ChironDbClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    client
        .execute_query(request(
            "SQL CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL);",
        ))
        .await
        .expect("create table");
    let response = client
        .execute_query(pb::ChironQlRequest {
            parameters: vec![
                pb::SqlValue {
                    value: Some(SqlValueKind::Text("grpc-doc".into())),
                },
                pb::SqlValue {
                    value: Some(SqlValueKind::Text("gRPC atomic".into())),
                },
            ],
            idempotency_key: None,
            retry_id: Some("grpc-multimodel-1".into()),
            ..request(
                r#"TRANSACTION {
  SQL INSERT INTO documents VALUES ($1, $2);
  VECTOR UPSERT INTO chunks
      {id: 'grpc-chunk', vector: [1,0]},
      {id: 'grpc-source', vector: [0,1]};
  GRAPH CONNECT chunks 'grpc-chunk' -> CITES -> 'grpc-source';
};"#,
            )
        })
        .await
        .expect("transaction")
        .into_inner();
    assert_eq!(response.committed, Some(true));
    assert_eq!(response.domains, ["relational", "vector", "graph"]);
    assert!(response.transaction_id.is_some());
    let stats: Value = serde_json::from_str(&response.stats_json).expect("stats");
    assert_eq!(stats["affected"], json!(4));
    handle.abort();
}

#[tokio::test]
async fn a_reject_becomes_invalid_argument_with_the_full_error_in_the_details() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let status = client
        .execute_query(request("SELECT * FROM products;"))
        .await
        .expect_err("rejected");

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("not SQL"), "{}", status.message());

    // A gRPC caller loses nothing by not being an HTTP caller: the code, hint
    // and caret position all arrive in the details.
    let details: Value = serde_json::from_slice(status.details()).expect("details json");
    assert_eq!(details["code"], json!("chironql.not_sql"));
    assert_eq!(details["position"], json!(0));
    assert!(
        details["hint"]
            .as_str()
            .expect("hint")
            .contains("SQL SELECT")
    );

    handle.abort();
}

#[tokio::test]
async fn a_missing_collection_becomes_not_found() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let status = client
        .execute_query(request("COUNT nope;"))
        .await
        .expect_err("rejected");

    assert_eq!(status.code(), tonic::Code::NotFound);

    handle.abort();
}

#[tokio::test]
async fn a_filtered_delete_needs_confirmation_here_too() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let status = client
        .execute_query(request("DELETE FROM products WHERE category = 'media';"))
        .await
        .expect_err("confirmation required");

    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    let details: Value = serde_json::from_slice(status.details()).expect("details json");
    assert_eq!(details["affected_estimate"], json!(1));

    // Confirmed, it runs.
    let response = client
        .execute_query(pb::ChironQlRequest {
            confirm: true,
            ..request("DELETE FROM products WHERE category = 'media';")
        })
        .await
        .expect("confirmed delete")
        .into_inner();

    assert_eq!(response.kind, "affected");
    let stats: Value = serde_json::from_str(&response.stats_json).expect("stats json");
    assert_eq!(stats["affected"], json!(1));

    handle.abort();
}

#[tokio::test]
async fn the_session_collection_may_travel_in_the_request() {
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.expect("connect");

    let response = client
        .execute_query(pb::ChironQlRequest {
            collection: Some(COLLECTION.to_string()),
            ..request("COUNT;")
        })
        .await
        .expect("execute")
        .into_inner();

    let row: Value = serde_json::from_str(&response.rows_json[0]).expect("row json");
    assert_eq!(row["count"], json!(2));

    handle.abort();
}

#[tokio::test]
async fn grpc_collection_hnsw_one_is_rejected_and_zero_retains_default_contract() {
    use chirondb::grpc::pb as compat;
    let (_data, url, handle) = start().await;
    let mut client = ChironDbClient::connect(url).await.unwrap();
    let error = client
        .create_collection(compat::CreateCollectionRequest {
            config: Some(compat::CollectionConfig {
                name: "invalid_hnsw".into(),
                vector_dim: 2,
                metric: "l2".into(),
                hnsw_m: Some(1),
                ..Default::default()
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("hnsw_m"));
    assert_eq!(
        client
            .list_collections(compat::ListCollectionsRequest {})
            .await
            .unwrap()
            .into_inner()
            .collections
            .len(),
        1
    );
    let config = client
        .create_collection(compat::CreateCollectionRequest {
            config: Some(compat::CollectionConfig {
                name: "zero_default".into(),
                vector_dim: 2,
                metric: "l2".into(),
                hnsw_m: Some(0),
                hnsw_ef_construction: Some(0),
                hnsw_ef_search: Some(0),
                ..Default::default()
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(config.hnsw_m, None);
    assert_eq!(config.hnsw_ef_construction, None);
    assert_eq!(config.hnsw_ef_search, None);
    assert_eq!(
        client
            .list_collections(compat::ListCollectionsRequest {})
            .await
            .unwrap()
            .into_inner()
            .collections
            .len(),
        2
    );
    handle.abort();
}
