//! RT-20 / RT-21: opt-in collection write bounds (`max_vector_norm`,
//! `max_sparse_nnz`, `max_sparse_weight`) are settable over HTTP and gRPC,
//! returned by both, and enforced on upsert. Unset = unbounded.

#[allow(dead_code)]
mod common;

use std::net::SocketAddr;

use chirondb::{
    Db, api,
    auth::AuthConfig,
    grpc::{self, GrpcServerOptions, pb},
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const KEY: &str = "write-bounds-secret-key-000000000000000";

fn auth() -> AuthConfig {
    AuthConfig::from_optional_key(Some(KEY.to_string()))
}

async fn serve_http(db: Db) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let router = api::router_with_options(db, auth(), api::ServerOptions::default());
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    address
}

async fn post(address: SocketAddr, path: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{address}{path}"))
        .bearer_auth(KEY)
        .json(&body)
        .send()
        .await
        .expect("request")
}

async fn put(address: SocketAddr, path: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("http://{address}{path}"))
        .bearer_auth(KEY)
        .json(&body)
        .send()
        .await
        .expect("request")
}

#[tokio::test]
async fn http_create_sets_limits_and_upsert_enforces_them() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let address = serve_http(db.clone()).await;

    let created = post(
        address,
        "/collections",
        json!({
            "name": "bounded",
            "vector_dim": 2,
            "metric": "dot",
            "max_vector_norm": 10.0,
            "max_sparse_nnz": 2,
            "max_sparse_weight": 5.0
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["max_vector_norm"], json!(10.0));
    assert_eq!(created["max_sparse_nnz"], json!(2));
    assert_eq!(created["max_sparse_weight"], json!(5.0));
    let stored = db
        .list_collections()
        .into_iter()
        .find(|config| config.name == "bounded")
        .unwrap();
    assert_eq!(stored.max_vector_norm, Some(10.0));
    assert_eq!(stored.max_sparse_nnz, Some(2));
    assert_eq!(stored.max_sparse_weight, Some(5.0));

    let upsert = |vector: Value, sparse: Option<Value>| {
        let mut point = json!({"id": "p", "vector": vector, "payload": {}});
        if let Some(sparse) = sparse {
            point["sparse_vector"] = sparse;
        }
        json!({"points": [point]})
    };
    let path = "/collections/bounded/points";
    assert_eq!(
        put(address, path, upsert(json!([6.0, 8.0]), None))
            .await
            .status(),
        StatusCode::OK
    );
    let rejected = put(address, path, upsert(json!([1.0e6, 0.0]), None)).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(rejected.text().await.unwrap().contains("max_vector_norm"));
    let rejected = put(
        address,
        path,
        upsert(
            json!([1.0, 0.0]),
            Some(json!({"indices": [1, 2, 3], "values": [1.0, 1.0, 1.0]})),
        ),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(rejected.text().await.unwrap().contains("max_sparse_nnz"));
    let rejected = put(
        address,
        path,
        upsert(
            json!([1.0, 0.0]),
            Some(json!({"indices": [1], "values": [-1000.0]})),
        ),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(rejected.text().await.unwrap().contains("max_sparse_weight"));

    // Unset limits are omitted from the response and stay unbounded.
    let plain = post(
        address,
        "/collections",
        json!({"name": "plain", "vector_dim": 2, "metric": "dot"}),
    )
    .await;
    assert_eq!(plain.status(), StatusCode::OK);
    let plain: Value = plain.json().await.unwrap();
    for key in ["max_vector_norm", "max_sparse_nnz", "max_sparse_weight"] {
        assert!(plain.get(key).is_none(), "{key}");
    }
    assert_eq!(
        put(
            address,
            "/collections/plain/points",
            upsert(json!([1.0e6, 0.0]), None)
        )
        .await
        .status(),
        StatusCode::OK
    );

    // Invalid limit values are refused at create.
    for body in [
        json!({"name": "bad-norm", "vector_dim": 2, "max_vector_norm": 0.0}),
        json!({"name": "bad-nnz", "vector_dim": 2, "max_sparse_nnz": 0}),
        json!({"name": "bad-weight", "vector_dim": 2, "max_sparse_weight": -1.0}),
    ] {
        let response = post(address, "/collections", body.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn grpc_create_round_trips_limits() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let address = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let server_db = db.clone();
    tokio::spawn(async move {
        grpc::serve_with_options(server_db, auth(), address, GrpcServerOptions::default())
            .await
            .expect("serve grpc");
    });
    let mut client = common::connect_grpc(address).await;

    let created = client
        .create_collection(common::grpc_auth_request(
            pb::CreateCollectionRequest {
                config: Some(pb::CollectionConfig {
                    name: "bounded".into(),
                    vector_dim: 2,
                    metric: "dot".into(),
                    shards: 1,
                    replicas: 1,
                    max_vector_norm: Some(3.0),
                    max_sparse_nnz: Some(4),
                    max_sparse_weight: Some(2.0),
                    ..Default::default()
                }),
            },
            KEY,
        ))
        .await
        .expect("create")
        .into_inner();
    assert_eq!(created.max_vector_norm, Some(3.0));
    assert_eq!(created.max_sparse_nnz, Some(4));
    assert_eq!(created.max_sparse_weight, Some(2.0));
    let stored = db
        .list_collections()
        .into_iter()
        .find(|config| config.name == "bounded")
        .unwrap();
    assert_eq!(stored.max_vector_norm, Some(3.0));
    assert_eq!(stored.max_sparse_nnz, Some(4));
    assert_eq!(stored.max_sparse_weight, Some(2.0));

    let plain = client
        .create_collection(common::grpc_auth_request(
            pb::CreateCollectionRequest {
                config: Some(pb::CollectionConfig {
                    name: "plain".into(),
                    vector_dim: 2,
                    metric: "dot".into(),
                    shards: 1,
                    replicas: 1,
                    ..Default::default()
                }),
            },
            KEY,
        ))
        .await
        .expect("create plain")
        .into_inner();
    assert_eq!(plain.max_vector_norm, None);
    assert_eq!(plain.max_sparse_nnz, None);
    assert_eq!(plain.max_sparse_weight, None);

    let invalid = client
        .create_collection(common::grpc_auth_request(
            pb::CreateCollectionRequest {
                config: Some(pb::CollectionConfig {
                    name: "invalid".into(),
                    vector_dim: 2,
                    metric: "dot".into(),
                    shards: 1,
                    replicas: 1,
                    max_vector_norm: Some(f32::NAN),
                    ..Default::default()
                }),
            },
            KEY,
        ))
        .await
        .expect_err("NaN max_vector_norm must be rejected");
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
}
