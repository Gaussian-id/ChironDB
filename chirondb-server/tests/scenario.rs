mod common;

use chirondb::{
    CollectionConfig, Db, DistanceMetric, PayloadType, Point, SparseVector, api,
    auth::AuthConfig,
    grpc::{
        self,
        chiron_pb::chiron_db_client::ChironDbClient,
        pb::{
            CollectionConfig as GrpcCollectionConfig, CompactRequest, CountRequest,
            CreateCollectionRequest, DeleteCollectionRequest, DeleteRequest, HealthRequest,
            HealthResponse, HybridSearchRequest as GrpcHybridSearchRequest,
            MultiSearchRequest as GrpcMultiSearchRequest, Point as GrpcPoint,
            PruneWalArchiveRequest, RecommendRequest, RestoreRequest, ScrollRequest, SearchQuery,
            SearchRequest, SetPayloadRequest, ShardMoveRequest, SnapshotRequest,
            SparseVector as GrpcSparseVector, UpdatePayloadSchemaRequest, UpsertRequest,
            WireRequest, wire_request, wire_response,
        },
    },
    security_paths::StoragePolicy,
    wire,
};
use prost::Message;
use serde_json::{Value, json};
use std::{collections::HashMap, net::TcpListener as StdTcpListener, process::Command};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tonic::Code;

#[test]
fn gaussdb_alpha_data_directory_reopens_under_chirondb_beta() {
    let data = TempDir::new().unwrap();
    {
        let alpha = Db::open(data.path()).unwrap();
        alpha
            .create_collection(CollectionConfig {
                name: "compat".to_string(),
                vector_dim: 2,
                metric: DistanceMetric::Cosine,
                shards: 1,
                replicas: 1,
                quantization: None,
                payload_schema: HashMap::new(),
                named_vector_dims: HashMap::new(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                index_kind: None,
                streamer_max_bytes: 0,
            })
            .unwrap();
        alpha
            .upsert(
                "compat",
                vec![Point {
                    id: "alpha".to_string(),
                    vector: vec![1.0, 0.0],
                    vectors: HashMap::new(),
                    sparse_vector: None,
                    payload: Value::Null,
                }],
            )
            .unwrap();
    }

    {
        let beta = Db::open(data.path()).unwrap();
        let hits = beta
            .search(
                "compat",
                chirondb::SearchRequest {
                    graph: None,
                    vector: vec![1.0, 0.0],
                    vector_name: None,
                    k: 1,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .unwrap();
        assert_eq!(hits.hits[0].id, "alpha");
        beta.upsert(
            "compat",
            vec![Point {
                id: "beta".to_string(),
                vector: vec![0.0, 1.0],
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: Value::Null,
            }],
        )
        .unwrap();
    }

    let restarted = Db::open(data.path()).unwrap();
    assert_eq!(restarted.count("compat", None).unwrap().count, 2);
}

#[tokio::test]
async fn live_server_supports_collection_ingest_search_and_snapshot() {
    let data = TempDir::new().unwrap();
    let snapshot_root = TempDir::new().unwrap();
    let snapshot_root_path = snapshot_root.path().canonicalize().unwrap();
    let snapshot = snapshot_root_path.join("snapshot");
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let storage_policy = StoragePolicy::new(Some(snapshot_root_path), None, false).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            api::router_with_options(
                db,
                AuthConfig::disabled(),
                api::ServerOptions {
                    storage_policy,
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let health: Value = client
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));

    client
        .post(format!("{base}/collections"))
        .json(&CollectionConfig {
            name: "products".to_string(),
            vector_dim: 3,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: Some("rabitq2".to_string()),
            payload_schema: Default::default(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    client
        .put(format!("{base}/collections/products/points"))
        .json(&json!({
            "points": [
                Point { id: "phone".to_string(), vector: vec![1.0, 0.0, 0.0], vectors: Default::default(), sparse_vector: Some(SparseVector { indices: vec![7], values: vec![1.0] }), payload: json!({"category": "electronics", "price": 699}) },
                Point { id: "charger".to_string(), vector: vec![0.9, 0.1, 0.0], vectors: Default::default(), sparse_vector: Some(SparseVector { indices: vec![11], values: vec![1.0] }), payload: json!({"category": "electronics", "price": 39}) },
                Point { id: "mug".to_string(), vector: vec![0.0, 1.0, 0.0], vectors: Default::default(), sparse_vector: Some(SparseVector { indices: vec![3], values: vec![1.0] }), payload: json!({"category": "home", "price": 12}) }
            ]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let search: Value = client
        .post(format!("{base}/collections/products/search"))
        .json(&json!({
            "vector": [1.0, 0.0, 0.0],
            "k": 1,
            "filter": {"category": "electronics"}
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search["hits"][0]["id"], "phone");
    assert_eq!(search["degraded"], false);
    assert!(search["searched"].as_u64().unwrap() >= 1);

    let hybrid_search: Value = client
        .post(format!("{base}/collections/products/hybrid_search"))
        .json(&json!({
            "vector": [1.0, 0.0, 0.0],
            "sparse_vector": {"indices": [11], "values": [1.0]},
            "k": 1,
            "fusion": "rrf",
            "filter": {"category": "electronics"}
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(hybrid_search["hits"][0]["id"], "charger");
    assert_eq!(hybrid_search["degraded"], false);

    let metrics = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("gaussdb_operations_total"));
    assert!(metrics.contains("gaussdb_operation_duration_seconds"));
    assert!(metrics.contains("gaussdb_collections"));
    assert!(metrics.contains("gaussdb_points"));

    let degraded_search: Value = client
        .post(format!("{base}/collections/products/search"))
        .json(&json!({
            "vector": [1.0, 0.0, 0.0],
            "k": 1,
            "budget_ms": 0
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(degraded_search["degraded"], true);

    let multi_search: Value = client
        .post(format!("{base}/collections/products/multi_search"))
        .json(&json!({
            "searches": [
                {"vector": [1.0, 0.0, 0.0], "k": 1},
                {"vector": [0.0, 1.0, 0.0], "k": 1}
            ],
            "fusion": "rrf",
            "fused_k": 2
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(multi_search["results"].as_array().unwrap().len(), 2);
    assert_eq!(multi_search["results"][0]["hits"][0]["id"], "phone");
    assert_eq!(multi_search["results"][1]["hits"][0]["id"], "mug");
    assert_eq!(multi_search["fused"]["hits"].as_array().unwrap().len(), 2);

    let recommend: Value = client
        .post(format!("{base}/collections/products/recommend"))
        .json(&json!({
            "positive": ["phone"],
            "negative": ["mug"],
            "k": 1
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(recommend["hits"][0]["id"], "charger");

    let compact: Value = client
        .post(format!("{base}/collections/products/compact"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(compact["points"], 3);
    assert!(compact["h2qg_cells"].as_u64().unwrap() >= 1);
    assert_eq!(compact["sparse_dimensions"], 3);
    assert_eq!(compact["sparse_postings"], 3);
    assert_eq!(compact["payload_fields"], 2);
    assert_eq!(compact["payload_values"], 5);
    assert_eq!(compact["payload_postings"], 6);
    assert_eq!(compact["tombstones"], 0);
    assert_eq!(compact["wal_archived_segments"], 1);
    assert!(compact["wal_archived_bytes"].as_u64().unwrap() > 0);
    assert_eq!(compact["wal_external_archived_segments"], 0);
    assert_eq!(compact["wal_external_archived_bytes"], 0);
    assert_eq!(compact["wal_object_archived_segments"], 0);
    assert_eq!(compact["wal_object_archived_bytes"], 0);
    assert_eq!(compact["wal_archive_command_executed"], false);
    assert_eq!(compact["wal_auto_retained_archives"], 0);
    assert_eq!(compact["wal_auto_pruned_archives"], 0);
    assert_eq!(compact["wal_auto_pruned_bytes"], 0);
    let segment_id = compact["segment_id"].as_str().unwrap().to_string();

    client
        .post(format!("{base}/admin/snapshot"))
        .json(&json!({ "path": snapshot }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert!(snapshot.join("catalog.json").exists());
    assert!(snapshot.join("snapshot.gdx").exists());
    assert!(
        snapshot
            .join("collections/products/checkpoint.gdx")
            .exists()
    );
    let snapshot_segment = snapshot
        .join("collections/products/searchers")
        .join(&segment_id);
    for artifact in ["seal.gdx", "ivf.gdx", "rabitq.gdx", "vamana.gdx"] {
        assert!(
            snapshot_segment.join(artifact).exists(),
            "default LS-VEC snapshot is missing {artifact}"
        );
    }
    assert!(
        snapshot
            .join("collections/products/searchers")
            .join(&segment_id)
            .join("payload.gdx")
            .exists()
    );
    assert!(
        snapshot
            .join("collections/products/searchers")
            .join(&segment_id)
            .join("tomb.gdx")
            .exists()
    );
    let archive_root = snapshot.join("collections/products/wal/archive");
    let archives = std::fs::read_dir(archive_root)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(archives.len(), 1);
    assert!(archives[0].path().join("000000.gdwal").exists());

    client
        .put(format!("{base}/collections/products/points"))
        .json(&json!({
            "points": [
                Point { id: "camera".to_string(), vector: vec![0.8, 0.2, 0.0], vectors: Default::default(), sparse_vector: Some(SparseVector { indices: vec![13], values: vec![1.0] }), payload: json!({"category": "electronics", "price": 299}) }
            ]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(format!("{base}/collections/products/compact"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let prune: Value = client
        .post(format!("{base}/collections/products/wal_archive/prune"))
        .json(&json!({ "retain_last": 1 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prune["collection"], "products");
    assert_eq!(prune["retained_archives"], 1);
    assert_eq!(prune["pruned_archives"], 1);
    assert!(prune["pruned_bytes"].as_u64().unwrap() > 0);

    server.abort();
}

#[tokio::test]
async fn http_payload_schema_validates_upserts() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    client
        .post(format!("{base}/collections"))
        .json(&CollectionConfig {
            name: "typed".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: [
                ("tenant".to_string(), PayloadType::String),
                ("price".to_string(), PayloadType::Number),
            ]
            .into_iter()
            .collect(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    client
        .put(format!("{base}/collections/typed/points"))
        .json(&json!({
            "points": [{
                "id": "valid",
                "vector": [1.0, 0.0],
                "payload": {"tenant": "acme", "price": 42}
            }]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let rejected = client
        .put(format!("{base}/collections/typed/points"))
        .json(&json!({
            "points": [{
                "id": "invalid",
                "vector": [1.0, 0.0],
                "payload": {"tenant": "acme", "price": "42"}
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);

    server.abort();
}

#[tokio::test]
async fn http_payload_schema_update_validates_existing_points() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    client
        .post(format!("{base}/collections"))
        .json(&CollectionConfig {
            name: "typed_update".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
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
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .put(format!("{base}/collections/typed_update/points"))
        .json(&json!({
            "points": [{
                "id": "valid",
                "vector": [1.0, 0.0],
                "payload": {"tenant": "acme"}
            }]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let updated: Value = client
        .put(format!("{base}/collections/typed_update/payload_schema"))
        .json(&json!({ "payload_schema": { "tenant": "string" } }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["payload_schema"]["tenant"], "string");

    let rejected = client
        .put(format!("{base}/collections/typed_update/payload_schema"))
        .json(&json!({ "payload_schema": { "tenant": "number" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);

    let collections: Value = client
        .get(format!("{base}/collections"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(collections[0]["payload_schema"]["tenant"], "string");

    server.abort();
}

#[tokio::test]
async fn grpc_server_supports_collection_ingest_and_search() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let server = tokio::spawn(async move {
        grpc::serve(db, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    let health = client.health(HealthRequest {}).await.unwrap().into_inner();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));

    let channel = common::connect_grpc_channel(addr).await;
    let mut chiron_client = ChironDbClient::new(channel);
    let chiron_health = chiron_client
        .health(HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(chiron_health.version, env!("CARGO_PKG_VERSION"));

    let created = client
        .create_collection(CreateCollectionRequest {
            config: Some(GrpcCollectionConfig {
                name: "products".to_string(),
                vector_dim: 3,
                metric: "cosine".to_string(),
                shards: 1,
                replicas: 1,
                quantization: "rabitq2".to_string(),
                payload_schema: Default::default(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                streamer_max_bytes: 1024,
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.streamer_max_bytes, 1024);

    client
        .upsert(chirondb::grpc::pb::UpsertRequest {
            collection: "products".to_string(),
            points: vec![
                GrpcPoint {
                    id: "phone".to_string(),
                    vector: vec![1.0, 0.0, 0.0],
                    payload_json: r#"{"category":"electronics","price":699}"#.to_string(),
                    vectors: Default::default(),
                    sparse_vector: Some(GrpcSparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                },
                GrpcPoint {
                    id: "mug".to_string(),
                    vector: vec![0.0, 1.0, 0.0],
                    payload_json: r#"{"category":"home","price":12}"#.to_string(),
                    vectors: Default::default(),
                    sparse_vector: Some(GrpcSparseVector {
                        indices: vec![3],
                        values: vec![1.0],
                    }),
                },
            ],
            no_wait: false,
        })
        .await
        .unwrap();

    let search = client
        .search(SearchRequest {
            collection: "products".to_string(),
            query: Some(SearchQuery {
                vector: vec![1.0, 0.0, 0.0],
                k: 1,
                filter_json: r#"{"category":"electronics"}"#.to_string(),
                budget_ms: None,
                vector_name: String::new(),
                ef_search: None,
                recall_target: Some(0.95),
                graph_json: None,
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(search.hits[0].id, "phone");
    assert!(!search.degraded);

    let hybrid = client
        .hybrid_search(GrpcHybridSearchRequest {
            collection: "products".to_string(),
            vector: Vec::new(),
            sparse_vector: Some(GrpcSparseVector {
                indices: vec![3],
                values: vec![1.0],
            }),
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
            fusion: "rrf".to_string(),
            dense_weight: 1.0,
            sparse_weight: 1.0,
            use_dense_vector: false,
            vector_name: String::new(),
            graph_json: None,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hybrid.hits[0].id, "mug");

    let multi = client
        .multi_search(GrpcMultiSearchRequest {
            collection: "products".to_string(),
            searches: vec![
                SearchQuery {
                    vector: vec![1.0, 0.0, 0.0],
                    k: 1,
                    filter_json: String::new(),
                    budget_ms: None,
                    vector_name: String::new(),
                    ef_search: None,
                    recall_target: None,
                    graph_json: None,
                },
                SearchQuery {
                    vector: vec![0.0, 1.0, 0.0],
                    k: 1,
                    filter_json: String::new(),
                    budget_ms: None,
                    vector_name: String::new(),
                    ef_search: None,
                    recall_target: None,
                    graph_json: None,
                },
            ],
            fusion: "rrf".to_string(),
            fused_k: 2,
            weights: Vec::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(multi.results.len(), 2);
    assert_eq!(multi.fused.unwrap().hits.len(), 2);

    server.abort();
}

#[tokio::test]
async fn gausswire_supports_collection_ingest_and_search() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        wire::serve_listener(db, listener).await.unwrap();
    });
    let endpoint = addr.to_string();

    let health = common::send_wire(
        &endpoint,
        1,
        wire_request::Operation::Health(HealthRequest {}),
    )
    .await;
    assert_eq!(
        match health.payload.unwrap() {
            wire_response::Payload::Health(response) => response.status,
            _ => panic!("expected health response"),
        },
        "ok"
    );

    common::send_wire(
        &endpoint,
        2,
        wire_request::Operation::CreateCollection(CreateCollectionRequest {
            config: Some(GrpcCollectionConfig {
                name: "wire_products".to_string(),
                vector_dim: 2,
                metric: "cosine".to_string(),
                shards: 1,
                replicas: 1,
                quantization: String::new(),
                payload_schema: Default::default(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                streamer_max_bytes: 0,
            }),
        }),
    )
    .await;

    common::send_wire(
        &endpoint,
        3,
        wire_request::Operation::Upsert(UpsertRequest {
            collection: "wire_products".to_string(),
            points: vec![
                GrpcPoint {
                    id: "target".to_string(),
                    vector: vec![1.0, 0.0],
                    payload_json: r#"{"tenant":"acme","price":125}"#.to_string(),
                    vectors: Default::default(),
                    sparse_vector: None,
                },
                GrpcPoint {
                    id: "other".to_string(),
                    vector: vec![0.0, 1.0],
                    payload_json: r#"{"tenant":"other","price":125}"#.to_string(),
                    vectors: Default::default(),
                    sparse_vector: None,
                },
            ],
            no_wait: false,
        }),
    )
    .await;

    let search = common::send_wire(
        &endpoint,
        4,
        wire_request::Operation::Search(SearchRequest {
            collection: "wire_products".to_string(),
            query: Some(SearchQuery {
                vector: vec![1.0, 0.0],
                k: 10,
                filter_json: r#"{"tenant":"acme","price":{"gte":100,"lt":200}}"#.to_string(),
                budget_ms: None,
                vector_name: String::new(),
                ef_search: None,
                recall_target: Some(0.95),
                graph_json: None,
            }),
        }),
    )
    .await;
    let search = match search.payload.unwrap() {
        wire_response::Payload::Search(response) => response,
        _ => panic!("expected search response"),
    };
    assert_eq!(search.hits.len(), 1);
    assert_eq!(search.hits[0].id, "target");
    assert_eq!(search.searched, 1);

    server.abort();
}

#[tokio::test]
async fn gausswire_supports_ordered_pipelined_frames() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        wire::serve_listener(db, listener).await.unwrap();
    });
    let endpoint = addr.to_string();

    let responses = wire::send_requests(
        &endpoint,
        vec![
            WireRequest {
                request_id: 100,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Health(HealthRequest {})),
            },
            WireRequest {
                request_id: 101,
                api_key: String::new(),
                operation: Some(wire_request::Operation::CreateCollection(
                    CreateCollectionRequest {
                        config: Some(GrpcCollectionConfig {
                            name: "wire_pipeline".to_string(),
                            vector_dim: 2,
                            metric: "cosine".to_string(),
                            shards: 1,
                            replicas: 1,
                            quantization: String::new(),
                            payload_schema: Default::default(),
                            hnsw_m: None,
                            hnsw_ef_construction: None,
                            hnsw_ef_search: None,
                            recall_sla: None,
                            streamer_max_bytes: 0,
                        }),
                    },
                )),
            },
            WireRequest {
                request_id: 102,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Upsert(UpsertRequest {
                    collection: "wire_pipeline".to_string(),
                    points: vec![GrpcPoint {
                        id: "target".to_string(),
                        vector: vec![1.0, 0.0],
                        payload_json: json!({"tenant": "acme"}).to_string(),
                        vectors: Default::default(),
                        sparse_vector: None,
                    }],
                    no_wait: false,
                })),
            },
            WireRequest {
                request_id: 103,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Count(CountRequest {
                    collection: "wire_pipeline".to_string(),
                    filter_json: json!({"tenant": "acme"}).to_string(),
                })),
            },
            // Write barrier: forces Count(103) to complete before executing,
            // ensuring deterministic ordering for the subsequent Search(105).
            WireRequest {
                request_id: 104,
                api_key: String::new(),
                operation: Some(wire_request::Operation::SetPayload(SetPayloadRequest {
                    collection: "wire_pipeline".to_string(),
                    id: "target".to_string(),
                    payload_json: json!({"tenant": "acme", "tagged": true}).to_string(),
                    merge: true,
                })),
            },
            WireRequest {
                request_id: 105,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Search(SearchRequest {
                    collection: "wire_pipeline".to_string(),
                    query: Some(SearchQuery {
                        vector: vec![1.0, 0.0],
                        k: 1,
                        filter_json: json!({"tenant": "acme"}).to_string(),
                        budget_ms: None,
                        vector_name: String::new(),
                        ef_search: None,
                        recall_target: None,
                        graph_json: None,
                    }),
                })),
            },
        ],
    )
    .await
    .unwrap();

    assert_eq!(
        responses
            .iter()
            .map(|response| response.request_id)
            .collect::<Vec<_>>(),
        vec![100, 101, 102, 103, 104, 105]
    );
    assert!(
        responses
            .iter()
            .all(|response| response.error_code.is_empty())
    );
    assert!(matches!(
        responses[0].payload,
        Some(wire_response::Payload::Health(_))
    ));
    assert!(matches!(
        responses[1].payload,
        Some(wire_response::Payload::Collection(_))
    ));
    assert!(matches!(
        responses[2].payload,
        Some(wire_response::Payload::Upsert(_))
    ));
    let Some(wire_response::Payload::Count(count)) = &responses[3].payload else {
        panic!("expected count response");
    };
    assert_eq!(count.count, 1);
    assert!(matches!(
        responses[4].payload,
        Some(wire_response::Payload::SetPayload(_))
    ));
    let Some(wire_response::Payload::Search(search)) = &responses[5].payload else {
        panic!("expected search response");
    };
    assert_eq!(search.hits[0].id, "target");

    server.abort();
}

#[tokio::test]
async fn gausswire_correlates_multiplexed_read_responses() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    db.create_collection(CollectionConfig {
        name: "wire_multiplex".to_string(),
        vector_dim: 2,
        metric: DistanceMetric::Cosine,
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
    db.upsert(
        "wire_multiplex",
        vec![Point {
            id: "target".to_string(),
            vector: vec![1.0, 0.0],
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"kind": "bulk"}),
        }],
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        wire::serve_listener(db, listener).await.unwrap();
    });

    let responses = wire::send_requests(
        &addr.to_string(),
        vec![
            WireRequest {
                request_id: 200,
                api_key: String::new(),
                operation: Some(wire_request::Operation::MultiSearch(
                    GrpcMultiSearchRequest {
                        collection: "wire_multiplex".to_string(),
                        searches: (0..128)
                            .map(|_| SearchQuery {
                                vector: vec![1.0, 0.0],
                                k: 1,
                                filter_json: String::new(),
                                budget_ms: None,
                                vector_name: String::new(),
                                ef_search: None,
                                recall_target: None,
                                graph_json: None,
                            })
                            .collect(),
                        fusion: String::new(),
                        fused_k: 0,
                        weights: Vec::new(),
                    },
                )),
            },
            WireRequest {
                request_id: 201,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Health(HealthRequest {})),
            },
        ],
    )
    .await
    .unwrap();

    let mut response_ids = responses
        .iter()
        .map(|response| response.request_id)
        .collect::<Vec<_>>();
    response_ids.sort_unstable();
    assert_eq!(response_ids, vec![200, 201]);
    assert!(
        responses
            .iter()
            .all(|response| response.error_code.is_empty())
    );
    let health = responses
        .iter()
        .find(|response| response.request_id == 201)
        .expect("health response");
    assert!(matches!(
        &health.payload,
        Some(wire_response::Payload::Health(_))
    ));
    let multi_search = responses
        .iter()
        .find(|response| response.request_id == 200)
        .expect("multi-search response");
    let Some(wire_response::Payload::MultiSearch(multi_search)) = &multi_search.payload else {
        panic!("expected multi-search response");
    };
    assert_eq!(multi_search.results.len(), 128);
    assert_eq!(multi_search.results[0].hits[0].id, "target");

    server.abort();
}

#[tokio::test]
async fn gausswire_python_client_compatibility_smoke() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        wire::serve_listener(db, listener).await.unwrap();
    });

    let script = std::env::current_dir()
        .unwrap()
        .join("tests/gausswire_python_compat.py");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .arg(script)
            .arg(addr.to_string())
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "python compat failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["request_id"], 501);
    assert_eq!(response["status"], "ok");

    server.abort();
}

#[tokio::test]
async fn generated_python_protobuf_compatibility_smoke() {
    let script = std::env::current_dir()
        .unwrap()
        .join("tests/generated_proto_compat.py");
    let output =
        tokio::task::spawn_blocking(move || Command::new("python3").arg(script).output().unwrap())
            .await
            .unwrap();

    assert!(
        output.status.success(),
        "generated protobuf compat failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["generated_python_protobuf"], "ok");
}

#[tokio::test]
async fn python_http_client_smoke() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let script = std::env::current_dir()
        .unwrap()
        .join("tests/http_python_client_smoke.py");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .arg(script)
            .arg(format!("http://{addr}"))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "python HTTP client smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["python_http_client"], "ok");

    server.abort();
}

#[tokio::test]
async fn gausswire_supports_admin_and_query_operation_set() {
    let data = TempDir::new().unwrap();
    let snapshot_root = TempDir::new().unwrap();
    let snapshot_root_path = snapshot_root.path().canonicalize().unwrap();
    let snapshot = snapshot_root_path.join("snapshot");
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let storage_policy = StoragePolicy::new(Some(snapshot_root_path), None, false).unwrap();
    let server = tokio::spawn(async move {
        wire::serve_listener_with_policy(db, AuthConfig::disabled(), listener, storage_policy)
            .await
            .unwrap();
    });
    let endpoint = addr.to_string();

    common::send_wire(
        &endpoint,
        30,
        wire_request::Operation::CreateCollection(CreateCollectionRequest {
            config: Some(GrpcCollectionConfig {
                name: "wire_ops".to_string(),
                vector_dim: 2,
                metric: "cosine".to_string(),
                shards: 1,
                replicas: 1,
                quantization: String::new(),
                payload_schema: Default::default(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                streamer_max_bytes: 0,
            }),
        }),
    )
    .await;

    common::send_wire(
        &endpoint,
        31,
        wire_request::Operation::Upsert(UpsertRequest {
            collection: "wire_ops".to_string(),
            points: vec![
                GrpcPoint {
                    id: "anchor".to_string(),
                    vector: vec![1.0, 0.0],
                    payload_json: json!({"tenant": "acme"}).to_string(),
                    vectors: Default::default(),
                    sparse_vector: Some(GrpcSparseVector {
                        indices: vec![7],
                        values: vec![1.0],
                    }),
                },
                GrpcPoint {
                    id: "other".to_string(),
                    vector: vec![0.0, 1.0],
                    payload_json: json!({"tenant": "other"}).to_string(),
                    vectors: Default::default(),
                    sparse_vector: Some(GrpcSparseVector {
                        indices: vec![3],
                        values: vec![1.0],
                    }),
                },
            ],
            no_wait: false,
        }),
    )
    .await;

    let updated = common::send_wire(
        &endpoint,
        32,
        wire_request::Operation::UpdatePayloadSchema(UpdatePayloadSchemaRequest {
            collection: "wire_ops".to_string(),
            payload_schema: [("tenant".to_string(), "string".to_string())]
                .into_iter()
                .collect(),
        }),
    )
    .await;
    assert!(matches!(
        updated.payload,
        Some(wire_response::Payload::Collection(_))
    ));

    let hybrid = common::send_wire(
        &endpoint,
        33,
        wire_request::Operation::HybridSearch(GrpcHybridSearchRequest {
            collection: "wire_ops".to_string(),
            vector: Vec::new(),
            sparse_vector: Some(GrpcSparseVector {
                indices: vec![7],
                values: vec![1.0],
            }),
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
            fusion: "rrf".to_string(),
            dense_weight: 1.0,
            sparse_weight: 1.0,
            use_dense_vector: false,
            vector_name: String::new(),
            graph_json: None,
        }),
    )
    .await;
    assert_eq!(common::wire_search_hit_id(hybrid), "anchor");

    let multi = common::send_wire(
        &endpoint,
        34,
        wire_request::Operation::MultiSearch(GrpcMultiSearchRequest {
            collection: "wire_ops".to_string(),
            searches: vec![
                SearchQuery {
                    vector: vec![1.0, 0.0],
                    k: 1,
                    filter_json: String::new(),
                    budget_ms: None,
                    vector_name: String::new(),
                    ef_search: None,
                    recall_target: None,
                    graph_json: None,
                },
                SearchQuery {
                    vector: vec![0.0, 1.0],
                    k: 1,
                    filter_json: String::new(),
                    budget_ms: None,
                    vector_name: String::new(),
                    ef_search: None,
                    recall_target: None,
                    graph_json: None,
                },
            ],
            fusion: "rrf".to_string(),
            fused_k: 2,
            weights: Vec::new(),
        }),
    )
    .await;
    let wire_response::Payload::MultiSearch(multi) = multi.payload.unwrap() else {
        panic!("expected multi-search response");
    };
    assert_eq!(multi.results.len(), 2);
    assert_eq!(multi.fused.unwrap().hits.len(), 2);

    let recommended = common::send_wire(
        &endpoint,
        35,
        wire_request::Operation::Recommend(RecommendRequest {
            collection: "wire_ops".to_string(),
            positive: vec!["anchor".to_string()],
            negative: Vec::new(),
            k: 1,
            filter_json: String::new(),
            budget_ms: None,
            vector_name: String::new(),
        }),
    )
    .await;
    assert_eq!(common::wire_search_hit_id(recommended), "other");

    let scroll = common::send_wire(
        &endpoint,
        36,
        wire_request::Operation::Scroll(ScrollRequest {
            collection: "wire_ops".to_string(),
            offset: String::new(),
            limit: 1,
            filter_json: json!({"tenant": "acme"}).to_string(),
        }),
    )
    .await;
    let wire_response::Payload::Scroll(scroll) = scroll.payload.unwrap() else {
        panic!("expected scroll response");
    };
    assert_eq!(scroll.points.len(), 1);
    assert_eq!(scroll.points[0].id, "anchor");

    let compact = common::send_wire(
        &endpoint,
        37,
        wire_request::Operation::Compact(CompactRequest {
            collection: "wire_ops".to_string(),
        }),
    )
    .await;
    let wire_response::Payload::Compact(compact) = compact.payload.unwrap() else {
        panic!("expected compact response");
    };
    assert_eq!(compact.collection, "wire_ops");
    assert_eq!(compact.points, 2);

    let prune = common::send_wire(
        &endpoint,
        42,
        wire_request::Operation::PruneWalArchive(PruneWalArchiveRequest {
            collection: "wire_ops".to_string(),
            retain_last: 1,
        }),
    )
    .await;
    let wire_response::Payload::WalArchivePrune(prune) = prune.payload.unwrap() else {
        panic!("expected wal archive prune response");
    };
    assert_eq!(prune.collection, "wire_ops");
    assert_eq!(prune.retained_archives, 1);
    assert_eq!(prune.pruned_archives, 0);

    common::send_wire(
        &endpoint,
        38,
        wire_request::Operation::Snapshot(SnapshotRequest {
            path: snapshot.display().to_string(),
        }),
    )
    .await;
    common::send_wire(
        &endpoint,
        39,
        wire_request::Operation::Delete(DeleteRequest {
            collection: "wire_ops".to_string(),
            ids: vec!["anchor".to_string()],
        }),
    )
    .await;
    common::send_wire(
        &endpoint,
        40,
        wire_request::Operation::Restore(RestoreRequest {
            path: snapshot.display().to_string(),
            target_wal_lsns: HashMap::new(),
            target_wal_unix_ms: HashMap::new(),
            wal_restore_archive_dir: String::new(),
            wal_restore_object_store_dir: String::new(),
            wal_restore_object_store_url: String::new(),
        }),
    )
    .await;
    let restored = common::send_wire(
        &endpoint,
        41,
        wire_request::Operation::Search(SearchRequest {
            collection: "wire_ops".to_string(),
            query: Some(SearchQuery {
                vector: vec![1.0, 0.0],
                k: 1,
                filter_json: json!({"tenant": "acme"}).to_string(),
                budget_ms: None,
                vector_name: String::new(),
                ef_search: None,
                recall_target: None,
                graph_json: None,
            }),
        }),
    )
    .await;
    assert_eq!(common::wire_search_hit_id(restored), "anchor");

    let shard_move = common::send_wire(
        &endpoint,
        42,
        wire_request::Operation::ShardMove(ShardMoveRequest {}),
    )
    .await;
    assert!(matches!(
        shard_move.payload,
        Some(wire_response::Payload::Status(_))
    ));

    server.abort();
}

#[tokio::test]
async fn gausswire_auth_requires_api_key_in_envelope() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthConfig::from_optional_key(Some("secret".to_string()));
    let server = tokio::spawn(async move {
        wire::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });
    let endpoint = addr.to_string();

    let rejected = common::send_wire_with_key(
        &endpoint,
        10,
        "",
        wire_request::Operation::Health(HealthRequest {}),
    )
    .await;
    assert_eq!(rejected.request_id, 10);
    assert_eq!(rejected.error_code, "UNAUTHENTICATED");
    assert!(rejected.payload.is_none());

    let accepted = common::send_wire_with_key(
        &endpoint,
        11,
        "secret",
        wire_request::Operation::Health(HealthRequest {}),
    )
    .await;
    assert_eq!(accepted.request_id, 11);
    assert_eq!(accepted.error_code, "");
    assert!(matches!(
        accepted.payload,
        Some(wire_response::Payload::Health(_))
    ));

    server.abort();
}

#[tokio::test]
async fn gausswire_rate_limit_rejects_excess_requests() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthConfig::disabled().with_rate_limit(Some(1));
    let server = tokio::spawn(async move {
        wire::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });
    let endpoint = addr.to_string();

    let first = common::send_wire_with_key(
        &endpoint,
        20,
        "",
        wire_request::Operation::Health(HealthRequest {}),
    )
    .await;
    assert_eq!(first.error_code, "");

    let limited = common::send_wire_with_key(
        &endpoint,
        21,
        "",
        wire_request::Operation::Health(HealthRequest {}),
    )
    .await;
    assert_eq!(limited.request_id, 21);
    assert_eq!(limited.error_code, "RESOURCE_EXHAUSTED");
    assert!(limited.payload.is_none());

    server.abort();
}

#[tokio::test]
async fn grpc_payload_schema_validates_upserts() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let server = tokio::spawn(async move {
        grpc::serve(db, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    client
        .create_collection(CreateCollectionRequest {
            config: Some(GrpcCollectionConfig {
                name: "typed".to_string(),
                vector_dim: 2,
                metric: "cosine".to_string(),
                shards: 1,
                replicas: 1,
                quantization: String::new(),
                payload_schema: [
                    ("tenant".to_string(), "string".to_string()),
                    ("price".to_string(), "number".to_string()),
                ]
                .into_iter()
                .collect(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                streamer_max_bytes: 0,
            }),
        })
        .await
        .unwrap();

    client
        .upsert(chirondb::grpc::pb::UpsertRequest {
            collection: "typed".to_string(),
            points: vec![GrpcPoint {
                id: "valid".to_string(),
                vector: vec![1.0, 0.0],
                payload_json: json!({"tenant": "acme", "price": 42}).to_string(),
                sparse_vector: None,
                vectors: Default::default(),
            }],
            no_wait: false,
        })
        .await
        .unwrap();

    let rejected = client
        .upsert(chirondb::grpc::pb::UpsertRequest {
            collection: "typed".to_string(),
            points: vec![GrpcPoint {
                id: "invalid".to_string(),
                vector: vec![1.0, 0.0],
                payload_json: json!({"tenant": "acme", "price": "42"}).to_string(),
                sparse_vector: None,
                vectors: Default::default(),
            }],
            no_wait: false,
        })
        .await
        .unwrap_err();
    assert_eq!(rejected.code(), Code::InvalidArgument);

    server.abort();
}

#[tokio::test]
async fn grpc_collection_crud_validates_payload_schema_and_delete() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let server = tokio::spawn(async move {
        grpc::serve(db, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    client
        .create_collection(CreateCollectionRequest {
            config: Some(GrpcCollectionConfig {
                name: "typed_update".to_string(),
                vector_dim: 2,
                metric: "cosine".to_string(),
                shards: 1,
                replicas: 1,
                quantization: String::new(),
                payload_schema: Default::default(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: None,
                streamer_max_bytes: 0,
            }),
        })
        .await
        .unwrap();
    client
        .upsert(chirondb::grpc::pb::UpsertRequest {
            collection: "typed_update".to_string(),
            points: vec![GrpcPoint {
                id: "valid".to_string(),
                vector: vec![1.0, 0.0],
                payload_json: json!({"tenant": "acme"}).to_string(),
                sparse_vector: None,
                vectors: Default::default(),
            }],
            no_wait: false,
        })
        .await
        .unwrap();

    let updated = client
        .update_payload_schema(UpdatePayloadSchemaRequest {
            collection: "typed_update".to_string(),
            payload_schema: [("tenant".to_string(), "string".to_string())]
                .into_iter()
                .collect(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.payload_schema["tenant"], "string");

    let rejected = client
        .update_payload_schema(UpdatePayloadSchemaRequest {
            collection: "typed_update".to_string(),
            payload_schema: [("tenant".to_string(), "number".to_string())]
                .into_iter()
                .collect(),
        })
        .await
        .unwrap_err();
    assert_eq!(rejected.code(), Code::InvalidArgument);

    let collections = client
        .list_collections(chirondb::grpc::pb::ListCollectionsRequest {})
        .await
        .unwrap()
        .into_inner()
        .collections;
    assert_eq!(collections[0].payload_schema["tenant"], "string");

    let deleted = client
        .delete_collection(DeleteCollectionRequest {
            collection: "typed_update".to_string(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(deleted.deleted, "typed_update");
    assert!(
        client
            .list_collections(chirondb::grpc::pb::ListCollectionsRequest {})
            .await
            .unwrap()
            .into_inner()
            .collections
            .is_empty()
    );

    server.abort();
}

#[tokio::test]
async fn http_auth_protects_data_and_metrics_routes() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthConfig::from_optional_key(Some("secret".to_string()));
    let server = tokio::spawn(async move {
        api::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert!(health.status().is_success());

    let metrics = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(metrics.status(), reqwest::StatusCode::UNAUTHORIZED);

    let rejected = client
        .post(format!("{base}/collections"))
        .json(&CollectionConfig {
            name: "secure".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
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
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::UNAUTHORIZED);

    client
        .post(format!("{base}/collections"))
        .bearer_auth("secret")
        .json(&CollectionConfig {
            name: "secure".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
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
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let collections: Value = client
        .get(format!("{base}/collections"))
        .header("x-gaussdb-api-key", "secret")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(collections.as_array().unwrap().len(), 1);

    server.abort();
}

#[tokio::test]
async fn http_auth_reloads_api_key_file_for_rotation() {
    let data = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();
    let key_file = keys.path().join("keys.txt");
    std::fs::write(&key_file, "old\n").unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthConfig::from_key_sources(None, Some(key_file.clone()));
    let server = tokio::spawn(async move {
        api::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    client
        .get(format!("{base}/collections"))
        .bearer_auth("old")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    std::fs::write(&key_file, "new,longer\n").unwrap();

    let old = client
        .get(format!("{base}/collections"))
        .bearer_auth("old")
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), reqwest::StatusCode::UNAUTHORIZED);

    client
        .get(format!("{base}/collections"))
        .bearer_auth("new")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    server.abort();
}

#[tokio::test]
async fn http_rate_limit_rejects_excess_protected_requests() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = AuthConfig::disabled().with_rate_limit(Some(1));
    let server = tokio::spawn(async move {
        api::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let first = client
        .get(format!("{base}/collections"))
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success());

    let limited = client
        .get(format!("{base}/collections"))
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert!(health.status().is_success());

    server.abort();
}

#[tokio::test]
async fn grpc_auth_requires_api_key_metadata() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let auth = AuthConfig::from_optional_key(Some("secret".to_string()));
    let server = tokio::spawn(async move {
        grpc::serve_with_auth(db, auth, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    let rejected = client.health(HealthRequest {}).await.unwrap_err();
    assert_eq!(rejected.code(), Code::Unauthenticated);

    let health = client
        .health(common::grpc_auth_request(HealthRequest {}, "secret"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, "ok");

    server.abort();
}

#[tokio::test]
async fn grpc_reflection_lists_gaussdb_service() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let server = tokio::spawn(async move {
        grpc::serve_with_auth(db, AuthConfig::disabled(), addr)
            .await
            .unwrap();
    });

    let channel = common::connect_grpc_channel(addr).await;
    let services = common::list_reflection_services(channel, None).await;
    assert!(services.iter().any(|name| name == "chirondb.v1.ChironDb"));
    assert!(services.iter().any(|name| name == "gaussdb.v1.GaussDb"));
    assert!(
        services
            .iter()
            .any(|name| name == "grpc.reflection.v1.ServerReflection")
    );

    server.abort();
}

#[tokio::test]
async fn grpc_web_health_cors_and_native_grpc_share_the_port() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let allowed_origin = "http://127.0.0.1:3100";
    let options = grpc::GrpcServerOptions {
        grpc_web_enabled: true,
        cors_origins: vec![allowed_origin.to_string()],
        storage_policy: Default::default(),
    };
    let server = tokio::spawn(async move {
        grpc::serve_with_options(db, AuthConfig::disabled(), addr, options)
            .await
            .unwrap();
    });

    let mut native = common::connect_grpc(addr).await;
    let health = native.health(HealthRequest {}).await.unwrap().into_inner();
    assert_eq!(health.status, "ok");

    let channel = common::connect_grpc_channel(addr).await;
    let services = common::list_reflection_services(channel, None).await;
    assert!(services.iter().any(|name| name == "gaussdb.v1.GaussDb"));

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/gaussdb.v1.GaussDb/Health");
    let valid_preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", allowed_origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type,x-grpc-web")
        .send()
        .await
        .unwrap();
    assert!(valid_preflight.status().is_success());
    assert_eq!(
        valid_preflight
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        allowed_origin
    );

    let invalid_preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", "http://malicious.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type,x-grpc-web")
        .send()
        .await
        .unwrap();
    assert!(
        invalid_preflight
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );

    // One uncompressed, zero-length protobuf request frame for HealthRequest.
    let response = client
        .post(url)
        .header("origin", allowed_origin)
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(vec![0_u8, 0, 0, 0, 0])
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        allowed_origin
    );
    let body = response.bytes().await.unwrap();
    assert_eq!(body[0], 0);
    let message_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    let health = HealthResponse::decode(&body[5..5 + message_len]).unwrap();
    assert_eq!(health.status, "ok");

    server.abort();
}

#[tokio::test]
async fn grpc_reflection_respects_api_key_auth() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let auth = AuthConfig::from_optional_key(Some("secret".to_string()));
    let server = tokio::spawn(async move {
        grpc::serve_with_auth(db, auth, addr).await.unwrap();
    });

    let endpoint = format!("http://{addr}");
    let channel = common::connect_grpc_channel(addr).await;
    let rejected = common::reflection_request(channel, None).await.unwrap_err();
    assert_eq!(rejected.code(), Code::Unauthenticated);

    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let services = common::list_reflection_services(channel, Some("secret")).await;
    assert!(services.iter().any(|name| name == "gaussdb.v1.GaussDb"));

    server.abort();
}

#[tokio::test]
async fn grpc_auth_reloads_api_key_file_for_rotation() {
    let data = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();
    let key_file = keys.path().join("keys.txt");
    std::fs::write(&key_file, "old\n").unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let auth = AuthConfig::from_key_sources(None, Some(key_file.clone()));
    let server = tokio::spawn(async move {
        grpc::serve_with_auth(db, auth, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    client
        .health(common::grpc_auth_request(HealthRequest {}, "old"))
        .await
        .unwrap();

    std::fs::write(&key_file, "new,longer\n").unwrap();

    let old = client
        .health(common::grpc_auth_request(HealthRequest {}, "old"))
        .await
        .unwrap_err();
    assert_eq!(old.code(), Code::Unauthenticated);

    client
        .health(common::grpc_auth_request(HealthRequest {}, "new"))
        .await
        .unwrap();

    server.abort();
}

#[tokio::test]
async fn grpc_rate_limit_rejects_excess_rpcs() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let auth = AuthConfig::disabled().with_rate_limit(Some(1));
    let server = tokio::spawn(async move {
        grpc::serve_with_auth(db, auth, addr).await.unwrap();
    });

    let mut client = common::connect_grpc(addr).await;
    client.health(HealthRequest {}).await.unwrap();
    let limited = client.health(HealthRequest {}).await.unwrap_err();
    assert_eq!(limited.code(), Code::ResourceExhausted);

    server.abort();
}

#[tokio::test]
async fn v1_versioned_routes_work() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // v1 health
    let health: Value = client
        .get(format!("{base}/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    // v1 create collection
    client
        .post(format!("{base}/v1/collections"))
        .json(&CollectionConfig {
            name: "v1col".to_string(),
            vector_dim: 2,
            metric: chirondb::DistanceMetric::Cosine,
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
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // v1 upsert
    client
        .put(format!("{base}/v1/collections/v1col/points"))
        .json(&json!({ "points": [
            Point { id: "a".to_string(), vector: vec![1.0, 0.0], vectors: Default::default(), sparse_vector: None, payload: json!({"x": 1}) }
        ]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // v1 search
    let result: Value = client
        .post(format!("{base}/v1/collections/v1col/search"))
        .json(&chirondb::SearchRequest {
            graph: None,
            vector: vec![1.0, 0.0],
            vector_name: None,
            k: 1,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["hits"][0]["id"], "a");

    server.abort();
}

#[tokio::test]
async fn crud_get_set_delete_by_filter() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    client
        .post(format!("{base}/collections"))
        .json(&CollectionConfig {
            name: "c".to_string(),
            vector_dim: 2,
            metric: chirondb::DistanceMetric::L2,
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
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    client
        .put(format!("{base}/collections/c/points"))
        .json(&json!({ "points": [
            Point { id: "a".to_string(), vector: vec![1.0, 0.0], vectors: Default::default(), sparse_vector: None, payload: json!({"cat": "x"}) },
            Point { id: "b".to_string(), vector: vec![0.0, 1.0], vectors: Default::default(), sparse_vector: None, payload: json!({"cat": "y"}) },
        ]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // get_points
    let result: Value = client
        .post(format!("{base}/collections/c/points/get"))
        .json(&json!({ "ids": ["a", "missing"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["points"].as_array().unwrap().len(), 1);
    assert_eq!(result["points"][0]["id"], "a");

    // set_payload merge
    let result: Value = client
        .post(format!("{base}/collections/c/points/payload"))
        .json(&json!({ "id": "a", "payload": {"extra": 42}, "merge": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["point"]["payload"]["cat"], "x");
    assert_eq!(result["point"]["payload"]["extra"], 42);

    // delete_by_filter
    let result: Value = client
        .post(format!("{base}/collections/c/points/delete/filter"))
        .json(&json!({ "filter": {"cat": "y"} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["deleted"], 1);

    let count: Value = client
        .post(format!("{base}/collections/c/count"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(count["count"], 1);

    server.abort();
}
