//! P5 gate — the typed SDK methods.
//!
//! `hybrid_search`, `multi_search`, `recommend` and `rerank` are endpoints the
//! HTTP API has always had and the SDKs never exposed. These tests drive the
//! Rust client against a live server so the request shapes are checked against
//! the real handlers rather than against the documentation.

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, api};
use chirondb_client::{
    ChironDbClient, Fusion, GraphConstraint, GraphDeferredSessionState, GraphDirection,
    GraphRelationScope, GraphTraversalQueryRequest, GraphTraversalReturn, GraphTraversalRows,
    GraphTraverseRequest, HybridQuery, MultiSearchQuery, RecommendQuery, RelateRequest,
    RerankQuery, ScoreBoost, SearchQuery, SparseVector, StructuralPoint as ClientStructuralPoint,
    TraversalBudget, UnsafeStructuralEmbeddingOverride,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;

const COLLECTION: &str = "products";

struct Harness {
    _data: TempDir,
    base_url: String,
    client: ChironDbClient,
    handle: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = Db::open(data.path()).expect("open db");
        db.create_collection(CollectionConfig {
            name: COLLECTION.to_string(),
            vector_dim: 3,
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
        .expect("create collection");
        db.upsert(
            COLLECTION,
            vec![
                Point {
                    id: "phone".to_string(),
                    vector: vec![1.0, 0.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: Some(chirondb::model::SparseVector {
                        indices: vec![1, 5],
                        values: vec![0.9, 0.4],
                    }),
                    payload: json!({"category": "electronics", "featured": true}),
                },
                Point {
                    id: "laptop".to_string(),
                    vector: vec![0.9, 0.1, 0.0],
                    vectors: Default::default(),
                    sparse_vector: Some(chirondb::model::SparseVector {
                        indices: vec![5],
                        values: vec![0.7],
                    }),
                    payload: json!({"category": "electronics", "featured": false}),
                },
                Point {
                    id: "book".to_string(),
                    vector: vec![0.0, 1.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"category": "media", "featured": false}),
                },
            ],
        )
        .expect("upsert");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            api::serve_listener(db, listener).await.expect("serve");
        });

        Self {
            _data: data,
            base_url: format!("http://{addr}"),
            client: ChironDbClient::new(format!("http://{addr}")),
            handle,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[test]
fn structural_sdk_rejects_zero_without_network_io() {
    let error = ClientStructuralPoint::new(chirondb_client::Point {
        id: "line-3".to_string(),
        vector: vec![0.0, -0.0, 0.0],
        ..Default::default()
    })
    .unwrap_err();
    assert!(error.to_string().contains("all-zero vectors are rejected"));
}

#[tokio::test]
async fn list_collections_decodes_the_http_array_contract() {
    let harness = Harness::start().await;
    let collections = harness
        .client
        .list_collections()
        .await
        .expect("list collections");
    assert_eq!(collections.len(), 1);
    assert_eq!(collections[0].name, COLLECTION);
}

fn graph_constraint(anchor: &str, edge_type: &str) -> GraphConstraint {
    GraphConstraint {
        anchors: vec![anchor.to_string()],
        edge_types: vec![edge_type.to_string()],
        direction: GraphDirection::Outgoing,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: 1,
            ..TraversalBudget::default()
        },
        allow_degraded: false,
    }
}

fn relate_request(source: &str, target: &str, edge_type: &str) -> RelateRequest {
    RelateRequest {
        source_point_id: source.to_string(),
        target_point_id: target.to_string(),
        edge_type: edge_type.to_string(),
        properties: json!({"weight": 0.8}),
        scope: GraphRelationScope::Local,
        idempotency_key: None,
    }
}

#[tokio::test]
async fn graph_sdk_covers_lifecycle_crud_traversal_and_constrained_search() {
    let harness = Harness::start().await;
    let enabled = harness
        .client
        .enable_graph(COLLECTION, true)
        .await
        .expect("enable graph");
    assert!(enabled.enabled);
    assert!(enabled.graph_epoch.is_some());

    let configured = harness
        .client
        .configure_edge_type(COLLECTION, "related_to", Some("weight".to_string()), true)
        .await
        .expect("configure edge type");
    assert_eq!(configured.edge_type.name, "related_to");
    let catalog = harness
        .client
        .list_edge_types(COLLECTION)
        .await
        .expect("list edge types");
    assert_eq!(catalog, vec![configured.edge_type.clone()]);

    let related = harness
        .client
        .relate(
            COLLECTION,
            relate_request("phone", "laptop", "related_to"),
            true,
        )
        .await
        .expect("relate");
    let edge_id = related.edge_id.clone();
    assert!(!edge_id.as_str().is_empty());
    harness
        .client
        .merge_edge_properties(COLLECTION, &edge_id, json!({"source": "sdk"}), true)
        .await
        .expect("merge properties");
    harness
        .client
        .replace_edge_properties(COLLECTION, &edge_id, json!({"only": true}), true)
        .await
        .expect("replace properties");

    let traversal = harness
        .client
        .traverse(
            COLLECTION,
            GraphTraversalQueryRequest {
                traversal: GraphTraverseRequest {
                    anchors: vec!["phone".to_string()],
                    edge_types: vec!["related_to".to_string()],
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        ..TraversalBudget::default()
                    },
                },
                returns: GraphTraversalReturn::Edges,
                limit: Some(10),
                with_payload: true,
            },
        )
        .await
        .expect("traverse");
    let GraphTraversalRows::Edges(edges) = traversal.result else {
        panic!("expected edge rows")
    };
    assert_eq!(edges[0].id, edge_id);
    assert_eq!(edges[0].properties, Some(json!({"only": true})));

    let response = harness
        .client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![0.9, 0.1, 0.0],
                k: 3,
                graph: Some(graph_constraint("phone", "related_to")),
                ..Default::default()
            },
        )
        .await
        .expect("graph-constrained search");
    assert_eq!(response.hits[0].id, "laptop");
    assert!(
        response.graph.is_some(),
        "graph planner trace must survive SDK decoding"
    );

    let deleted = harness
        .client
        .unrelate(COLLECTION, &edge_id, false)
        .await
        .expect("unrelate");
    assert_eq!(deleted.deleted, 1);
    assert!(!deleted.receipt.durable);
    let dropped = harness
        .client
        .drop_graph(COLLECTION, true)
        .await
        .expect("drop graph");
    assert!(!dropped.enabled);
}

#[tokio::test]
async fn graph_sdk_deferred_session_binds_absent_endpoints() {
    let harness = Harness::start().await;
    harness
        .client
        .enable_graph(COLLECTION, true)
        .await
        .expect("enable graph");
    harness
        .client
        .configure_edge_type(COLLECTION, "references", None, true)
        .await
        .expect("configure edge type");

    let opened = harness
        .client
        .open_deferred_graph_session(COLLECTION, true)
        .await
        .expect("open deferred session");
    assert_eq!(opened.state, GraphDeferredSessionState::Open);
    let related = harness
        .client
        .deferred_relate(
            COLLECTION,
            &opened.session_id,
            relate_request("late-a", "late-b", "references"),
            true,
        )
        .await
        .expect("deferred relate");
    let upserted = harness
        .client
        .deferred_upsert(
            COLLECTION,
            &opened.session_id,
            vec![
                chirondb_client::Point {
                    id: "late-a".to_string(),
                    vector: vec![0.2, 0.8, 0.0],
                    ..Default::default()
                },
                chirondb_client::Point {
                    id: "late-b".to_string(),
                    vector: vec![0.1, 0.9, 0.0],
                    ..Default::default()
                },
            ],
            false,
        )
        .await
        .expect("deferred upsert");
    assert_eq!(upserted.bound_endpoints, 2);
    let committed = harness
        .client
        .commit_deferred_graph_session(COLLECTION, &opened.session_id, true)
        .await
        .expect("commit deferred session");
    assert_eq!(committed.state, GraphDeferredSessionState::Committed);
    assert_eq!(committed.session_id, opened.session_id);

    let traversal = harness
        .client
        .traverse(
            COLLECTION,
            GraphTraversalQueryRequest {
                traversal: GraphTraverseRequest {
                    anchors: vec!["late-a".to_string()],
                    edge_types: vec!["references".to_string()],
                    direction: GraphDirection::Outgoing,
                    node_filter: None,
                    edge_filter: None,
                    budget: TraversalBudget {
                        max_depth: 1,
                        ..TraversalBudget::default()
                    },
                },
                returns: GraphTraversalReturn::Edges,
                limit: Some(10),
                with_payload: false,
            },
        )
        .await
        .expect("traverse committed deferred edge");
    let GraphTraversalRows::Edges(edges) = traversal.result else {
        panic!("expected edge rows")
    };
    assert_eq!(edges[0].id, related.edge_id);
}

#[tokio::test]
async fn unsafe_structural_override_is_server_audited_without_raw_ids() {
    let harness = Harness::start().await;
    let reason = "legacy import cannot be re-embedded";
    let point = ClientStructuralPoint::with_unsafe_zero_vector_override(
        chirondb_client::Point {
            id: "line-3".to_string(),
            vector: vec![0.0, 0.0, 0.0],
            ..Default::default()
        },
        UnsafeStructuralEmbeddingOverride::new(reason).unwrap(),
    )
    .unwrap();

    let response = harness
        .client
        .upsert_structural(COLLECTION, vec![point], true)
        .await
        .expect("unsafe structural upsert");
    assert!(response.operation_lsn > 0);
    assert!(response.unsafe_override_audited);

    let audit_log =
        std::fs::read_to_string(harness._data.path().join(chirondb::audit::AUDIT_LOG_FILE))
            .unwrap();
    assert!(!audit_log.contains("line-3"));
    let record = audit_log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|record| {
            record["operation"] == "upsert"
                && record["outcome"] == "success"
                && record["details"]["unsafe_structural_embedding"].is_object()
        })
        .expect("unsafe structural audit record");
    assert_eq!(record["collection"], COLLECTION);
    assert!(
        record["principal_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(record["details"]["operation_lsn"], response.operation_lsn);
    assert_eq!(
        record["details"]["unsafe_structural_embedding"]["reason"],
        reason
    );
    assert_eq!(
        record["details"]["unsafe_structural_embedding"]["point_count"],
        1
    );
    let digest = record["details"]["unsafe_structural_embedding"]["point_id_sha256"][0]
        .as_str()
        .unwrap();
    assert_eq!(digest.len(), 64);
    chirondb::audit::verify_hash_chain(harness._data.path()).unwrap();
}

#[tokio::test]
async fn server_rejects_forged_structural_zero_without_override() {
    let harness = Harness::start().await;
    let response = reqwest::Client::new()
        .put(format!(
            "{}/collections/{COLLECTION}/points",
            harness.base_url
        ))
        .header("x-chiron-structural-points", "1")
        .json(&json!({
            "points": [{"id": "forged-zero", "vector": [0.0, 0.0, 0.0]}],
            "wait": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.text().await.unwrap().contains("all-zero vector"));
}

#[tokio::test]
async fn search_accepts_the_tuning_fields_the_http_api_documents() {
    let harness = Harness::start().await;

    // ef_search, recall_target and with_payload were in the HTTP API but not
    // reachable from the client.
    let response = harness
        .client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![1.0, 0.0, 0.0],
                k: 2,
                ef_search: Some(32),
                with_payload: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("search");

    assert_eq!(response.hits.len(), 2);
    assert!(
        response.hits[0].payload.is_null(),
        "with_payload=false means no payload came back"
    );
}

#[tokio::test]
async fn recall_target_is_accepted_as_a_request() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![1.0, 0.0, 0.0],
                k: 2,
                recall_target: Some(0.99),
                ..Default::default()
            },
        )
        .await
        .expect("search");

    // The response reports what the engine measured; there is no recall field
    // to read back, and the client does not invent one.
    assert_eq!(response.hits.len(), 2);
}

#[tokio::test]
async fn hybrid_search_fuses_dense_and_sparse() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .hybrid_search(
            COLLECTION,
            HybridQuery {
                vector: Some(vec![1.0, 0.0, 0.0]),
                sparse_vector: Some(SparseVector {
                    indices: vec![5],
                    values: vec![1.0],
                }),
                k: 3,
                fusion: Fusion::Rrf,
                ..Default::default()
            },
        )
        .await
        .expect("hybrid search");

    assert!(!response.hits.is_empty());
}

#[tokio::test]
async fn hybrid_search_supports_weighted_fusion() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .hybrid_search(
            COLLECTION,
            HybridQuery {
                vector: Some(vec![1.0, 0.0, 0.0]),
                sparse_vector: Some(SparseVector {
                    indices: vec![1, 5],
                    values: vec![0.8, 0.2],
                }),
                k: 3,
                fusion: Fusion::Weighted,
                dense_weight: 0.7,
                sparse_weight: 0.3,
                ..Default::default()
            },
        )
        .await
        .expect("weighted hybrid search");

    assert!(!response.hits.is_empty());
}

#[tokio::test]
async fn multi_search_returns_one_result_set_per_search() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .multi_search(
            COLLECTION,
            MultiSearchQuery {
                searches: vec![
                    SearchQuery {
                        vector: vec![1.0, 0.0, 0.0],
                        k: 2,
                        ..Default::default()
                    },
                    SearchQuery {
                        vector: vec![0.0, 1.0, 0.0],
                        k: 2,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        )
        .await
        .expect("multi search");

    assert_eq!(response.results.len(), 2);
    assert_eq!(response.results[0].hits[0].id, "phone");
    assert_eq!(response.results[1].hits[0].id, "book");
}

#[tokio::test]
async fn multi_search_fuses_when_asked() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .multi_search(
            COLLECTION,
            MultiSearchQuery {
                searches: vec![
                    SearchQuery {
                        vector: vec![1.0, 0.0, 0.0],
                        k: 3,
                        ..Default::default()
                    },
                    SearchQuery {
                        vector: vec![0.9, 0.1, 0.0],
                        k: 3,
                        ..Default::default()
                    },
                ],
                fusion: Some(Fusion::Rrf),
                fused_k: Some(3),
                ..Default::default()
            },
        )
        .await
        .expect("fused multi search");

    assert!(!response.results.is_empty());
}

#[tokio::test]
async fn recommend_moves_towards_and_away_from_stored_points() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .recommend(
            COLLECTION,
            RecommendQuery {
                positive: vec!["phone".to_string()],
                negative: vec!["book".to_string()],
                k: 2,
                ..Default::default()
            },
        )
        .await
        .expect("recommend");

    assert!(!response.hits.is_empty());
    assert!(
        !response.hits.iter().any(|hit| hit.id == "book"),
        "the negative example should not come back first"
    );
}

#[tokio::test]
async fn recommend_honours_a_filter() {
    let harness = Harness::start().await;

    let response = harness
        .client
        .recommend(
            COLLECTION,
            RecommendQuery {
                positive: vec!["phone".to_string()],
                k: 5,
                filter: Some(json!({"category": {"eq": "electronics"}})),
                ..Default::default()
            },
        )
        .await
        .expect("recommend");

    assert!(
        response.hits.iter().all(|hit| hit.id != "book"),
        "the filter excluded the media point"
    );
}

#[tokio::test]
async fn rerank_applies_payload_score_boosts() {
    let harness = Harness::start().await;

    let plain = harness
        .client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![0.95, 0.05, 0.0],
                k: 2,
                ..Default::default()
            },
        )
        .await
        .expect("search");

    let boosted = harness
        .client
        .rerank(
            COLLECTION,
            RerankQuery {
                vector: vec![0.95, 0.05, 0.0],
                k: 2,
                prefetch_k: Some(3),
                score_boosts: vec![ScoreBoost {
                    field: "featured".to_string(),
                    value: json!(true),
                    boost: 10.0,
                }],
                ..Default::default()
            },
        )
        .await
        .expect("rerank");

    assert!(!plain.hits.is_empty());
    assert_eq!(
        boosted.hits[0].id, "phone",
        "the featured point should be boosted to the top"
    );

    // Worth knowing: the boost is multiplicative and the results are sorted
    // descending, so it only lifts a match when scores are positive. This
    // collection is cosine. Under L2 the score is a negated distance, and a
    // boost above 1.0 pushes a match *down* — see the note on RerankQuery.
}
