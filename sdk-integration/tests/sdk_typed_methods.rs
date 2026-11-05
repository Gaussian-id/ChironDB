//! P5 gate — the typed SDK methods.
//!
//! `hybrid_search`, `multi_search`, `recommend` and `rerank` are endpoints the
//! HTTP API has always had and the SDKs never exposed. These tests drive the
//! Rust client against a live server so the request shapes are checked against
//! the real handlers rather than against the documentation.

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, api};
use chirondb_client::{
    ChironDbClient, ChironQlRequest, ExecutionDomain, Fusion, GraphConstraint,
    GraphDeferredSessionState, GraphDirection, GraphRelationScope, GraphTraversalQueryRequest,
    GraphTraversalReturn, GraphTraversalRows, GraphTraverseRequest, HybridQuery, MultiSearchQuery,
    RecommendQuery, RelateRequest, RelationalValue, RerankQuery, ScoreBoost, SearchQuery,
    SparseVector, SqlExecutionRequest, SqlResult, SqlStatementRequest,
    StructuralPoint as ClientStructuralPoint, TraversalBudget, UnsafeStructuralEmbeddingOverride,
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

#[tokio::test]
async fn model_views_preserve_typed_sql_transactions_and_values() {
    use chirondb_client::{
        RecordRef, RelationalValue as V, SqlExecutionRequest, SqlOutcome, SqlResult,
        SqlStatementRequest, TransactionState,
    };
    let h = Harness::start().await;
    let sql = h.client.relational();
    sql.sql("CREATE TABLE sdk_values (id BIGINT PRIMARY KEY, b BOOLEAN, f DOUBLE PRECISION, d DECIMAL(20,4), t TEXT, raw BYTEA, dt DATE, ts TIMESTAMP WITH TIME ZONE, u UUID, j JSONB, v VECTOR(3), r RECORD_REF('products'), n TEXT)", vec![]).await.unwrap();
    let values = vec![
        V::Integer(i64::MAX),
        V::Boolean(true),
        V::Float(1.25),
        V::Decimal("100.2500".into()),
        V::Text("'雪\\; DROP TABLE sdk_values".into()),
        V::Bytes(vec![0, 127, 255]),
        V::Date("2026-10-12".into()),
        V::TimestampUtc("2026-10-12T00:00:00Z".into()),
        V::Uuid("123e4567-e89b-12d3-a456-426614174000".parse().unwrap()),
        V::Json(json!({"nested":[null,true,"'\\雪"]})),
        V::Vector(vec![1., 0., 0.]),
        V::RecordRef(RecordRef {
            namespace: COLLECTION.into(),
            id: "phone".into(),
        }),
        V::Null,
    ];
    let request = SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: format!(
                "INSERT INTO sdk_values VALUES ({}) RETURNING *",
                (1..=13)
                    .map(|i| format!("${i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            parameters: values.clone(),
        }],
        idempotency_key: Some("typed-sdk-values".into()),
        retry_id: None,
    };
    let first = sql.execute(&request).await.unwrap();
    assert_eq!(first, sql.execute(&request).await.unwrap());
    assert_eq!(first.outcome, SqlOutcome::Committed);
    let SqlResult::Rows { rows, .. } = &first.results[0] else {
        panic!("expected typed rows")
    };
    for i in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12] {
        assert_eq!(rows[0][i], values[i]);
    }
    let tx = sql.begin().await.unwrap();
    tx.sql("SAVEPOINT saved", vec![]).await.unwrap();
    tx.sql(
        "UPDATE sdk_values SET t=$1",
        vec![V::Text("private".into())],
    )
    .await
    .unwrap();
    let outside = sql.sql("SELECT t FROM sdk_values", vec![]).await.unwrap();
    assert!(matches!(&outside.results[0], SqlResult::Rows {rows,..} if rows[0][0] == values[4]));
    tx.sql("ROLLBACK TO SAVEPOINT saved", vec![]).await.unwrap();
    tx.sql(
        "UPDATE sdk_values SET t=$1",
        vec![V::Text("committed".into())],
    )
    .await
    .unwrap();
    let receipt = tx.commit().await.unwrap();
    assert_eq!(receipt.transaction_id, tx.transaction_id);
    assert_eq!(
        receipt.transaction_id,
        tx.commit().await.unwrap().transaction_id
    );
    let status = sql
        .transaction_status(tx.transaction_id.as_deref().unwrap())
        .await
        .unwrap();
    assert_eq!(status.state, TransactionState::Committed);
    assert!(status.storage_projected && status.audit_projected);
    let discarded = sql.begin().await.unwrap();
    discarded
        .sql("DELETE FROM sdk_values", vec![])
        .await
        .unwrap();
    discarded.rollback().await.unwrap();
    assert_eq!(h.client.vector().count(COLLECTION, None).await.unwrap(), 3);
    for bad in [V::Float(f64::NAN), V::Vector(vec![f32::INFINITY])] {
        assert!(matches!(
            sql.sql("SELECT $1", vec![bad]).await,
            Err(chirondb_client::Error::InvalidInput(_))
        ));
    }
}

#[tokio::test]
async fn sdk_query_commits_three_models_and_guards_sibling_writes() {
    use chirondb_client::{ChironQlRequest, RelationalValue as V, SqlResult};
    let h = Harness::start().await;
    h.client
        .graph()
        .enable_graph(COLLECTION, true)
        .await
        .unwrap();
    h.client
        .graph()
        .configure_edge_type(COLLECTION, "cites", None, true)
        .await
        .unwrap();
    h.client.relational().sql("CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT, chunk RECORD_REF('products'), source RECORD_REF('products'))", vec![]).await.unwrap();
    let create = ChironQlRequest { query: "TRANSACTION { SQL INSERT INTO documents VALUES ($1,$2,RECORD_REF('products','phone'),RECORD_REF('products','laptop')); EXPECT SQL ROWS 1; VECTOR UPSERT INTO products {id:'phone',vector:[1,0,0]}; GRAPH CONNECT products 'phone' -> cites -> 'laptop'; };".into(),
        parameters: vec![V::Text("doc".into()),V::Text("雪'\\".into())], idempotency_key: Some("sdk-atomic-create".into()), ..Default::default() };
    let first = h.client.query(&create).await.unwrap();
    let replay = h.client.query(&create).await.unwrap();
    assert_eq!(first.rows, replay.rows);
    assert_eq!(first.transaction_id, replay.transaction_id);
    assert_eq!(replay.stats.replayed, Some(true));
    let pipeline = ChironQlRequest { query: "PIPELINE\n VECTOR v { SEARCH products NEAR $1 LIMIT 1 }\n GRAPH g { TRAVERSE products FROM v.record_ref VIA cites DEPTH 1 RETURN NODES LIMIT 20 }\n RELATIONAL r { SQL SELECT id, title, chunk, source FROM documents LIMIT 20 }\n INNER JOIN r ON r.chunk = v.record_ref\n LEFT JOIN g ON g.record_ref = r.source\n RETURN r.id, r.title, v.score, g.depth\n LIMIT 10;".into(), parameters: vec![V::Vector(vec![1.,0.,0.])], ..Default::default() };
    let result = h.client.graph().query(&pipeline).await.unwrap();
    assert_eq!(result.rows[0]["id"], "doc");
    let direct: chirondb_client::ChironQlResponse = reqwest::Client::new()
        .post(format!("{}/v1/chironql", h.base_url))
        .json(&pipeline)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result.rows, direct.rows);
    let edge = first.rows[0]["edge_id"].as_str().unwrap();
    let mut update = ChironQlRequest {
        query: format!(
            "TRANSACTION {{ SQL UPDATE documents SET title=$1 WHERE id='doc'; EXPECT SQL ROWS 2; VECTOR UPSERT INTO products {{id:'phone',vector:[0,1,0]}}; GRAPH UPDATE products EDGE '{edge}' SET PROPERTIES {{kind:'updated'}} REPLACE; }};"
        ),
        parameters: vec![V::Text("updated".into())],
        ..Default::default()
    };
    assert_eq!(
        h.client
            .query(&update)
            .await
            .unwrap_err()
            .api_details()
            .unwrap()
            .code
            .as_deref(),
        Some("chironql.sql_row_precondition_failed")
    );
    let unchanged = h
        .client
        .relational()
        .sql("SELECT title FROM documents", vec![])
        .await
        .unwrap();
    assert!(
        matches!(&unchanged.results[0], SqlResult::Rows {rows,..} if rows[0][0] == V::Text("雪'\\".into()))
    );
    update.query = update.query.replace("ROWS 2", "ROWS 1");
    update.idempotency_key = Some("sdk-atomic-update".into());
    assert_eq!(h.client.query(&update).await.unwrap().committed, Some(true));
    let delete = ChironQlRequest {
        query: format!(
            "TRANSACTION {{ SQL DELETE FROM documents WHERE id='doc'; EXPECT SQL ROWS 1; VECTOR DELETE FROM products POINTS 'phone'; GRAPH UNRELATE products EDGE '{edge}'; }};"
        ),
        idempotency_key: Some("sdk-atomic-delete".into()),
        ..Default::default()
    };
    assert_eq!(h.client.query(&delete).await.unwrap().committed, Some(true));
    assert_eq!(h.client.vector().count(COLLECTION, None).await.unwrap(), 2);
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

#[tokio::test]
async fn relational_sql_uses_typed_sdk_contract() {
    let harness = Harness::start().await;
    harness
        .client
        .execute_sql(&SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "CREATE TABLE sdk_rows (id INTEGER PRIMARY KEY, label TEXT NOT NULL)".into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("create relational table");
    harness
        .client
        .execute_sql(&SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "INSERT INTO sdk_rows VALUES ($1, $2)".into(),
                parameters: vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("typed".into()),
                ],
            }],
            idempotency_key: None,
            retry_id: Some("rust-sdk-relational-1".into()),
        })
        .await
        .expect("insert relational row");
    let selected = harness
        .client
        .execute_sql(&SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "SELECT label FROM sdk_rows".into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("select relational row");
    assert!(matches!(
        &selected.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("typed".into())]]
    ));

    let transaction = harness
        .client
        .begin_sql_transaction()
        .await
        .expect("begin interactive transaction");
    let private = harness
        .client
        .execute_sql_transaction(
            &transaction.handle,
            &SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "INSERT INTO sdk_rows VALUES ($1, $2) RETURNING label".into(),
                    parameters: vec![
                        RelationalValue::Integer(2),
                        RelationalValue::Text("private".into()),
                    ],
                }],
                idempotency_key: None,
                retry_id: None,
            },
        )
        .await
        .expect("execute in interactive transaction");
    assert!(!private.committed);
    let outside = harness
        .client
        .execute_sql(&SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: "SELECT COUNT(*) FROM sdk_rows".into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("read outside transaction");
    assert!(matches!(
        &outside.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(1)]]
    ));
    let committed = harness
        .client
        .commit_sql_transaction(&transaction.handle)
        .await
        .expect("commit interactive transaction");
    assert!(committed.committed);
    assert!(committed.transaction_id.is_some());

    let rollback = harness
        .client
        .begin_sql_transaction()
        .await
        .expect("begin rollback transaction");
    harness
        .client
        .execute_sql_transaction(
            &rollback.handle,
            &SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "DELETE FROM sdk_rows".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            },
        )
        .await
        .expect("execute rollback mutation");
    harness
        .client
        .rollback_sql_transaction(&rollback.handle)
        .await
        .expect("rollback interactive transaction");
}

#[tokio::test]
async fn chironql_sdk_routes_native_sql_with_typed_metadata() {
    let harness = Harness::start().await;
    harness
        .client
        .execute_chironql(&ChironQlRequest {
            query: "SQL CREATE TABLE cql_sdk (id TEXT PRIMARY KEY);".into(),
            ..Default::default()
        })
        .await
        .expect("create through ChironQL");
    let response = harness
        .client
        .execute_chironql(&ChironQlRequest {
            query: "SQL INSERT INTO cql_sdk VALUES ($1);".into(),
            parameters: vec![RelationalValue::Text("sdk-1".into())],
            retry_id: Some("rust-sdk-chironql-1".into()),
            ..Default::default()
        })
        .await
        .expect("insert through ChironQL");
    assert_eq!(response.domains, vec![ExecutionDomain::Relational]);
    assert_eq!(response.committed, Some(true));
    assert!(response.transaction_id.is_some());
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
    assert!(deleted.receipt.durable);
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

#[tokio::test]
async fn http_collection_hnsw_one_is_rejected_and_zero_retains_default_contract() {
    let harness = Harness::start().await;
    let http = reqwest::Client::new();
    let endpoint = format!("{}/v1/collections", harness.base_url);
    let rejected = http
        .post(&endpoint)
        .json(&json!({"name":"invalid_hnsw","vector_dim":2,"metric":"l2","hnsw_m":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(rejected.text().await.unwrap().contains("hnsw_m"));
    assert_eq!(harness.client.list_collections().await.unwrap().len(), 1);
    let response=http.post(&endpoint).json(&json!({"name":"zero_default","vector_dim":2,"metric":"l2","hnsw_m":0,"hnsw_ef_construction":0,"hnsw_ef_search":0})).send().await.unwrap();
    assert!(response.status().is_success());
    let config = response.json::<CollectionConfig>().await.unwrap();
    assert_eq!(config.hnsw_m, None);
    assert_eq!(config.hnsw_ef_construction, None);
    assert_eq!(config.hnsw_ef_search, None);
    assert_eq!(harness.client.list_collections().await.unwrap().len(), 2);
}

#[tokio::test]
async fn sdk_collection_recall_contract_and_default_query_match_http() {
    let harness = Harness::start().await;
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let result = harness
            .client
            .create_collection(chirondb_client::CollectionConfig {
                name: "invalid-recall".into(),
                vector_dim: 3,
                metric: "cosine".into(),
                recall_sla: Some(value),
                ..Default::default()
            })
            .await;
        assert!(matches!(result, Err(chirondb_client::Error::Http(error)) if error.is_builder()));
        let result = harness
            .client
            .search(
                COLLECTION,
                SearchQuery {
                    vector: vec![1., 0., 0.],
                    recall_target: Some(value),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(result, Err(chirondb_client::Error::Http(error)) if error.is_builder()));
    }
    assert!(
        !harness
            .client
            .list_collections()
            .await
            .unwrap()
            .iter()
            .any(|c| c.name == "invalid-recall")
    );
    let name = "named";
    let config = harness
        .client
        .create_collection(chirondb_client::CollectionConfig {
            name: name.into(),
            vector_dim: 3,
            metric: "cosine".into(),
            recall_sla: Some(0.95),
            named_vector_dims: [("title".into(), 2)].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(config.recall_sla, Some(0.95));
    assert_eq!(config.named_vector_dims["title"], 2);
    let listed = harness.client.list_collections().await.unwrap();
    assert_eq!(
        listed.iter().find(|c| c.name == name).unwrap().recall_sla,
        Some(0.95)
    );
    let query = SearchQuery {
        vector: vec![1., 0., 0.],
        recall_target: Some(0.95),
        ..Default::default()
    };
    assert_eq!(query.k, 10);
    let raw: serde_json::Value = reqwest::Client::new()
        .post(format!(
            "{}/collections/{COLLECTION}/search",
            harness.base_url
        ))
        .json(&query)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let typed = harness.client.search(COLLECTION, query).await.unwrap();
    let raw_hits: Vec<chirondb_client::SearchHit> =
        serde_json::from_value(raw["hits"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(typed.hits).unwrap(),
        serde_json::to_value(raw_hits).unwrap()
    );
    assert!(raw.get("achieved_recall").is_none());
    assert!(harness.client.compact(COLLECTION).await.is_ok());
}

#[tokio::test]
async fn sdk_preserves_graph_budget_and_missing_endpoint_errors() {
    let harness = Harness::start().await;
    harness.client.enable_graph(COLLECTION, true).await.unwrap();
    harness
        .client
        .configure_edge_type(COLLECTION, "cites", None, true)
        .await
        .unwrap();
    let error = harness
        .client
        .relate(COLLECTION, relate_request("phone", "absent", "cites"), true)
        .await
        .unwrap_err();
    assert_eq!(
        error.api_details().unwrap().code.as_deref(),
        Some("graph.endpoint_not_found")
    );
    let mut constraint = graph_constraint("phone", "cites");
    constraint.budget.max_memory_bytes = 1;
    let error = harness
        .client
        .search(
            COLLECTION,
            SearchQuery {
                vector: vec![1., 0., 0.],
                graph: Some(constraint),
                recall_target: Some(0.95),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.api_details().unwrap().code.as_deref(),
        Some("graph.slo_unavailable")
    );
}

#[tokio::test]
async fn sdk_encodes_route_segments_and_retains_non_json_failures() {
    use axum::{
        Router,
        http::{StatusCode, Uri},
        routing::get,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/health",
            get(|| async { (StatusCode::BAD_GATEWAY, "gateway unavailable") }),
        )
        .fallback(|uri: Uri| async move { (StatusCode::BAD_REQUEST, uri.to_string()) });
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = ChironDbClient::new(format!("http://{address}"));
    let error = client.list_edge_types("a/b?# 日本語").await.unwrap_err();
    let chirondb_client::Error::Api { status, message } = error else {
        panic!("API error required")
    };
    assert_eq!(status, 400);
    assert_eq!(
        message,
        "/collections/a%2Fb%3F%23%20%E6%97%A5%E6%9C%AC%E8%AA%9E/graph/types"
    );
    let error = client.health().await.unwrap_err();
    assert!(error.api_details().is_none());
    assert!(
        matches!(error, chirondb_client::Error::Api { status:502, ref message } if message == "gateway unavailable")
    );
    assert!(matches!(
        client.delete_collection("..").await,
        Err(chirondb_client::Error::InvalidInput(_))
    ));
    server.abort();
}

#[tokio::test]
async fn sdk_timeout_is_applied_to_injected_transport() {
    use axum::{Router, routing::get};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/health",
        get(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            axum::Json(json!({"status":"ok"}))
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = ChironDbClient::new(format!("http://{address}"))
        .with_http_client(reqwest::Client::new())
        .with_timeout(std::time::Duration::from_millis(20));
    assert!(
        matches!(client.health().await, Err(chirondb_client::Error::Http(error)) if error.is_timeout())
    );
    server.abort();
}
