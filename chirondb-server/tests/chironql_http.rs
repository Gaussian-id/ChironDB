//! ChironQL P2 gate — the HTTP surface.
//!
//! The load-bearing test is `console_and_http_agree`: the same statement run
//! through the embedded console and through `POST /v1/chironql` must produce
//! the same rows, the same stats and the same trace stages. That is what keeps
//! "four doors, one executor" true rather than aspirational.

use chirondb::chironql_repl::{ExecuteOptions, LocalSink, QuerySink};
use chirondb::rbac::Role;
use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, api, graph::ConfigureEdgeTypeRequest,
    tenant::TenantScope,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const COLLECTION: &str = "products";

/// Same request shape the HTTP side sends: trace on, no confirmation.
fn traced() -> ExecuteOptions {
    ExecuteOptions {
        trace: true,
        confirm: false,
    }
}

fn seeded_db(path: &std::path::Path) -> Db {
    let db = Db::open(path).expect("open db");
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
                payload: json!({"category": "electronics", "price": 699}),
            },
            Point {
                id: "laptop".to_string(),
                vector: vec![0.9, 0.1, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "electronics", "price": 1499}),
            },
            Point {
                id: "book".to_string(),
                vector: vec![0.0, 1.0, 0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"category": "media", "price": 25}),
            },
        ],
    )
    .expect("upsert");
    db
}

struct Harness {
    _data: TempDir,
    base: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = seeded_db(data.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            api::serve_listener(db, listener).await.expect("serve");
        });
        Self {
            _data: data,
            base: format!("http://{addr}"),
            client: reqwest::Client::new(),
            server,
        }
    }

    async fn post(&self, path: &str, body: Value) -> (reqwest::StatusCode, Value) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .expect("send");
        let status = response.status();
        let value = response.json::<Value>().await.expect("json body");
        (status, value)
    }

    async fn query(&self, body: Value) -> (reqwest::StatusCode, Value) {
        self.post("/v1/chironql", body).await
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn executes_a_search_and_returns_rows_with_stats() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "SEARCH products NEAR [1,0,0] LIMIT 2 WITH PAYLOAD;"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["kind"], json!("rows"));
    assert_eq!(body["columns"], json!(["id", "score", "payload"]));
    assert_eq!(body["rows"][0]["id"], json!("phone"));
    assert!(body["stats"]["searched"].is_number(), "{body}");
    assert!(
        body["query_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("q_"),
        "{body}"
    );
    // Trace is opt-in on the success path.
    assert!(body["trace"].is_null(), "{body}");
}

#[tokio::test]
async fn sql_wrapper_routes_typed_parameters_and_metadata_over_http() {
    let harness = Harness::start().await;
    let (status, created) = harness
        .query(json!({"query": "SQL CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL);"}))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{created}");
    assert_eq!(created["domains"], json!(["relational"]));

    let (status, inserted) = harness
        .query(json!({
            "query": "SQL INSERT INTO documents VALUES ($1, $2);",
            "parameters": [
                {"type": "text", "value": "doc-1"},
                {"type": "text", "value": "Native SQL"}
            ],
            "retry_id": "http-cql-relational-1"
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{inserted}");
    assert_eq!(inserted["committed"], json!(true));
    assert!(inserted["transaction_id"].is_string(), "{inserted}");

    let (status, selected) = harness
        .query(json!({
            "query": "SQL SELECT id, title FROM documents WHERE id = $1;",
            "parameters": [{"type": "text", "value": "doc-1"}]
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{selected}");
    assert_eq!(
        selected["rows"][0],
        json!({"id": "doc-1", "title": "Native SQL"})
    );
    assert_eq!(selected["domains"], json!(["relational"]));
    assert_eq!(
        selected["column_types"],
        json!([{"kind": "text"}, {"kind": "text"}])
    );
    assert!(selected["snapshot_id"].is_string(), "{selected}");

    let (status, cte) = harness
        .query(json!({
            "query": "SQL WITH selected(doc_id, doc_title) AS (SELECT id, title FROM documents WHERE id = $1) SELECT doc_id, doc_title FROM selected;",
            "parameters": [{"type": "text", "value": "doc-1"}]
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{cte}");
    assert_eq!(
        cte["rows"][0],
        json!({"doc_id": "doc-1", "doc_title": "Native SQL"})
    );
    assert_eq!(cte["domains"], json!(["relational"]));

    let (status, subquery) = harness
        .query(json!({
            "query": "SQL SELECT id, (SELECT title FROM documents WHERE id = $1) AS selected_title FROM documents WHERE EXISTS (SELECT id FROM documents WHERE id = $1);",
            "parameters": [{"type": "text", "value": "doc-1"}]
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{subquery}");
    assert_eq!(
        subquery["rows"][0],
        json!({"id": "doc-1", "selected_title": "Native SQL"})
    );

    let (status, altered_type) = harness
        .query(json!({"query": "SQL ALTER TABLE documents ALTER COLUMN title TYPE VARCHAR(64);"}))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{altered_type}");
    assert_eq!(altered_type["committed"], json!(true), "{altered_type}");

    let (status, typed_row) = harness
        .query(json!({
            "query": "SQL SELECT title FROM documents WHERE id = $1;",
            "parameters": [{"type": "text", "value": "doc-1"}]
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{typed_row}");
    assert_eq!(typed_row["rows"][0], json!({"title": "Native SQL"}));
    assert_eq!(
        typed_row["column_types"],
        json!([{"kind": "varchar", "length": 64}])
    );

    for statement in [
        "SQL ALTER TABLE documents ALTER COLUMN title SET DEFAULT 'Untitled';",
        "SQL ALTER TABLE documents ALTER COLUMN title DROP DEFAULT;",
        "SQL ALTER TABLE documents ALTER COLUMN title DROP NOT NULL;",
        "SQL ALTER TABLE documents ALTER COLUMN title SET NOT NULL;",
    ] {
        let (status, altered_column) = harness.query(json!({"query": statement})).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{altered_column}");
        assert_eq!(
            altered_column["domains"],
            json!(["relational"]),
            "{altered_column}"
        );
    }

    let (status, renamed_constraint) = harness
        .query(json!({
            "query": "SQL ALTER TABLE documents RENAME CONSTRAINT documents_pkey TO documents_identity_pk;"
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{renamed_constraint}");
    assert_eq!(
        renamed_constraint["committed"],
        json!(true),
        "{renamed_constraint}"
    );
    assert_eq!(renamed_constraint["domains"], json!(["relational"]));

    let (status, renamed) = harness
        .query(json!({"query": "SQL ALTER TABLE documents RENAME TO archived_documents;"}))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{renamed}");
    assert_eq!(renamed["committed"], json!(true), "{renamed}");
    assert_eq!(renamed["domains"], json!(["relational"]));

    let (status, renamed_row) = harness
        .query(json!({
            "query": "SQL SELECT id, title FROM archived_documents WHERE id = $1;",
            "parameters": [{"type": "text", "value": "doc-1"}]
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{renamed_row}");
    assert_eq!(
        renamed_row["rows"][0],
        json!({"id": "doc-1", "title": "Native SQL"})
    );
}

#[tokio::test]
async fn sql_wrapper_executes_select_distinct_over_http() {
    let harness = Harness::start().await;
    for query in [
        "SQL CREATE TABLE distinct_http (id INTEGER PRIMARY KEY, category TEXT);",
        "SQL INSERT INTO distinct_http VALUES (1, 'a'), (2, 'a'), (3, 'b'), (4, NULL);",
    ] {
        let (status, body) = harness.query(json!({"query": query})).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    }

    let (status, distinct) = harness
        .query(json!({
            "query": "SQL SELECT DISTINCT category FROM distinct_http ORDER BY category NULLS LAST;"
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{distinct}");
    assert_eq!(
        distinct["rows"],
        json!([
            {"category": "a"},
            {"category": "b"},
            {"category": null}
        ])
    );
    assert_eq!(distinct["domains"], json!(["relational"]));
    assert_eq!(distinct["column_types"], json!([{"kind": "text"}]));

    let (status, aggregate) = harness
        .query(json!({
            "query": "SQL SELECT COUNT(DISTINCT category) AS categories FROM distinct_http;"
        }))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{aggregate}");
    assert_eq!(aggregate["rows"], json!([{"categories": 2}]));
    assert_eq!(aggregate["column_types"], json!([{"kind": "big_int"}]));
}

#[tokio::test]
async fn atomic_multimodel_transaction_runs_over_http() {
    let data = TempDir::new().expect("tempdir");
    let db = seeded_db(data.path());
    db.set_graph_lifecycle_scoped(COLLECTION, true, true, &TenantScope::system())
        .expect("enable graph");
    db.configure_edge_type_scoped(
        COLLECTION,
        ConfigureEdgeTypeRequest {
            name: "CITES".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .expect("edge type");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.expect("serve");
    });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/v1/chironql");
    let created: Value = client
        .post(&endpoint)
        .json(&json!({"query": "SQL CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL);"}))
        .send()
        .await
        .expect("create")
        .json()
        .await
        .expect("create json");
    assert_eq!(created["committed"], json!(true), "{created}");
    let query = r#"TRANSACTION {
  SQL INSERT INTO documents VALUES ($1, $2);
  VECTOR UPSERT INTO products
      {id: 'http-chunk', vector: [1,0,0]},
      {id: 'http-source', vector: [0,1,0]};
  GRAPH CONNECT products 'http-chunk' -> CITES -> 'http-source';
};"#;
    let response: Value = client
        .post(&endpoint)
        .json(&json!({
            "query": query,
            "parameters": [
                {"type": "text", "value": "http-doc"},
                {"type": "text", "value": "HTTP atomic"}
            ],
            "retry_id": "http-multimodel-1"
        }))
        .send()
        .await
        .expect("transaction")
        .json()
        .await
        .expect("transaction json");
    assert_eq!(response["committed"], json!(true), "{response}");
    assert_eq!(
        response["domains"],
        json!(["relational", "vector", "graph"])
    );
    assert!(response["transaction_id"].is_string(), "{response}");
    assert_eq!(response["stats"]["affected"], json!(4));
    server.abort();
}

#[tokio::test]
async fn the_collection_may_travel_in_the_body_instead_of_the_statement() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "SEARCH NEAR [1,0,0] LIMIT 1;", "collection": "products"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0]["id"], json!("phone"));
}

#[tokio::test]
async fn trace_is_returned_when_requested() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "COUNT products;", "trace": true}))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let stages: Vec<&str> = body["trace"]["stages"]
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
}

#[tokio::test]
async fn a_parse_reject_is_400_with_code_hint_position_and_trace() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "SELECT * FROM products;"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], json!("chironql.not_sql"));
    assert_eq!(body["position"], json!(0));
    assert!(body["hint"].as_str().expect("hint").contains("SQL SELECT"));
    // Failures always carry the trace, whether or not it was requested.
    assert_eq!(body["trace"]["stages"][0]["name"], json!("parse"));
    assert_eq!(body["trace"]["stages"][0]["outcome"], json!("failed"));
}

#[tokio::test]
async fn a_missing_collection_is_404() {
    let harness = Harness::start().await;
    let (status, body) = harness.query(json!({"query": "COUNT nope;"})).await;

    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], json!("chironql.collection_not_found"));
}

#[tokio::test]
async fn a_write_over_http_runs_and_reports_what_it_affected() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "DELETE FROM products POINTS phone;"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["kind"], json!("affected"));
    assert_eq!(body["stats"]["affected"], json!(1));
}

#[tokio::test]
async fn a_filtered_delete_over_http_is_refused_without_confirmation() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({"query": "DELETE FROM products WHERE category = 'electronics';"}))
        .await;

    // The guardrail is server-side, so an HTTP caller with no prompt is
    // protected by exactly the same gate the terminal is.
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], json!("chironql.confirmation_required"));
    assert_eq!(body["affected_estimate"], json!(2));

    let (_, after) = harness.query(json!({"query": "COUNT products;"})).await;
    assert_eq!(after["rows"][0]["count"], json!(3), "nothing was deleted");
}

#[tokio::test]
async fn a_confirmed_filtered_delete_over_http_runs() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .query(json!({
            "query": "DELETE FROM products WHERE category = 'electronics';",
            "confirm": true
        }))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["stats"]["affected"], json!(2));

    let (_, after) = harness.query(json!({"query": "COUNT products;"})).await;
    assert_eq!(after["rows"][0]["count"], json!(1));
}

#[tokio::test]
async fn one_request_carries_one_statement() {
    let harness = Harness::start().await;
    let (status, body) = harness
        .query(json!({"query": "COUNT products; COUNT products;"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], json!("chironql.multiple_statements"));
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_validates_without_touching_the_engine() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .post(
            "/v1/chironql/parse",
            json!({"query": "SEARCH products NEAR [1,0,0] LIMIT 5;"}),
        )
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["kind"], json!("read"));
    assert_eq!(body["class"], json!("read"));
    assert_eq!(body["statement"], json!("SEARCH"));
    assert_eq!(body["collection"], json!("products"));
}

#[tokio::test]
async fn parse_reports_writes_as_writes_so_the_ui_can_warn_before_running() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .post(
            "/v1/chironql/parse",
            json!({"query": "DELETE FROM products WHERE category = 'archived';"}),
        )
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["kind"], json!("write"));
}

#[tokio::test]
async fn parse_rejects_bad_syntax_without_running_it() {
    let harness = Harness::start().await;

    let (status, body) = harness
        .post(
            "/v1/chironql/parse",
            json!({"query": "SEARCH products NEAR [1,0,0] WHERE a = 1 OR b = 2;"}),
        )
        .await;

    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["ok"], json!(false));
    assert_eq!(body["code"], json!("chironql.no_or_across_fields"));
    assert!(body["position"].is_number());
}

#[tokio::test]
async fn parse_never_reaches_a_collection_that_does_not_exist() {
    let harness = Harness::start().await;

    // Valid syntax against a collection that is not there: parsing succeeds,
    // because parsing is not execution.
    let (status, body) = harness
        .post("/v1/chironql/parse", json!({"query": "COUNT nope;"}))
        .await;

    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["ok"], json!(true));
}

// ---------------------------------------------------------------------------
// The gate: four doors, one executor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn console_and_http_agree_on_rows_stats_and_trace() {
    let data = TempDir::new().expect("tempdir");
    let db = seeded_db(data.path());

    let statements = [
        "SEARCH products NEAR [1,0,0] LIMIT 2 WITH PAYLOAD;",
        "SEARCH products NEAR [1,0,0] WHERE category = 'electronics' LIMIT 5;",
        "SEARCH products NEAR @phone LIMIT 2;",
        "COUNT products;",
        "COUNT products WHERE category = 'media';",
        "GET products POINTS phone, book;",
        "SCROLL products LIMIT 2;",
        "SHOW COLLECTIONS;",
        "DESCRIBE products;",
        "RECOMMEND products LIKE phone LIMIT 2;",
    ];

    // Same Db, one door in process and one over HTTP.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let http_db = db.clone();
    let server = tokio::spawn(async move {
        api::serve_listener(http_db, listener).await.expect("serve");
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let mut console = LocalSink::new(db, Role::Admin);

    for statement in statements {
        let via_console = console.execute(statement, traced()).expect(statement);

        let via_http: Value = client
            .post(format!("{base}/v1/chironql"))
            .json(&json!({"query": statement, "trace": true}))
            .send()
            .await
            .expect("send")
            .json()
            .await
            .expect("json");

        assert_eq!(
            serde_json::to_value(&via_console.rows).expect("rows"),
            via_http["rows"],
            "rows differ for `{statement}`"
        );
        assert_eq!(
            serde_json::to_value(&via_console.columns).expect("columns"),
            via_http["columns"],
            "columns differ for `{statement}`"
        );
        assert_eq!(
            json!(via_console.stats.searched),
            via_http["stats"]["searched"],
            "scanned differs for `{statement}`"
        );
        assert_eq!(
            json!(via_console.stats.degraded),
            via_http["stats"]["degraded"],
            "degraded differs for `{statement}`"
        );

        let console_stages: Vec<String> = via_console
            .trace
            .expect("console trace")
            .stages
            .iter()
            .map(|stage| stage.name.clone())
            .collect();
        let http_stages: Vec<String> = via_http["trace"]["stages"]
            .as_array()
            .expect("http trace")
            .iter()
            .map(|stage| stage["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            console_stages, http_stages,
            "trace stages differ for `{statement}`"
        );
    }

    server.abort();
}

#[tokio::test]
async fn console_and_http_agree_on_rejects() {
    let data = TempDir::new().expect("tempdir");
    let db = seeded_db(data.path());

    let rejects = [
        "SELECT * FROM products;",
        "SEARCH products NEAR [1,0,0] WHERE a = 1 OR b = 2;",
        "COUNT nope;",
        "SEARCH products NEAR @missing LIMIT 1;",
        "BEGIN;",
    ];

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let http_db = db.clone();
    let server = tokio::spawn(async move {
        api::serve_listener(http_db, listener).await.expect("serve");
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let mut console = LocalSink::new(db, Role::Admin);

    for statement in rejects {
        let console_error = console
            .execute(statement, traced())
            .expect_err(&format!("`{statement}` should be rejected"));

        let via_http: Value = client
            .post(format!("{base}/v1/chironql"))
            .json(&json!({"query": statement}))
            .send()
            .await
            .expect("send")
            .json()
            .await
            .expect("json");

        assert_eq!(
            json!(console_error.code),
            via_http["code"],
            "error code differs for `{statement}`"
        );
        assert_eq!(
            json!(console_error.position),
            via_http["position"],
            "caret position differs for `{statement}`"
        );
    }

    server.abort();
}
