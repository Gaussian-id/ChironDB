//! ChironQL P2 gate — the HTTP surface.
//!
//! The load-bearing test is `console_and_http_agree`: the same statement run
//! through the embedded console and through `POST /v1/chironql` must produce
//! the same rows, the same stats and the same trace stages. That is what keeps
//! "four doors, one executor" true rather than aspirational.

use chirondb::chironql_repl::{ExecuteOptions, LocalSink, QuerySink};
use chirondb::rbac::Role;
use chirondb::{CollectionConfig, Db, DistanceMetric, Point, api};
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
    assert!(body["hint"].as_str().expect("hint").contains("SEARCH"));
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
