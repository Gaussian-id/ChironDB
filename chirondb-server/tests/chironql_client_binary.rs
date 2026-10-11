//! ChironQL P3 gate — the `chironql` client binary.
//!
//! Drives the real binary against a real server: piped sessions, `--exec`, the
//! three exit codes, and format selection. Interactive line editing is not
//! covered here (it needs a pty); what is covered is everything a script can
//! depend on.

use std::process::{Command, Stdio};

use chirondb::chironql_exec::{ExecContext, Session, execute};
use chirondb::rbac::Role;
use chirondb::tenant::TenantScope;
use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, RelationalValue, SqlExecutionRequest,
    SqlStatementRequest, api,
};
use chirondb_types::ConfigureEdgeTypeRequest;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Path to the binary under test, next to the integration test executable.
fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test exe path");
    path.pop(); // deps/
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chironql")
}

fn seeded_db(path: &std::path::Path) -> Db {
    let db = Db::open(path).expect("open db");
    db.create_collection(CollectionConfig {
        name: "products".to_string(),
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
        "products",
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
    db.set_graph_lifecycle_scoped("products", true, true, &TenantScope::system())
        .expect("enable graph fixture");
    db.configure_edge_type_scoped(
        "products",
        ConfigureEdgeTypeRequest {
            name: "CITES".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .expect("configure graph fixture");
    let mut session = Session::default();
    let mut context = ExecContext {
        db: &db,
        session: &mut session,
        role: Role::ReadWrite,
        allowed_collections: None,
        want_trace: false,
        confirm: true,
        parameters: vec![],
        idempotency_key: None,
        retry_id: None,
        tenant: TenantScope::system(),
    };
    execute(&mut context, "RELATE products phone -> CITES -> book;").expect("create graph fixture");
    db.execute_sql(SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: "CREATE TABLE cli_rows (id TEXT PRIMARY KEY)".into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    })
    .expect("create relational fixture");
    db.execute_sql(SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: "INSERT INTO cli_rows VALUES ($1)".into(),
            parameters: vec![RelationalValue::Text("owner-1".into())],
        }],
        idempotency_key: None,
        retry_id: None,
    })
    .expect("insert relational fixture");
    db.execute_sql(SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: "CREATE TABLE documents (id TEXT PRIMARY KEY, title TEXT NOT NULL, chunk_ref RECORD_REF('products') NOT NULL, source_ref RECORD_REF('products') NOT NULL)".into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    })
    .expect("create pipeline relational fixture");
    db.execute_sql(SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: "INSERT INTO documents VALUES ('doc-phone', 'Phone', RECORD_REF('products', 'phone'), RECORD_REF('products', 'book'))".into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    })
    .expect("insert pipeline relational fixture");
    db
}

struct Server {
    _data: TempDir,
    url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = seeded_db(data.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            api::serve_listener(db, listener).await.expect("serve");
        });
        Self {
            _data: data,
            url: format!("http://{addr}"),
            handle,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct Output {
    code: i32,
    stdout: String,
}

/// Runs the binary with `stdin` piped in. Stdout is a pipe, so the client sees
/// a non-terminal and picks its non-interactive defaults.
fn run_client(args: &[&str], stdin: &str) -> Output {
    use std::io::Write;

    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chironql");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait");
    Output {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
    }
}

fn run_exec_json(url: &str, query: &str, parameters: Option<&str>) -> Value {
    let mut args = vec!["--url", url, "--exec", query];
    if let Some(parameters) = parameters {
        args.extend(["--params-json", parameters]);
    }
    let output = run_client(&args, "");
    assert_eq!(output.code, 0, "query: {query}\n{}", output.stdout);
    serde_json::from_str(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "query: {query}\ninvalid JSON terminal response: {error}\n{}",
            output.stdout
        )
    })
}

fn run_exec_error(url: &str, query: &str) -> Value {
    let output = run_client(&["--url", url, "--exec", query], "");
    assert_eq!(output.code, 1, "query: {query}\n{}", output.stdout);
    serde_json::from_str(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "query: {query}\ninvalid JSON terminal error: {error}\n{}",
            output.stdout
        )
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_piped_session_returns_json_and_exit_code_zero() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(&["--url", &url], "SEARCH products NEAR [1,0,0] LIMIT 1;\n")
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    // Piped stdout means JSON by default, with no flag needed.
    let parsed: Value = serde_json::from_str(&output.stdout).expect("json output");
    assert_eq!(parsed["rows"][0]["id"], json!("phone"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_runs_one_statement_without_reading_stdin() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(&["--url", &url, "--exec", "COUNT products;"], "")
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    let parsed: Value = serde_json::from_str(&output.stdout).expect("json output");
    assert_eq!(parsed["rows"][0]["count"], json!(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_forwards_typed_positional_parameters() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(
            &[
                "--url",
                &url,
                "--exec",
                "SQL SELECT id AS owner_id FROM cli_rows WHERE id = $1;",
                "--params-json",
                r#"[{"type":"text","value":"owner-1"}]"#,
            ],
            "",
        )
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    let parsed: Value = serde_json::from_str(&output.stdout).expect("json output");
    assert_eq!(parsed["rows"][0]["owner_id"], json!("owner-1"));
    assert_eq!(parsed["domains"], json!(["relational"]));
    assert_eq!(parsed["column_types"][0]["kind"], json!("text"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_retries_reuse_the_durable_receipt() {
    let server = Server::start().await;
    let url = server.url.clone();
    tokio::task::spawn_blocking(move || {
        let mut receipts = Vec::new();
        for attempt in ["first", "second"] {
            let output = run_client(
                &[
                    "--url",
                    &url,
                    "--exec",
                    "SQL CREATE TABLE cli_retry (id BIGINT PRIMARY KEY)",
                    "--idempotency-key",
                    "cli-create-1",
                    "--retry-id",
                    attempt,
                ],
                "",
            );
            assert_eq!(output.code, 0, "{}", output.stdout);
            let parsed: Value = serde_json::from_str(&output.stdout).unwrap();
            assert_eq!(parsed["committed"], true);
            receipts.push(parsed["transaction_id"].as_str().unwrap().to_string());
        }
        assert_eq!(receipts[0], receipts[1]);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_executes_select_distinct_through_chironql() {
    let server = Server::start().await;
    let url = server.url.clone();

    tokio::task::spawn_blocking(move || {
        for query in [
            "SQL CREATE TABLE terminal_distinct (id INTEGER PRIMARY KEY, category TEXT);",
            "SQL INSERT INTO terminal_distinct VALUES (1, 'hardware');",
            "SQL INSERT INTO terminal_distinct VALUES (2, 'hardware');",
            "SQL INSERT INTO terminal_distinct VALUES (3, 'software');",
        ] {
            let response = run_exec_json(&url, query, None);
            assert_eq!(response["kind"], json!("affected"), "query: {query}");
        }

        let response = run_exec_json(
            &url,
            "SQL SELECT DISTINCT category FROM terminal_distinct ORDER BY category LIMIT 10;",
            None,
        );
        assert_eq!(response["domains"], json!(["relational"]));
        assert_eq!(
            response["rows"],
            json!([
                {"category": "hardware"},
                {"category": "software"}
            ])
        );

        let aggregate = run_exec_json(
            &url,
            "SQL SELECT COUNT(DISTINCT category) AS categories FROM terminal_distinct;",
            None,
        );
        assert_eq!(aggregate["rows"], json!([{"categories": 2}]));
        assert_eq!(aggregate["column_types"], json!([{"kind": "big_int"}]));
    })
    .await
    .expect("terminal SELECT DISTINCT");
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_keeps_and_executes_an_atomic_multimodel_block() {
    let server = Server::start().await;
    let url = server.url.clone();
    let output = tokio::task::spawn_blocking(move || {
        let transaction = r#"TRANSACTION {
  SQL INSERT INTO documents (id, title, chunk_ref, source_ref)
      VALUES ('terminal-doc', 'Terminal atomic', RECORD_REF('products', 'terminal-chunk'), RECORD_REF('products', 'terminal-source'));
  VECTOR UPSERT INTO products
      {id: 'terminal-chunk', vector: [0.8,0.2,0]},
      {id: 'terminal-source', vector: [0.2,0.8,0]};
  GRAPH CONNECT products 'terminal-chunk' -> CITES -> 'terminal-source';
};
"#;
        let committed = run_client(&["--url", &url], transaction);
        assert_eq!(committed.code, 0, "{}", committed.stdout);
        let committed: Value = serde_json::from_str(&committed.stdout).expect("transaction json");
        assert_eq!(committed["committed"], json!(true));
        assert_eq!(
            committed["domains"],
            json!(["relational", "vector", "graph"])
        );
        assert_eq!(committed["stats"]["affected"], json!(4));
        assert!(committed["transaction_id"].is_string());

        let row = run_exec_json(
            &url,
            "SQL SELECT title FROM documents WHERE id = 'terminal-doc';",
            None,
        );
        assert_eq!(row["rows"][0]["title"], json!("Terminal atomic"));
        let points = run_exec_json(
            &url,
            "GET products POINTS 'terminal-chunk', 'terminal-source';",
            None,
        );
        assert_eq!(points["rows"].as_array().map(Vec::len), Some(2));
        let graph = run_exec_json(
            &url,
            "TRAVERSE products FROM 'terminal-chunk' VIA CITES DEPTH 1 RETURN NODES LIMIT 10;",
            None,
        );
        assert_eq!(graph["rows"][0]["id"], json!("terminal-source"));
    })
    .await;
    output.expect("terminal transaction");
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_executes_the_documented_domain_and_relational_syntax_matrix() {
    let server = Server::start().await;
    let url = server.url.clone();

    tokio::task::spawn_blocking(move || {
        let read_cases = [
            ("SHOW COLLECTIONS;", json!(["catalog"])),
            ("DESCRIBE products;", json!(["catalog"])),
            ("COUNT products;", json!(["vector"])),
            ("GET products POINTS phone, book;", json!(["vector"])),
            ("SCROLL products LIMIT 2;", json!(["vector"])),
            ("SEARCH products NEAR [1,0,0] LIMIT 2;", json!(["vector"])),
            (
                "HYBRID products NEAR [1,0,0] TEXT {1:1.0} LIMIT 2;",
                json!(["vector"]),
            ),
            (
                "MULTI products NEAR [1,0,0], NEAR [0,1,0] FUSION rrf LIMIT 2;",
                json!(["vector"]),
            ),
            (
                "RECOMMEND products LIKE phone UNLIKE book LIMIT 1;",
                json!(["vector"]),
            ),
            (
                "TRAVERSE products FROM phone VIA CITES DEPTH 1 RETURN NODES LIMIT 10;",
                json!(["graph"]),
            ),
            (
                "SEARCH products NEAR [1,0,0] CONNECTED TO phone VIA CITES WITHIN 1 HOPS LIMIT 2;",
                json!(["vector", "graph"]),
            ),
            (
                "SQL SELECT id, title, chunk_ref FROM documents ORDER BY id LIMIT 10;",
                json!(["relational"]),
            ),
        ];
        for (query, expected_domains) in read_cases {
            let response = run_exec_json(&url, query, None);
            assert_eq!(response["domains"], expected_domains, "query: {query}");
        }

        let explained = run_exec_json(
            &url,
            "SQL EXPLAIN SELECT id FROM documents WHERE id = $1 LIMIT 1;",
            Some(r#"[{"type":"text","value":"doc-phone"}]"#),
        );
        assert_eq!(explained["domains"], json!(["relational"]));
        assert!(
            explained["rows"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
        );

        let pipeline = r#"PIPELINE
  VECTOR v { SEARCH products NEAR $1 LIMIT 2 }
  GRAPH g { TRAVERSE products FROM v.record_ref VIA CITES DEPTH 1 RETURN NODES LIMIT 10 }
  RELATIONAL r { SQL SELECT id, title, chunk_ref, source_ref FROM documents LIMIT 10 }
  INNER JOIN r ON r.chunk_ref = v.record_ref
  LEFT JOIN g ON g.record_ref = r.source_ref
  RETURN r.id, r.title, v.score, g.depth
  ORDER BY v.score DESC
  LIMIT 5;"#;
        let pipeline_response = run_exec_json(
            &url,
            pipeline,
            Some(r#"[{"type":"vector","value":[1.0,0.0,0.0]}]"#),
        );
        assert_eq!(
            pipeline_response["domains"],
            json!(["relational", "vector", "graph"])
        );
        assert_eq!(pipeline_response["rows"][0]["id"], json!("doc-phone"));
        assert_eq!(pipeline_response["rows"][0]["title"], json!("Phone"));
        assert!(pipeline_response["snapshot_id"].is_string());

        let explained_pipeline = run_exec_json(&url, &format!("EXPLAIN {pipeline}"), None);
        assert_eq!(
            explained_pipeline["domains"],
            json!(["relational", "vector", "graph"])
        );
        assert!(
            explained_pipeline["rows"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
        );
    })
    .await
    .expect("terminal matrix");
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_executes_sql_and_vector_mutation_syntax() {
    let server = Server::start().await;
    let url = server.url.clone();

    tokio::task::spawn_blocking(move || {
        for query in [
            "SQL CREATE TABLE terminal_notes (id TEXT PRIMARY KEY, title TEXT NOT NULL);",
            "SQL INSERT INTO terminal_notes VALUES ('n-1', 'first');",
            "SQL UPDATE terminal_notes SET title = 'changed' WHERE id = 'n-1';",
            "SQL DELETE FROM terminal_notes WHERE id = 'n-1';",
            "SQL DROP TABLE terminal_notes;",
            "UPSERT INTO products {id: 'tablet', vector: [0.8,0.2,0], payload: {category: 'electronics'}};",
            "UPDATE products POINT tablet SET PAYLOAD {featured: true};",
            "DELETE FROM products POINTS tablet;",
        ] {
            let response = run_exec_json(&url, query, None);
            assert_eq!(response["kind"], json!("affected"), "query: {query}");
        }
    })
    .await
    .expect("terminal mutations");
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_rejects_ambiguous_unbounded_and_mutating_pipeline_syntax() {
    let server = Server::start().await;
    let url = server.url.clone();

    tokio::task::spawn_blocking(move || {
        let cases = [
            ("SELECT * FROM products;", "chironql.not_sql"),
            (
                "SQL SELECT id FROM documents; SELECT title FROM documents;",
                "chironql.invalid_sql",
            ),
            (
                "SQL INSERT INTO cli_rows VALUES ('must-not-commit'); SELECT id FROM cli_rows;",
                "chironql.invalid_sql",
            ),
            (
                "SQL EXPLAIN ANALYZE SELECT id FROM documents;",
                "chironql.invalid_sql",
            ),
            (
                "PIPELINE VECTOR v { SEARCH products NEAR [1,0,0] } RELATIONAL r { SQL SELECT id, chunk_ref FROM documents LIMIT 10 } INNER JOIN r ON r.chunk_ref = v.record_ref RETURN r.id LIMIT 5;",
                "chironql.unbounded_pipeline",
            ),
            (
                "PIPELINE VECTOR v { SEARCH products NEAR [1,0,0] LIMIT 2 } RELATIONAL r { SQL DELETE FROM documents WHERE id = 'doc-phone' } INNER JOIN r ON r.chunk_ref = v.record_ref RETURN r.id LIMIT 5;",
                "chironql.pipeline_write",
            ),
            (
                "PIPELINE VECTOR v { SEARCH products NEAR [1,0,0] LIMIT 2 } RELATIONAL r { SQL SELECT id FROM cli_rows LIMIT 10 } INNER JOIN r ON r.id = v.record_ref RETURN r.id LIMIT 5;",
                "chironql.invalid_pipeline_join",
            ),
        ];
        for (query, expected_code) in cases {
            let error = run_exec_error(&url, query);
            assert_eq!(error["code"], json!(expected_code), "query: {query}");
        }
        let unchanged = run_exec_json(
            &url,
            "SQL SELECT id FROM cli_rows WHERE id = 'must-not-commit' LIMIT 1;",
            None,
        );
        assert!(
            unchanged
                .get("rows")
                .is_none_or(|rows| rows.as_array().is_some_and(Vec::is_empty))
        );
    })
    .await
    .expect("terminal rejection matrix");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_query_exits_one() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(&["--url", &url, "--exec", "SELECT * FROM products;"], "")
    })
    .await
    .expect("join");

    assert_eq!(output.code, 1, "{}", output.stdout);
    let parsed: Value = serde_json::from_str(&output.stdout).expect("json output");
    assert_eq!(parsed["code"], json!("chironql.not_sql"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_exits_two() {
    // Port 1 on loopback: nothing listens there, and the failure is a
    // connection failure rather than a query failure.
    let output = tokio::task::spawn_blocking(|| {
        run_client(
            &["--url", "http://127.0.0.1:1", "--exec", "COUNT products;"],
            "",
        )
    })
    .await
    .expect("join");

    assert_eq!(output.code, 2, "{}", output.stdout);
    assert!(
        output.stdout.contains("chironql.connection_failed"),
        "{}",
        output.stdout
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_collection_flag_presets_the_session() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(
            &[
                "--url",
                &url,
                "--collection",
                "products",
                "--exec",
                "COUNT;",
            ],
            "",
        )
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    let parsed: Value = serde_json::from_str(&output.stdout).expect("json output");
    assert_eq!(parsed["rows"][0]["count"], json!(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn use_persists_across_statements_in_one_piped_session() {
    let server = Server::start().await;
    let url = server.url.clone();

    // HTTP has no session, so the client is the thing that remembers `USE`.
    let output = tokio::task::spawn_blocking(move || {
        run_client(&["--url", &url], "USE products;\nCOUNT;\n")
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    assert!(output.stdout.contains("\"count\": 2"), "{}", output.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_format_flag_overrides_the_piped_default() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(
            &[
                "--url",
                &url,
                "--format",
                "table",
                "--exec",
                "COUNT products;",
            ],
            "",
        )
    })
    .await
    .expect("join");

    assert_eq!(output.code, 0, "{}", output.stdout);
    // Table output, not JSON: a header rule and a footer.
    assert!(output.stdout.contains("─"), "{}", output.stdout);
    assert!(output.stdout.contains("1 row"), "{}", output.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_reports_the_trace_without_being_asked() {
    let server = Server::start().await;
    let url = server.url.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_client(
            &[
                "--url",
                &url,
                "--format",
                "table",
                "--exec",
                "SEARCH products NEAR @missing LIMIT 1;",
            ],
            "",
        )
    })
    .await
    .expect("join");

    assert_eq!(output.code, 1, "{}", output.stdout);
    assert!(
        output.stdout.contains("at resolve_vector"),
        "{}",
        output.stdout
    );
    assert!(output.stdout.contains("trace"), "{}", output.stdout);
}
