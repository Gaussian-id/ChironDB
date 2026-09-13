//! ChironQL P3 gate — the `chironql` client binary.
//!
//! Drives the real binary against a real server: piped sessions, `--exec`, the
//! three exit codes, and format selection. Interactive line editing is not
//! covered here (it needs a pty); what is covered is everything a script can
//! depend on.

use std::process::{Command, Stdio};

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, api};
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
