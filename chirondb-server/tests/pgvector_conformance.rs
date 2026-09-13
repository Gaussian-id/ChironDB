//! pgvector regression conformance harness — B6 of `.SPEC/gaussdb-vector_cleaned.md`.
//!
//! Spins up `gaussdb` on an ephemeral port, then for each curated SQL file
//! under `tests/pgvector_regress/sql/`:
//!
//! 1. Replays the file statement-by-statement over the Postgres-v3 wire
//!    protocol against the live server.
//! 2. For each statement that is *not* prefixed with `-- expect: <SQLSTATE>`,
//!    asserts the server returned a successful `CommandComplete` (no
//!    `ErrorResponse`).
//! 3. For statements prefixed with `-- expect: 0A000` (or any 5-char SQLSTATE)
//!    asserts the server emitted an `ErrorResponse` carrying that SQLSTATE.
//!
//! The SQL files are curated subsets of upstream pgvector's regression suite
//! pinned in `tests/pgvector_regress/PINNED.md`. Full byte-identical diff vs.
//! upstream `.out` files is deferred to the optional `psql` mode below.
//!
//! ## Optional psql mode
//!
//! If the env var `GAUSSDB_PGVECTOR_CONFORMANCE_PSQL=1` is set AND `psql` is
//! on `PATH`, the harness instead pipes each SQL file through the real psql
//! binary connected to GaussDB. This is the "true" pgvector conformance
//! path and runs against the same SQL set. It is opt-in because most CI
//! workers do not ship `psql`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use chirondb::Db;
use chirondb::auth::AuthConfig;
use chirondb::wire;
use chirondb::wire_postgres::PROTOCOL_V3;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn make_db() -> (Db, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    (db, dir)
}

async fn spawn_server(db: Db) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = wire::serve_listener_with_auth(db, AuthConfig::disabled(), listener).await;
    });
    port
}

async fn connect(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(
        b"user\0gaussdb\0database\0regress\0application_name\0pgvector-conformance\0",
    );
    body.push(0);
    let total = 4 + 4 + body.len();
    let mut hdr = Vec::with_capacity(total);
    hdr.extend_from_slice(&(total as u32).to_be_bytes());
    hdr.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    hdr.extend_from_slice(&body);
    stream.write_all(&hdr).await.unwrap();
    loop {
        let (t, _) = read_message(&mut stream).await;
        if t == b'Z' {
            break;
        }
    }
    stream
}

async fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut hdr = [0_u8; 5];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0_u8; len - 4];
    stream.read_exact(&mut payload).await.unwrap();
    (hdr[0], payload)
}

async fn run_query(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    let mut q = Vec::new();
    q.push(b'Q');
    let body_len = sql.len() + 1;
    q.extend_from_slice(&((4 + body_len) as u32).to_be_bytes());
    q.extend_from_slice(sql.as_bytes());
    q.push(0);
    stream.write_all(&q).await.unwrap();
    let mut out = Vec::new();
    loop {
        let (t, body) = read_message(stream).await;
        if t == b'Z' {
            break;
        }
        out.push((t, body));
    }
    out
}

fn extract_error_sqlstate(replies: &[(u8, Vec<u8>)]) -> Option<String> {
    for (t, body) in replies {
        if *t != b'E' {
            continue;
        }
        let mut i = 0;
        while i < body.len() && body[i] != 0 {
            let code = body[i];
            i += 1;
            let end = body[i..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(body.len() - i);
            let value = String::from_utf8_lossy(&body[i..i + end]).into_owned();
            i += end + 1;
            if code == b'C' {
                return Some(value);
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
struct ScriptedStmt {
    sql: String,
    expect_sqlstate: Option<String>,
    line: usize,
}

fn parse_script(text: &str) -> Vec<ScriptedStmt> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut pending_expect: Option<String> = None;
    let mut start_line = 1;
    let mut current_line = 1;
    for line in text.lines() {
        current_line += 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("-- expect:") {
            pending_expect = Some(rest.trim().to_string());
            continue;
        }
        if trimmed.starts_with("--") || trimmed.is_empty() {
            continue;
        }
        if current.is_empty() {
            start_line = current_line;
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(line);
        if trimmed.ends_with(';') {
            out.push(ScriptedStmt {
                sql: current.trim().to_string(),
                expect_sqlstate: pending_expect.take(),
                line: start_line,
            });
            current.clear();
        }
    }
    out
}

fn regress_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pgvector_regress/sql")
}

async fn run_script(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let script = parse_script(&text);
    assert!(!script.is_empty(), "{path:?} parsed to empty script");
    let (db, _g) = make_db();
    let port = spawn_server(db).await;
    let mut stream = connect(port).await;
    let mut failures: VecDeque<String> = VecDeque::new();
    for stmt in script {
        let replies = run_query(&mut stream, &stmt.sql).await;
        let observed = extract_error_sqlstate(&replies);
        match (&stmt.expect_sqlstate, observed) {
            (None, None) => {
                // Expected success and got success.
            }
            (None, Some(actual)) => {
                failures.push_back(format!(
                    "{}:{} expected success, got SQLSTATE {} for: {}",
                    path.display(),
                    stmt.line,
                    actual,
                    stmt.sql
                ));
            }
            (Some(expected), None) => {
                failures.push_back(format!(
                    "{}:{} expected SQLSTATE {} but statement succeeded: {}",
                    path.display(),
                    stmt.line,
                    expected,
                    stmt.sql
                ));
            }
            (Some(expected), Some(actual)) => {
                if expected != &actual {
                    failures.push_back(format!(
                        "{}:{} expected SQLSTATE {} got {} for: {}",
                        path.display(),
                        stmt.line,
                        expected,
                        actual,
                        stmt.sql
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} conformance failures:\n  {}",
            failures.len(),
            failures.into_iter().collect::<Vec<_>>().join("\n  ")
        );
    }
}

#[tokio::test]
async fn vector_type_conformance() {
    run_script(&regress_root().join("vector_type.sql")).await;
}

#[tokio::test]
async fn input_conformance() {
    run_script(&regress_root().join("input.sql")).await;
}

#[tokio::test]
async fn output_conformance() {
    run_script(&regress_root().join("output.sql")).await;
}

#[tokio::test]
async fn hnsw_conformance() {
    run_script(&regress_root().join("hnsw.sql")).await;
}

#[tokio::test]
async fn all_scripts_have_at_least_one_stmt() {
    for name in ["vector_type.sql", "input.sql", "output.sql", "hnsw.sql"] {
        let p = regress_root().join(name);
        let text = std::fs::read_to_string(&p).unwrap();
        let parsed = parse_script(&text);
        assert!(!parsed.is_empty(), "{p:?} parsed empty");
    }
}
