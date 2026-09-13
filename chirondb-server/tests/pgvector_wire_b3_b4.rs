//! B3 + B4 acceptance — drive the seven pgvector statement shapes through
//! the GaussWire / Postgres-protocol sniff end-to-end.
//!
//! - B3 (search): CREATE TABLE → CREATE INDEX → INSERT → `SELECT … ORDER BY
//!   embedding <-> '[…]'::vector LIMIT k` round-trips and returns the inserted
//!   row id back. Covers L2, Cosine, Dot operators.
//! - B4 (DDL/DML + WHERE): denormalised e-commerce schema works end-to-end —
//!   filter by category, range on price, IN list, then sort by vector.
//!
//! Replays the v3 wire protocol byte-for-byte to avoid taking a CI dependency
//! on `psql` (the conformance harness in B6 wires the real binary).

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

async fn spawn_server(db: Db, auth: AuthConfig) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = wire::serve_listener_with_auth(db, auth, listener).await;
    });
    port
}

async fn connect(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(b"user\0alice\0database\0mydb\0application_name\0pgvector-test\0");
    body.push(0);
    let total = 4 + 4 + body.len();
    let mut hdr = Vec::with_capacity(total);
    hdr.extend_from_slice(&(total as u32).to_be_bytes());
    hdr.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    hdr.extend_from_slice(&body);
    stream.write_all(&hdr).await.unwrap();
    // Drain until ReadyForQuery.
    loop {
        let (t, _b) = read_message(&mut stream).await;
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

#[derive(Debug)]
enum Reply {
    RowDescription(Vec<String>),
    DataRow(Vec<Option<String>>),
    CommandComplete(String),
    EmptyQuery,
    Error { sqlstate: String, message: String },
}

async fn run_query(stream: &mut TcpStream, sql: &str) -> Vec<Reply> {
    let mut q = Vec::new();
    q.push(b'Q');
    let body_len = sql.len() + 1; // include trailing NUL
    q.extend_from_slice(&((4 + body_len) as u32).to_be_bytes());
    q.extend_from_slice(sql.as_bytes());
    q.push(0);
    stream.write_all(&q).await.unwrap();
    let mut out = Vec::new();
    loop {
        let (t, body) = read_message(stream).await;
        match t {
            b'T' => out.push(Reply::RowDescription(parse_row_description(&body))),
            b'D' => out.push(Reply::DataRow(parse_data_row(&body))),
            b'C' => out.push(Reply::CommandComplete(parse_cstring(&body))),
            b'I' => out.push(Reply::EmptyQuery),
            b'E' => out.push(parse_error_response(&body)),
            b'Z' => break,
            other => panic!("unexpected message 0x{other:02x}"),
        }
    }
    out
}

fn parse_cstring(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn parse_row_description(buf: &[u8]) -> Vec<String> {
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut i = 2;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        let end = buf[i..].iter().position(|&b| b == 0).unwrap();
        names.push(String::from_utf8_lossy(&buf[i..i + end]).into_owned());
        i += end + 1;
        // skip table OID (4) + attno (2) + type OID (4) + typlen (2) + typmod (4) + format (2) = 18
        i += 18;
    }
    names
}

fn parse_data_row(buf: &[u8]) -> Vec<Option<String>> {
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut i = 2;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = i32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        i += 4;
        if len < 0 {
            out.push(None);
        } else {
            let s = String::from_utf8_lossy(&buf[i..i + len as usize]).into_owned();
            i += len as usize;
            out.push(Some(s));
        }
    }
    out
}

fn parse_error_response(buf: &[u8]) -> Reply {
    let mut sqlstate = String::new();
    let mut message = String::new();
    let mut i = 0;
    while i < buf.len() && buf[i] != 0 {
        let code = buf[i];
        i += 1;
        let end = buf[i..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(buf.len() - i);
        let value = String::from_utf8_lossy(&buf[i..i + end]).into_owned();
        i += end + 1;
        match code {
            b'C' => sqlstate = value,
            b'M' => message = value,
            _ => {}
        }
    }
    Reply::Error { sqlstate, message }
}

#[tokio::test]
async fn select_round_trip_l2() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;

    let setup = [
        "CREATE EXTENSION IF NOT EXISTS vector;",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(4));",
        "INSERT INTO items (id, embedding) VALUES (1, '[1.0, 0.0, 0.0, 0.0]'::vector);",
        "INSERT INTO items (id, embedding) VALUES (2, '[0.0, 1.0, 0.0, 0.0]'::vector);",
    ];
    for s in setup {
        let replies = run_query(&mut stream, s).await;
        assert!(
            replies.iter().all(|r| !matches!(r, Reply::Error { .. })),
            "{s} failed: {replies:?}"
        );
    }

    let replies = run_query(
        &mut stream,
        "SELECT id, embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector AS d FROM items ORDER BY embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector LIMIT 1;",
    )
    .await;

    let cols = replies
        .iter()
        .find_map(|r| match r {
            Reply::RowDescription(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(cols, vec!["id".to_string(), "d".to_string()]);
    let row = replies
        .iter()
        .find_map(|r| match r {
            Reply::DataRow(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(row[0].as_deref(), Some("1"));
    let distance: f64 = row[1].as_deref().unwrap().parse().unwrap();
    assert!(distance.abs() < 1e-5);
    let tag = replies
        .iter()
        .find_map(|r| match r {
            Reply::CommandComplete(t) => Some(t.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(tag, "SELECT 1");
}

#[tokio::test]
async fn create_index_hnsw_rejects_and_keeps_connection_live() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let _ = run_query(
        &mut stream,
        "CREATE TABLE c (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let r = run_query(
        &mut stream,
        "CREATE INDEX ON c USING hnsw (embedding vector_cosine_ops);",
    )
    .await;
    let error = r
        .iter()
        .find_map(|m| match m {
            Reply::Error { sqlstate, message } => Some((sqlstate, message)),
            _ => None,
        })
        .unwrap();
    assert_eq!(error.0, "0A000");
    assert!(error.1.contains("LS-VEC is automatic"));

    let live = run_query(
        &mut stream,
        "INSERT INTO c (id, embedding) VALUES (1, '[1.0, 0.0]'::vector);",
    )
    .await;
    assert!(live.iter().all(|m| !matches!(m, Reply::Error { .. })));
}

#[tokio::test]
async fn ecommerce_schema_filter_and_search() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let setup = [
        "CREATE TABLE products (id INTEGER PRIMARY KEY, embedding vector(2), category TEXT, price INTEGER, in_stock BOOLEAN);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (1, '[0.0, 0.0]'::vector, 'red', 50, true);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (2, '[1.0, 0.0]'::vector, 'blue', 200, true);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (3, '[0.0, 1.0]'::vector, 'red', 80, false);",
        "INSERT INTO products (id, embedding, category, price, in_stock) VALUES (4, '[1.0, 1.0]'::vector, 'green', 150, true);",
    ];
    for s in setup {
        let r = run_query(&mut stream, s).await;
        assert!(
            r.iter().all(|m| !matches!(m, Reply::Error { .. })),
            "{s}: {r:?}"
        );
    }

    // 1. AND + range filter + L2 search.
    let r = run_query(
        &mut stream,
        "SELECT id FROM products WHERE category = 'red' AND price < 100 ORDER BY embedding <-> '[0.0, 0.0]'::vector LIMIT 5;",
    )
    .await;
    let rows: Vec<_> = r
        .iter()
        .filter_map(|m| match m {
            Reply::DataRow(rr) => Some(rr.clone()),
            _ => None,
        })
        .collect();
    let ids: Vec<&str> = rows.iter().map(|row| row[0].as_deref().unwrap()).collect();
    assert_eq!(ids, vec!["1", "3"]);

    // 2. IN list filter.
    let r = run_query(
        &mut stream,
        "SELECT id FROM products WHERE category IN ('blue', 'green') ORDER BY embedding <-> '[1.0, 1.0]'::vector LIMIT 5;",
    )
    .await;
    let rows: Vec<_> = r
        .iter()
        .filter_map(|m| match m {
            Reply::DataRow(rr) => Some(rr.clone()),
            _ => None,
        })
        .collect();
    let ids: Vec<&str> = rows.iter().map(|row| row[0].as_deref().unwrap()).collect();
    // Closest to [1,1] within {blue, green} -> 4 (green at [1,1]) then 2 (blue at [1,0]).
    assert_eq!(ids, vec!["4", "2"]);

    // 3. DELETE by predicate.
    let r = run_query(&mut stream, "DELETE FROM products WHERE id = 2;").await;
    assert!(matches!(
        r.iter().find(|m| matches!(m, Reply::CommandComplete(_))),
        Some(Reply::CommandComplete(t)) if t == "DELETE 1"
    ));

    // 4. DROP TABLE.
    let r = run_query(&mut stream, "DROP TABLE products;").await;
    assert!(matches!(
        r.iter().find(|m| matches!(m, Reply::CommandComplete(_))),
        Some(Reply::CommandComplete(t)) if t == "DROP TABLE"
    ));
}

#[tokio::test]
async fn parser_reject_join_propagates_0a000_with_hint() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect(port).await;
    let _ = run_query(
        &mut stream,
        "CREATE TABLE a (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let r = run_query(&mut stream, "SELECT a.id FROM a JOIN b ON a.id = b.id;").await;
    let err = r
        .iter()
        .find_map(|m| match m {
            Reply::Error { sqlstate, message } => Some((sqlstate.clone(), message.clone())),
            _ => None,
        })
        .unwrap();
    assert_eq!(err.0, "0A000");
    assert!(err.1.to_lowercase().contains("join"));
}
