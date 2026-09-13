//! B5 acceptance — pg_catalog intercept + complete reject taxonomy through
//! the wire (`.SPEC/gaussdb-vector_cleaned.md` §3.0.1 + §7).
//!
//! - Every row of the §3.0.1 reject taxonomy returns SQLSTATE `0A000` with
//!   the documented Hint URL anchor.
//! - psql / driver catalog probes (`SELECT version()`, `pg_class`, etc.) are
//!   served by `pg_catalog::intercept` without going through the parser.

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

async fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut hdr = [0_u8; 5];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0_u8; len - 4];
    stream.read_exact(&mut payload).await.unwrap();
    (hdr[0], payload)
}

async fn connect(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(b"user\0alice\0database\0mydb\0application_name\0pgcatalog-test\0");
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

async fn query_collect_replies(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
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

fn extract_error(replies: &[(u8, Vec<u8>)]) -> (String, String) {
    for (t, body) in replies {
        if *t != b'E' {
            continue;
        }
        let mut sqlstate = String::new();
        let mut message = String::new();
        let mut hint = String::new();
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
            match code {
                b'C' => sqlstate = value,
                b'M' => message = value,
                b'H' => hint = value,
                _ => {}
            }
        }
        let _ = message;
        return (sqlstate, hint);
    }
    panic!("no ErrorResponse in {replies:?}");
}

async fn assert_reject(stream: &mut TcpStream, sql: &str, hint_anchor: &str) {
    let r = query_collect_replies(stream, sql).await;
    let (sqlstate, hint) = extract_error(&r);
    assert_eq!(sqlstate, "0A000", "{sql}");
    assert!(
        hint.ends_with(hint_anchor),
        "{sql}: expected hint to end with {hint_anchor}, got {hint:?}"
    );
}

#[tokio::test]
async fn reject_taxonomy_complete_through_wire() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut s = connect(port).await;

    // Need a real table for some queries.
    let _ = query_collect_replies(
        &mut s,
        "CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;

    // §3.0.1 row 1: JOIN
    assert_reject(
        &mut s,
        "SELECT a.id FROM items a JOIN items b ON a.id = b.id;",
        "#joins",
    )
    .await;
    // §3.0.1 row 1 variant: comma-list join
    assert_reject(
        &mut s,
        "SELECT a.id FROM items a, items b WHERE a.id = b.id;",
        "#joins",
    )
    .await;
    // §3.0.1 row 2: CTE
    assert_reject(&mut s, "WITH x AS (SELECT 1) SELECT * FROM x;", "#cte").await;
    // §3.0.1 row 3: subquery
    assert_reject(
        &mut s,
        "SELECT id FROM items WHERE id IN (SELECT id FROM other);",
        "#subquery",
    )
    .await;
    // §3.0.1 row 4: transaction control (executed at dispatch — exec layer)
    assert_reject(&mut s, "BEGIN;", "#transactions").await;
    assert_reject(&mut s, "COMMIT;", "#transactions").await;
    assert_reject(&mut s, "ROLLBACK;", "#transactions").await;
    // §3.0.1 row 5: PREPARE/EXECUTE
    assert_reject(&mut s, "PREPARE q AS SELECT 1;", "#extended-protocol").await;
    // §3.0.1 row 6: aggregates / GROUP BY
    assert_reject(
        &mut s,
        "SELECT category, count(*) FROM items GROUP BY category;",
        "#aggregates",
    )
    .await;
    // §3.0.1 row 7: multi-table mutations / plain UPDATE
    assert_reject(&mut s, "UPDATE items SET id = 1;", "#mutations").await;
    // §3.0.1 row 8: EXPLAIN ANALYZE
    assert_reject(
        &mut s,
        "EXPLAIN ANALYZE SELECT id FROM items ORDER BY embedding <-> '[0,0]'::vector LIMIT 1;",
        "#explain",
    )
    .await;
    // §3.0.1 row 9: USING ivfflat
    assert_reject(
        &mut s,
        "CREATE INDEX ON items USING ivfflat (embedding vector_l2_ops);",
        "#index-am",
    )
    .await;
    // §3.0.1 row 10: <+> L1
    assert_reject(
        &mut s,
        "SELECT id FROM items ORDER BY embedding <+> '[1, 2]'::vector LIMIT 1;",
        "#operators",
    )
    .await;

    // Rev 3.4 D9: graph is native-protocol-only. ChironQL, constrained
    // retrieval clauses, Cypher/SQL-PGQ shapes and graph DDL all fail as one
    // stable PostgreSQL unsupported-feature class.
    for sql in [
        "RELATE items a -> CITES -> b;",
        "UNRELATE items EDGE opaque-token;",
        "UPDATE EDGE opaque-token SET {weight: 1};",
        "TRAVERSE items FROM a VIA CITES RETURN NODES;",
        "SEARCH items NEAR [1,0] CONNECTED TO a VIA CITES;",
        "SELECT id FROM items CONNECTED TO a WITHIN 2 HOPS;",
        "SELECT * FROM GRAPH_TABLE (items MATCH (a)-[e]->(b));",
        "SELECT * FROM cypher('items', 'MATCH (n) RETURN n');",
        "CREATE PROPERTY GRAPH item_graph;",
    ] {
        assert_reject(&mut s, sql, "#graph").await;
    }
}

#[tokio::test]
async fn graph_words_in_values_and_identifiers_do_not_false_positive() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut s = connect(port).await;

    for sql in [
        "CREATE TABLE graph (id INTEGER PRIMARY KEY, embedding vector(2), traverse TEXT);",
        "INSERT INTO graph (id, embedding, traverse) VALUES (1, '[0,0]'::vector, 'CONNECTED TO root VIA cites');",
        "SELECT traverse FROM graph; -- TRAVERSE graph FROM root",
    ] {
        let replies = query_collect_replies(&mut s, sql).await;
        if replies.iter().any(|(kind, _)| *kind == b'E') {
            let (_, hint) = extract_error(&replies);
            assert!(
                !hint.ends_with("#graph"),
                "unexpected graph false positive for {sql}: {replies:?}"
            );
        }
    }
}

#[tokio::test]
async fn pg_catalog_version_intercept() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut s = connect(port).await;
    let r = query_collect_replies(&mut s, "SELECT version();").await;
    let row = r
        .iter()
        .find_map(|(t, b)| if *t == b'D' { Some(b.clone()) } else { None })
        .unwrap();
    // First field length + bytes.
    let len = i32::from_be_bytes([row[2], row[3], row[4], row[5]]);
    assert!(len > 0);
    let text = String::from_utf8_lossy(&row[6..6 + len as usize]).into_owned();
    assert!(text.contains("PostgreSQL"));
}

#[tokio::test]
async fn pg_class_lists_collections() {
    let (db, _g) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut s = connect(port).await;
    let _ = query_collect_replies(
        &mut s,
        "CREATE TABLE alpha (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let _ = query_collect_replies(
        &mut s,
        "CREATE TABLE beta (id INTEGER PRIMARY KEY, embedding vector(2));",
    )
    .await;
    let r = query_collect_replies(
        &mut s,
        "SELECT c.oid, c.relname, c.relkind FROM pg_catalog.pg_class c;",
    )
    .await;
    let row_count = r.iter().filter(|(t, _)| *t == b'D').count();
    assert_eq!(row_count, 2);
}
