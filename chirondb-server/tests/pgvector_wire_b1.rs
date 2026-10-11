//! B1 acceptance — `psql` (any Postgres v3 client) can connect, idle, and
//! terminate against port 7403 over the GaussWire listener via the
//! Postgres-protocol sniff in `wire::dispatch_by_first_bytes`.
//!
//! This test replays the v3 frontend protocol byte-for-byte to avoid taking
//! a hard CI dependency on the `psql` binary. The conformance harness in B6
//! exercises the real psql client.

use std::sync::Arc;

use chirondb::Db;
use chirondb::auth::AuthConfig;
use chirondb::wire;
use chirondb::wire_postgres::{CANCEL_REQUEST_MAGIC, PROTOCOL_V3, SSL_REQUEST_MAGIC};
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

fn startup_message(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.extend_from_slice(b"application_name\0gaussdb-test\0");
    body.push(0); // terminator

    let total_len = 4 + 4 + body.len(); // length(4) + protocol(4) + body
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

async fn read_message(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut hdr = [0_u8; 5];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0_u8; len - 4];
    stream.read_exact(&mut payload).await.unwrap();
    (hdr[0], payload)
}

async fn connect_without_auth(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();
    loop {
        let (message_type, _body) = read_message(&mut stream).await;
        if message_type == b'Z' {
            return stream;
        }
    }
}

async fn connect_with_backend_key(port: u16) -> (TcpStream, u32, u32) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();
    let mut backend_key = None;
    loop {
        let (message_type, body) = read_message(&mut stream).await;
        if message_type == b'K' {
            backend_key = Some((
                u32::from_be_bytes(body[..4].try_into().unwrap()),
                u32::from_be_bytes(body[4..].try_into().unwrap()),
            ));
        }
        if message_type == b'Z' {
            let (pid, secret) = backend_key.expect("startup must return BackendKeyData");
            return (stream, pid, secret);
        }
    }
}

async fn send_cancel_request(port: u16, pid: u32, secret: u32) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut request = Vec::with_capacity(16);
    request.extend_from_slice(&16_u32.to_be_bytes());
    request.extend_from_slice(&CANCEL_REQUEST_MAGIC.to_be_bytes());
    request.extend_from_slice(&pid.to_be_bytes());
    request.extend_from_slice(&secret.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn simple_query(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    let mut message = Vec::with_capacity(body.len() + 5);
    message.push(b'Q');
    message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(&body);
    stream.write_all(&message).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = Vec::new();
    loop {
        let message = read_message(stream).await;
        let done = message.0 == b'Z';
        response.push(message);
        if done {
            return response;
        }
    }
}

#[tokio::test]
async fn psql_style_connect_idle_terminate_no_auth() {
    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Expect: AuthenticationOk ('R') + ParameterStatus ('S')xN + BackendKeyData ('K') + ReadyForQuery ('Z')
    let (auth_type, auth_body) = read_message(&mut stream).await;
    assert_eq!(auth_type, b'R');
    assert_eq!(
        u32::from_be_bytes([auth_body[0], auth_body[1], auth_body[2], auth_body[3]]),
        0,
        "expected AuthenticationOk(0)"
    );

    let mut saw_server_version = false;
    let mut saw_backend_key = false;
    loop {
        let (msg_type, body) = read_message(&mut stream).await;
        match msg_type {
            b'S' => {
                // key\0value\0
                let mut split = body.split(|&b| b == 0);
                let k = std::str::from_utf8(split.next().unwrap_or(&[])).unwrap_or("");
                if k == "server_version" {
                    saw_server_version = true;
                }
            }
            b'K' => {
                assert_eq!(body.len(), 8);
                saw_backend_key = true;
            }
            b'Z' => {
                assert_eq!(body, vec![b'I'], "expected ReadyForQuery 'I'");
                break;
            }
            other => panic!("unexpected message type 0x{other:02x}"),
        }
    }
    assert!(saw_server_version, "missing server_version ParameterStatus");
    assert!(saw_backend_key, "missing BackendKeyData");

    // \q -> Terminate ('X', length=4)
    stream.write_all(b"X").await.unwrap();
    stream.write_all(&4_u32.to_be_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_cancel_request_does_not_poison_the_next_query() {
    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let (mut stream, pid, secret) = connect_with_backend_key(port).await;

    send_cancel_request(port, pid, secret).await;
    let response = simple_query(
        &mut stream,
        "CREATE TABLE cancel_idle (id INTEGER PRIMARY KEY)",
    )
    .await;
    assert!(
        response
            .iter()
            .all(|(message_type, _)| *message_type != b'E'),
        "an idle CancelRequest must not cancel a future query"
    );
    assert!(
        response
            .iter()
            .any(|(message_type, _)| *message_type == b'C')
    );
    assert_eq!(response.last(), Some(&(b'Z', vec![b'I'])));
}

#[tokio::test]
async fn ssl_request_refused_then_handshake_succeeds() {
    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // libpq sends SSLRequest (length=8, magic=80877103) before the StartupMessage.
    let mut req = Vec::new();
    req.extend_from_slice(&8_u32.to_be_bytes());
    req.extend_from_slice(&SSL_REQUEST_MAGIC.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    stream.flush().await.unwrap();

    // Server replies with single byte 'N' (refuse TLS, downgrade to plaintext).
    let mut reply = [0_u8; 1];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [b'N']);

    // Now send real StartupMessage.
    stream
        .write_all(&startup_message("bob", "mydb"))
        .await
        .unwrap();

    let (auth_type, auth_body) = read_message(&mut stream).await;
    assert_eq!(auth_type, b'R');
    assert_eq!(
        u32::from_be_bytes([auth_body[0], auth_body[1], auth_body[2], auth_body[3]]),
        0
    );

    // Drain until ReadyForQuery.
    loop {
        let (msg_type, _body) = read_message(&mut stream).await;
        if msg_type == b'Z' {
            break;
        }
    }

    stream.write_all(b"X").await.unwrap();
    stream.write_all(&4_u32.to_be_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn cleartext_password_auth_accepts_api_key() {
    let (db, _dir) = make_db();
    let auth = AuthConfig::from_optional_key(Some("sek1".to_string()));
    let port = spawn_server(db, auth).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Expect AuthenticationCleartextPassword (R, code 3).
    let (msg_type, body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'R');
    assert_eq!(u32::from_be_bytes([body[0], body[1], body[2], body[3]]), 3);

    // Send PasswordMessage with the API key.
    let pw = b"sek1\0";
    let mut pmsg = Vec::new();
    pmsg.push(b'p');
    pmsg.extend_from_slice(&((4 + pw.len()) as u32).to_be_bytes());
    pmsg.extend_from_slice(pw);
    stream.write_all(&pmsg).await.unwrap();
    stream.flush().await.unwrap();

    // Expect AuthenticationOk (R, code 0).
    let (msg_type, body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'R');
    assert_eq!(u32::from_be_bytes([body[0], body[1], body[2], body[3]]), 0);

    // Drain to ReadyForQuery.
    loop {
        let (msg_type, _body) = read_message(&mut stream).await;
        if msg_type == b'Z' {
            break;
        }
    }

    stream.write_all(b"X").await.unwrap();
    stream.write_all(&4_u32.to_be_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn cleartext_password_auth_rejects_wrong_key() {
    let (db, _dir) = make_db();
    let auth = AuthConfig::from_optional_key(Some("right".to_string()));
    let port = spawn_server(db, auth).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();

    // Skip the AuthenticationCleartextPassword challenge.
    let (msg_type, _body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'R');

    let pw = b"wrong\0";
    let mut pmsg = Vec::new();
    pmsg.push(b'p');
    pmsg.extend_from_slice(&((4 + pw.len()) as u32).to_be_bytes());
    pmsg.extend_from_slice(pw);
    stream.write_all(&pmsg).await.unwrap();

    let (msg_type, body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'E', "expected ErrorResponse");
    // Body should contain SQLSTATE 28P01.
    assert!(
        body.windows(7).any(|w| w == b"C28P01\0"),
        "missing SQLSTATE 28P01 in error body"
    );
}

#[tokio::test]
async fn relational_transaction_reports_ready_for_query_state() {
    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(&startup_message("alice", "mydb"))
        .await
        .unwrap();
    loop {
        let (t, _b) = read_message(&mut stream).await;
        if t == b'Z' {
            break;
        }
    }

    let sql = b"BEGIN;\0";
    let mut q = Vec::new();
    q.push(b'Q');
    q.extend_from_slice(&((4 + sql.len()) as u32).to_be_bytes());
    q.extend_from_slice(sql);
    stream.write_all(&q).await.unwrap();

    let (msg_type, _body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'C');
    let (t, b) = read_message(&mut stream).await;
    assert_eq!(t, b'Z');
    assert_eq!(b, vec![b'T']);

    let sql = b"ROLLBACK;\0";
    let mut q = Vec::new();
    q.push(b'Q');
    q.extend_from_slice(&((4 + sql.len()) as u32).to_be_bytes());
    q.extend_from_slice(sql);
    stream.write_all(&q).await.unwrap();
    let (msg_type, _body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'C');
    let (t, b) = read_message(&mut stream).await;
    assert_eq!(t, b'Z');
    assert_eq!(b, vec![b'I']);
}

#[tokio::test]
async fn relational_upsert_works_over_postgres_simple_query_and_maps_cardinality_error() {
    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let mut stream = connect_without_auth(port).await;

    for sql in [
        "CREATE TABLE pg_upsert (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)",
        "INSERT INTO pg_upsert VALUES (1, 10)",
        "INSERT INTO pg_upsert VALUES (1, 5) ON CONFLICT (id) DO UPDATE SET value = pg_upsert.value + excluded.value RETURNING id, value",
    ] {
        let response = simple_query(&mut stream, sql).await;
        assert!(
            response
                .iter()
                .any(|(message_type, _)| *message_type == b'C'),
            "query did not complete: {sql}"
        );
        assert!(
            response
                .iter()
                .all(|(message_type, _)| *message_type != b'E'),
            "query returned an error: {sql}"
        );
    }

    let selected = simple_query(&mut stream, "SELECT value FROM pg_upsert WHERE id = 1").await;
    let data_row = selected
        .iter()
        .find(|(message_type, _)| *message_type == b'D')
        .map(|(_, body)| body)
        .expect("SELECT must return a DataRow");
    assert!(data_row.windows(2).any(|window| window == b"15"));

    let error = simple_query(
        &mut stream,
        "INSERT INTO pg_upsert VALUES (1, 20), (1, 30) ON CONFLICT (id) DO UPDATE SET value = excluded.value",
    )
    .await;
    let error_body = error
        .iter()
        .find(|(message_type, _)| *message_type == b'E')
        .map(|(_, body)| body)
        .expect("duplicate affected row must return ErrorResponse");
    assert!(
        error_body.windows(7).any(|window| window == b"C21000\0"),
        "missing cardinality-violation SQLSTATE"
    );

    let selected = simple_query(&mut stream, "SELECT value FROM pg_upsert WHERE id = 1").await;
    let data_row = selected
        .iter()
        .find(|(message_type, _)| *message_type == b'D')
        .map(|(_, body)| body)
        .expect("row must remain visible after rejected statement");
    assert!(data_row.windows(2).any(|window| window == b"15"));
}

#[tokio::test]
async fn native_gausswire_clients_still_work_after_sniff() {
    use chirondb::grpc::pb::wire_request::Operation;
    use chirondb::grpc::pb::{HealthRequest, WireRequest};

    let (db, _dir) = make_db();
    let port = spawn_server(db, AuthConfig::disabled()).await;
    let addr = format!("127.0.0.1:{port}");

    let request = WireRequest {
        request_id: 7,
        api_key: String::new(),
        operation: Some(Operation::Health(HealthRequest {})),
    };
    let response = wire::send_request(&addr, request).await.unwrap();
    assert_eq!(response.request_id, 7);
    assert!(response.error_message.is_empty());
}

#[allow(dead_code)]
fn force_arc_send_marker() -> Arc<()> {
    Arc::new(())
}
