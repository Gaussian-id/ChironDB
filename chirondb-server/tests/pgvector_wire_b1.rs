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
use chirondb::wire_postgres::{PROTOCOL_V3, SSL_REQUEST_MAGIC};
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
async fn rejected_transaction_returns_sqlstate_0a000() {
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

    let (msg_type, body) = read_message(&mut stream).await;
    assert_eq!(msg_type, b'E');
    assert!(
        body.windows(7).any(|w| w == b"C0A000\0"),
        "expected SQLSTATE 0A000 on BEGIN"
    );
    let has_hint_url = body
        .windows(b"Hhttps://docs.gaussdb/pgvector-compat".len())
        .any(|w| w.starts_with(b"Hhttps://docs.gaussdb/pgvector-compat"));
    assert!(
        has_hint_url,
        "expected Hint URL in BEGIN reject; body={body:?}"
    );

    let (t, b) = read_message(&mut stream).await;
    assert_eq!(t, b'Z');
    assert_eq!(b, vec![b'I']);
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
