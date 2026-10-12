use super::*;
use crate::response_buffer::ResponseReservation;
use std::{
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncWriteExt, ReadBuf};

fn child(key: &str, test: &str) -> bool {
    if std::env::var_os(key).is_some() {
        return true;
    }
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(key, "1")
            .status()
            .unwrap()
            .success()
    );
    false
}
fn small_profile() {
    let mut profile = crate::resource_profile::ResourceProfile::from_limits(1 << 30, 1);
    profile.sql_pool_bytes = 256 * 1024;
    crate::resource_profile::install(profile);
}

#[test]
fn startup_maps_preserve_values_and_refuse_before_owned_growth() {
    let budget = 64 * 1024;
    let memory = memory::SessionMemory::with_capacity(budget);
    let body = "user\0first\0database\0日本語\0user\0last\0\0ignored";
    let params = startup(body.as_bytes(), &memory).unwrap();
    assert_eq!(params.get("user").unwrap(), "last");
    assert_eq!(params.get("database").unwrap(), "日本語");
    assert_eq!(params.len(), 2);
    assert!(memory.available().0 < budget);
    drop(params);
    assert_eq!(memory.available(), (budget, budget));
    for count in [29, 57, 113, 225] {
        let mut body = String::new();
        for n in 0..count {
            body.push_str(&format!("key{n}\0value{n}\0"));
        }
        body.push('\0');
        let params = startup(body.as_bytes(), &memory).unwrap();
        assert_eq!(params.len(), count);
        assert!(budget - memory.available().0 >= params.capacity() * size_of::<(String, String)>());
        drop(params);
        assert_eq!(memory.available(), (budget, budget));
    }
    let tiny = memory::SessionMemory::with_capacity(16);
    assert!(startup(body.as_bytes(), &tiny).is_err());
    assert_eq!(tiny.available(), (16, 16));
    for bad in [&b"user\0"[..], &b"\xff\0v\0\0"[..], &b"user\0\xff\0\0"[..]] {
        assert!(startup(bad, &memory).is_err());
        assert_eq!(memory.available(), (budget, budget));
    }
    let request = vec![
        crate::RelationalValue::Json(serde_json::json!({"nested":["雪",null,1]})),
        crate::RelationalValue::Text("text".into()),
    ];
    let (owned, charge) = super::request("SELECT $1, $2", &request, &memory).unwrap();
    assert_eq!(owned.statements[0].parameters, request);
    assert!(memory.available().0 < budget);
    assert!(super::request("SELECT $1", &request, &tiny).is_err());
    drop(owned);
    drop(charge);
    assert_eq!(memory.available(), (budget, budget));
}

#[test]
fn describe_execute_and_close_borrow_the_frontend_name() {
    use super::super::{close_native_target, parse_describe_message, parse_execute_message};
    let describe = "P日本語\0".as_bytes().to_vec();
    let (kind, name) = parse_describe_message(&describe).unwrap();
    assert_eq!(kind, b'P');
    assert_eq!(name, "日本語");
    assert_eq!(name.as_ptr(), describe[1..].as_ptr());
    let mut execute = "日本語\0".as_bytes().to_vec();
    execute.extend(9u32.to_be_bytes());
    let (name, count) = parse_execute_message(&execute).unwrap();
    assert_eq!(name, "日本語");
    assert_eq!(count, 9);
    assert_eq!(name.as_ptr(), execute.as_ptr());
    assert!(parse_describe_message(b"Ps\0x").is_err());
    assert!(parse_execute_message(b"p\0").is_err());
    close_native_target(b"Ss\0", &mut HashMap::new(), &mut HashMap::new()).unwrap();
}

struct Spy(Arc<AtomicUsize>);
impl AsyncRead for Spy {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        let bytes = [7; 256];
        let count = buf.remaining().min(bytes.len());
        buf.put_slice(&bytes[..count]);
        Poll::Ready(Ok(()))
    }
}
struct Pending(Option<tokio::sync::oneshot::Sender<()>>);
impl AsyncRead for Pending {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(ready) = self.0.take() {
            ready.send(()).unwrap();
        }
        Poll::Pending
    }
}

#[tokio::test]
async fn frame_admission_precedes_read_and_survives_until_abort_or_release() {
    if !child(
        "CHIRON_PG_FRONTEND_QUOTA_CHILD",
        "wire_postgres::frontend::tests::frame_admission_precedes_read_and_survives_until_abort_or_release",
    ) {
        return;
    }
    small_profile();
    let held = ResponseReservation::new(90 * 1024).unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let mut spy = Spy(polls.clone());
    assert!(
        read(&mut spy, 48 * 1024, super::super::MAX_MESSAGE_LEN)
            .await
            .is_err()
    );
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert!(read(&mut spy, 17, 16).await.is_err());
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    drop(held);
    let bytes = read(&mut spy, 90 * 1024, super::super::MAX_MESSAGE_LEN)
        .await
        .unwrap();
    assert!(bytes.as_ref().iter().all(|b| *b == 7));
    assert!(ResponseReservation::new(64 * 1024).is_err());
    drop(bytes);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        read(
            &mut Pending(Some(ready)),
            90 * 1024,
            super::super::MAX_MESSAGE_LEN,
        )
        .await
    });
    timeout(Duration::from_secs(3), started)
        .await
        .unwrap()
        .unwrap();
    assert!(ResponseReservation::new(64 * 1024).is_err());
    task.abort();
    assert!(task.await.err().unwrap().is_cancelled());
    assert!(ResponseReservation::new(120 * 1024).is_ok());
    assert!(read(&mut &b""[..], 8, 16).await.is_err());
    assert!(ResponseReservation::new(120 * 1024).is_ok());
    let mut stream = &[4u8; 8193][..];
    discard(&mut stream, 8192).await.unwrap();
    assert_eq!(stream, &[4]);

    let held = ResponseReservation::new(120 * 1024).unwrap();
    let mut writer = tokio::io::BufWriter::new(Vec::new());
    let verifier = chirondb_core::security::SqlVerifier {
        id: "test".into(),
        salt: [0; 16],
        stored_key: [0; 32],
        server_key: [0; 32],
        iterations: 4096,
    };
    assert!(
        super::super::scram::authenticate(&mut &b""[..], &mut writer, &verifier)
            .await
            .is_err()
    );
    assert!(
        writer.get_ref().is_empty(),
        "SCRAM must reserve before writing its first challenge"
    );
    super::super::write_error_response(&mut writer, "ERROR", "53200", "overloaded", None)
        .await
        .unwrap();
    super::super::write_command_complete(&mut writer, "ROLLBACK")
        .await
        .unwrap();
    super::super::write_ready_for_query(&mut writer, b'I')
        .await
        .unwrap();
    writer.flush().await.unwrap();
    assert!(writer.get_ref().windows(9).any(|s| s == b"ROLLBACK\0"));
    let large = "x".repeat(20 * 1024);
    assert!(
        super::super::write_error_response(&mut writer, "ERROR", "42601", &large, None)
            .await
            .is_err()
    );
    assert!(writer.get_ref().windows(6).any(|s| s == b"53200\0"));
    drop(held);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
}

fn wire(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend(((body.len() + 4) as u32).to_be_bytes());
    bytes.extend(body);
    bytes
}
#[tokio::test]
async fn control_frames_match_independent_protocol_bytes_and_limits() {
    use super::super::{
        write_command_complete, write_error_response, write_parameter_description,
        write_required_parameter_status,
    };
    let mut bytes = Vec::new();
    write_parameter_description(&mut bytes, &[20, 3802])
        .await
        .unwrap();
    assert_eq!(bytes, wire(b't', &[0, 2, 0, 0, 0, 20, 0, 0, 14, 218]));
    bytes.clear();
    write_command_complete(&mut bytes, "DELETE 7")
        .await
        .unwrap();
    assert_eq!(bytes, wire(b'C', b"DELETE 7\0"));
    bytes.clear();
    write_error_response(&mut bytes, "ERROR", "42601", "雪", Some("hint"))
        .await
        .unwrap();
    assert_eq!(
        bytes,
        wire(b'E', "SERROR\0VERROR\0C42601\0M雪\0Hhint\0\0".as_bytes())
    );
    bytes.clear();
    write_required_parameter_status(&mut bytes).await.unwrap();
    let mut expected = Vec::new();
    for (name, value) in [
        ("server_version", super::super::SERVER_VERSION_STRING),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("TimeZone", "UTC"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
        ("is_superuser", "off"),
        ("session_authorization", "gaussdb"),
        ("application_name", ""),
    ] {
        expected.extend(wire(b'S', format!("{name}\0{value}\0").as_bytes()));
    }
    assert_eq!(bytes, expected);
    assert_eq!(output::control(b'C', 1019).unwrap().as_ref().len(), 1024);
    assert_eq!(output::control(b'C', 1020).unwrap().as_ref().len(), 1025);
    assert!(output::control(b'C', usize::MAX).is_err());
    assert!(output::control(b'C', super::super::MAX_MESSAGE_LEN - 3).is_err());
}

#[test]
fn backend_registry_admission_and_last_removal_release_memory() {
    if !child(
        "CHIRON_PG_REGISTRY_QUOTA_CHILD",
        "wire_postgres::frontend::tests::backend_registry_admission_and_last_removal_release_memory",
    ) {
        return;
    }
    small_profile();
    let held = ResponseReservation::new(120 * 1024).unwrap();
    let backend = super::super::register_backend().unwrap();
    let pid = backend.pid;
    let secret = backend.secret;
    assert!(
        super::super::BACKEND_CANCELLATIONS
            .lock()
            .unwrap()
            .contains_key(&pid)
    );
    assert!(super::super::register_backend().is_err());
    drop(backend);
    assert!(
        super::super::BACKEND_CANCELLATIONS
            .lock()
            .unwrap()
            .is_empty()
    );
    super::super::cancel_backend(pid, secret);
    let backend = super::super::register_backend().unwrap();
    drop(backend);
    drop(held);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
}

async fn send(client: &mut tokio::io::DuplexStream, kind: u8, body: &[u8]) {
    client.write_all(&wire(kind, body)).await.unwrap();
}
async fn message(client: &mut tokio::io::DuplexStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    timeout(Duration::from_secs(5), client.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let count = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize - 4;
    assert!(count < 1024 * 1024);
    let mut bytes = vec![0; count];
    client.read_exact(&mut bytes).await.unwrap();
    (header[0], bytes)
}
async fn query(client: &mut tokio::io::DuplexStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    send(client, b'Q', format!("{sql}\0").as_bytes()).await;
    let mut out = Vec::new();
    loop {
        let item = message(client).await;
        let done = item.0 == b'Z';
        out.push(item);
        if done {
            return out;
        }
    }
}
fn parse(name: &str, sql: &str) -> Vec<u8> {
    let mut bytes = format!("{name}\0{sql}\0").into_bytes();
    bytes.extend(0i16.to_be_bytes());
    bytes
}
fn bind(name: &str, statement: &str) -> Vec<u8> {
    let mut bytes = format!("{name}\0{statement}\0").into_bytes();
    bytes.extend([0; 6]);
    bytes
}

#[tokio::test]
async fn native_session_object_limits_keep_sync_close_and_rollback_reachable() {
    use super::super::{AuthConfig, Db, PROTOCOL_V3, handle_connection};
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let (server, mut client) = tokio::io::duplex(65536);
    let body = b"user\0alice\0database\0db\0\0";
    let mut prefix = [0; 8];
    prefix[..4].copy_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    prefix[4..].copy_from_slice(&PROTOCOL_V3.to_be_bytes());
    let handler = tokio::spawn(handle_connection(
        db,
        AuthConfig::disabled(),
        server,
        prefix,
    ));
    client.write_all(body).await.unwrap();
    while message(&mut client).await.0 != b'Z' {}
    assert!(
        query(&mut client, "CREATE TABLE items (id BIGINT PRIMARY KEY)")
            .await
            .iter()
            .all(|m| m.0 != b'E')
    );
    for n in 0..MAX_SESSION_OBJECTS {
        send(&mut client, b'P', &parse(&format!("s{n}"), "SELECT 1")).await;
        assert_eq!(message(&mut client).await.0, b'1');
    }
    send(&mut client, b'P', &parse("overflow", "SELECT 2")).await;
    let error = message(&mut client).await;
    assert_eq!(error.0, b'E');
    assert!(error.1.windows(6).any(|s| s == b"54000\0"));
    send(&mut client, b'Q', b"INSERT INTO items VALUES (1)\0").await;
    send(&mut client, b'S', &[]).await;
    assert_eq!(message(&mut client).await, (b'Z', vec![b'I']));
    let count = query(&mut client, "SELECT COUNT(*) FROM items").await;
    let data = &count.iter().find(|m| m.0 == b'D').unwrap().1;
    assert_eq!(&data[6..], b"0");
    send(&mut client, b'P', &parse("s0", "SELECT 9")).await;
    assert_eq!(message(&mut client).await.0, b'1');
    send(&mut client, b'C', b"Ss0\0").await;
    assert_eq!(message(&mut client).await.0, b'3');
    send(&mut client, b'P', &parse("overflow", "SELECT 2")).await;
    assert_eq!(message(&mut client).await.0, b'1');
    assert!(
        query(&mut client, "DEALLOCATE ALL")
            .await
            .iter()
            .all(|m| m.0 != b'E')
    );
    send(&mut client, b'P', &parse("s", "SELECT 1")).await;
    assert_eq!(message(&mut client).await.0, b'1');
    for n in 0..MAX_SESSION_OBJECTS {
        send(&mut client, b'B', &bind(&format!("p{n}"), "s")).await;
        assert_eq!(message(&mut client).await.0, b'2');
    }
    send(&mut client, b'B', &bind("overflow", "s")).await;
    let error = message(&mut client).await;
    assert_eq!(error.0, b'E');
    assert!(error.1.windows(6).any(|s| s == b"54000\0"));
    send(&mut client, b'S', &[]).await;
    assert_eq!(message(&mut client).await, (b'Z', vec![b'I']));
    send(&mut client, b'B', &bind("p0", "s")).await;
    assert_eq!(message(&mut client).await.0, b'2');
    send(&mut client, b'C', b"Pp1\0").await;
    assert_eq!(message(&mut client).await.0, b'3');
    send(&mut client, b'B', &bind("overflow", "s")).await;
    assert_eq!(message(&mut client).await.0, b'2');
    assert!(
        query(&mut client, "DEALLOCATE ALL")
            .await
            .iter()
            .all(|m| m.0 != b'E')
    );
    assert_eq!(
        query(&mut client, "BEGIN").await.last().unwrap(),
        &(b'Z', vec![b'T'])
    );
    send(&mut client, b'P', &parse("bad", "not SQL")).await;
    assert_eq!(message(&mut client).await.0, b'E');
    send(&mut client, b'S', &[]).await;
    assert_eq!(message(&mut client).await, (b'Z', vec![b'E']));
    assert_eq!(
        query(&mut client, "ROLLBACK").await.last().unwrap(),
        &(b'Z', vec![b'I'])
    );
    send(&mut client, b'X', &[]).await;
    assert!(handler.await.unwrap().is_ok());
}
