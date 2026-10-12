#![cfg(unix)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use chirondb::{Db, grpc::pb};
use prost::Message;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn wait_ready(child: &mut Child, addresses: &[SocketAddr]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "server exited before readiness"
        );
        if addresses
            .iter()
            .all(|address| TcpStream::connect_timeout(address, Duration::from_millis(100)).is_ok())
        {
            thread::sleep(Duration::from_millis(50));
            return;
        }
        assert!(Instant::now() < deadline, "server readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate(child: &mut Child) -> Duration {
    let started = Instant::now();
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let deadline = started + Duration::from_secs(12);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "server exceeded shutdown deadline"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "unexpected shutdown status: {status}");
    started.elapsed()
}

#[test]
fn sigterm_finishes_cleanly_within_the_process_deadline() {
    let directory = TempDir::new().unwrap();
    let http = unused_address();
    let grpc = unused_address();
    let wire = unused_address();
    let mut child = Command::new(env!("CARGO_BIN_EXE_chirondb"))
        .args([
            "--data-dir",
            directory.path().to_str().unwrap(),
            "--listen-http",
            &http.to_string(),
            "--listen-grpc",
            &grpc.to_string(),
            "--listen-wire",
            &wire.to_string(),
            "--drift-monitor-interval-secs",
            "0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(&mut child, &[http, grpc, wire]);

    let elapsed = terminate(&mut child);
    assert!(elapsed < Duration::from_secs(12));

    let reopened = Db::open(directory.path()).unwrap();
    assert!(reopened.durability_ready());
}

fn accepted_idle_wire_connection(address: &SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect_timeout(address, Duration::from_secs(1)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let request = pb::WireRequest {
        request_id: 1,
        operation: Some(pb::wire_request::Operation::Health(pb::HealthRequest {})),
        ..Default::default()
    };
    let payload = request.encode_to_vec();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 1024, "unexpected health response size");
    let mut response = vec![0; length];
    stream.read_exact(&mut response).unwrap();
    let response = pb::WireResponse::decode(response.as_slice()).unwrap();
    assert_eq!(response.request_id, request.request_id);
    assert!(response.error_code.is_empty());
    assert!(matches!(
        response.payload,
        Some(pb::wire_response::Payload::Health(_))
    ));
    stream
}

#[test]
fn sigterm_bounds_five_hundred_idle_wire_connections() {
    let directory = TempDir::new().unwrap();
    let http = unused_address();
    let grpc = unused_address();
    let wire = unused_address();
    let mut child = Command::new(env!("CARGO_BIN_EXE_chirondb"))
        .args([
            "--data-dir",
            directory.path().to_str().unwrap(),
            "--listen-http",
            &http.to_string(),
            "--listen-grpc",
            &grpc.to_string(),
            "--listen-wire",
            &wire.to_string(),
            "--drift-monitor-interval-secs",
            "0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(&mut child, &[http, grpc, wire]);
    let setup = Instant::now();
    let connections = (0..500)
        .map(|_| {
            assert!(setup.elapsed() < Duration::from_secs(30));
            accepted_idle_wire_connection(&wire)
        })
        .collect::<Vec<_>>();
    thread::sleep(Duration::from_millis(100));

    let elapsed = terminate(&mut child);

    assert!(elapsed >= Duration::from_secs(4));
    assert!(elapsed < Duration::from_secs(12));
    drop(connections);
    let reopened = Db::open(directory.path()).unwrap();
    assert!(reopened.durability_ready());
}

#[tokio::test]
async fn draining_http_rejects_new_work_before_listener_exit() {
    let directory = TempDir::new().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let address = unused_address();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(chirondb::api::serve_with_options_until(
        db.clone(),
        chirondb::auth::AuthConfig::disabled(),
        address,
        chirondb::api::ServerOptions::default(),
        shutdown.clone(),
    ));
    let client = reqwest::Client::new();
    let health = format!("http://{address}/health");
    for _ in 0..100 {
        if client.get(&health).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    db.begin_shutdown();
    let response = client
        .get(format!("http://{address}/v1/collections"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["code"], "server.shutting_down");
    assert_eq!(body["retryable"], true);
    assert_eq!(
        client.get(health).send().await.unwrap().status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("HTTP server did not finish after cancellation")
        .unwrap()
        .unwrap();
}
