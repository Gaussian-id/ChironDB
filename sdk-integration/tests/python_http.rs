use chirondb::{Db, api};
use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;
use tokio::net::TcpListener;

#[tokio::test]
async fn python_http_client_smoke() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });

    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../chirondb-server/tests/http_python_client_smoke.py");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .arg(script)
            .arg(format!("http://{addr}"))
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "python HTTP client smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["python_http_client"], "ok");

    server.abort();
}
