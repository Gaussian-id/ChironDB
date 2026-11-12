//! Network regressions for credential redaction, session revocation and denial audit.
use chirondb::{Db, api, auth::AuthConfig, security::*, wire};
use std::{collections::BTreeSet, fs, path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn key() -> String {
    format!("synthetic-{}", uuid::Uuid::new_v4())
}

fn audit(root: &Path) -> String {
    fs::read_to_string(root.join("audit/audit.jsonl")).unwrap()
}

#[tokio::test]
async fn legacy_authenticated_audit_never_contains_the_bearer_key() {
    let root = tempfile::tempdir().unwrap();
    let db = Db::open(root.path()).unwrap();
    let key = key();
    let auth = AuthConfig::from_optional_key(Some(key.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = api::router_with_auth(db, auth);
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    for path in ["/collections", "/v1/collections"] {
        let denied = client
            .get(format!("http://{address}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
        let allowed = client
            .get(format!("http://{address}{path}"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(allowed.status(), reqwest::StatusCode::OK);
    }
    let contents = audit(root.path());
    assert!(contents.contains("http_authenticate"));
    assert!(
        !contents.contains(&key),
        "audit must never persist bearer credential"
    );
    server.abort();
}

async fn send(stream: &mut TcpStream, kind: u8, body: &[u8]) {
    stream.write_all(&[kind]).await.unwrap();
    stream
        .write_all(&((body.len() + 4) as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}

async fn receive(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    if stream.read_exact(&mut header).await.is_err() {
        return None;
    }
    let n = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!((4..=65536).contains(&n));
    let mut body = vec![0; n - 4];
    stream.read_exact(&mut body).await.unwrap();
    Some((header[0], body))
}

async fn connect(address: std::net::SocketAddr, key: &str) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut body = 196608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0synthetic\0database\0chiron\0\0");
    stream
        .write_all(&((body.len() + 4) as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&body).await.unwrap();
    let (kind, challenge) = receive(&mut stream).await.unwrap();
    assert_eq!(
        (kind, challenge.as_slice()),
        (b'R', 3u32.to_be_bytes().as_slice())
    );
    send(&mut stream, b'p', format!("{key}\0").as_bytes()).await;
    loop {
        let (kind, _) = receive(&mut stream).await.expect("authentication response");
        assert_ne!(kind, b'E', "synthetic valid credential must authenticate");
        if kind == b'Z' {
            break;
        }
    }
    stream
}

async fn query(stream: &mut TcpStream, sql: &str) -> Vec<(u8, Vec<u8>)> {
    send(stream, b'Q', format!("{sql}\0").as_bytes()).await;
    let mut messages = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), receive(stream))
            .await
            .unwrap();
        let Some(message) = message else {
            return messages;
        };
        let done = message.0 == b'Z' || message.0 == b'E';
        messages.push(message);
        if done {
            return messages;
        }
    }
}

fn succeeded(messages: &[(u8, Vec<u8>)]) -> bool {
    messages.iter().any(|(kind, _)| *kind == b'C')
        && !messages.iter().any(|(kind, _)| *kind == b'E')
}

#[tokio::test]
async fn legacy_pgwire_revocation_rejects_query_portal_and_commit_on_existing_connections() {
    for (mode, with_rbac) in [
        ("query", false),
        ("query", true),
        ("readd", true),
        ("portal", true),
        ("commit", true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let db = Db::open(root.path()).unwrap();
        let revoked = key();
        let retained = key();
        let keys = root.path().join("synthetic-keys");
        fs::write(&keys, format!("{revoked}\n{retained}\n")).unwrap();
        let mut auth = AuthConfig::from_key_sources(None, Some(keys.clone()));
        if with_rbac {
            auth = auth.with_rbac(chirondb::rbac::RbacConfig {
                keys: [&revoked, &retained]
                    .into_iter()
                    .enumerate()
                    .map(|(index, key)| chirondb::rbac::ApiKeyEntry {
                        id: Some(format!("stable-admin-{index}")),
                        key: key.clone(),
                        tenant_id: None,
                        role: chirondb::rbac::Role::Admin,
                        allowed_collections: vec![],
                        max_collections: None,
                        capabilities: vec![],
                    })
                    .collect(),
            });
        }
        let observer = auth.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            wire::serve_listener_with_auth(db, auth, listener)
                .await
                .unwrap()
        });
        let mut owner = connect(address, &revoked).await;
        assert!(succeeded(
            &query(
                &mut owner,
                "CREATE TABLE secret_rows (id INTEGER PRIMARY KEY);"
            )
            .await
        ));
        assert!(succeeded(
            &query(&mut owner, "INSERT INTO secret_rows VALUES (1);").await
        ));
        assert!(succeeded(
            &query(&mut owner, "SELECT id FROM secret_rows;").await
        ));
        let mut still_allowed = connect(address, &retained).await;
        if mode == "commit" {
            assert!(succeeded(&query(&mut owner, "BEGIN;").await));
            assert!(succeeded(
                &query(&mut owner, "INSERT INTO secret_rows VALUES (2);").await
            ));
        }
        if mode == "portal" {
            let mut parse = b"prepared\0SELECT id FROM secret_rows;\0".to_vec();
            parse.extend_from_slice(&0u16.to_be_bytes());
            send(&mut owner, b'P', &parse).await;
            send(&mut owner, b'H', &[]).await;
            assert_eq!(receive(&mut owner).await.unwrap().0, b'1');
            let mut bind = b"portal\0prepared\0".to_vec();
            bind.extend_from_slice(&[0; 6]);
            send(&mut owner, b'B', &bind).await;
            send(&mut owner, b'H', &[]).await;
            assert_eq!(receive(&mut owner).await.unwrap().0, b'2');
        }
        fs::write(&keys, format!("{retained}\n")).unwrap();
        if mode == "readd" {
            assert!(observer.permission_for(Some(&retained)).is_some());
            fs::write(&keys, format!("{revoked}\n{retained}\n")).unwrap();
            let mut replacement = connect(address, &revoked).await;
            assert!(succeeded(
                &query(&mut replacement, "SELECT id FROM secret_rows;").await
            ));
            send(&mut replacement, b'X', &[]).await;
        }
        let result = if mode == "portal" {
            let mut execute = b"portal\0".to_vec();
            execute.extend_from_slice(&0u32.to_be_bytes());
            send(&mut owner, b'E', &execute).await;
            // No Flush is required: rejection terminates the revoked connection.
            let mut messages = Vec::new();
            loop {
                let next = tokio::time::timeout(Duration::from_secs(5), receive(&mut owner))
                    .await
                    .unwrap();
                let Some(next) = next else {
                    break;
                };
                let done = matches!(next.0, b'C' | b'E');
                messages.push(next);
                if done {
                    break;
                }
            }
            messages
        } else {
            query(
                &mut owner,
                if mode == "commit" {
                    "COMMIT;"
                } else {
                    "SELECT id FROM secret_rows;"
                },
            )
            .await
        };
        assert!(!succeeded(&result), "revoked session succeeded: {mode}");
        assert!(
            !result.iter().any(|(kind, _)| *kind == b'D'),
            "revoked session published rows: {mode}"
        );
        let positive = query(&mut still_allowed, "SELECT id FROM secret_rows;").await;
        assert!(succeeded(&positive));
        assert_eq!(
            positive.iter().filter(|(kind, _)| *kind == b'D').count(),
            1,
            "revoked uncommitted write leaked"
        );
        send(&mut still_allowed, b'X', &[]).await;
        drop(owner);
        server.abort();
    }
}

#[tokio::test]
async fn protected_http_denials_are_audited_without_credential_material() {
    let root = tempfile::tempdir().unwrap();
    chirondb_core::storage_layout::initialize_empty(root.path()).unwrap();
    let admin = IdentityAuthority::bootstrap(
        root.path(),
        PrincipalRecord {
            id: "admin".into(),
            tenant: "acme".into(),
            enabled: true,
            attributes: SubjectAttributes {
                department: "Security".into(),
                clearance: Classification::Restricted,
            },
            grants: vec![],
            installation_actions: BTreeSet::from([Action::IdentityManage, Action::Observe]),
            delegation: vec![],
        },
    )
    .unwrap();
    let db = Db::open(root.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = api::router_with_auth(db, AuthConfig::disabled());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let invalid = key();
    let positive = client
        .get(format!("http://{address}/v1/security/whoami"))
        .bearer_auth(&admin.secret)
        .send()
        .await
        .unwrap();
    assert_eq!(positive.status(), reqwest::StatusCode::OK);
    for path in ["/security/whoami", "/v1/security/whoami"] {
        let negative = client
            .get(format!("http://{address}{path}"))
            .bearer_auth(&invalid)
            .send()
            .await
            .unwrap();
        assert_eq!(negative.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    let contents = audit(root.path());
    let failures: Vec<_> = contents
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["category"] == "authentication" && event["outcome"] == "failure")
        .collect();
    assert!(
        !failures.is_empty(),
        "protected authentication denial must be recorded"
    );
    for event in failures {
        assert_eq!(event["operation"], "http_authenticate");
        assert_eq!(event["principal_id"], "unknown");
        assert_eq!(event["transport"], "http");
        assert_eq!(event["error_code"], "invalid_credential");
        for field in ["collection", "tenant_id", "request_id"] {
            assert!(event[field].is_null());
        }
    }
    assert!(!contents.contains(&invalid));
    assert!(!contents.contains(&admin.secret));
    server.abort();
}
