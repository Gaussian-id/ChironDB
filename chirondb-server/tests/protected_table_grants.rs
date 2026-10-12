#[allow(dead_code)]
mod common;

use chirondb::{Db, api, auth::AuthConfig, grpc, security::onboarding, wire};
use grpc::{
    chiron_pb as pb,
    pb::{WireChironQlRequest, wire_request},
};
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn table_grants_share_http_grpc_and_wire_authority_without_a_vector_collection() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.join("data");
    let key_path = root.join("admin.key");
    onboarding::initialize(
        &data,
        "acme",
        "admin",
        &root.join("storage.json"),
        &key_path,
        false,
    )
    .unwrap();
    let secret = std::fs::read_to_string(&key_path).unwrap();
    let secret = secret.trim();
    let mut db = Db::open(&data).unwrap();
    db.migrate_table_authority_offline().unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let actor = || authority.authenticate(secret).unwrap();
    db.execute_sql_authorized(&actor(), serde_json::from_value(json!({"statements":[{"sql":"CREATE TABLE sql_only (id BIGINT PRIMARY KEY, title TEXT)"}]})).unwrap(), "test").unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    authority
        .create_role(&actor(), authority.revision(), "writer")
        .unwrap();
    authority
        .assign_role(&actor(), authority.revision(), "writer", "admin", true)
        .unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/chironql", http.local_addr().unwrap());
    let router = api::router_with_auth(db.clone(), AuthConfig::disabled());
    let http_task = tokio::spawn(async move { axum::serve(http, router).await.unwrap() });
    let client = reqwest::Client::new();
    for query in [
        "SQL CREATE TABLE IF NOT EXISTS sql_only (id BIGINT PRIMARY KEY, title TEXT);".to_string(),
        format!(
            "GRANT CREATE ON TABLE sql_only TO ROLE writer IF REVISION {};",
            authority.revision()
        ),
    ] {
        let response = client
            .post(&url)
            .bearer_auth(secret)
            .json(&json!({"query":query,"confirm":true}))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{}",
            response.text().await.unwrap()
        );
    }
    let grpc_addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let served = db.clone();
    let grpc_task = tokio::spawn(async move { grpc::serve(served, grpc_addr).await.unwrap() });
    let mut grpc_client =
        pb::chiron_db_client::ChironDbClient::new(common::connect_grpc_channel(grpc_addr).await);
    grpc_client
        .execute_query(common::grpc_auth_request(
            pb::ChironQlRequest {
                query: format!(
                    "GRANT READ ON TABLE sql_only TO ROLE writer IF REVISION {};",
                    authority.revision()
                ),
                confirm: true,
                ..Default::default()
            },
            secret,
        ))
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wire_address = listener.local_addr().unwrap().to_string();
    let served = db.clone();
    let wire_task = tokio::spawn(async move {
        wire::serve_listener_with_auth(served, AuthConfig::disabled(), listener)
            .await
            .unwrap()
    });
    let response = common::send_wire_with_key(
        &wire_address,
        1,
        secret,
        wire_request::Operation::Chironql(WireChironQlRequest {
            query: format!(
                "GRANT UPDATE, DELETE ON TABLE sql_only TO ROLE writer IF REVISION {};",
                authority.revision()
            ),
            confirm: true,
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.error_code, "", "{}", response.error_message);
    let response = client
        .post(&url)
        .bearer_auth(secret)
        .json(&json!({"query":"SQL INSERT INTO sql_only VALUES (1, 'public-transport');"}))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let rows = grpc_client
        .execute_query(common::grpc_auth_request(
            pb::ChironQlRequest {
                query: "SQL SELECT title FROM sql_only WHERE id=1;".into(),
                ..Default::default()
            },
            secret,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rows.rows_json.len(), 1);
    let privileges = client
        .post(&url)
        .bearer_auth(secret)
        .json(&json!({"query":"SHOW CURRENT USER PRIVILEGES;"}))
        .send()
        .await
        .unwrap();
    assert!(privileges.status().is_success());
    assert!(privileges.text().await.unwrap().contains("sql_only"));
    let revoked = common::send_wire_with_key(
        &wire_address,
        2,
        secret,
        wire_request::Operation::Chironql(WireChironQlRequest {
            query: format!(
                "REVOKE READ ON TABLE sql_only FROM ROLE writer IF REVISION {};",
                authority.revision()
            ),
            confirm: true,
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(revoked.error_code, "", "{}", revoked.error_message);
    let denied = grpc_client
        .execute_query(common::grpc_auth_request(
            pb::ChironQlRequest {
                query: "SQL SELECT title FROM sql_only;".into(),
                ..Default::default()
            },
            secret,
        ))
        .await;
    assert!(denied.is_err());
    http_task.abort();
    grpc_task.abort();
    wire_task.abort();
}
