use chirondb::tenant::TenantEnforcement;
use chirondb::{Db, api};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

#[tokio::test]
async fn removed_foundation_models_are_rejected_before_scheduling() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    for model in ["TABFM", "CAUSILO"] {
        let response = http
            .post(format!("{base}/v1/chironql"))
            .json(&json!({"query": format!("ML MATERIALIZE gated_view FROM source TARGET label FEATURES (feature) TASK CLASSIFICATION USING {model};")}))
            .send()
            .await
            .unwrap();
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "chironql.ml_model");
        assert!(body["error"].as_str().unwrap().contains("DECISION_TREE"));
    }
    server.abort();
}

#[tokio::test]
async fn tenant_enforcement_denies_unscoped_ml_routes() {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    let http = reqwest::Client::new();
    for path in ["/v1/ml/jobs/00000000", "/ml/views/secret_view"] {
        let response = http.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
    let response = http
        .post(format!("{base}/v1/chironql"))
        .json(&json!({"query":"ML MATERIALIZE secret_view FROM source TARGET label FEATURES (feature) TASK REGRESSION USING DECISION_TREE;"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "chironql.ml_tenant_unsupported");
    server.abort();
}
