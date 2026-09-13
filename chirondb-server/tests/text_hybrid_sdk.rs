use chirondb::{Db, TenantScope, TextHybridSearchRequest, api};
use chirondb_client::{ChironDbClient, TextHybridQuery};
use serde_json::json;
use tempfile::TempDir;

#[tokio::test]
async fn rust_sdk_matches_embedded_native_text_retrieval() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap())
        .unwrap();
    db.upsert(
        "docs",
        serde_json::from_value(json!([
            {"id":"a","vector":[1,0],"payload":{"text":"refund policy"}},
            {"id":"b","vector":[0,1],"payload":{"text":"delivery policy"}}
        ]))
        .unwrap(),
    )
    .unwrap();
    let expected = db
        .text_hybrid_search_scoped(
            "docs",
            TextHybridSearchRequest {
                vector: vec![1.0, 0.0],
                query: "refund".into(),
                text_field: "text".into(),
                k: 2,
                filter: None,
                budget_ms: None,
            },
            &TenantScope::system(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, api::router(db)).await.unwrap() });
    let client = ChironDbClient::new(format!("http://{address}"));
    let actual = client
        .text_hybrid_search(
            "docs",
            TextHybridQuery {
                vector: vec![1.0, 0.0],
                query: "refund".into(),
                text_field: "text".into(),
                k: 2,
                filter: None,
                budget_ms: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(actual.hits.len(), expected.hits.len());
    for (actual, expected) in actual.hits.iter().zip(&expected.hits) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.score, expected.score);
    }
    server.abort();
    let _ = server.await;
}
