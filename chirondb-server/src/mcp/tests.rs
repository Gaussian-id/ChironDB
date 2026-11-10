use super::*;
use crate::rbac::RbacConfig;
use tempfile::TempDir;

fn config() -> McpConfig {
    toml::from_str(
        r#"
        [embedding]
        endpoint = "http://127.0.0.1:9/v1/embeddings"
        [collections.docs]
        model = "fixture"
        dimensions = 2
        text_field = "text"
    "#,
    )
    .unwrap()
}

#[test]
fn operator_endpoint_and_authentication_boundaries() {
    for url in [
        "http://127.0.0.1:8000/v1/embeddings",
        "http://[::1]:8000/v1/embeddings",
        "https://embeddings.example/v1/embeddings",
    ] {
        assert!(validate_endpoint(url).is_ok(), "{url}");
    }
    for url in [
        "http://embeddings.example/v1/embeddings",
        "file:///model",
        "https://key:secret@example.com",
        "https://example.com/#secret",
    ] {
        assert!(validate_endpoint(url).is_err(), "{url}");
    }
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    assert!(McpServer::new(db.clone(), AuthConfig::disabled(), config()).is_err());
    assert!(
        McpServer::new(
            db,
            AuthConfig::from_optional_key(Some("test-key".into())),
            config()
        )
        .is_err()
    );
}

#[tokio::test]
async fn tenant_mode_and_model_dimensions_fail_before_embedding_io() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(serde_json::from_value(json!({"name":"docs","vector_dim":3})).unwrap())
        .unwrap();
    let key = "mcp-unit-test-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let rbac: RbacConfig = serde_json::from_value(json!({"keys":[{"id":"alice","key":key,"role":"read_only","tenant_id":"a","allowed_collections":["docs"]}]})).unwrap();
    let auth = AuthConfig::from_optional_key(Some(key.into())).with_rbac(rbac);
    let principal = auth.permission_for(Some(key)).unwrap();
    let server = McpServer::new(db.clone(), auth, config()).unwrap();
    let args = json!({"collection":"docs","query":"refund"});
    assert_eq!(
        server
            .execute("search_documents", args.clone(), &principal, Instant::now())
            .await
            .unwrap_err(),
        "tenant_enforcement_required"
    );
    db.set_tenant_enforcement(crate::TenantEnforcement::Enforced);
    assert_eq!(
        server
            .execute("search_documents", args, &principal, Instant::now())
            .await
            .unwrap_err(),
        "embedding_binding_mismatch"
    );
    let args = json!({"collection":"denied","query":"refund"});
    assert_eq!(
        server
            .execute("search_documents", args, &principal, Instant::now())
            .await
            .unwrap_err(),
        "access_denied"
    );
    let permits = server.workers.available_permits() as u32;
    let held = server.workers.acquire_many(permits).await.unwrap();
    let args = json!({"collection":"docs","id":"missing"});
    assert_eq!(
        server
            .execute("get_document", args.clone(), &principal, Instant::now())
            .await
            .unwrap_err(),
        "overloaded"
    );
    drop(held);
    let mut tenant_work = Vec::new();
    while let Some(work) = server.auth.try_begin_work(&principal) {
        tenant_work.push(work);
    }
    assert!(!tenant_work.is_empty());
    for (name, arguments) in [
        ("list_collections", json!({})),
        ("get_document", args.clone()),
    ] {
        assert_eq!(
            server
                .execute(name, arguments, &principal, Instant::now())
                .await
                .unwrap_err(),
            "overloaded"
        );
    }
    drop(tenant_work);
    assert_eq!(
        server
            .execute("get_document", args, &principal, Instant::now())
            .await
            .unwrap_err(),
        "not_found"
    );
}

#[tokio::test]
async fn http_boundary_rejects_unauthenticated_malformed_and_oversized_input() {
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    let key = "synthetic-mcp-boundary-key";
    let rbac: RbacConfig = serde_json::from_value(json!({"keys":[{
        "id":"reader", "key":key, "role":"read_only", "allowed_collections":["docs"]
    }]}))
    .unwrap();
    let auth = AuthConfig::from_optional_key(Some(key.into())).with_rbac(rbac);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/mcp", listener.local_addr().unwrap());
    let router = McpServer::new(db, auth, config()).unwrap().router();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let request = || {
        client
            .post(&endpoint)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2025-11-25")
    };
    let list = json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"});
    for supplied in [None, Some("wrong-synthetic-key")] {
        let mut req = request().json(&list);
        if let Some(supplied) = supplied {
            req = req.bearer_auth(supplied);
        }
        assert_eq!(req.send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
    let response = request().bearer_auth(key).json(&list).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = response.json().await.unwrap();
    assert_eq!(value["result"]["tools"].as_array().unwrap().len(), 3);
    assert_eq!(
        request()
            .bearer_auth(key)
            .body("{")
            .send()
            .await
            .unwrap()
            .status(),
        // rmcp's expect_json explicitly maps malformed JSON to HTTP 415.
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        request()
            .bearer_auth(key)
            .body(" ".repeat(64 * 1024 + 1))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // A rejected request must not poison the next authorized operation.
    assert_eq!(
        request()
            .bearer_auth(key)
            .json(&list)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    server.abort();
}

#[test]
fn result_publication_bounds_reject_or_truncate_without_losing_small_results() {
    let small = json!({"id":"visible", "text":"authorized"});
    assert_eq!(
        bounded(small.clone(), false).unwrap().structured_content,
        Some(small)
    );
    assert_eq!(
        bounded(json!({"text":"x".repeat(MAX_RESPONSE)}), false).unwrap_err(),
        "response_too_large"
    );
    let result = bounded(
        json!({"hits":[{"text":"x".repeat(MAX_RESPONSE)}, {"text":"small"}]}),
        true,
    )
    .unwrap();
    assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESPONSE);
    assert_eq!(result.structured_content.unwrap()["truncated"], true);
}

#[tokio::test]
async fn rejected_tool_names_are_not_retained_in_transport_schema_cache() {
    #[derive(Clone)]
    struct CountLookups(Arc<std::sync::atomic::AtomicUsize>);
    impl ServerHandler for CountLookups {
        fn get_info(&self) -> ServerConfig {
            server_info()
        }
        fn get_tool(&self, _: &str) -> Option<Tool> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = CountLookups(lookups.clone());
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route_service("/mcp", service))
            .await
            .unwrap()
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for id in 0..8 {
        // Missing standard method/name headers deliberately reject the request
        // after lookup. The old transport cached even these unknown names.
        let response = client
            .post(&endpoint)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":"tools/call",
                "params":{"name":format!("unknown-{}", id % 4), "arguments":{}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(lookups.load(Ordering::Relaxed), 8);
    server.abort();
}
