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
    assert_eq!(
        server
            .execute("get_document", args, &principal, Instant::now())
            .await
            .unwrap_err(),
        "not_found"
    );
}
