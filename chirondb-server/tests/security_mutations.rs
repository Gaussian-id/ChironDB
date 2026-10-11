//! Adversarial tenant mutation regressions, originally reproduced during the security review.
use chirondb::tenant::{TenantCapability, TenantEnforcement, TenantScope};
use chirondb::{CollectionConfig, Db, DistanceMetric, Filter, Point};
use serde_json::json;
use tempfile::TempDir;

fn setup() -> (TempDir, Db) {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.create_collection(CollectionConfig {
        name: "docs".into(),
        vector_dim: 2,
        metric: DistanceMetric::L2,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .unwrap();
    db.upsert("docs", vec![point("a", "acme"), point("b", "globex")])
        .unwrap();
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    (dir, db)
}
fn point(id: &str, tenant: &str) -> Point {
    Point {
        id: id.into(),
        vector: vec![1.0, 0.0],
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({"tenant_id": tenant, "department": "HR"}),
    }
}
fn owner(db: &Db) -> Option<String> {
    db.get_points_scoped("docs", &["b".into()], &TenantScope::system())
        .unwrap()
        .first()
        .map(|p| p.payload["tenant_id"].as_str().unwrap().to_string())
}

#[test]
fn foreign_existing_id_must_not_be_overwritten_by_upsert() {
    let (_dir, db) = setup();
    let outcome = db.upsert_scoped(
        "docs",
        vec![point("b", "acme")],
        true,
        &TenantScope::tenant("writer-a", "acme"),
    );
    eprintln!("upsert outcome={outcome:?}; owner_after={:?}", owner(&db));
    assert_eq!(
        owner(&db).as_deref(),
        Some("globex"),
        "foreign owner must survive"
    );
}

#[test]
fn cross_read_must_not_authorize_foreign_delete_by_id() {
    let (_dir, db) = setup();
    let scope =
        TenantScope::tenant("reader-writer-a", "acme").with_capability(TenantCapability::CrossRead);
    let outcome = db.delete_scoped("docs", &["b".into()], &scope);
    eprintln!("delete outcome={outcome:?}; owner_after={:?}", owner(&db));
    assert_eq!(
        owner(&db).as_deref(),
        Some("globex"),
        "cross_read grants no cross_write"
    );
}

#[test]
fn cross_read_must_not_authorize_foreign_filtered_delete() {
    let (_dir, db) = setup();
    let scope =
        TenantScope::tenant("reader-writer-a", "acme").with_capability(TenantCapability::CrossRead);
    let outcome =
        db.delete_by_filter_scoped("docs", &Filter(json!({"tenant_id":"globex"})), &scope);
    eprintln!(
        "filtered delete outcome={outcome:?}; owner_after={:?}",
        owner(&db)
    );
    assert_eq!(
        owner(&db).as_deref(),
        Some("globex"),
        "filter reads must not authorize writes"
    );
}

#[tokio::test]
async fn authenticated_http_aliases_must_preserve_foreign_ownership() {
    use chirondb::{
        api,
        auth::AuthConfig,
        rbac::{ApiKeyEntry, RbacConfig, Role},
    };
    let mut violations = Vec::new();
    for prefix in ["", "/v1"] {
        for operation in ["upsert", "delete", "delete/filter"] {
            let (_dir, db) = setup();
            let key = "synthetic-research-api-key-0000000001";
            let auth = AuthConfig::from_optional_key(Some(key.into()))
                .with_validated_rbac(
                    RbacConfig {
                        keys: vec![ApiKeyEntry {
                            id: Some("research-writer".into()),
                            key: key.into(),
                            tenant_id: Some("acme".into()),
                            role: Role::ReadWrite,
                            allowed_collections: vec!["docs".into()],
                            max_collections: None,
                            capabilities: if operation == "upsert" {
                                vec![]
                            } else {
                                vec!["tenant:cross_read".into()]
                            },
                        }],
                    },
                    true,
                )
                .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let served = db.clone();
            let server = tokio::spawn(async move {
                api::serve_listener_with_auth(served, auth, listener)
                    .await
                    .unwrap();
            });
            let client = reqwest::Client::new();
            let base = format!("http://{address}{prefix}/collections/docs/points");
            let request = match operation {
                "upsert" => client
                    .put(format!("{base}?wait=true"))
                    .json(&json!({"points": [point("b", "acme")]})),
                "delete" => client
                    .post(format!("{base}/delete"))
                    .json(&json!({"ids":["b"]})),
                _ => client
                    .post(format!("{base}/delete/filter"))
                    .json(&json!({"filter":{"tenant_id":"globex"}})),
            };
            let response = request
                .header("x-gaussdb-api-key", key)
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            let owner_after = owner(&db);
            eprintln!(
                "HTTP prefix={prefix:?} operation={operation} status={status} body={body} owner_after={owner_after:?}"
            );
            server.abort();
            if owner_after.as_deref() != Some("globex") {
                violations.push(format!("{prefix}/{operation}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "authenticated mutation violations: {violations:?}"
    );
}

#[test]
fn mixed_batch_refusal_is_atomic_and_survives_restart() {
    for sealed in [false, true] {
        let (dir, db) = setup();
        if sealed {
            db.compact_collection("docs").unwrap();
        }
        let scope = TenantScope::tenant("writer-a", "acme");
        let mut own = point("a", "acme");
        own.payload["department"] = json!("modified");
        assert!(
            db.upsert_scoped("docs", vec![own, point("b", "acme")], true, &scope)
                .is_err()
        );
        assert!(
            db.delete_scoped("docs", &["a".into(), "b".into()], &scope)
                .is_err()
        );
        assert_eq!(
            db.get_points_scoped("docs", &["a".into()], &scope).unwrap()[0].payload["department"],
            "HR"
        );
        drop(db);
        let reopened = Db::open(dir.path()).unwrap();
        assert_eq!(
            reopened
                .get_points("docs", &["a".into(), "b".into()])
                .unwrap()
                .len(),
            2
        );
        assert_eq!(owner(&reopened).as_deref(), Some("globex"));
    }
}

fn enable_graph(db: &Db) {
    db.set_graph_lifecycle_scoped("docs", true, true, &TenantScope::system())
        .unwrap();
    db.configure_edge_type_scoped(
        "docs",
        chirondb::graph::ConfigureEdgeTypeRequest {
            name: "references".into(),
            weight_property: None,
        },
        true,
        &TenantScope::system(),
    )
    .unwrap();
}

#[test]
fn deferred_session_cannot_be_finished_or_used_by_another_principal() {
    for other_tenant in ["acme", "globex"] {
        let (_dir, db) = setup();
        enable_graph(&db);
        let owner = TenantScope::tenant("owner", "acme");
        let other = TenantScope::tenant("other", other_tenant);
        let session = db
            .open_deferred_graph_session_scoped("docs", true, &owner)
            .unwrap()
            .session_id;
        assert!(
            db.upsert_deferred_scoped(
                "docs",
                &session,
                vec![point("new", other_tenant)],
                true,
                &other
            )
            .is_err(),
            "another principal used deferred session"
        );
        assert!(
            db.abort_deferred_graph_session_scoped("docs", &session, true, &other)
                .is_err(),
            "another principal aborted deferred session"
        );
        db.commit_deferred_graph_session_scoped("docs", &session, true, &owner)
            .unwrap();
    }
}

#[test]
fn graph_idempotency_replay_requires_current_endpoint_authorization() {
    let (_dir, db) = setup();
    enable_graph(&db);
    let privileged =
        TenantScope::tenant("writer", "acme").with_capability(TenantCapability::CrossWrite);
    let request = chirondb::graph::RelateRequest {
        source_point_id: "a".into(),
        target_point_id: "b".into(),
        edge_type: "references".into(),
        properties: json!({}),
        scope: chirondb::graph::GraphRelationScope::AdminCrossTenant,
        idempotency_key: Some("known-key".into()),
    };
    db.relate_scoped("docs", request.clone(), true, &privileged)
        .unwrap();
    let revoked = TenantScope::tenant("writer", "acme");
    assert!(
        db.relate_scoped("docs", request.clone(), true, &revoked)
            .is_err(),
        "retry leaked the old edge after losing cross-write"
    );
    let other = TenantScope::tenant("other", "acme");
    assert!(
        db.relate_scoped("docs", request, true, &other).is_err(),
        "retry leaked another principal's edge"
    );
}

#[test]
fn deferred_session_owner_survives_wal_and_checkpoint_recovery() {
    for checkpoint in [false, true] {
        let (dir, db) = setup();
        enable_graph(&db);
        let owner = TenantScope::tenant("owner", "acme");
        let session = db
            .open_deferred_graph_session_scoped("docs", true, &owner)
            .unwrap()
            .session_id;
        if checkpoint {
            db.compact_collection("docs").unwrap();
        }
        drop(db);
        let db = Db::open(dir.path()).unwrap();
        db.set_tenant_enforcement(TenantEnforcement::Enforced);
        assert!(
            db.commit_deferred_graph_session_scoped(
                "docs",
                &session,
                true,
                &TenantScope::tenant("other", "acme")
            )
            .is_err()
        );
        db.commit_deferred_graph_session_scoped("docs", &session, true, &owner)
            .unwrap();
    }
}

#[test]
fn idempotency_keys_are_scoped_to_principal_and_deleted_edges_are_not_replayed() {
    let (_dir, db) = setup();
    enable_graph(&db);
    let owner = TenantScope::tenant("owner", "acme");
    let peer = TenantScope::tenant("peer", "acme");
    let request = chirondb::graph::RelateRequest {
        source_point_id: "a".into(),
        target_point_id: "a".into(),
        edge_type: "references".into(),
        properties: json!({}),
        scope: chirondb::graph::GraphRelationScope::Local,
        idempotency_key: Some("shared-retry-key".into()),
    };
    let first = db
        .relate_scoped("docs", request.clone(), true, &owner)
        .unwrap();
    let second = db
        .relate_scoped("docs", request.clone(), true, &peer)
        .unwrap();
    assert_ne!(first.edge_id, second.edge_id);
    assert!(!second.receipt.replayed);
    db.unrelate_scoped("docs", &first.edge_id, true, &owner)
        .unwrap();
    assert!(db.relate_scoped("docs", request, true, &owner).is_err());
}

#[tokio::test]
async fn tenant_writer_cannot_manage_collections_or_read_global_metrics() {
    use chirondb::{
        api,
        auth::AuthConfig,
        rbac::{ApiKeyEntry, RbacConfig, Role},
    };
    let (_dir, db) = setup();
    let key = "synthetic-regression-api-key-0000000001";
    let auth = AuthConfig::from_optional_key(Some(key.into()))
        .with_validated_rbac(
            RbacConfig {
                keys: vec![ApiKeyEntry {
                    id: Some("tenant-writer".into()),
                    key: key.into(),
                    tenant_id: Some("acme".into()),
                    role: Role::ReadWrite,
                    allowed_collections: vec!["docs".into()],
                    max_collections: None,
                    capabilities: vec![],
                }],
            },
            true,
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = db.clone();
    let server = tokio::spawn(async move {
        api::serve_listener_with_auth(served, auth, listener)
            .await
            .unwrap();
    });
    let client = reqwest::Client::new();
    for prefix in ["", "/v1"] {
        for (method, path, body) in [
            (reqwest::Method::DELETE, "/collections/docs", json!({})),
            (
                reqwest::Method::PUT,
                "/collections/docs/payload_schema",
                json!({"payload_schema":{}}),
            ),
            (
                reqwest::Method::POST,
                "/collections/docs/compact",
                json!({}),
            ),
            (reqwest::Method::GET, "/metrics", json!({})),
        ] {
            let response = client
                .request(method, format!("http://{address}{prefix}{path}"))
                .header("x-chirondb-api-key", key)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::FORBIDDEN,
                "{prefix}{path}"
            );
        }
    }
    assert_eq!(owner(&db).as_deref(), Some("globex"));
    server.abort();
}
