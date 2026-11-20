//! RT-11/12/13/50/61: the legacy admin plane under tenant enforcement.
//!
//! Collections are one namespace shared by every tenant. A tenant-bound
//! `admin` key administers its tenant, not the installation: destroying,
//! reshaping or snapshotting a shared collection needs installation authority
//! (no `tenant_id`, or the explicit `installation:admin` capability). With
//! enforcement off nothing changes.

#[allow(dead_code)]
mod common;

use std::{net::SocketAddr, path::Path};

use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, api,
    auth::AuthConfig,
    grpc::{self, GrpcServerOptions, pb, pb::wire_request},
    rbac::{ApiKeyEntry, RbacConfig, Role},
    security_paths::StoragePolicy,
    tenant::{TenantEnforcement, TenantScope},
    wire,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tonic::Code;

const COLLECTION: &str = "docs";
const OTHER: &str = "other";

const OPS: &str = "installation-ops-key-000000000000000000";
const TB_ADMIN: &str = "tenant-b-admin-key-0000000000000000000";
const TB_INSTALL: &str = "tenant-b-install-key-00000000000000000";
const TB_WRITER: &str = "tenant-b-writer-key-0000000000000000000";
const TA_READER: &str = "tenant-a-reader-key-0000000000000000000";
const TA_AUDITOR: &str = "tenant-a-auditor-key-000000000000000000";
const TA_SCOPED: &str = "tenant-a-scoped-key-0000000000000000000";

fn entry(
    id: &str,
    key: &str,
    tenant: Option<&str>,
    role: Role,
    allowed: &[&str],
    capabilities: &[&str],
) -> ApiKeyEntry {
    ApiKeyEntry {
        id: Some(id.to_string()),
        key: key.to_string(),
        tenant_id: tenant.map(str::to_string),
        role,
        allowed_collections: allowed.iter().map(|value| value.to_string()).collect(),
        max_collections: None,
        capabilities: capabilities.iter().map(|value| value.to_string()).collect(),
    }
}

fn auth() -> AuthConfig {
    let rbac = RbacConfig {
        keys: vec![
            entry("ops", OPS, None, Role::Admin, &[], &[]),
            entry(
                "tb-admin",
                TB_ADMIN,
                Some("tenant-b"),
                Role::Admin,
                &[],
                &[],
            ),
            entry(
                "tb-install",
                TB_INSTALL,
                Some("tenant-b"),
                Role::Admin,
                &[],
                &["installation:admin"],
            ),
            entry(
                "tb-writer",
                TB_WRITER,
                Some("tenant-b"),
                Role::ReadWrite,
                &[],
                &[],
            ),
            entry(
                "ta-reader",
                TA_READER,
                Some("tenant-a"),
                Role::ReadOnly,
                &[],
                &[],
            ),
            entry(
                "ta-auditor",
                TA_AUDITOR,
                Some("tenant-a"),
                Role::ReadOnly,
                &[],
                &["tenant:cross_read"],
            ),
            entry(
                "ta-scoped",
                TA_SCOPED,
                Some("tenant-a"),
                Role::ReadOnly,
                &[COLLECTION],
                &[],
            ),
        ],
    };
    let keys = [
        OPS, TB_ADMIN, TB_INSTALL, TB_WRITER, TA_READER, TA_AUDITOR, TA_SCOPED,
    ]
    .join(",");
    AuthConfig::from_optional_key(Some(keys))
        .with_validated_rbac(rbac, true)
        .expect("valid rbac")
}

fn config(name: &str) -> CollectionConfig {
    CollectionConfig {
        name: name.to_string(),
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
        max_vector_norm: None,
        max_sparse_nnz: None,
        max_sparse_weight: None,
        index_kind: None,
        streamer_max_bytes: 0,
    }
}

fn point(id: &str, tenant: &str) -> Point {
    Point {
        id: id.to_string(),
        vector: vec![1.0, 0.0],
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({"tenant_id": tenant}),
    }
}

/// `docs` holds two tenant-a rows and one tenant-b row; `other` is empty.
fn seeded_db(path: &Path, enforcement: TenantEnforcement) -> Db {
    let db = Db::open(path.join("data")).expect("open db");
    db.create_collection(config(COLLECTION)).expect("create");
    db.create_collection(config(OTHER)).expect("create other");
    db.upsert(
        COLLECTION,
        vec![
            point("a-1", "tenant-a"),
            point("a-2", "tenant-a"),
            point("b-1", "tenant-b"),
        ],
    )
    .expect("seed");
    db.set_tenant_enforcement(enforcement);
    db
}

fn storage_policy(path: &Path) -> StoragePolicy {
    StoragePolicy::new(Some(path.join("snapshots")), None, false).expect("storage policy")
}

fn tenant_a_rows(db: &Db) -> usize {
    db.count_scoped(COLLECTION, None, &TenantScope::tenant("probe", "tenant-a"))
        .expect("count")
        .count
}

async fn serve_http(db: Db, auth: AuthConfig, policy: StoragePolicy, tls: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let options = api::ServerOptions {
        storage_policy: policy,
        ..Default::default()
    };
    let router = if tls {
        api::tls_router_with_options(db, auth, options)
    } else {
        api::router_with_options(db, auth, options)
    };
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    address
}

async fn http(
    address: SocketAddr,
    method: Method,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> reqwest::Response {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method, format!("http://{address}{path}"))
        .bearer_auth(key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.expect("request")
}

/// Every installation-wide HTTP route, with a body that would succeed.
fn installation_routes() -> Vec<(Method, String, Option<Value>)> {
    let c = COLLECTION;
    vec![
        (Method::DELETE, format!("/collections/{c}"), None),
        (
            Method::PUT,
            format!("/collections/{c}/payload_schema"),
            Some(json!({"payload_schema": {}})),
        ),
        (Method::POST, format!("/collections/{c}/compact"), None),
        (
            Method::POST,
            format!("/collections/{c}/compact/stream"),
            None,
        ),
        (
            Method::POST,
            format!("/collections/{c}/calibrate"),
            Some(json!({})),
        ),
        (Method::POST, format!("/collections/{c}/cold/tier"), None),
        (
            Method::POST,
            format!("/collections/{c}/wal_archive/prune"),
            Some(json!({"retain_last": 1})),
        ),
        (
            Method::POST,
            "/admin/snapshot".into(),
            Some(json!({"path": "s"})),
        ),
        (
            Method::POST,
            "/admin/snapshot/stream".into(),
            Some(json!({"path": "s"})),
        ),
        (
            Method::POST,
            "/admin/restore".into(),
            Some(json!({"path": "s"})),
        ),
        (
            Method::POST,
            "/admin/restore/stream".into(),
            Some(json!({"path": "s"})),
        ),
        (Method::POST, "/admin/shard_move".into(), Some(json!({}))),
        (Method::GET, "/metrics".into(), None),
    ]
}

#[tokio::test]
async fn http_tenant_bound_admin_cannot_run_installation_routes_under_enforcement() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Enforced);
    let address = serve_http(db.clone(), auth(), storage_policy(dir.path()), false).await;

    for prefix in ["", "/v1"] {
        for (method, path, body) in installation_routes() {
            for key in [TB_ADMIN, TB_WRITER, TA_READER] {
                let response = http(
                    address,
                    method.clone(),
                    &format!("{prefix}{path}"),
                    key,
                    body.clone(),
                )
                .await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{method} {prefix}{path} must be forbidden for a tenant-bound key"
                );
                // Only the admin is told the migration remedy; a lower role
                // keeps the generic body.
                let body = response.text().await.unwrap();
                if key == TB_ADMIN {
                    assert!(
                        body.contains("'installation:admin'")
                            && body.contains("chironctl security installation-check"),
                        "{method} {prefix}{path}: {body}"
                    );
                } else {
                    assert_eq!(body, "forbidden", "{method} {prefix}{path}");
                }
            }
        }
    }
    assert_eq!(tenant_a_rows(&db), 2, "tenant-a rows must survive");
    assert!(
        !dir.path().join("snapshots/s").exists(),
        "no snapshot may be written"
    );

    // Creating a collection touches no existing rows and stays a tenant-admin
    // operation; the tenant data plane keeps working.
    let created = http(
        address,
        Method::POST,
        "/collections",
        TB_ADMIN,
        Some(serde_json::to_value(config("tenant-b-new")).unwrap()),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let counted = http(
        address,
        Method::POST,
        &format!("/collections/{COLLECTION}/count"),
        TB_ADMIN,
        Some(json!({})),
    )
    .await;
    assert_eq!(counted.status(), StatusCode::OK);
    assert_eq!(counted.json::<Value>().await.unwrap()["count"], json!(1));

    // Installation authority: explicit capability, or no tenant binding.
    for (key, method, path, body) in [
        (
            TB_INSTALL,
            Method::POST,
            "/admin/snapshot".to_string(),
            Some(json!({"path": "s"})),
        ),
        (
            OPS,
            Method::PUT,
            format!("/collections/{COLLECTION}/payload_schema"),
            Some(json!({"payload_schema": {}})),
        ),
        (
            OPS,
            Method::POST,
            format!("/collections/{COLLECTION}/compact"),
            None,
        ),
        (OPS, Method::GET, "/metrics".to_string(), None),
        (
            TB_INSTALL,
            Method::POST,
            "/admin/restore".to_string(),
            Some(json!({"path": "s"})),
        ),
        (
            TB_INSTALL,
            Method::DELETE,
            format!("/collections/{COLLECTION}"),
            None,
        ),
    ] {
        let response = http(address, method.clone(), &path, key, body).await;
        let status = response.status();
        assert_eq!(
            status,
            StatusCode::OK,
            "{method} {path} must succeed for installation admin: {}",
            response.text().await.unwrap_or_default()
        );
    }
}

#[tokio::test]
async fn http_admin_plane_is_unchanged_without_tenant_enforcement() {
    // A tenant label without enforcement is only an audit/rate-limit key.
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Disabled);
    let address = serve_http(db.clone(), auth(), storage_policy(dir.path()), false).await;
    for (method, path, body) in [
        (
            Method::PUT,
            format!("/collections/{COLLECTION}/payload_schema"),
            Some(json!({"payload_schema": {}})),
        ),
        (
            Method::POST,
            format!("/collections/{COLLECTION}/compact"),
            None,
        ),
        (
            Method::POST,
            "/admin/snapshot".to_string(),
            Some(json!({"path": "s"})),
        ),
        (Method::GET, "/metrics".to_string(), None),
        (Method::DELETE, format!("/collections/{COLLECTION}"), None),
    ] {
        let response = http(address, method.clone(), &path, TB_ADMIN, body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        // Non-admins stay denied by role, as before.
        let response = http(address, method.clone(), &path, TB_WRITER, body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }

    // Single-tenant deployment with a plain API key and no RBAC.
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Disabled);
    let address = serve_http(
        db,
        AuthConfig::from_optional_key(Some("single-tenant-secret".into())),
        storage_policy(dir.path()),
        false,
    )
    .await;
    for (method, path, body) in [
        (
            Method::POST,
            "/admin/snapshot".to_string(),
            Some(json!({"path": "s"})),
        ),
        (
            Method::POST,
            format!("/collections/{COLLECTION}/compact"),
            None,
        ),
        (Method::DELETE, format!("/collections/{COLLECTION}"), None),
    ] {
        let response = http(address, method.clone(), &path, "single-tenant-secret", body).await;
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
    }
}

#[tokio::test]
async fn http_index_status_does_not_leak_other_tenants_counts() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Enforced);
    let address = serve_http(db.clone(), auth(), StoragePolicy::default(), false).await;
    let path = format!("/collections/{COLLECTION}/index_status");
    let total = |key: &'static str| {
        let path = path.clone();
        async move {
            let response = http(address, Method::GET, &path, key, None).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = response.json().await.unwrap();
            assert!(
                body["indexed_points"].as_u64().unwrap() <= body["total_points"].as_u64().unwrap()
            );
            body["total_points"].as_u64().unwrap()
        }
    };
    assert_eq!(total(TA_READER).await, 2);
    assert_eq!(total(TB_WRITER).await, 1);
    // A tenant-bound admin is still only a tenant reader here.
    assert_eq!(total(TB_ADMIN).await, 1);
    // Cross-tenant readers and installation admins see the collection total.
    assert_eq!(total(TA_AUDITOR).await, 3);
    assert_eq!(total(TB_INSTALL).await, 3);
    assert_eq!(total(OPS).await, 3);

    db.set_tenant_enforcement(TenantEnforcement::Disabled);
    assert_eq!(total(TA_READER).await, 3, "unchanged without enforcement");
}

#[tokio::test]
async fn list_collections_honours_the_allowlist_on_http_grpc_and_wire() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Enforced);
    let address = serve_http(db.clone(), auth(), StoragePolicy::default(), false).await;
    let names = |body: Value| {
        let mut names: Vec<String> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|config| config["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    };
    let scoped = http(address, Method::GET, "/v1/collections", TA_SCOPED, None).await;
    assert_eq!(names(scoped.json().await.unwrap()), vec![COLLECTION]);
    let unrestricted = http(address, Method::GET, "/v1/collections", OPS, None).await;
    assert_eq!(
        names(unrestricted.json().await.unwrap()),
        vec![COLLECTION, OTHER]
    );

    let grpc_address = serve_grpc(db.clone(), StoragePolicy::default()).await;
    let mut client = common::connect_grpc(grpc_address).await;
    let listed = client
        .list_collections(common::grpc_auth_request(
            pb::ListCollectionsRequest {},
            TA_SCOPED,
        ))
        .await
        .expect("list")
        .into_inner();
    let listed: Vec<_> = listed.collections.into_iter().map(|c| c.name).collect();
    assert_eq!(listed, vec![COLLECTION.to_string()]);

    let wire_endpoint = serve_wire(db, StoragePolicy::default()).await;
    let response = common::send_wire_with_key(
        &wire_endpoint,
        1,
        TA_SCOPED,
        wire_request::Operation::ListCollections(pb::ListCollectionsRequest {}),
    )
    .await;
    let Some(pb::wire_response::Payload::ListCollections(listed)) = response.payload else {
        panic!("expected list response: {response:?}");
    };
    let listed: Vec<_> = listed.collections.into_iter().map(|c| c.name).collect();
    assert_eq!(listed, vec![COLLECTION.to_string()]);
}

#[tokio::test]
async fn http_security_headers_and_tls_only_hsts() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Disabled);
    let plain = serve_http(db.clone(), auth(), StoragePolicy::default(), false).await;
    let tls = serve_http(db, auth(), StoragePolicy::default(), true).await;
    for (address, hsts) in [(plain, false), (tls, true)] {
        for (path, key) in [
            ("/health", ""),
            ("/v1/collections", OPS),
            ("/metrics", "bad"),
        ] {
            let response = http(address, Method::GET, path, key, None).await;
            let headers = response.headers();
            assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
            assert_eq!(
                headers["cross-origin-resource-policy"], "same-origin",
                "{path}"
            );
            assert_eq!(
                headers
                    .get("strict-transport-security")
                    .map(|value| value.to_str().unwrap()),
                hsts.then_some("max-age=31536000"),
                "{path}"
            );
        }
    }
}

async fn serve_grpc(db: Db, policy: StoragePolicy) -> SocketAddr {
    let address = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let options = GrpcServerOptions {
        storage_policy: policy,
        ..Default::default()
    };
    tokio::spawn(async move {
        grpc::serve_with_options(db, auth(), address, options)
            .await
            .expect("serve grpc");
    });
    address
}

async fn serve_wire(db: Db, policy: StoragePolicy) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        wire::serve_listener_with_policy(db, auth(), listener, policy)
            .await
            .expect("serve wire");
    });
    endpoint
}

async fn grpc_installation_calls(
    client: &mut pb::gauss_db_client::GaussDbClient<tonic::transport::Channel>,
    key: &str,
) -> Vec<(&'static str, Result<(), tonic::Status>)> {
    use common::grpc_auth_request as auth_request;
    let c = COLLECTION.to_string();
    vec![
        (
            "update_payload_schema",
            client
                .update_payload_schema(auth_request(
                    pb::UpdatePayloadSchemaRequest {
                        collection: c.clone(),
                        payload_schema: Default::default(),
                    },
                    key,
                ))
                .await
                .map(drop),
        ),
        (
            "compact",
            client
                .compact(auth_request(
                    pb::CompactRequest {
                        collection: c.clone(),
                    },
                    key,
                ))
                .await
                .map(drop),
        ),
        (
            "prune_wal_archive",
            client
                .prune_wal_archive(auth_request(
                    pb::PruneWalArchiveRequest {
                        collection: c.clone(),
                        retain_last: 1,
                    },
                    key,
                ))
                .await
                .map(drop),
        ),
        (
            "snapshot",
            client
                .snapshot(auth_request(pb::SnapshotRequest { path: "g".into() }, key))
                .await
                .map(drop),
        ),
        (
            "restore",
            client
                .restore(auth_request(
                    pb::RestoreRequest {
                        path: "g".into(),
                        ..Default::default()
                    },
                    key,
                ))
                .await
                .map(drop),
        ),
        (
            "shard_move",
            client
                .shard_move(auth_request(pb::ShardMoveRequest {}, key))
                .await
                .map(drop),
        ),
        (
            "tier_cold",
            client
                .tier_cold(auth_request(
                    pb::ColdTierRequest {
                        collection: c.clone(),
                    },
                    key,
                ))
                .await
                .map(drop),
        ),
        (
            "delete_collection",
            client
                .delete_collection(auth_request(
                    pb::DeleteCollectionRequest { collection: c },
                    key,
                ))
                .await
                .map(drop),
        ),
    ]
}

#[tokio::test]
async fn grpc_tenant_bound_admin_cannot_run_installation_rpcs_under_enforcement() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Enforced);
    let address = serve_grpc(db.clone(), storage_policy(dir.path())).await;
    let mut client = common::connect_grpc(address).await;

    for key in [TB_ADMIN, TB_WRITER] {
        for (name, result) in grpc_installation_calls(&mut client, key).await {
            let status = result.expect_err(name);
            assert_eq!(
                status.code(),
                Code::PermissionDenied,
                "{name} must be denied for a tenant-bound key"
            );
            assert_eq!(
                status.message().contains("'installation:admin'"),
                key == TB_ADMIN,
                "{name}: {}",
                status.message()
            );
        }
    }
    assert_eq!(tenant_a_rows(&db), 2, "tenant-a rows must survive");
    assert!(!dir.path().join("snapshots/g").exists());

    // Collection creation remains available to the tenant admin.
    client
        .create_collection(common::grpc_auth_request(
            pb::CreateCollectionRequest {
                config: Some(pb::CollectionConfig {
                    name: "tenant-b-grpc".into(),
                    vector_dim: 2,
                    metric: "l2".into(),
                    shards: 1,
                    replicas: 1,
                    ..Default::default()
                }),
            },
            TB_ADMIN,
        ))
        .await
        .expect("tenant admin creates a collection");

    // Installation admin (explicit capability) runs every one of them.
    for (name, result) in grpc_installation_calls(&mut client, TB_INSTALL).await {
        if let Err(status) = result {
            assert_ne!(status.code(), Code::PermissionDenied, "{name}: {status:?}");
        }
    }
    assert!(dir.path().join("snapshots/g").exists());
}

#[tokio::test]
async fn grpc_admin_plane_is_unchanged_without_tenant_enforcement() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Disabled);
    let address = serve_grpc(db, storage_policy(dir.path())).await;
    let mut client = common::connect_grpc(address).await;
    for (name, result) in grpc_installation_calls(&mut client, TB_ADMIN).await {
        if let Err(status) = result {
            assert_ne!(status.code(), Code::PermissionDenied, "{name}: {status:?}");
        }
    }
    assert!(dir.path().join("snapshots/g").exists());
}

#[tokio::test]
async fn wire_tenant_bound_admin_cannot_run_installation_frames_under_enforcement() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Enforced);
    let endpoint = serve_wire(db.clone(), storage_policy(dir.path())).await;
    let operations = || {
        vec![
            wire_request::Operation::Compact(pb::CompactRequest {
                collection: COLLECTION.into(),
            }),
            wire_request::Operation::UpdatePayloadSchema(pb::UpdatePayloadSchemaRequest {
                collection: COLLECTION.into(),
                payload_schema: Default::default(),
            }),
            wire_request::Operation::Snapshot(pb::SnapshotRequest { path: "w".into() }),
            wire_request::Operation::Restore(pb::RestoreRequest {
                path: "w".into(),
                ..Default::default()
            }),
            wire_request::Operation::ShardMove(pb::ShardMoveRequest {}),
        ]
    };
    for (index, operation) in operations().into_iter().enumerate() {
        let response =
            common::send_wire_with_key(&endpoint, index as u64 + 1, TB_ADMIN, operation).await;
        assert_eq!(response.error_code, "PERMISSION_DENIED", "{response:?}");
    }
    assert!(!dir.path().join("snapshots/w").exists());
    for (index, operation) in operations().into_iter().enumerate() {
        let response =
            common::send_wire_with_key(&endpoint, index as u64 + 100, OPS, operation).await;
        assert_ne!(response.error_code, "PERMISSION_DENIED", "{response:?}");
    }
    assert!(dir.path().join("snapshots/w").exists());
    assert_eq!(tenant_a_rows(&db), 2);
}

#[tokio::test]
async fn grpc_reflection_requires_an_admin_principal() {
    let dir = TempDir::new().unwrap();
    let db = seeded_db(dir.path(), TenantEnforcement::Disabled);
    let address = serve_grpc(db, StoragePolicy::default()).await;

    let channel = common::connect_grpc_channel(address).await;
    let denied = common::reflection_request(channel, Some(TA_READER))
        .await
        .expect_err("non-admin reflection");
    assert_eq!(denied.code(), Code::PermissionDenied);

    let channel = common::connect_grpc_channel(address).await;
    let unauthenticated = common::reflection_request(channel, None)
        .await
        .expect_err("anonymous reflection");
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);

    let channel = common::connect_grpc_channel(address).await;
    let services = common::list_reflection_services(channel, Some(OPS)).await;
    assert!(services.iter().any(|name| name == "gaussdb.v1.GaussDb"));
}
