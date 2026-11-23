//! Policy/status parity, permission boundaries and additive wire compatibility.
#[allow(dead_code)]
mod common;

use chirondb::{
    Db, api,
    auth::AuthConfig,
    grpc,
    rbac::{ApiKeyEntry, RbacConfig, Role},
    tenant::TenantEnforcement,
    wire,
};
use grpc::{chiron_pb as pb, pb::wire_request::Operation};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const READ: &str = "ml-refresh-reader-0000000000000000";
const WRITE: &str = "ml-refresh-writer-0000000000000000";

struct Harness {
    _data: TempDir,
    db: Db,
    http: String,
    wire: String,
    grpc: pb::chiron_db_client::ChironDbClient<tonic::transport::Channel>,
    servers: Vec<tokio::task::JoinHandle<()>>,
}
impl Harness {
    async fn new(protected: bool) -> Self {
        let data = TempDir::new().unwrap();
        let db = Db::open(data.path()).unwrap();
        if protected {
            db.set_tenant_enforcement(TenantEnforcement::Enforced);
        }
        let auth = AuthConfig::disabled().with_rbac(RbacConfig {
            keys: [
                ("read", READ, Role::ReadOnly),
                ("write", WRITE, Role::ReadWrite),
            ]
            .into_iter()
            .map(|(id, key, role)| ApiKeyEntry {
                id: Some(id.into()),
                key: key.into(),
                role,
                tenant_id: None,
                allowed_collections: vec![],
                max_collections: None,
                capabilities: vec![],
            })
            .collect(),
        });
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_url = format!("http://{}", http.local_addr().unwrap());
        let wire = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wire_url = wire.local_addr().unwrap().to_string();
        let grpc_addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (hdb, wauth, wdb, gauth, gdb) = (
            db.clone(),
            auth.clone(),
            db.clone(),
            auth.clone(),
            db.clone(),
        );
        let servers = vec![
            tokio::spawn(async move {
                api::serve_listener_with_auth(hdb, auth, http)
                    .await
                    .unwrap();
            }),
            tokio::spawn(async move {
                wire::serve_listener_with_auth(wdb, wauth, wire)
                    .await
                    .unwrap();
            }),
            tokio::spawn(async move {
                grpc::serve_with_auth(gdb, gauth, grpc_addr).await.unwrap();
            }),
        ];
        let grpc = pb::chiron_db_client::ChironDbClient::new(
            common::connect_grpc_channel(grpc_addr).await,
        );
        Self {
            _data: data,
            db,
            http: http_url,
            wire: wire_url,
            grpc,
            servers,
        }
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}
fn policy(mode: i32) -> pb::SetMlRefreshPolicyRequest {
    pb::SetMlRefreshPolicyRequest {
        name: "missing".into(),
        mode,
    }
}
fn status() -> pb::GetMlRefreshStatusRequest {
    pb::GetMlRefreshStatusRequest {
        name: "missing".into(),
    }
}

fn seed_persisted_auto_view(path: &std::path::Path) -> chirondb::MlSourceRevision {
    let db = Db::open(path).unwrap();
    let execute = |statements, transport: &str| {
        db.execute_sql_with_audit(
            chirondb::SqlExecutionRequest {
                statements,
                idempotency_key: None,
                retry_id: None,
            },
            &chirondb::audit::AuditContext {
                principal_id: "native-startup-fixture".into(),
                tenant_id: None,
                transport: transport.into(),
                request_id: None,
            },
        )
        .unwrap();
    };
    let statement = |sql: &str, parameters| chirondb::SqlStatementRequest {
        sql: sql.into(),
        parameters,
    };
    execute(
        vec![
            statement(
                "CREATE TABLE source (id INTEGER PRIMARY KEY, x DOUBLE PRECISION, y DOUBLE PRECISION)",
                vec![],
            ),
            statement("INSERT INTO source VALUES (1, 1.0, 2.0)", vec![]),
        ],
        "native-startup-fixture",
    );
    db.ensure_ml_source_format().unwrap();
    let source = db.ml_source_revision("source").unwrap().unwrap();
    let definition = json!({"source":"source", "target":"y", "features":["x"],
        "task":"regression", "model":"decision_tree"})
    .to_string();
    let schedule = json!({
        "format":1, "name":"forecast", "epoch":uuid::Uuid::new_v4().to_string(),
        "definition":definition, "mode":"auto", "source_id":source.revision.table_id,
        "lineage":source.lineage, "desired":source.revision, "published":source.revision,
        "first_dirty":null, "last_dirty":null, "pending":false, "manual":false,
        "job":null, "claim":null, "requested_revision":null, "retry_at":null,
        "failures":0, "blocked":false, "error_code":null, "error":null,
        "last_success":1, "version":3, "actor":"native-startup-fixture", "tenant":null,
    });
    execute(
        vec![
            statement(
                "CREATE TABLE __chiron_ml_views (name TEXT PRIMARY KEY, definition TEXT NOT NULL, source TEXT NOT NULL, version BIGINT NOT NULL, source_version BIGINT, row_count BIGINT)",
                vec![],
            ),
            statement(
                "CREATE TABLE __chiron_ml_schedule (name TEXT PRIMARY KEY, state TEXT NOT NULL)",
                vec![],
            ),
            statement(
                "INSERT INTO __chiron_ml_views (name, definition, source, version) VALUES ('forecast', $1, 'source', 3)",
                vec![chirondb::RelationalValue::Text(definition)],
            ),
            statement(
                "INSERT INTO __chiron_ml_schedule VALUES ('forecast', $1)",
                vec![chirondb::RelationalValue::Text(schedule.to_string())],
            ),
            // Commit after the persisted schedule's watermark, with no scheduler or
            // HTTP router ever constructed in this process.
            statement("UPDATE source SET y = 3.0 WHERE id = 1", vec![]),
        ],
        "chironql-ml",
    );
    source.revision
}

#[tokio::test]
async fn standalone_native_startup_recovers_auto_without_http_or_mutating_requests() {
    for use_grpc in [true, false] {
        let data = TempDir::new().unwrap();
        let published = seed_persisted_auto_view(data.path());
        let db = Db::open(data.path()).unwrap();
        let current = db.ml_source_revision("source").unwrap().unwrap().revision;
        assert_ne!(current.data_revision, published.data_revision);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = if use_grpc {
            drop(listener);
            tokio::spawn(async move {
                grpc::serve(db, addr).await.unwrap();
            })
        } else {
            tokio::spawn(async move {
                wire::serve_listener(db, listener).await.unwrap();
            })
        };
        let mut grpc = if use_grpc {
            Some(pb::chiron_db_client::ChironDbClient::new(
                common::connect_grpc_channel(addr).await,
            ))
        } else {
            None
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let observed = loop {
            let request = pb::GetMlRefreshStatusRequest {
                name: "forecast".into(),
            };
            let status = if let Some(client) = &mut grpc {
                client
                    .get_ml_refresh_status(request)
                    .await
                    .unwrap()
                    .into_inner()
            } else {
                let response = common::send_wire_with_key(
                    &addr.to_string(),
                    1,
                    "",
                    Operation::GetMlRefreshStatus(request),
                )
                .await;
                assert_eq!(response.error_code, "");
                let Some(grpc::pb::wire_response::Payload::MlRefreshStatus(status)) =
                    response.payload
                else {
                    panic!("wrong response payload")
                };
                status
            };
            if status.activity == pb::MlRefreshActivity::Debouncing as i32 {
                break status;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "AUTO did not resume: {status:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(observed.mode, pb::MlRefreshMode::Auto as i32);
        assert_eq!(observed.refresh_version, 3);
        assert_eq!(
            observed.availability,
            pb::MlRefreshAvailability::Available as i32
        );
        assert_eq!(observed.freshness, pb::MlRefreshFreshness::Stale as i32);
        assert_eq!(
            observed.published_revision.unwrap().data,
            published.data_revision
        );
        assert_eq!(
            observed.current_revision.unwrap().data,
            current.data_revision
        );
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn refresh_routes_enforce_roles_and_protected_denial_before_catalog_access() {
    let http = reqwest::Client::new();
    for protected in [false, true] {
        let mut h = Harness::new(protected).await;
        for prefix in ["", "/v1"] {
            let route = format!("{}{prefix}/ml/views/missing", h.http);
            assert_eq!(
                http.put(format!("{route}/refresh-policy"))
                    .bearer_auth(READ)
                    .json(&json!({"mode":"auto"}))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::FORBIDDEN
            );
            let read = http
                .get(format!("{route}/refresh-status"))
                .bearer_auth(READ)
                .send()
                .await
                .unwrap();
            assert_eq!(
                read.status(),
                if protected {
                    reqwest::StatusCode::FORBIDDEN
                } else {
                    reqwest::StatusCode::NOT_FOUND
                }
            );
            let write = http
                .put(format!("{route}/refresh-policy"))
                .bearer_auth(WRITE)
                .json(&json!({"mode":"manual"}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                write.status(),
                if protected {
                    reqwest::StatusCode::FORBIDDEN
                } else {
                    reqwest::StatusCode::NOT_FOUND
                }
            );
        }
        for key in [READ, WRITE] {
            let read = h
                .grpc
                .get_ml_refresh_status(common::grpc_auth_request(status(), key))
                .await
                .unwrap_err();
            assert_eq!(
                read.code(),
                if protected {
                    tonic::Code::PermissionDenied
                } else {
                    tonic::Code::NotFound
                }
            );
            let write = h
                .grpc
                .set_ml_refresh_policy(common::grpc_auth_request(
                    policy(pb::MlRefreshMode::Manual as i32),
                    key,
                ))
                .await
                .unwrap_err();
            assert_eq!(
                write.code(),
                if protected || key == READ {
                    tonic::Code::PermissionDenied
                } else {
                    tonic::Code::NotFound
                }
            );
            let read = common::send_wire_with_key(
                &h.wire,
                1,
                key,
                Operation::GetMlRefreshStatus(status()),
            )
            .await;
            assert_eq!(
                read.error_code,
                if protected {
                    "PERMISSION_DENIED"
                } else {
                    "NOT_FOUND"
                }
            );
            let write = common::send_wire_with_key(
                &h.wire,
                2,
                key,
                Operation::SetMlRefreshPolicy(policy(pb::MlRefreshMode::Manual as i32)),
            )
            .await;
            assert_eq!(
                write.error_code,
                if protected || key == READ {
                    "PERMISSION_DENIED"
                } else {
                    "NOT_FOUND"
                }
            );
        }
        assert!(
            h.db.relational_tables().is_empty(),
            "denied/missing requests created a catalog"
        );
    }
}

#[tokio::test]
async fn invalid_modes_reject_consistently_without_creating_catalog() {
    let mut h = Harness::new(false).await;
    let http = reqwest::Client::new();
    for body in [
        json!({}),
        json!({"mode":"AUTO"}),
        json!({"mode":"auto","debounce":0}),
    ] {
        let response = http
            .put(format!("{}/v1/ml/views/missing/refresh-policy", h.http))
            .bearer_auth(WRITE)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>().await.unwrap()["code"],
            "chironql.ml_invalid_policy"
        );
    }
    for mode in [0, 99, -1] {
        let response = h
            .grpc
            .set_ml_refresh_policy(common::grpc_auth_request(policy(mode), WRITE))
            .await
            .unwrap_err();
        assert_eq!(response.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            serde_json::from_slice::<Value>(response.details()).unwrap()["code"],
            "chironql.ml_invalid_policy"
        );
        let response = common::send_wire_with_key(
            &h.wire,
            3,
            WRITE,
            Operation::SetMlRefreshPolicy(policy(mode)),
        )
        .await;
        assert_eq!(response.error_code, "INVALID_ARGUMENT");
    }
    assert!(h.db.relational_tables().is_empty());
}

#[tokio::test]
async fn legacy_unknown_provenance_and_policy_round_trip_across_transports() {
    // A persisted pre-scheduler view has no trustworthy source revision. All
    // transports must preserve that absence while retaining its generation.
    let mut h = Harness::new(false).await;
    let definition = json!({"source":"source", "target":"y", "features":["x"],
        "task":"regression", "model":"decision_tree"})
    .to_string();
    h.db.execute_sql_with_audit(chirondb::SqlExecutionRequest {
        statements: vec![
            chirondb::SqlStatementRequest { sql: "CREATE TABLE source (id INTEGER PRIMARY KEY, x DOUBLE PRECISION, y DOUBLE PRECISION)".into(), parameters: vec![] },
            chirondb::SqlStatementRequest { sql: "CREATE TABLE __chiron_ml_views (name TEXT PRIMARY KEY, definition TEXT NOT NULL, source TEXT NOT NULL, version BIGINT NOT NULL, source_version BIGINT, row_count BIGINT)".into(), parameters: vec![] },
            chirondb::SqlStatementRequest { sql: "INSERT INTO __chiron_ml_views (name, definition, source, version) VALUES ('forecast', $1, 'source', 3)".into(), parameters: vec![chirondb::RelationalValue::Text(definition)] },
        ], idempotency_key: None, retry_id: None,
    }, &chirondb::audit::AuditContext {
        principal_id: "legacy-ml-fixture".into(), tenant_id: None,
        transport: "chironql-ml".into(), request_id: None,
    }).unwrap();
    chirondb::ml_runtime::initialize(&h.db).unwrap();
    let http = reqwest::Client::new();
    let expected: chirondb_types::MlRefreshStatus = http
        .get(format!("{}/v1/ml/views/forecast/refresh-status", h.http))
        .bearer_auth(READ)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        expected.availability,
        chirondb_types::MlRefreshAvailability::Available
    );
    assert_eq!(expected.refresh_version, 3);
    assert!(expected.published_revision.is_none());
    assert!(expected.source_table_id.is_none());
    assert!(expected.current_revision.is_some());
    let assigned: chirondb_types::MlRefreshStatus = http
        .put(format!("{}/ml/views/forecast/refresh-policy", h.http))
        .bearer_auth(WRITE)
        .json(&json!({"mode":"manual"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(assigned, expected);
    let request = pb::GetMlRefreshStatusRequest {
        name: "forecast".into(),
    };
    let read = h
        .grpc
        .get_ml_refresh_status(common::grpc_auth_request(request.clone(), READ))
        .await
        .unwrap()
        .into_inner();
    let policy = pb::SetMlRefreshPolicyRequest {
        name: "forecast".into(),
        mode: pb::MlRefreshMode::Manual as i32,
    };
    let assigned = h
        .grpc
        .set_ml_refresh_policy(common::grpc_auth_request(policy.clone(), WRITE))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(read, assigned);
    assert_eq!(read.refresh_version, expected.refresh_version);
    assert_eq!(
        read.availability,
        pb::MlRefreshAvailability::Available as i32
    );
    assert_eq!(read.activity, pb::MlRefreshActivity::Idle as i32);
    assert_eq!(read.freshness, pb::MlRefreshFreshness::Stale as i32);
    assert!(read.published_revision.is_none());
    assert!(read.source_table_id.is_none());
    assert!(read.current_revision.is_some());
    for (id, key, operation) in [
        (4, READ, Operation::GetMlRefreshStatus(request)),
        (5, WRITE, Operation::SetMlRefreshPolicy(policy)),
    ] {
        let response = common::send_wire_with_key(&h.wire, id, key, operation).await;
        assert_eq!(response.error_code, "");
        let grpc::pb::wire_response::Payload::MlRefreshStatus(status) = response.payload.unwrap()
        else {
            panic!("wrong response payload")
        };
        assert_eq!(status, read);
    }
}
