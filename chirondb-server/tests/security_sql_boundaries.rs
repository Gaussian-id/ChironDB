//! Regression coverage for SQL scope, statement class and read/write separation.
#[allow(dead_code)]
mod common;

use chirondb::{
    Db, SqlExecutionRequest, api,
    auth::AuthConfig,
    db::temporal::{SensorValue, TemporalAccess, TemporalSample},
    grpc::{
        self, chiron_pb as pb,
        pb::{WireChironQlRequest, WireSqlRequest, wire_request, wire_response},
    },
    rbac::{ApiKeyEntry, RbacConfig, Role},
    security::*,
    tenant::TenantEnforcement,
    wire,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn pg_message(stream: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    let mut h = [0; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_exact(&mut h),
    )
    .await
    .unwrap()
    .unwrap();
    let n = u32::from_be_bytes(h[1..].try_into().unwrap()) as usize;
    assert!((4..=65536).contains(&n));
    let mut b = vec![0; n - 4];
    stream.read_exact(&mut b).await.unwrap();
    (h[0], b)
}
async fn pg_send(stream: &mut tokio::net::TcpStream, kind: u8, body: &[u8]) {
    stream.write_all(&[kind]).await.unwrap();
    stream
        .write_all(&((body.len() + 4) as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}

fn sql(s: &str) -> SqlExecutionRequest {
    serde_json::from_value(json!({"statements":[{"sql":s}]})).unwrap()
}

fn row_security_view(db: &Db, actor: &AuthenticatedIdentity, table: &str) -> Value {
    let output = db
        .relational_security_authorized(actor, table, 0, 16)
        .unwrap();
    let chirondb::SqlResult::Rows { rows, .. } = &output.results[0] else {
        panic!()
    };
    let chirondb::RelationalValue::Json(value) = &rows[0][0] else {
        panic!()
    };
    value.clone()
}
fn row_security_delta(view: &Value) -> chirondb_types::relational::RelationalSecurityDelta {
    let mut policy: chirondb_types::RelationalRowPolicy =
        serde_json::from_value(view["policy"].clone()).unwrap();
    let expected_revision = policy.revision;
    policy.revision += 1;
    let records = view["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let mut record: ResourceRecord =
                serde_json::from_value(row["authority"].clone()).unwrap();
            record.revision = policy.revision;
            record
        })
        .collect();
    chirondb_types::relational::RelationalSecurityDelta {
        table: view["table"].as_str().unwrap().into(),
        incarnation: serde_json::from_value(view["incarnation"].clone()).unwrap(),
        expected_revision,
        policy,
        records,
    }
}

#[tokio::test]
async fn native_row_security_administration_is_shared_by_all_protocols() {
    if isolated("native_row_security_administration_is_shared_by_all_protocols") {
        return;
    }
    let (_temp, mut db, key) = protected();
    db.migrate_table_authority_offline().unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let actor = db.identity_authority().unwrap().authenticate(&key).unwrap();
    db.execute_sql_authorized(
        &actor,
        sql("CREATE TABLE native_security(id BIGINT PRIMARY KEY, secret TEXT)"),
        "test",
    )
    .unwrap();
    db.execute_sql_authorized(
        &actor,
        sql("INSERT INTO native_security VALUES(1,'secret')"),
        "test",
    )
    .unwrap();
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    for protocol in 0..4 {
        let rows = endpoints
            .query_ok(
                protocol,
                &key,
                "SHOW ROW SECURITY native_security LIMIT 16;",
            )
            .await;
        assert_eq!(rows.len(), 1);
        let view = &rows[0]["security"];
        assert_eq!(view["table"], "native_security");
        let mut delta = row_security_delta(view);
        delta.records[0]
            .properties
            .get_mut("/secret")
            .unwrap()
            .actions
            .remove(&PropertyAction::Read);
        let query = format!(
            "ALTER ROW SECURITY native_security APPLY JSON '{}' IF REVISION {};",
            serde_json::to_string(&delta).unwrap().replace('\'', "''"),
            delta.expected_revision
        );
        endpoints.query_ok(protocol, &key, &query).await;
        endpoints.query_all(&key, &query, None).await; // exact revision is consumed once
        endpoints
            .query_all(&key, "SQL SELECT secret FROM native_security;", None)
            .await;
        endpoints
            .query_all(
                &key,
                "SQL SELECT id FROM native_security WHERE secret='secret';",
                Some(vec![json!({"id":1})]),
            )
            .await;
        delta = row_security_delta(&row_security_view(&db, &actor, "native_security"));
        delta.records[0]
            .properties
            .get_mut("/secret")
            .unwrap()
            .actions
            .insert(PropertyAction::Read);
        let query = format!(
            "ALTER ROW SECURITY native_security APPLY JSON '{}' IF REVISION {};",
            serde_json::to_string(&delta).unwrap().replace('\'', "''"),
            delta.expected_revision
        );
        endpoints.query_ok(protocol, &key, &query).await;
        endpoints
            .query_all(
                &key,
                "SQL SELECT secret FROM native_security;",
                Some(vec![json!({"secret":"secret"})]),
            )
            .await;
    }
}

fn isolated(name: &str) -> bool {
    if std::env::var("CHIRON_RLS_AUDIT_CHILD").ok().as_deref() == Some(name) {
        return false;
    }
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("CHIRON_RLS_AUDIT_CHILD", name)
            .status()
            .unwrap()
            .success()
    );
    true
}

async fn http(db: Db, auth: AuthConfig) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        api::serve_listener_with_auth(db, auth, listener)
            .await
            .unwrap();
    });
    (url, task)
}

async fn post(base: &str, path: &str, key: &str, body: Value) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let code = r.status().as_u16();
    (code, r.json().await.unwrap())
}

fn protected() -> (tempfile::TempDir, Db, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    onboarding::initialize(
        &root.join("data"),
        "acme",
        "admin",
        &root.join("storage.json"),
        &root.join("admin.key"),
        false,
    )
    .unwrap();
    let key = fs::read_to_string(root.join("admin.key"))
        .unwrap()
        .trim()
        .to_string();
    let db = Db::open(root.join("data")).unwrap();
    (temp, db, key)
}

struct Endpoints {
    http: String,
    wire: String,
    grpc: pb::chiron_db_client::ChironDbClient<tonic::transport::Channel>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Endpoints {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Endpoints {
    async fn start(db: &Db, auth: AuthConfig) -> Self {
        let (http, ht) = http(db.clone(), auth.clone()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wire = listener.local_addr().unwrap().to_string();
        let wd = db.clone();
        let wa = auth.clone();
        let wt = tokio::spawn(async move {
            wire::serve_listener_with_auth(wd, wa, listener)
                .await
                .unwrap();
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let gd = db.clone();
        let gt = tokio::spawn(async move {
            grpc::serve_with_auth(gd, auth, addr).await.unwrap();
        });
        let grpc =
            pb::chiron_db_client::ChironDbClient::new(common::connect_grpc_channel(addr).await);
        Self {
            http,
            wire,
            grpc,
            tasks: vec![ht, wt, gt],
        }
    }
    async fn deny(&mut self, key: &str, statement: &str) {
        for path in ["/sql", "/v1/sql"] {
            let (code, body) = post(
                &self.http,
                path,
                key,
                serde_json::to_value(sql(statement)).unwrap(),
            )
            .await;
            assert_eq!(code, 403, "{path}: {statement}: {body}");
            assert!(!body.to_string().contains("private-secret"));
        }
        let (code, body) = post(
            &self.http,
            "/v1/chironql",
            key,
            json!({"query": format!("SQL {statement};"), "confirm":true}),
        )
        .await;
        assert_eq!(code, 403, "ChironQL {statement}: {body}");
        let result = self
            .grpc
            .execute_sql(common::grpc_auth_request(
                pb::SqlExecutionRequest {
                    statements: vec![pb::SqlStatement {
                        sql: statement.into(),
                        parameters: vec![],
                    }],
                    idempotency_key: None,
                    retry_id: None,
                },
                key,
            ))
            .await;
        assert_eq!(
            result.unwrap_err().code(),
            tonic::Code::PermissionDenied,
            "gRPC {statement}"
        );
        let response = common::send_wire_with_key(
            &self.wire,
            1,
            key,
            wire_request::Operation::Sql(WireSqlRequest {
                request_json: serde_json::to_string(&sql(statement)).unwrap(),
            }),
        )
        .await;
        assert!(!response.error_code.is_empty(), "Wire {statement}");
        assert!(!format!("{response:?}").contains("private-secret"));
    }
    async fn query_all(&mut self, key: &str, query: &str, expected: Option<Vec<Value>>) {
        for prefix in ["", "/v1"] {
            let (status, body) = post(
                &self.http,
                &format!("{prefix}/chironql"),
                key,
                json!({"query":query, "confirm":true}),
            )
            .await;
            match &expected {
                Some(rows) => {
                    assert_eq!(status, 200, "{query}: {body}");
                    assert_eq!(
                        body.get("rows").cloned().unwrap_or(json!([])),
                        json!(rows),
                        "HTTP {query}"
                    );
                }
                None => {
                    assert!(
                        matches!(status, 403 | 404)
                            || (query.starts_with("ALTER ROW SECURITY ") && status == 409),
                        "{query}: {status} {body}"
                    );
                    assert!(
                        body.get("rows").is_none(),
                        "denial must not carry result rows: {body}"
                    );
                }
            }
        }
        let response = self
            .grpc
            .execute_query(common::grpc_auth_request(
                pb::ChironQlRequest {
                    query: query.into(),
                    confirm: true,
                    ..Default::default()
                },
                key,
            ))
            .await;
        match &expected {
            Some(rows) => {
                let actual: Vec<Value> = response
                    .unwrap()
                    .into_inner()
                    .rows_json
                    .iter()
                    .map(|row| serde_json::from_str(row).unwrap())
                    .collect();
                assert_eq!(&actual, rows, "gRPC {query}");
            }
            None => {
                let error = response.unwrap_err();
                assert!(
                    matches!(
                        error.code(),
                        tonic::Code::PermissionDenied | tonic::Code::NotFound
                    ) || (query.starts_with("ALTER ROW SECURITY ")
                        && error.code() == tonic::Code::Aborted),
                    "{error}"
                );
                assert!(!error.message().contains("\"value\":9001"));
            }
        }
        let response = common::send_wire_with_key(
            &self.wire,
            1,
            key,
            wire_request::Operation::Chironql(WireChironQlRequest {
                query: query.into(),
                confirm: true,
                ..Default::default()
            }),
        )
        .await;
        match expected {
            Some(rows) => {
                assert!(response.error_code.is_empty(), "{response:?}");
                let Some(wire_response::Payload::Chironql(response)) = response.payload else {
                    panic!("missing ChironQL response")
                };
                let actual: Vec<Value> = response
                    .rows_json
                    .iter()
                    .map(|row| serde_json::from_str(row).unwrap())
                    .collect();
                assert_eq!(actual, rows, "Wire {query}");
            }
            None => {
                assert!(!response.error_code.is_empty(), "Wire accepted {query}");
                assert!(
                    response.payload.is_none(),
                    "denial must not carry result payload"
                );
            }
        }
    }

    async fn query_ok(&mut self, protocol: usize, key: &str, query: &str) -> Vec<Value> {
        if protocol < 2 {
            let path = if protocol == 0 {
                "/chironql"
            } else {
                "/v1/chironql"
            };
            let (status, body) =
                post(&self.http, path, key, json!({"query":query,"confirm":true})).await;
            assert_eq!(status, 200, "{query}: {body}");
            return body
                .get("rows")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }
        let rows = if protocol == 2 {
            self.grpc
                .execute_query(common::grpc_auth_request(
                    pb::ChironQlRequest {
                        query: query.into(),
                        confirm: true,
                        ..Default::default()
                    },
                    key,
                ))
                .await
                .unwrap()
                .into_inner()
                .rows_json
        } else {
            let response = common::send_wire_with_key(
                &self.wire,
                1,
                key,
                wire_request::Operation::Chironql(WireChironQlRequest {
                    query: query.into(),
                    confirm: true,
                    ..Default::default()
                }),
            )
            .await;
            assert!(response.error_code.is_empty(), "{query}: {response:?}");
            let Some(wire_response::Payload::Chironql(response)) = response.payload else {
                panic!("missing ChironQL response")
            };
            response.rows_json
        };
        rows.iter()
            .map(|row| serde_json::from_str(row).unwrap())
            .collect()
    }
    async fn deny_ddl_batch_and_transaction(&mut self, key: &str) {
        let mut request = sql("UPDATE records SET secret='batch-leak' WHERE id=1");
        request
            .statements
            .push(sql("CREATE TABLE denied (id BIGINT)").statements.remove(0));
        let dto = pb::SqlExecutionRequest {
            statements: request
                .statements
                .iter()
                .map(|s| pb::SqlStatement {
                    sql: s.sql.clone(),
                    parameters: vec![],
                })
                .collect(),
            ..Default::default()
        };
        for prefix in ["", "/v1"] {
            let (code, body) = post(
                &self.http,
                &format!("{prefix}/sql"),
                key,
                serde_json::to_value(&request).unwrap(),
            )
            .await;
            assert_eq!(code, 403, "{body}");
            let (code, body) = post(
                &self.http,
                &format!("{prefix}/sql/transactions"),
                key,
                json!({}),
            )
            .await;
            assert_eq!(code, 200, "{body}");
            let handle = body["handle"].as_str().unwrap();
            let (code, body) = post(
                &self.http,
                &format!("{prefix}/sql/transactions/{handle}/execute"),
                key,
                serde_json::to_value(&request).unwrap(),
            )
            .await;
            assert_eq!(code, 403, "{body}");
            let rollback = reqwest::Client::new()
                .delete(format!("{}{prefix}/sql/transactions/{handle}", self.http))
                .bearer_auth(key)
                .send()
                .await
                .unwrap();
            assert_eq!(rollback.status(), 200);
        }
        assert_eq!(
            self.grpc
                .execute_sql(common::grpc_auth_request(dto.clone(), key))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        let handle = self
            .grpc
            .begin_sql_transaction(common::grpc_auth_request(
                pb::BeginSqlTransactionRequest {},
                key,
            ))
            .await
            .unwrap()
            .into_inner()
            .handle;
        assert_eq!(
            self.grpc
                .execute_sql_transaction(common::grpc_auth_request(
                    pb::SqlTransactionExecuteRequest {
                        handle: handle.clone(),
                        request: Some(dto)
                    },
                    key
                ))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        self.grpc
            .rollback_sql_transaction(common::grpc_auth_request(
                pb::SqlTransactionHandleRequest { handle },
                key,
            ))
            .await
            .unwrap();
        let response = common::send_wire_with_key(
            &self.wire,
            1,
            key,
            wire_request::Operation::Sql(WireSqlRequest {
                request_json: serde_json::to_string(&request).unwrap(),
            }),
        )
        .await;
        assert!(!response.error_code.is_empty());
        let command = |action: &str, handle, request_json| {
            wire_request::Operation::SqlTransaction(chirondb::grpc::pb::WireSqlTransactionRequest {
                action: action.into(),
                handle,
                request_json,
            })
        };
        let response =
            common::send_wire_with_key(&self.wire, 2, key, command("begin", None, None)).await;
        assert!(response.error_code.is_empty(), "{response:?}");
        let Some(wire_response::Payload::Sql(body)) = response.payload else {
            panic!("expected SQL handle")
        };
        let body: Value = serde_json::from_str(&body.response_json).unwrap();
        let handle = body["handle"].as_str().unwrap().to_string();
        let response = common::send_wire_with_key(
            &self.wire,
            3,
            key,
            command(
                "execute",
                Some(handle.clone()),
                Some(serde_json::to_string(&request).unwrap()),
            ),
        )
        .await;
        assert!(!response.error_code.is_empty());
        let response =
            common::send_wire_with_key(&self.wire, 4, key, command("rollback", Some(handle), None))
                .await;
        assert!(response.error_code.is_empty(), "{response:?}");
    }
    async fn pg(&self, key: &str) -> tokio::net::TcpStream {
        let mut pg = tokio::net::TcpStream::connect(&self.wire).await.unwrap();
        let mut startup = 196608u32.to_be_bytes().to_vec();
        startup.extend_from_slice(b"user\0audit\0database\0postgres\0\0");
        pg.write_all(&((startup.len() + 4) as u32).to_be_bytes())
            .await
            .unwrap();
        pg.write_all(&startup).await.unwrap();
        let (kind, body) = pg_message(&mut pg).await;
        assert_eq!(kind, b'R');
        assert_eq!(u32::from_be_bytes(body[..4].try_into().unwrap()), 3);
        pg_send(&mut pg, b'p', format!("{key}\0").as_bytes()).await;
        loop {
            let (kind, body) = pg_message(&mut pg).await;
            assert_ne!(kind, b'E', "{body:?}");
            if kind == b'Z' {
                break;
            }
        }
        pg
    }
}
async fn pg_denied(pg: &mut tokio::net::TcpStream, statement: &str) {
    pg_send(pg, b'Q', format!("{statement};\0").as_bytes()).await;
    let mut denied = false;
    loop {
        let (kind, body) = pg_message(pg).await;
        if kind == b'E' {
            denied = true;
            assert!(String::from_utf8_lossy(&body).contains("42501"));
        }
        assert_ne!(kind, b'D', "denied SQL returned a row");
        if kind == b'Z' {
            break;
        }
    }
    assert!(denied, "PG {statement}");
}
async fn pg_extended_denied(pg: &mut tokio::net::TcpStream, statement: &str) {
    let mut parse = vec![0];
    parse.extend_from_slice(statement.as_bytes());
    parse.extend_from_slice(&[0, 0, 0]);
    pg_send(pg, b'P', &parse).await;
    pg_send(pg, b'B', &[0, 0, 0, 0, 0, 0, 0, 0]).await;
    pg_send(pg, b'D', b"P\0").await;
    pg_send(pg, b'E', &[0, 0, 0, 0, 0]).await;
    pg_send(pg, b'S', &[]).await;
    let mut denied = false;
    loop {
        let (kind, body) = pg_message(pg).await;
        if kind == b'E' {
            denied = true;
            assert!(String::from_utf8_lossy(&body).contains("42501"));
        }
        assert!(
            !matches!(kind, b'D' | b'T' | b't'),
            "denied preparation leaked data/metadata"
        );
        if kind == b'Z' {
            break;
        }
    }
    assert!(denied, "PG extended {statement}");
}
#[tokio::test]
async fn legacy_sql_scope_and_admin_are_consistent_across_protocols() {
    let temp = tempfile::tempdir().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.execute_sql(sql(
        "CREATE TABLE records (id BIGINT PRIMARY KEY, secret TEXT)",
    ))
    .unwrap();
    db.execute_sql(sql("INSERT INTO records VALUES (1,'private-secret')"))
        .unwrap();
    let scoped = "scoped-test-key-0123456789012345678901234";
    let tenant = "tenant-test-key-0123456789012345678901234";
    let writer = "writer-test-key-0123456789012345678901234";
    let admin = "admin-test-key-01234567890123456789012345";
    let keys = [
        (scoped, Role::Admin, None, vec!["records"]),
        (tenant, Role::Admin, Some("b"), vec![]),
        (writer, Role::ReadWrite, None, vec![]),
        (admin, Role::Admin, None, vec![]),
    ];
    let key_file = temp.path().join("keys");
    fs::write(
        &key_file,
        keys.iter().map(|k| k.0).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    let auth = AuthConfig::from_key_sources(None, Some(key_file))
        .with_validated_rbac(
            RbacConfig {
                keys: keys
                    .iter()
                    .enumerate()
                    .map(|(i, (key, role, tenant, names))| ApiKeyEntry {
                        id: Some(format!("test-{i}")),
                        key: key.to_string(),
                        role: *role,
                        tenant_id: tenant.map(str::to_string),
                        allowed_collections: names.iter().map(|n| n.to_string()).collect(),
                        max_collections: None,
                        capabilities: vec![],
                    })
                    .collect(),
            },
            true,
        )
        .unwrap();
    let mut endpoints = Endpoints::start(&db, auth).await;
    for key in [scoped, tenant] {
        db.set_tenant_enforcement(if key == tenant {
            TenantEnforcement::Enforced
        } else {
            TenantEnforcement::Disabled
        });
        let mut pg = endpoints.pg(key).await;
        for statement in [
            "SELECT secret FROM records",
            "INSERT INTO records VALUES(2,'bad')",
            "UPDATE records SET secret='bad'",
            "DELETE FROM records RETURNING secret",
            "EXPLAIN SELECT * FROM records",
            "DROP TABLE records",
        ] {
            endpoints.deny(key, statement).await;
            pg_denied(&mut pg, statement).await;
            pg_extended_denied(&mut pg, statement).await;
        }
        pg_denied(&mut pg, "BEGIN").await;
        for prefix in ["", "/v1"] {
            let (status, body) = post(
                &endpoints.http,
                &format!("{prefix}/sql/transactions"),
                key,
                json!({}),
            )
            .await;
            assert_eq!(status, 403, "{body}");
        }
        let result = endpoints
            .grpc
            .begin_sql_transaction(common::grpc_auth_request(
                pb::BeginSqlTransactionRequest {},
                key,
            ))
            .await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
        let response = common::send_wire_with_key(
            &endpoints.wire,
            1,
            key,
            wire_request::Operation::SqlTransaction(
                chirondb::grpc::pb::WireSqlTransactionRequest {
                    action: "begin".into(),
                    handle: None,
                    request_json: None,
                },
            ),
        )
        .await;
        assert!(!response.error_code.is_empty());
    }
    db.set_tenant_enforcement(TenantEnforcement::Disabled);
    endpoints.deny_ddl_batch_and_transaction(writer).await;
    let untouched = db
        .execute_sql(sql("SELECT secret FROM records WHERE id=1"))
        .unwrap();
    assert!(
        !serde_json::to_string(&untouched)
            .unwrap()
            .contains("batch-leak")
    );
    let mut pg = endpoints.pg(writer).await;
    for statement in [
        "CREATE TABLE denied (id BIGINT PRIMARY KEY)",
        "ALTER TABLE records ADD COLUMN extra TEXT",
        "CREATE INDEX denied_idx ON records(secret)",
        "DROP TABLE records",
    ] {
        endpoints.deny(writer, statement).await;
        pg_denied(&mut pg, statement).await;
    }
    for statement in [
        "SELECT secret FROM records",
        "UPDATE records SET secret='private-secret' WHERE id=1 RETURNING secret",
    ] {
        let (code, body) = post(
            &endpoints.http,
            "/v1/sql",
            writer,
            serde_json::to_value(sql(statement)).unwrap(),
        )
        .await;
        assert_eq!(code, 200, "{body}");
    }
    db.set_tenant_enforcement(TenantEnforcement::Enforced);
    endpoints.deny(admin, "SELECT secret FROM records").await;
    assert!(db.execute_sql(sql("SELECT * FROM records")).is_err());
    assert!(
        db.begin_sql_transaction(&chirondb::audit::AuditContext::embedded())
            .is_err()
    );
    db.set_tenant_enforcement(TenantEnforcement::Disabled);
    let response = db.execute_sql(sql("SELECT secret FROM records")).unwrap();
    assert!(
        serde_json::to_string(&response)
            .unwrap()
            .contains("private-secret")
    );
}

#[tokio::test]
async fn protected_write_only_cannot_read_through_mutations_or_returning() {
    if isolated("protected_write_only_cannot_read_through_mutations_or_returning") {
        return;
    }
    let (_temp, mut db, key) = protected();
    db.migrate_table_authority_offline().unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let admin = || authority.authenticate(&key).unwrap();
    for statement in [
        "CREATE TABLE records (id BIGINT PRIMARY KEY, secret TEXT)",
        "INSERT INTO records VALUES(1,'private-secret')",
    ] {
        db.execute_sql_authorized(&admin(), sql(statement), "test")
            .unwrap();
    }
    authority
        .create_role(&admin(), authority.revision(), "writer")
        .unwrap();
    authority
        .create_user(
            &admin(),
            authority.revision(),
            "writer",
            SubjectAttributes {
                department: "Finance".into(),
                clearance: Classification::Restricted,
            },
        )
        .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "writer",
        "records",
        BTreeSet::from([Action::Create, Action::Update, Action::Delete]),
        true,
    )
    .unwrap();
    authority
        .assign_role(&admin(), authority.revision(), "writer", "writer", true)
        .unwrap();
    let principal = authority.resolve_user(&admin(), "writer").unwrap();
    let writer = authority
        .issue_credential(&admin(), authority.revision(), &principal)
        .unwrap()
        .secret;
    // Blind writers explicitly receive Query on the shared unique-key domain.
    // This does not grant object Read or projection of another owner's values.
    let metadata = row_security_view(&db, &admin(), "records");
    let mut delta = row_security_delta(&metadata);
    delta.records[0].grants.push(ObjectGrant {
        subject: Subject::Principal(principal),
        effect: Effect::Permit,
        actions: BTreeSet::from([Action::Search]),
        inherit: false,
    });
    db.change_relational_security_authorized(&admin(), delta)
        .unwrap()
        .consume(|_| Ok(()))
        .unwrap();
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    for statement in [
        "SELECT secret FROM records",
        "UPDATE records SET secret='bad' WHERE id=1 RETURNING secret",
        "UPDATE records SET secret=secret",
        "DELETE FROM records WHERE secret='private-secret'",
        "DELETE FROM records RETURNING *",
        "INSERT INTO records(id) VALUES(1) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING secret",
        "INSERT INTO records VALUES(1,'bad') ON CONFLICT(id) DO NOTHING",
        "INSERT INTO records VALUES(2,'new') RETURNING *",
    ] {
        endpoints.deny(&writer, statement).await;
    }
    // Blind INSERT VALUES remains usable; denied operations leave existing data intact.
    let (code, body) = post(
        &endpoints.http,
        "/v1/sql",
        &writer,
        serde_json::to_value(sql("INSERT INTO records VALUES(2,'new')")).unwrap(),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let current = db
        .execute_sql_authorized(&admin(), sql("SELECT * FROM records ORDER BY id"), "test")
        .unwrap();
    let encoded = serde_json::to_string(&current).unwrap();
    assert!(encoded.contains("private-secret"));
    assert!(
        !encoded.contains("new"),
        "table owner has no implicit access to another writer's rows"
    );
    // Explicit Read restores the legitimate read+write behavior on the same credential.
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "writer",
        "records",
        BTreeSet::from([Action::Read]),
        true,
    )
    .unwrap();
    let (code, body) = post(
        &endpoints.http,
        "/v1/sql",
        &writer,
        serde_json::to_value(sql(
            "UPDATE records SET secret='writer-secret' WHERE id=2 RETURNING secret",
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    assert!(body.to_string().contains("writer-secret"));
    let mut saved = sql("UPDATE records SET secret='writer-secret' WHERE id=2 RETURNING secret");
    saved.idempotency_key = Some("read-write-receipt".into());
    let writer_before_revoke = authority.authenticate(&writer).unwrap();
    let receipt = db
        .execute_sql_authorized(&writer_before_revoke, saved.clone(), "test")
        .unwrap();
    assert!(receipt.committed);
    let (code, handle) = post(&endpoints.http, "/v1/sql/transactions", &writer, json!({})).await;
    assert_eq!(code, 200, "{handle}");
    let handle = handle["handle"].as_str().unwrap();
    let (code, body) = post(
        &endpoints.http,
        &format!("/v1/sql/transactions/{handle}/execute"),
        &writer,
        serde_json::to_value(sql(
            "UPDATE records SET secret='uncommitted' WHERE id=2 RETURNING secret",
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(code, 200, "{body}");
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "writer",
        "records",
        BTreeSet::from([Action::Read]),
        false,
    )
    .unwrap();
    assert!(writer_before_revoke.publication_permit().is_err());
    let current_writer = authority.authenticate(&writer).unwrap();
    assert!(
        db.execute_sql_authorized(&current_writer, saved.clone(), "retry")
            .is_err()
    );
    let (code, body) = post(
        &endpoints.http,
        "/v1/sql",
        &writer,
        serde_json::to_value(saved).unwrap(),
    )
    .await;
    assert_eq!(code, 403, "{body}");
    let (code, body) = post(
        &endpoints.http,
        &format!("/v1/sql/transactions/{handle}/commit"),
        &writer,
        json!({}),
    )
    .await;
    assert_eq!(code, 403, "{body}");
    let rows = db
        .execute_sql_authorized(
            &admin(),
            sql("SELECT secret FROM records WHERE id=1"),
            "test",
        )
        .unwrap();
    let rows = serde_json::to_string(&rows).unwrap();
    assert!(rows.contains("private-secret") && !rows.contains("uncommitted"));
}

#[tokio::test]
async fn temporal_enforces_asset_and_property_authority() {
    if isolated("temporal_enforces_asset_and_property_authority") {
        return;
    }
    let (_temp, db, key) = protected();
    let authority = db.identity_authority().unwrap().clone();
    let admin = || authority.authenticate(&key).unwrap();
    db.create_protected_collection_authorized(
        &admin(),
        db.catalog_revision_authorized(&admin()).unwrap(),
        serde_json::from_value(json!({"name":"assets","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let mut principal = manager.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["assets".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::TemporalRead,
            Action::TemporalAppend,
        ]),
    });
    authority
        .put_principal(&manager, authority.revision(), principal)
        .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let policy = db
        .bind_access(&manager, "assets", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(
        &policy,
        RevisionUpdate {
            expected_revision: policy.policy_revision(),
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([
                    Action::Read,
                    Action::Update,
                    Action::Delete,
                    Action::TemporalRead,
                    Action::TemporalAppend,
                ]),
                templates: BTreeMap::from([(
                    "standard".into(),
                    IngestTemplate {
                        department: "HR".into(),
                        classification: Classification::Restricted,
                        properties: BTreeMap::from([(
                            "/secret".into(),
                            PropertyRule {
                                classification: Classification::Restricted,
                                actions: BTreeSet::from([
                                    PropertyAction::Read,
                                    PropertyAction::Query,
                                    PropertyAction::Write,
                                ]),
                            },
                        )]),
                        representations: BTreeMap::from([(
                            "dense".into(),
                            Representation {
                                source_fields: BTreeSet::from(["/secret".into()]),
                                classification: Classification::Restricted,
                            },
                        )]),
                    },
                )]),
            },
        },
    )
    .unwrap();
    let create = db
        .bind_access(&admin(), "assets", "acme", Action::Create)
        .unwrap();
    let ids = db
        .create_points_authorized(
            &create,
            "standard",
            vec![NewPoint {
                vector: vec![1., 0.],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"secret":"restricted"}),
            }],
            true,
        )
        .unwrap()
        .publish(|v| v)
        .unwrap();
    let asset = &ids[0];
    let append = db
        .bind_access(&admin(), "assets", "acme", Action::TemporalAppend)
        .unwrap();
    db.append_temporal_batch(
        "assets",
        TemporalAccess::Authorized(&append),
        vec![TemporalSample::new(
            asset,
            "secret",
            1,
            SensorValue::Float(9001.),
        )],
    )
    .unwrap();
    let mut p = admin().principal().clone();
    p.id = "audit-limited".into();
    p.attributes = SubjectAttributes {
        department: "Finance".into(),
        clearance: Classification::Internal,
    };
    p.installation_actions.clear();
    p.delegation.clear();
    p.grants = vec![ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["assets".into()]),
        actions: BTreeSet::from([Action::Read, Action::TemporalRead, Action::TemporalAppend]),
    }];
    authority
        .put_principal(&admin(), authority.revision(), p)
        .unwrap();
    let token = authority
        .issue_credential(&admin(), authority.revision(), "audit-limited")
        .unwrap()
        .secret;
    let limited = authority.authenticate(&token).unwrap();
    let read = db
        .bind_access(&limited, "assets", "acme", Action::Read)
        .unwrap();
    assert!(
        db.get_points_authorized(&read, &ids)
            .unwrap()
            .publish(|v| v)
            .unwrap()
            .is_empty()
    );
    let temporal = db
        .bind_access(&limited, "assets", "acme", Action::TemporalRead)
        .unwrap();
    assert!(
        db.latest_temporal(
            "assets",
            TemporalAccess::Authorized(&temporal),
            asset,
            "secret"
        )
        .is_err()
    );
    assert!(
        db.append_temporal_batch(
            "assets",
            TemporalAccess::Authorized(&temporal),
            vec![TemporalSample::new(
                asset,
                "secret",
                2,
                SensorValue::Float(1.)
            )]
        )
        .is_err()
    );
    assert!(
        db.bind_access(&limited, "assets", "other-tenant", Action::TemporalRead)
            .is_err()
    );
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    for q in [
        format!("LATEST assets ASSET '{asset}' PROPERTY 'secret';"),
        format!("HISTORY assets ASSET '{asset}' PROPERTY 'secret' FROM '0' TO '10' LIMIT 10;"),
    ] {
        endpoints.query_all(&token, &q, None).await;
    }
    endpoints
        .query_all(
            &token,
            &format!(
                "APPEND INTO assets [{{asset:'{asset}',property:'secret',time_ns:'2',value:42}}];"
            ),
            None,
        )
        .await;
    let visible = vec![
        json!({"asset_ref":{"namespace":"assets","id":asset},"property":"secret","time_ns":"1","value":9001.0}),
    ];
    for q in [
        format!("LATEST assets ASSET '{asset}' PROPERTY 'secret' WHERE secret = 'restricted';"),
        format!(
            "HISTORY assets ASSET '{asset}' PROPERTY 'secret' FROM '0' TO '10' LIMIT 10 WHERE secret = 'restricted';"
        ),
    ] {
        endpoints.query_all(&key, &q, Some(visible.clone())).await;
    }
    let q = format!("LATEST assets ASSET '{asset}' PROPERTY 'secret' WHERE secret = 'other';");
    endpoints.query_all(&key, &q, Some(vec![])).await;
    let q = format!("LATEST assets ASSET '{asset}' PROPERTY 'secret' WHERE unknown = 'other';");
    endpoints.query_all(&key, &q, None).await;
    // A caller with the right object action cannot invent an unlabelled series.
    let append = db
        .bind_access(&admin(), "assets", "acme", Action::TemporalAppend)
        .unwrap();
    assert!(
        db.append_temporal_batch(
            "assets",
            TemporalAccess::Authorized(&append),
            vec![
                TemporalSample::new(asset, "secret", 2, SensorValue::Float(42.)),
                TemporalSample::new(asset, "unknown", 2, SensorValue::Float(99.)),
            ]
        )
        .is_err()
    );
    let read = db
        .bind_access(&admin(), "assets", "acme", Action::TemporalRead)
        .unwrap();
    assert_eq!(
        db.scan_temporal(
            "assets",
            TemporalAccess::Authorized(&read),
            asset,
            "secret",
            0..10,
            10
        )
        .unwrap()
        .len(),
        1
    );
    // Changing field rules invalidates a queued read and blocks future reads
    // while retaining an explicitly granted write-only ingestion path.
    let labels_context = db
        .bind_access(
            &db.management_identity(&admin()).unwrap(),
            "assets",
            "acme",
            Action::LabelsManage,
        )
        .unwrap();
    let mut record = labels_context.authorize(asset).unwrap();
    record.properties.get_mut("/secret").unwrap().actions = BTreeSet::from([PropertyAction::Write]);
    db.replace_object_labels_authorized(
        &labels_context,
        asset,
        RevisionUpdate {
            expected_revision: labels_context.policy_revision(),
            value: ObjectLabels {
                labels: record.labels,
                properties: record.properties,
            },
        },
    )
    .unwrap();
    assert!(read.publication_permit().is_err());
    let append = db
        .bind_access(&admin(), "assets", "acme", Action::TemporalAppend)
        .unwrap();
    db.append_temporal_batch(
        "assets",
        TemporalAccess::Authorized(&append),
        vec![TemporalSample::new(
            asset,
            "secret",
            2,
            SensorValue::Float(42.),
        )],
    )
    .unwrap();
    let read = db
        .bind_access(&admin(), "assets", "acme", Action::TemporalRead)
        .unwrap();
    assert!(
        db.latest_temporal("assets", TemporalAccess::Authorized(&read), asset, "secret")
            .is_err()
    );
    let labels = |actions| {
        let context = db
            .bind_access(
                &db.management_identity(&admin()).unwrap(),
                "assets",
                "acme",
                Action::LabelsManage,
            )
            .unwrap();
        let mut record = context.authorize(asset).unwrap();
        record.properties.get_mut("/secret").unwrap().actions = actions;
        db.replace_object_labels_authorized(
            &context,
            asset,
            RevisionUpdate {
                expected_revision: context.policy_revision(),
                value: ObjectLabels {
                    labels: record.labels,
                    properties: record.properties,
                },
            },
        )
        .unwrap();
    };
    // Read does not grant Query, and neither grants Write. Replaying an
    // existing sample must go through the same current write authorization.
    labels(BTreeSet::from([
        PropertyAction::Read,
        PropertyAction::Write,
    ]));
    endpoints.query_all(&key, &format!("LATEST assets ASSET '{asset}' PROPERTY 'secret';"), Some(vec![
        json!({"asset_ref":{"namespace":"assets","id":asset},"property":"secret","time_ns":"2","value":42.0})
    ])).await;
    endpoints
        .query_all(
            &key,
            &format!(
                "LATEST assets ASSET '{asset}' PROPERTY 'secret' WHERE secret = 'restricted';"
            ),
            None,
        )
        .await;
    labels(BTreeSet::from([
        PropertyAction::Read,
        PropertyAction::Query,
    ]));
    endpoints
        .query_all(
            &key,
            &format!(
                "APPEND INTO assets [{{asset:'{asset}',property:'secret',time_ns:'2',value:42}}];"
            ),
            None,
        )
        .await;
    endpoints
        .query_all(
            &key,
            &format!(
                "APPEND INTO assets [{{asset:'{asset}',property:'secret',time_ns:'3',value:43}}];"
            ),
            None,
        )
        .await;
}

#[tokio::test]
async fn metadata_only_assets_enforce_authority_across_protocols() {
    if isolated("metadata_only_assets_enforce_authority_across_protocols") {
        return;
    }
    let (_temp, db, key) = protected();
    let authority = db.identity_authority().unwrap().clone();
    let admin = || authority.authenticate(&key).unwrap();
    db.create_protected_collection_authorized(
        &admin(),
        db.catalog_revision_authorized(&admin()).unwrap(),
        serde_json::from_value(json!({"name":"assets","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let mut principal = manager.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["assets".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::TemporalRead,
            Action::TemporalAppend,
        ]),
    });
    authority
        .put_principal(&manager, authority.revision(), principal)
        .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let policy = db
        .bind_access(&manager, "assets", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(
        &policy,
        RevisionUpdate {
            expected_revision: policy.policy_revision(),
            value: CollectionPolicy {
                owner_actions: BTreeSet::from([
                    Action::Read,
                    Action::Update,
                    Action::Delete,
                    Action::TemporalRead,
                    Action::TemporalAppend,
                ]),
                department_actions: BTreeSet::new(),
                templates: BTreeMap::from([(
                    "asset".into(),
                    IngestTemplate {
                        department: "HR".into(),
                        classification: Classification::Restricted,
                        representations: BTreeMap::new(),
                        properties: ["/location", "/temperature"]
                            .into_iter()
                            .map(|field| {
                                (
                                    field.into(),
                                    PropertyRule {
                                        classification: Classification::Restricted,
                                        actions: BTreeSet::from([
                                            PropertyAction::Read,
                                            PropertyAction::Query,
                                            PropertyAction::Write,
                                        ]),
                                    },
                                )
                            })
                            .collect(),
                    },
                )]),
            },
        },
    )
    .unwrap();
    let mut restricted = admin().principal().clone();
    restricted.id = "asset-limited".into();
    restricted.attributes.clearance = Classification::Internal;
    restricted.installation_actions.clear();
    restricted.delegation.clear();
    authority
        .put_principal(&admin(), authority.revision(), restricted)
        .unwrap();
    let limited = authority
        .issue_credential(&admin(), authority.revision(), "asset-limited")
        .unwrap()
        .secret;
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    for protocol in 0..4 {
        let result = endpoints
            .query_ok(
                protocol,
                &key,
                "CREATE ASSET assets TEMPLATE asset METADATA {location:'north'};",
            )
            .await;
        let id = result[0]["id"].as_str().unwrap();
        uuid::Uuid::parse_str(id).unwrap();
        endpoints
            .query_all(
                &key,
                &format!("GET ASSET assets ID '{id}';"),
                Some(vec![json!({"id":id,"metadata":{"location":"north"}})]),
            )
            .await;
        endpoints.query_ok(protocol, &key, &format!(
            "APPEND INTO assets [{{asset:'{id}',property:'temperature',time_ns:'1',value:42}}];")).await;
        endpoints.query_all(&key, &format!(
            "LATEST assets ASSET '{id}' PROPERTY 'temperature' WHERE location = 'north';"),
            Some(vec![json!({"asset_ref":{"namespace":"assets","id":id},"property":"temperature","time_ns":"1","value":42.0})])).await;
        let revision = db
            .bind_access(&admin(), "assets", "acme", Action::Update)
            .unwrap()
            .policy_revision();
        for q in [
            format!("GET ASSET assets ID '{id}';"),
            format!("LATEST assets ASSET '{id}' PROPERTY 'temperature';"),
            format!(
                "UPDATE ASSET assets ID '{id}' METADATA {{location:'stolen'}} IF REVISION {revision};"
            ),
            format!("DELETE ASSET assets ID '{id}' IF REVISION {revision};"),
            format!(
                "APPEND INTO assets [{{asset:'{id}',property:'temperature',time_ns:'2',value:9001}}];"
            ),
            "REGISTER ASSET assets ID 'historic' TEMPLATE asset METADATA {location:'claim'};"
                .into(),
        ] {
            endpoints.query_all(&limited, &q, None).await;
        }
        endpoints.query_ok(protocol, &key, &format!(
            "UPDATE ASSET assets ID '{id}' METADATA {{location:'south'}} IF REVISION {revision};")).await;
        endpoints
            .query_all(
                &key,
                &format!(
                    "LATEST assets ASSET '{id}' PROPERTY 'temperature' WHERE location = 'north';"
                ),
                Some(vec![]),
            )
            .await;
        let revision = db
            .bind_access(&admin(), "assets", "acme", Action::Delete)
            .unwrap()
            .policy_revision();
        endpoints
            .query_ok(
                protocol,
                &key,
                &format!("DELETE ASSET assets ID '{id}' IF REVISION {revision};"),
            )
            .await;
        endpoints
            .query_all(&key, &format!("GET ASSET assets ID '{id}';"), None)
            .await;
        endpoints
            .query_all(
                &key,
                &format!("LATEST assets ASSET '{id}' PROPERTY 'temperature';"),
                None,
            )
            .await;
    }
}

#[tokio::test]
async fn independent_edge_authority_is_enforced_across_protocols() {
    if isolated("independent_edge_authority_is_enforced_across_protocols") {
        return;
    }
    let (_temp, mut db, key) = protected();
    db.migrate_table_authority_offline().unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let admin = || authority.authenticate(&key).unwrap();
    db.create_protected_collection_authorized(
        &admin(),
        db.catalog_revision_authorized(&admin()).unwrap(),
        serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let mut principal = manager.principal().clone();
    let grant = ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["docs".into()]),
        actions: BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Ingest,
            Action::Update,
            Action::Delete,
            Action::GraphRead,
            Action::GraphWrite,
        ]),
    };
    principal.grants.push(grant.clone());
    principal.delegation.push(grant);
    authority
        .put_principal(&manager, authority.revision(), principal)
        .unwrap();
    let manager = db.management_identity(&admin()).unwrap();
    let policy = db
        .bind_access(&manager, "docs", "acme", Action::PolicyManage)
        .unwrap();
    db.replace_collection_policy_authorized(
        &policy,
        RevisionUpdate {
            expected_revision: policy.policy_revision(),
            value: CollectionPolicy {
                department_actions: BTreeSet::new(),
                owner_actions: BTreeSet::from([
                    Action::Read,
                    Action::Update,
                    Action::Delete,
                    Action::GraphRead,
                    Action::GraphWrite,
                ]),
                templates: BTreeMap::from([(
                    "standard".into(),
                    IngestTemplate {
                        department: "Security".into(),
                        classification: Classification::Internal,
                        properties: ["/text", "/edges/kind"]
                            .into_iter()
                            .map(|path| {
                                (
                                    path.into(),
                                    PropertyRule {
                                        classification: Classification::Internal,
                                        actions: BTreeSet::from([
                                            PropertyAction::Read,
                                            PropertyAction::Query,
                                            PropertyAction::Write,
                                        ]),
                                    },
                                )
                            })
                            .collect(),
                        representations: BTreeMap::from([(
                            "dense".into(),
                            Representation {
                                source_fields: BTreeSet::from(["/text".into()]),
                                classification: Classification::Internal,
                            },
                        )]),
                    },
                )]),
            },
        },
    )
    .unwrap();
    let schema = db
        .bind_access(&manager, "docs", "acme", Action::Schema)
        .unwrap();
    db.set_graph_lifecycle_authorized(&schema, schema.policy_revision(), true)
        .unwrap();
    let schema = db
        .bind_access(&manager, "docs", "acme", Action::Schema)
        .unwrap();
    db.configure_edge_type_authorized(
        &schema,
        schema.policy_revision(),
        chirondb::graph::ConfigureEdgeTypeRequest {
            name: "cites".into(),
            weight_property: None,
        },
    )
    .unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("CREATE TABLE docs (id TEXT PRIMARY KEY, state TEXT)"),
        "test",
    )
    .unwrap();
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    let revision = || {
        let actor = db.management_identity(&admin()).unwrap();
        db.bind_access(&actor, "docs", "acme", Action::LabelsManage)
            .unwrap()
            .policy_revision()
    };
    for protocol in 0..4 {
        let rows=endpoints.query_ok(protocol,&key,&format!("TRANSACTION {{ SQL INSERT INTO docs VALUES ('row-{protocol}','initial'); VECTOR CREATE POINTS INTO docs USING TEMPLATE standard {{binding:'source',point:{{vector:[1,0],payload:{{text:'source'}}}}}}, {{binding:'target',point:{{vector:[0,1],payload:{{text:'target'}}}}}}; GRAPH CONNECT docs NEW source -> cites -> NEW target SET {{kind:'allow'}}; }};")).await;
        let source =
            rows.iter().find(|row| row["binding"] == "source").unwrap()["record_ref"]["id"]
                .as_str()
                .unwrap()
                .to_string();
        let target =
            rows.iter().find(|row| row["binding"] == "target").unwrap()["record_ref"]["id"]
                .as_str()
                .unwrap()
                .to_string();
        let edge = rows
            .iter()
            .find_map(|row| row["edge_id"].as_str())
            .unwrap()
            .to_string();
        let traversal = format!(
            "TRAVERSE docs FROM '{source}' VIA cites DEPTH 1 EDGE WHERE kind = 'allow' WITH PAYLOAD RETURN EDGES LIMIT 10;"
        );
        let visible = endpoints.query_ok(protocol, &key, &traversal).await;
        assert_eq!(visible.len(), 1);
        endpoints
            .query_all(&key, &traversal, Some(visible.clone()))
            .await;
        // Mutating own edge grants over each transport hides topology through all transports.
        endpoints.query_ok(protocol,&key,&format!("DENY GRAPH_READ, GRAPH_WRITE ON EDGE '{edge}' IN docs TO USER admin IF REVISION {};",revision())).await;
        endpoints.query_all(&key, &traversal, Some(vec![])).await;
        assert!(
            !endpoints
                .query_ok(protocol, &key, &format!("GET docs POINTS '{target}';"))
                .await
                .is_empty()
        );
        let update = format!(
            "TRANSACTION {{ SQL UPDATE docs SET state='changed' WHERE id='row-{protocol}'; VECTOR UPSERT INTO docs {{id:'{source}',vector:[1,0],payload:{{text:'source'}}}}; GRAPH UPDATE docs EDGE '{edge}' SET PROPERTIES {{kind:'changed'}}; }};"
        );
        endpoints.query_all(&key, &update, None).await;
        endpoints
            .query_all(
                &key,
                &format!("SQL SELECT state FROM docs WHERE id='row-{protocol}';"),
                Some(vec![json!({"state":"initial"})]),
            )
            .await;
        endpoints.query_ok(protocol,&key,&format!("REVOKE DENY GRAPH_READ, GRAPH_WRITE ON EDGE '{edge}' IN docs FROM USER admin IF REVISION {};",revision())).await;
        endpoints.query_all(&key, &traversal, Some(visible)).await;
        endpoints
            .query_ok(
                protocol,
                &key,
                &format!(
                    "ALTER EDGE '{edge}' IN docs SET CLASSIFICATION CONFIDENTIAL IF REVISION {};",
                    revision()
                ),
            )
            .await;
        endpoints.query_ok(protocol, &key, &update).await;
        endpoints.query_all(&key, &traversal, Some(vec![])).await;
        let deletion = format!(
            "TRANSACTION {{ SQL DELETE FROM docs WHERE id='row-{protocol}'; VECTOR DELETE FROM docs POINTS '{source}'; GRAPH UNRELATE docs EDGE '{edge}'; }};"
        );
        endpoints.query_ok(protocol, &key, &deletion).await;
        endpoints.query_all(&key, &traversal, None).await;
    }
}

#[tokio::test]
async fn native_relational_table_read_does_not_grant_another_owners_rows() {
    if isolated("native_relational_table_read_does_not_grant_another_owners_rows") {
        return;
    }
    let (_temp, mut db, key) = protected();
    db.migrate_table_authority_offline().unwrap();
    db.migrate_sql_scopes_offline().unwrap();
    let authority = db.identity_authority().unwrap().clone();
    let admin = || authority.authenticate(&key).unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("CREATE TABLE rows_private (id BIGINT PRIMARY KEY, secret TEXT)"),
        "test",
    )
    .unwrap();
    db.execute_sql_authorized(
        &admin(),
        sql("INSERT INTO rows_private VALUES (1,'other-owner-secret')"),
        "test",
    )
    .unwrap();
    authority
        .create_role(&admin(), authority.revision(), "row_reader")
        .unwrap();
    authority
        .create_user(
            &admin(),
            authority.revision(),
            "row_reader",
            SubjectAttributes {
                department: "Security".into(),
                clearance: Classification::Restricted,
            },
        )
        .unwrap();
    db.change_role_table_privileges_authorized(
        &admin(),
        authority.revision(),
        "row_reader",
        "rows_private",
        BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
        true,
    )
    .unwrap();
    authority
        .assign_role(
            &admin(),
            authority.revision(),
            "row_reader",
            "row_reader",
            true,
        )
        .unwrap();
    let principal = authority.resolve_user(&admin(), "row_reader").unwrap();
    let token = authority
        .issue_credential(&admin(), authority.revision(), &principal)
        .unwrap()
        .secret;
    let mut endpoints = Endpoints::start(&db, AuthConfig::disabled()).await;
    for query in [
        "SQL SELECT secret FROM rows_private;",
        "SQL SELECT secret FROM rows_private WHERE id=1;",
        "SQL WITH visible AS (SELECT id,secret FROM rows_private) SELECT secret FROM visible;",
        "SQL SELECT p.secret FROM rows_private p INNER JOIN rows_private q ON p.id=q.id;",
    ] {
        endpoints.query_all(&token, query, Some(vec![])).await;
    }
    endpoints
        .query_all(
            &token,
            "SQL SELECT COUNT(*) AS n FROM rows_private;",
            Some(vec![json!({"n":0})]),
        )
        .await;
    endpoints
        .query_all(
            &token,
            "SQL UPDATE rows_private SET secret='overwritten' WHERE id=1;",
            None,
        )
        .await;
    endpoints
        .query_all(&token, "SQL DELETE FROM rows_private WHERE id=1;", None)
        .await;
    endpoints
        .query_all(
            &key,
            "SQL SELECT secret FROM rows_private;",
            Some(vec![json!({"secret":"other-owner-secret"})]),
        )
        .await;
}
