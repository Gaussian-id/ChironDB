use chiron_pb::{
    BeginSqlTransactionRequest, SqlExecutionRequest, SqlStatement, SqlTransactionExecuteRequest,
    SqlTransactionHandleRequest, SqlTransactionState, SqlValue, chiron_db_client::ChironDbClient,
    sql_result::Result as SqlResult, sql_value::Value as SqlValueKind,
};
use chirondb::{
    Db,
    auth::AuthConfig,
    grpc::{self, chiron_pb},
};
use tempfile::TempDir;
use tokio::net::TcpListener;

struct Harness {
    _data: TempDir,
    url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = Db::open(data.path()).expect("open database");
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = probe.local_addr().expect("address");
        drop(probe);
        let server = tokio::spawn(async move {
            grpc::serve_with_auth(db, AuthConfig::disabled(), address)
                .await
                .expect("serve");
        });
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Self {
            _data: data,
            url: format!("http://{address}"),
            server,
        }
    }

    async fn client(&self) -> ChironDbClient<tonic::transport::Channel> {
        ChironDbClient::connect(self.url.clone())
            .await
            .expect("connect")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn statement(sql: &str) -> SqlStatement {
    SqlStatement {
        sql: sql.to_string(),
        parameters: Vec::new(),
    }
}

#[tokio::test]
async fn typed_sql_values_round_trip_over_grpc() {
    let harness = Harness::start().await;
    let mut client = harness.client().await;
    client
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                "CREATE TABLE documents (id INTEGER PRIMARY KEY, title TEXT NOT NULL)",
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("create table");

    client
        .execute_sql(SqlExecutionRequest {
            statements: vec![SqlStatement {
                sql: "INSERT INTO documents VALUES ($1, $2)".into(),
                parameters: vec![
                    SqlValue {
                        value: Some(SqlValueKind::Integer(7)),
                    },
                    SqlValue {
                        value: Some(SqlValueKind::Text("native SQL".into())),
                    },
                ],
            }],
            idempotency_key: None,
            retry_id: Some("grpc-relational-1".into()),
        })
        .await
        .expect("insert row");

    let response = client
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement("SELECT id, title FROM documents")],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("select row")
        .into_inner();
    assert!(response.committed);
    assert!(response.transaction_id.is_none());
    let Some(SqlResult::Rows(rows)) = &response.results[0].result else {
        panic!("expected rows result");
    };
    assert_eq!(rows.columns, ["id", "title"]);
    assert!(matches!(
        rows.rows[0].values[0].value,
        Some(SqlValueKind::Integer(7))
    ));
    assert!(matches!(
        &rows.rows[0].values[1].value,
        Some(SqlValueKind::Text(value)) if value == "native SQL"
    ));
}

#[tokio::test]
async fn schema_cascade_uses_the_grpc_relational_executor() {
    let harness = Harness::start().await;
    let mut client = harness.client().await;
    for sql in [
        "CREATE TABLE cascade_parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
        "CREATE TABLE cascade_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES cascade_parent(code))",
        "ALTER TABLE cascade_parent DROP CONSTRAINT cascade_parent_code_key CASCADE",
        "INSERT INTO cascade_child VALUES (1, 'orphan')",
        "CREATE TABLE drop_parent (id INTEGER PRIMARY KEY)",
        "CREATE TABLE drop_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES drop_parent(id))",
        "DROP TABLE drop_parent CASCADE",
        "INSERT INTO drop_child VALUES (1, 999)",
        "CREATE TABLE column_parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, obsolete TEXT, keep TEXT)",
        "CREATE TABLE column_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES column_parent(code))",
        "ALTER TABLE column_parent DROP COLUMN code CASCADE, DROP COLUMN obsolete",
        "INSERT INTO column_child VALUES (1, 'orphan')",
    ] {
        let response = client
            .execute_sql(SqlExecutionRequest {
                statements: vec![statement(sql)],
                idempotency_key: None,
                retry_id: None,
            })
            .await
            .expect("execute relational cascade")
            .into_inner();
        assert!(response.committed);
    }
}

#[tokio::test]
async fn orm_bytea_date_and_jsonb_values_round_trip_over_grpc() {
    let harness = Harness::start().await;
    let mut client = harness.client().await;
    client
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                "CREATE TABLE grpc_types (id INTEGER PRIMARY KEY, bytes_value BYTEA, date_value DATE, payload JSONB)",
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("create typed table");
    client
        .execute_sql(SqlExecutionRequest {
            statements: vec![SqlStatement {
                sql: "INSERT INTO grpc_types VALUES ($1, $2, $3, $4)".into(),
                parameters: vec![
                    SqlValue {
                        value: Some(SqlValueKind::Integer(1)),
                    },
                    SqlValue {
                        value: Some(SqlValueKind::BytesValue(vec![0, 255])),
                    },
                    SqlValue {
                        value: Some(SqlValueKind::Date("2026-09-17".into())),
                    },
                    SqlValue {
                        value: Some(SqlValueKind::Jsonb("{\"ready\":true}".into())),
                    },
                ],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("insert typed values");
    let response = client
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                "SELECT bytes_value, date_value, payload FROM grpc_types WHERE id = 1",
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("select typed values")
        .into_inner();
    let Some(SqlResult::Rows(rows)) = &response.results[0].result else {
        panic!("expected rows result");
    };
    assert!(matches!(
        &rows.rows[0].values[0].value,
        Some(SqlValueKind::BytesValue(value)) if value == &vec![0, 255]
    ));
    assert!(matches!(
        &rows.rows[0].values[1].value,
        Some(SqlValueKind::Date(value)) if value == "2026-09-17"
    ));
    assert!(matches!(
        &rows.rows[0].values[2].value,
        Some(SqlValueKind::Jsonb(value)) if value == "{\"ready\":true}"
    ));
}

#[tokio::test]
async fn interactive_transaction_round_trips_over_grpc() {
    let harness = Harness::start().await;
    let mut client = harness.client().await;
    client
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement("CREATE TABLE jobs (id INTEGER PRIMARY KEY)")],
            idempotency_key: None,
            retry_id: None,
        })
        .await
        .expect("create table");
    let transaction = client
        .begin_sql_transaction(BeginSqlTransactionRequest {})
        .await
        .expect("begin transaction")
        .into_inner();
    assert_eq!(transaction.state, SqlTransactionState::Active as i32);
    let executed = client
        .execute_sql_transaction(SqlTransactionExecuteRequest {
            handle: transaction.handle.clone(),
            request: Some(SqlExecutionRequest {
                statements: vec![statement("INSERT INTO jobs VALUES (1)")],
                idempotency_key: None,
                retry_id: None,
            }),
        })
        .await
        .expect("execute transaction")
        .into_inner();
    assert!(!executed.committed);
    let committed = client
        .commit_sql_transaction(SqlTransactionHandleRequest {
            handle: transaction.handle,
        })
        .await
        .expect("commit transaction")
        .into_inner();
    assert!(committed.committed);
    assert!(committed.transaction_id.is_some());

    let rollback = client
        .begin_sql_transaction(BeginSqlTransactionRequest {})
        .await
        .expect("begin rollback transaction")
        .into_inner();
    let rolled_back = client
        .rollback_sql_transaction(SqlTransactionHandleRequest {
            handle: rollback.handle,
        })
        .await
        .expect("rollback transaction")
        .into_inner();
    assert_eq!(rolled_back.state, SqlTransactionState::RolledBack as i32);
}
