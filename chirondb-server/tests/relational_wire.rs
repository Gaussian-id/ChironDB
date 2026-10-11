use chirondb::{
    Db, RelationalValue, SqlExecutionRequest, SqlExecutionResponse, SqlResult, SqlStatementRequest,
    SqlTransactionHandleResponse,
    grpc::pb::{
        WireRequest, WireSqlRequest, WireSqlTransactionRequest, wire_request, wire_response,
    },
    wire,
};
use tempfile::TempDir;
use tokio::net::TcpListener;

struct Harness {
    _data: TempDir,
    endpoint: String,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = Db::open(data.path()).expect("open database");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            wire::serve_listener(db, listener).await.expect("serve");
        });
        Self {
            _data: data,
            endpoint: address.to_string(),
            server,
        }
    }

    async fn execute(&self, id: u64, request: SqlExecutionRequest) -> SqlExecutionResponse {
        let response = wire::send_request(
            &self.endpoint,
            WireRequest {
                request_id: id,
                api_key: String::new(),
                operation: Some(wire_request::Operation::Sql(WireSqlRequest {
                    request_json: serde_json::to_string(&request).expect("encode request"),
                })),
            },
        )
        .await
        .expect("wire request");
        assert!(response.error_code.is_empty(), "{}", response.error_message);
        let Some(wire_response::Payload::Sql(response)) = response.payload else {
            panic!("expected SQL payload");
        };
        serde_json::from_str(&response.response_json).expect("decode response")
    }

    async fn transaction<T: serde::de::DeserializeOwned>(
        &self,
        id: u64,
        action: &str,
        handle: Option<String>,
        request: Option<SqlExecutionRequest>,
    ) -> T {
        let response = wire::send_request(
            &self.endpoint,
            WireRequest {
                request_id: id,
                api_key: String::new(),
                operation: Some(wire_request::Operation::SqlTransaction(
                    WireSqlTransactionRequest {
                        action: action.to_string(),
                        handle,
                        request_json: request.map(|request| {
                            serde_json::to_string(&request).expect("encode request")
                        }),
                    },
                )),
            },
        )
        .await
        .expect("wire transaction request");
        assert!(response.error_code.is_empty(), "{}", response.error_message);
        let Some(wire_response::Payload::Sql(response)) = response.payload else {
            panic!("expected SQL payload");
        };
        serde_json::from_str(&response.response_json).expect("decode response")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn request(sql: &str) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.to_string(),
            parameters: Vec::new(),
        }],
        idempotency_key: None,
        retry_id: None,
    }
}

#[tokio::test]
async fn chironwire_uses_the_native_relational_executor() {
    let harness = Harness::start().await;
    harness
        .execute(
            1,
            request("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"),
        )
        .await;
    harness
        .execute(2, request("INSERT INTO records VALUES (1, 'wire')"))
        .await;
    let response = harness
        .execute(3, request("SELECT value FROM records"))
        .await;
    assert!(matches!(
        &response.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("wire".into())]]
    ));
}

#[tokio::test]
async fn schema_cascade_uses_the_chironwire_relational_executor() {
    let harness = Harness::start().await;
    for (id, sql) in [
        (
            1,
            "CREATE TABLE cascade_parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
        ),
        (
            2,
            "CREATE TABLE cascade_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES cascade_parent(code))",
        ),
        (
            3,
            "ALTER TABLE cascade_parent DROP CONSTRAINT cascade_parent_code_key CASCADE",
        ),
        (4, "INSERT INTO cascade_child VALUES (1, 'orphan')"),
        (5, "CREATE TABLE drop_parent (id INTEGER PRIMARY KEY)"),
        (
            6,
            "CREATE TABLE drop_child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES drop_parent(id))",
        ),
        (7, "DROP TABLE drop_parent CASCADE"),
        (8, "INSERT INTO drop_child VALUES (1, 999)"),
        (
            9,
            "CREATE TABLE column_parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE, obsolete TEXT, keep TEXT)",
        ),
        (
            10,
            "CREATE TABLE column_child (id INTEGER PRIMARY KEY, parent_code TEXT REFERENCES column_parent(code))",
        ),
        (
            11,
            "ALTER TABLE column_parent DROP COLUMN code CASCADE, DROP COLUMN obsolete",
        ),
        (12, "INSERT INTO column_child VALUES (1, 'orphan')"),
    ] {
        let response = harness.execute(id, request(sql)).await;
        assert!(response.committed);
    }
}

#[tokio::test]
async fn chironwire_supports_interactive_sql_transactions() {
    let harness = Harness::start().await;
    harness
        .execute(1, request("CREATE TABLE records (id INTEGER PRIMARY KEY)"))
        .await;
    let transaction: SqlTransactionHandleResponse =
        harness.transaction(2, "begin", None, None).await;
    let executed: SqlExecutionResponse = harness
        .transaction(
            3,
            "execute",
            Some(transaction.handle.clone()),
            Some(request("INSERT INTO records VALUES (1)")),
        )
        .await;
    assert!(!executed.committed);
    let committed: SqlExecutionResponse = harness
        .transaction(4, "commit", Some(transaction.handle), None)
        .await;
    assert!(committed.committed);
    assert!(committed.transaction_id.is_some());
}
