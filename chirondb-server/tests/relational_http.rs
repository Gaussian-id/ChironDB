use chirondb::{
    Db, RelationalValue, SqlExecutionRequest, SqlExecutionResponse, SqlResult, SqlStatementRequest,
    SqlTransactionHandleResponse, SqlTransactionState, api,
};
use tempfile::TempDir;
use tokio::net::TcpListener;

struct Harness {
    _data: TempDir,
    base: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

#[tokio::test]
async fn interactive_sql_transaction_is_private_until_commit_and_can_rollback() {
    let harness = Harness::start().await;
    harness
        .execute(
            "/sql",
            request("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)"),
        )
        .await;
    let begin = harness
        .client
        .post(format!("{}/v1/sql/transactions", harness.base))
        .send()
        .await
        .expect("begin transaction");
    assert_eq!(begin.status(), reqwest::StatusCode::OK);
    let transaction: SqlTransactionHandleResponse = begin.json().await.expect("transaction handle");
    assert_eq!(transaction.state, SqlTransactionState::Active);

    let inserted = harness
        .execute(
            &format!("/v1/sql/transactions/{}/execute", transaction.handle),
            request("INSERT INTO accounts VALUES (1, 100)"),
        )
        .await;
    assert!(!inserted.committed);
    let outside = harness
        .execute("/sql", request("SELECT COUNT(*) FROM accounts"))
        .await;
    assert!(matches!(
        &outside.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(0)]]
    ));

    let commit = harness
        .client
        .post(format!(
            "{}/v1/sql/transactions/{}/commit",
            harness.base, transaction.handle
        ))
        .send()
        .await
        .expect("commit transaction");
    assert_eq!(commit.status(), reqwest::StatusCode::OK);
    let committed: SqlExecutionResponse = commit.json().await.expect("commit response");
    assert!(committed.committed);
    assert!(committed.transaction_id.is_some());

    let rollback_begin: SqlTransactionHandleResponse = harness
        .client
        .post(format!("{}/sql/transactions", harness.base))
        .send()
        .await
        .expect("begin rollback transaction")
        .json()
        .await
        .expect("rollback transaction handle");
    harness
        .execute(
            &format!("/sql/transactions/{}/execute", rollback_begin.handle),
            request("UPDATE accounts SET balance = 0 WHERE id = 1"),
        )
        .await;
    let rollback = harness
        .client
        .delete(format!(
            "{}/sql/transactions/{}",
            harness.base, rollback_begin.handle
        ))
        .send()
        .await
        .expect("rollback transaction");
    assert_eq!(rollback.status(), reqwest::StatusCode::OK);
    let rolled_back: SqlTransactionHandleResponse =
        rollback.json().await.expect("rollback response");
    assert_eq!(rolled_back.state, SqlTransactionState::RolledBack);
    let balance = harness
        .execute(
            "/v1/sql",
            request("SELECT balance FROM accounts WHERE id = 1"),
        )
        .await;
    assert!(matches!(
        &balance.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Integer(100)]]
    ));
}

#[tokio::test]
async fn schema_cascade_uses_the_http_relational_executor() {
    let harness = Harness::start().await;
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
        let response = harness.execute("/v1/sql", request(sql)).await;
        assert!(response.committed);
    }
}

impl Harness {
    async fn start() -> Self {
        let data = TempDir::new().expect("tempdir");
        let db = Db::open(data.path()).expect("open database");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            api::serve_listener(db, listener).await.expect("serve");
        });
        Self {
            _data: data,
            base: format!("http://{address}"),
            client: reqwest::Client::new(),
            server,
        }
    }

    async fn execute(&self, path: &str, request: SqlExecutionRequest) -> SqlExecutionResponse {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .json(&request)
            .send()
            .await
            .expect("SQL request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.expect("SQL response")
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
async fn sql_aliases_share_typed_atomic_executor() {
    let harness = Harness::start().await;
    let created = harness
        .execute(
            "/sql",
            request("CREATE TABLE documents (id UUID PRIMARY KEY, title TEXT NOT NULL)"),
        )
        .await;
    assert!(created.committed);
    assert!(created.transaction_id.is_some());

    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let inserted = harness
        .execute(
            "/v1/sql",
            SqlExecutionRequest {
                statements: vec![
                    SqlStatementRequest {
                        sql: "INSERT INTO documents VALUES ($1, $2)".into(),
                        parameters: vec![
                            RelationalValue::Uuid(first),
                            RelationalValue::Text("first".into()),
                        ],
                    },
                    SqlStatementRequest {
                        sql: "INSERT INTO documents VALUES ($1, $2)".into(),
                        parameters: vec![
                            RelationalValue::Uuid(second),
                            RelationalValue::Text("second".into()),
                        ],
                    },
                ],
                idempotency_key: None,
                retry_id: Some("http-relational-1".into()),
            },
        )
        .await;
    assert!(inserted.committed);
    assert_eq!(inserted.results.len(), 2);

    let selected = harness
        .execute(
            "/sql",
            request("SELECT title FROM documents ORDER BY title DESC LIMIT 1"),
        )
        .await;
    assert_eq!(selected.transaction_id, None);
    assert!(matches!(
        &selected.results[0],
        SqlResult::Rows { rows, .. }
            if rows == &vec![vec![RelationalValue::Text("second".into())]]
    ));
}
