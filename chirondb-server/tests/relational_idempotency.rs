use chirondb::{
    Db, SqlExecutionRequest, SqlExecutionResponse, SqlStatementRequest, api,
    auth::AuthConfig,
    grpc::{self, chiron_pb, pb},
    wire,
};
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_grpc_and_chironwire_share_the_same_sql_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wire_address = tcp.local_addr().unwrap().to_string();
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_address = probe.local_addr().unwrap();
    drop(probe);
    let http_db = db.clone();
    let wire_db = db.clone();
    let grpc_db = db.clone();
    let http_task = tokio::spawn(async move { api::serve_listener(http_db, http).await.unwrap() });
    let wire_task = tokio::spawn(async move { wire::serve_listener(wire_db, tcp).await.unwrap() });
    let grpc_task = tokio::spawn(async move {
        grpc::serve_with_auth(grpc_db, AuthConfig::disabled(), grpc_address)
            .await
            .unwrap()
    });
    let client = reqwest::Client::new();
    let url = format!("http://{http_address}/v1/sql");
    let setup = request("CREATE TABLE receipt_rows (id BIGINT PRIMARY KEY)", None);
    assert!(
        client
            .post(&url)
            .json(&setup)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let sql = "INSERT INTO receipt_rows (id) VALUES (1) RETURNING id";
    let mutation = request(sql, Some("same-key"));
    let sdk = chirondb_client::ChironDbClient::new(format!("http://{http_address}"));
    let first = sdk.execute_sql(&mutation).await.unwrap();
    let mut grpc_client = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match chiron_pb::chiron_db_client::ChironDbClient::connect(format!(
                "http://{grpc_address}"
            ))
            .await
            {
                Ok(client) => break client,
                Err(_) if !grpc_task.is_finished() => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                Err(error) => panic!("gRPC server failed: {error}"),
            }
        }
    })
    .await
    .expect("gRPC readiness deadline");
    let grpc_result = grpc_client
        .execute_sql(chiron_pb::SqlExecutionRequest {
            statements: vec![chiron_pb::SqlStatement {
                sql: sql.into(),
                parameters: vec![],
            }],
            retry_id: Some("another-correlation".into()),
            idempotency_key: Some("same-key".into()),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grpc_result.transaction_id, first.transaction_id);
    assert_eq!(grpc_result.commit_sequence, first.commit_sequence);
    let wire_result = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 1,
            api_key: String::new(),
            operation: Some(pb::wire_request::Operation::Sql(pb::WireSqlRequest {
                request_json: serde_json::to_string(&mutation).unwrap(),
            })),
        },
    )
    .await
    .unwrap();
    assert!(
        wire_result.error_code.is_empty(),
        "{}",
        wire_result.error_message
    );
    let Some(pb::wire_response::Payload::Sql(result)) = wire_result.payload else {
        panic!("missing SQL response")
    };
    assert_eq!(
        serde_json::from_str::<SqlExecutionResponse>(&result.response_json).unwrap(),
        first
    );
    // Language wrappers use the same core SQL fingerprint, independent of
    // HTTP/gRPC/wire encoding, query tracing and audit correlation.
    let query = format!("SQL {sql}");
    let wrapped = chirondb_types::chironql::ChironQlRequest {
        query: query.clone(),
        idempotency_key: Some("same-key".into()),
        retry_id: Some("chironql-sdk-attempt".into()),
        trace: true,
        ..Default::default()
    };
    let sdk_result = sdk.execute_chironql(&wrapped).await.unwrap();
    assert_eq!(sdk_result.transaction_id, first.transaction_id);
    let language_grpc = grpc_client
        .execute_query(chiron_pb::ChironQlRequest {
            query: query.clone(),
            idempotency_key: Some("same-key".into()),
            retry_id: Some("chironql-grpc-attempt".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(language_grpc.transaction_id, first.transaction_id);
    let language_wire = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 2,
            api_key: String::new(),
            operation: Some(pb::wire_request::Operation::Chironql(
                pb::WireChironQlRequest {
                    query,
                    idempotency_key: Some("same-key".into()),
                    retry_id: Some("chironql-wire-attempt".into()),
                    ..Default::default()
                },
            )),
        },
    )
    .await
    .unwrap();
    assert!(
        language_wire.error_code.is_empty(),
        "{}",
        language_wire.error_message
    );
    let Some(pb::wire_response::Payload::Chironql(language_wire)) = language_wire.payload else {
        panic!("missing ChironQL response")
    };
    assert_eq!(language_wire.transaction_id, first.transaction_id);
    for query in [
        "SQL SELECT COUNT(*) FROM receipt_rows",
        "CREATE COLLECTION must_not_exist DIM 2 METRIC cosine",
    ] {
        assert!(chirondb::chironql_parser::parse(query).is_ok());
        assert!(
            sdk.execute_chironql(&chirondb_types::chironql::ChironQlRequest {
                query: query.into(),
                idempotency_key: Some("unsupported-key".into()),
                ..Default::default()
            })
            .await
            .is_err()
        );
    }
    assert!(
        !db.list_collections()
            .iter()
            .any(|c| c.name == "must_not_exist")
    );
    let conflict = request("INSERT INTO receipt_rows (id) VALUES (2)", Some("same-key"));
    assert!(
        client
            .post(&url)
            .json(&conflict)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    let result: SqlExecutionResponse = client
        .post(&url)
        .json(&request("SELECT COUNT(*) FROM receipt_rows", None))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        matches!(&result.results[0], chirondb::SqlResult::Rows { rows, .. }
        if rows == &vec![vec![chirondb::RelationalValue::Integer(1)]])
    );
    let transaction = sdk.begin_sql_transaction().await.unwrap();
    assert_eq!(
        transaction.transaction_id.as_deref(),
        Some(transaction.handle.as_str())
    );
    sdk.execute_sql_transaction(
        &transaction.handle,
        &request("INSERT INTO receipt_rows (id) VALUES (3)", None),
    )
    .await
    .unwrap();
    let receipt = sdk
        .commit_sql_transaction(&transaction.handle)
        .await
        .unwrap();
    assert_eq!(receipt.transaction_id, transaction.transaction_id);
    let grpc_receipt = grpc_client
        .commit_sql_transaction(chiron_pb::SqlTransactionHandleRequest {
            handle: transaction.handle.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grpc_receipt.transaction_id, receipt.transaction_id);
    assert_eq!(grpc_receipt.commit_sequence, receipt.commit_sequence);
    let wire_receipt = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 3,
            api_key: String::new(),
            operation: Some(pb::wire_request::Operation::SqlTransaction(
                pb::WireSqlTransactionRequest {
                    action: "commit".into(),
                    handle: Some(transaction.handle.clone()),
                    request_json: None,
                },
            )),
        },
    )
    .await
    .unwrap();
    assert!(
        wire_receipt.error_code.is_empty(),
        "{}",
        wire_receipt.error_message
    );
    let Some(pb::wire_response::Payload::Sql(wire_receipt)) = wire_receipt.payload else {
        panic!("missing commit receipt")
    };
    assert_eq!(
        serde_json::from_str::<SqlExecutionResponse>(&wire_receipt.response_json).unwrap(),
        receipt
    );
    let status: serde_json::Value = client
        .get(format!(
            "http://{http_address}/v1/transactions/{}",
            transaction.handle
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["state"], "committed");
    assert_eq!(status["transaction_id"], transaction.handle);
    let rows = sdk
        .execute_sql(&request("SELECT id FROM receipt_rows ORDER BY id", None))
        .await
        .unwrap();
    assert!(
        matches!(&rows.results[0], chirondb::SqlResult::Rows { rows, .. }
        if rows == &vec![vec![chirondb::RelationalValue::Integer(1)], vec![chirondb::RelationalValue::Integer(3)]])
    );

    db.create_collection(
        serde_json::from_value(serde_json::json!({"name":"mm","vector_dim":2})).unwrap(),
    )
    .unwrap();
    db.set_graph_lifecycle_scoped("mm", true, true, &chirondb::tenant::TenantScope::system())
        .unwrap();
    db.configure_edge_type_scoped(
        "mm",
        chirondb_types::ConfigureEdgeTypeRequest {
            name: "CITES".into(),
            weight_property: None,
        },
        true,
        &chirondb::tenant::TenantScope::system(),
    )
    .unwrap();
    let multi = "TRANSACTION { SQL INSERT INTO receipt_rows VALUES (10); VECTOR UPSERT INTO mm {id: 'a', vector: [1,0], payload: {}}, {id: 'b', vector: [0,1], payload: {}}; GRAPH CONNECT mm 'a' -> CITES -> 'b'; };";
    let first_mm = sdk
        .execute_chironql(&chirondb_types::chironql::ChironQlRequest {
            query: multi.into(),
            confirm: true,
            idempotency_key: Some("protocol-multi".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let grpc_mm = grpc_client
        .execute_query(chiron_pb::ChironQlRequest {
            query: multi.into(),
            confirm: true,
            idempotency_key: Some("protocol-multi".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(grpc_mm.transaction_id, first_mm.transaction_id);
    assert_eq!(
        grpc_mm
            .rows_json
            .iter()
            .map(|row| serde_json::from_str::<serde_json::Value>(row).unwrap())
            .collect::<Vec<_>>(),
        first_mm.rows
    );
    let wire_mm = wire::send_request(
        &wire_address,
        pb::WireRequest {
            request_id: 4,
            api_key: String::new(),
            operation: Some(pb::wire_request::Operation::Chironql(
                pb::WireChironQlRequest {
                    query: multi.into(),
                    confirm: true,
                    idempotency_key: Some("protocol-multi".into()),
                    ..Default::default()
                },
            )),
        },
    )
    .await
    .unwrap();
    assert!(wire_mm.error_code.is_empty(), "{}", wire_mm.error_message);
    let Some(pb::wire_response::Payload::Chironql(wire_mm)) = wire_mm.payload else {
        panic!("missing multi-model receipt");
    };
    assert_eq!(wire_mm.transaction_id, first_mm.transaction_id);
    assert_eq!(
        wire_mm
            .rows_json
            .iter()
            .map(|row| serde_json::from_str::<serde_json::Value>(row).unwrap())
            .collect::<Vec<_>>(),
        first_mm.rows
    );
    for task in [http_task, wire_task, grpc_task] {
        task.abort();
        let _ = task.await;
    }
}

fn request(sql: &str, key: Option<&str>) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        retry_id: None,
        idempotency_key: key.map(str::to_string),
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn chironql_idempotency_fault_replays_committed_or_rejected_decisions() {
    use chirondb::chironql_exec::{ExecContext, Session, execute};
    const CHILD: &str = "CHIRONDB_CHIRONQL_IDEMPOTENCY_FAULT_CHILD";
    let run = |db: &Db, query: &str, keyed: bool| {
        execute(
            &mut ExecContext {
                db,
                session: &mut Session::default(),
                role: chirondb::rbac::Role::Admin,
                allowed_collections: None,
                want_trace: false,
                confirm: false,
                parameters: Vec::new(),
                idempotency_key: keyed.then(|| "fault-key".into()),
                retry_id: None,
                tenant: chirondb::tenant::TenantScope::untenanted("fault-client"),
            },
            query,
        )
    };
    let query = "SQL INSERT INTO receipts (id) VALUES (1) RETURNING id";
    if let Some(directory) = std::env::var_os(CHILD) {
        let db = Db::open(directory).unwrap();
        let error = run(&db, query, true).unwrap_err();
        if std::env::var("CHIRONDB_FAILPOINT")
            .unwrap()
            .ends_with("before_commit_fsync")
        {
            assert_eq!(error.code, "chironql.outcome_unknown");
            let transaction_id = error.error.rsplit(' ').next().unwrap();
            uuid::Uuid::parse_str(transaction_id).unwrap();
            assert!(error.hint.unwrap().contains(transaction_id));
        }
        return;
    }
    for cut in [
        "transaction.after_prepare",
        "transaction.before_commit_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        {
            let db = Db::open(directory.path()).unwrap();
            run(
                &db,
                "SQL CREATE TABLE receipts (id BIGINT PRIMARY KEY)",
                false,
            )
            .unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "chironql_idempotency_fault_replays_committed_or_rejected_decisions",
                "--nocapture",
            ])
            .env(CHILD, directory.path())
            .env("CHIRONDB_FAILPOINT", format!("error:{cut}"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let db = Db::open(directory.path()).unwrap();
        let expected_commit = cut.ends_with("before_commit_fsync");
        let mut ids = Vec::new();
        for _ in 0..2 {
            let receipt = run(&db, query, true).unwrap();
            assert_eq!(receipt.committed, Some(expected_commit));
            assert_eq!(receipt.rows.len(), usize::from(expected_commit));
            ids.push(receipt.transaction_id.unwrap());
        }
        assert_eq!(ids[0], ids[1]);
        let count = run(&db, "SQL SELECT COUNT(*) AS total FROM receipts", false).unwrap();
        assert_eq!(
            count.rows,
            vec![serde_json::json!({"total": usize::from(expected_commit)})]
        );
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn interactive_commit_reconciles_after_process_kill_with_the_begin_identity() {
    use chirondb_core::{TransactionState, audit::AuditContext};
    use std::{
        io::Write,
        process::Command,
        time::{Duration, Instant},
    };
    const CHILD: &str = "CHIRONDB_INTERACTIVE_KILL_CHILD";
    let owner = AuditContext {
        principal_id: "interactive-owner".into(),
        tenant_id: None,
        transport: "native-test".into(),
        request_id: None,
    };
    if let Some(data) = std::env::var_os(CHILD) {
        let db = Db::open(data).unwrap();
        let transaction = db.begin_sql_transaction(&owner).unwrap();
        assert_eq!(
            transaction.transaction_id.as_deref(),
            Some(transaction.handle.as_str())
        );
        db.execute_sql_transaction(
            &transaction.handle,
            request("INSERT INTO interactive_rows VALUES (1)", None),
            &owner,
        )
        .unwrap();
        let mut file =
            std::fs::File::create(std::env::var_os("CHIRONDB_INTERACTIVE_HANDLE_FILE").unwrap())
                .unwrap();
        file.write_all(transaction.handle.as_bytes()).unwrap();
        file.sync_all().unwrap();
        db.commit_sql_transaction(&transaction.handle, &owner)
            .unwrap();
        panic!("parent must kill the child at its paused COMMIT boundary");
    }
    for (cut, expected) in [
        ("transaction.before_prepare", TransactionState::Expired),
        ("transaction.after_prepare", TransactionState::Rejected),
        (
            "transaction.before_commit_fsync",
            TransactionState::Committed,
        ),
        ("transaction.after_commit", TransactionState::Committed),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let marker = directory.path().join("paused");
        let handle_file = directory.path().join("client-handle");
        {
            let db = Db::open(&data).unwrap();
            db.execute_sql(request(
                "CREATE TABLE interactive_rows (id BIGINT PRIMARY KEY)",
                None,
            ))
            .unwrap();
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "interactive_commit_reconciles_after_process_kill_with_the_begin_identity",
                "--nocapture",
            ])
            .env(CHILD, &data)
            .env("CHIRONDB_INTERACTIVE_HANDLE_FILE", &handle_file)
            .env("CHIRONDB_FAILPOINT", format!("pause:{cut}"))
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env(
                "CHIRONDB_FAILPOINT_RELEASE",
                directory.path().join("never-release"),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "child exited before {cut}: {status}\n{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("child did not reach {cut}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let handle = std::fs::read_to_string(&handle_file).unwrap();
        uuid::Uuid::parse_str(&handle).unwrap();
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(9));
        }
        assert!(!output.status.success());
        let db = Db::open(&data).unwrap();
        let status = db.transaction_status(&handle).unwrap();
        assert_eq!(status.state, expected, "{cut}");
        if expected == TransactionState::Committed {
            assert!(status.storage_projected, "{cut}: storage recovery");
            assert!(status.audit_projected, "{cut}: audit recovery");
        }
        for _ in 0..2 {
            let receipt = db.commit_sql_transaction(&handle, &owner);
            if expected == TransactionState::Expired {
                assert!(
                    receipt.is_err(),
                    "uncommitted private session cannot reappear"
                );
            } else {
                let receipt = receipt.unwrap();
                assert_eq!(receipt.transaction_id.as_deref(), Some(handle.as_str()));
                assert_eq!(receipt.committed, expected == TransactionState::Committed);
            }
        }
        let count = db
            .execute_sql(request("SELECT COUNT(*) FROM interactive_rows", None))
            .unwrap();
        let expected_rows = i64::from(expected == TransactionState::Committed);
        assert!(
            matches!(&count.results[0], chirondb::SqlResult::Rows { rows, .. }
            if rows == &vec![vec![chirondb::RelationalValue::Integer(expected_rows)]])
        );
        println!(
            "process kill at {cut}: {:?}, rows={expected_rows}, stable BEGIN identity reconciled",
            status.state
        );
    }
}
