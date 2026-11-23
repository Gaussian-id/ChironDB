use super::*;

// These qualification fixtures intentionally exercise the full preview row cap
// and a single over-budget row. Isolate their process-wide memory reservations
// from other independent database fixtures, without changing production limits.
fn run_isolated(test_name: &str) -> bool {
    const CHILD: &str = "CHIRONDB_BOUNDED_DELETE_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test_name) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD, test_name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated test {test_name} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn request(sql: String) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql,
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    }
}

fn seed(engine: &RelationalEngine) {
    let columns = (1..17)
        .map(|column| format!("feature_{column} DOUBLE PRECISION"))
        .collect::<Vec<_>>()
        .join(", ");
    engine
        .execute(request(format!(
            "CREATE TABLE forecast (id BIGINT PRIMARY KEY, {columns})"
        )))
        .unwrap();
    for start in (0..10_000).step_by(400) {
        let rows = (start..start + 400)
            .map(|id| {
                let values = (1..17)
                    .map(|column| format!("{}.125", 100_000 + id + column))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("({id},{values})")
            })
            .collect::<Vec<_>>()
            .join(",");
        engine
            .execute(request(format!("INSERT INTO forecast VALUES {rows}")))
            .unwrap();
    }
}

fn count(engine: &RelationalEngine) -> i64 {
    let response = engine
        .execute(request("SELECT COUNT(*) FROM forecast".into()))
        .unwrap()
        .response;
    match &response.results[0] {
        SqlResult::Rows { rows, .. } => match rows[0][0] {
            RelationalValue::Integer(count) => count,
            _ => panic!("count"),
        },
        _ => panic!("rows"),
    }
}

#[test]
fn full_table_delete_replaces_ten_thousand_wide_rows_without_retaining_images() {
    if run_isolated(
        "relational::delete::tests::full_table_delete_replaces_ten_thousand_wide_rows_without_retaining_images",
    ) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let engine = RelationalEngine::open(directory.path(), Arc::clone(&journal)).unwrap();
    seed(&engine);
    let original_id = engine
        .ml_source_revision("forecast")
        .unwrap()
        .unwrap()
        .revision
        .table_id;
    let original_revision = engine
        .ml_source_revision("forecast")
        .unwrap()
        .unwrap()
        .revision;
    let duplicate = format!("(0,{})", ["1.25"; 16].join(","));
    let mut rejected = request("DELETE FROM forecast".into());
    rejected.statements.push(crate::SqlStatementRequest {
        sql: format!("INSERT INTO forecast VALUES {duplicate},{duplicate}"),
        parameters: vec![],
    });
    assert!(engine.execute(rejected).is_err());
    assert_eq!(
        count(&engine),
        10_000,
        "failed replacement preserves the entire old generation"
    );
    assert_eq!(
        engine
            .ml_source_revision("forecast")
            .unwrap()
            .unwrap()
            .revision,
        original_revision
    );
    let audit = AuditContext::embedded();
    let old = engine.begin_interactive(&audit).unwrap();
    let replacement = format!(
        "INSERT INTO forecast VALUES (10000,{})",
        ["1.25"; 16].join(",")
    );
    let mut publication = request("DELETE FROM forecast".into());
    publication.statements.push(crate::SqlStatementRequest {
        sql: replacement,
        parameters: vec![],
    });
    engine.execute(publication).unwrap();
    assert_eq!(count(&engine), 1);
    assert_eq!(
        engine
            .ml_source_revision("forecast")
            .unwrap()
            .unwrap()
            .revision
            .table_id,
        original_id
    );
    let previous = engine
        .execute_interactive(
            &old.handle,
            request("SELECT COUNT(*) FROM forecast".into()),
            &audit,
        )
        .unwrap();
    assert!(
        matches!(&previous.results[0], SqlResult::Rows {rows,..} if rows == &vec![vec![RelationalValue::Integer(10_000)]])
    );
    engine.rollback_interactive(&old.handle, &audit).unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    drop(journal);
    let reopened = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    assert_eq!(count(&reopened), 1);
    assert_eq!(
        reopened
            .ml_source_revision("forecast")
            .unwrap()
            .unwrap()
            .revision
            .table_id,
        original_id
    );
}

#[test]
fn full_delete_keeps_single_row_budget_fk_actions_and_returning_contracts() {
    if run_isolated(
        "relational::delete::tests::full_delete_keeps_single_row_budget_fk_actions_and_returning_contracts",
    ) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    engine
        .execute(request(
            "CREATE TABLE parent (id INTEGER PRIMARY KEY)".into(),
        ))
        .unwrap();
    engine
        .execute(request(
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
                .into(),
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO parent VALUES (1)".into()))
        .unwrap();
    engine
        .execute(request("INSERT INTO child VALUES (1, 1)".into()))
        .unwrap();
    assert!(
        engine
            .execute(request("DELETE FROM parent".into()))
            .is_err()
    );
    let deleted = engine
        .execute(request("DELETE FROM child RETURNING id".into()))
        .unwrap()
        .response;
    assert!(
        matches!(&deleted.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
    );
    engine
        .execute(request("DELETE FROM parent".into()))
        .unwrap();
    engine
        .execute(request(
            "CREATE TABLE wide (id INTEGER PRIMARY KEY, payload TEXT)".into(),
        ))
        .unwrap();
    let payload = "x".repeat(query_operator_budget() / 2);
    engine
        .execute(SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: "INSERT INTO wide VALUES (0, 'small'), (1, $1)".into(),
                parameters: vec![RelationalValue::Text(payload)],
            }],
            idempotency_key: None,
            retry_id: None,
        })
        .unwrap();
    let revision = engine.ml_source_revision("wide").unwrap().unwrap().revision;
    let error = engine
        .execute(request("DELETE FROM wide".into()))
        .err()
        .unwrap();
    assert!(matches!(&error, GaussError::SqlLimitExceeded(_)));
    assert!(
        error.to_string().contains("SQL operator memory budget"),
        "{error}"
    );
    assert_eq!(
        engine.ml_source_revision("wide").unwrap().unwrap().revision,
        revision
    );
    let result = engine
        .execute(request("SELECT COUNT(*) FROM wide".into()))
        .unwrap()
        .response;
    assert!(
        matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(2)]])
    );
}
