//! Public Db contract: atomic batches, MVCC snapshots, conflict validation and
//! the documented snapshot-isolation ceiling (not a serializable transaction).
use chirondb_core::{
    Db, RelationalValue, SqlExecutionRequest, SqlExecutionResponse, SqlResult, audit,
};

fn sql(statements: &[&str]) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({
        "statements": statements.iter().map(|sql| serde_json::json!({"sql":sql})).collect::<Vec<_>>()
    })).unwrap()
}
fn integers(result: SqlExecutionResponse) -> Vec<Vec<i64>> {
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        panic!("rows expected")
    };
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|value| match value {
                    RelationalValue::Integer(v) => *v,
                    other => panic!("integer expected, got {other:?}"),
                })
                .collect()
        })
        .collect()
}

#[test]
fn db_atomic_constraint_failure_rollback_and_snapshot_survive_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path()).unwrap();
    db.execute_sql(sql(&["CREATE TABLE accounts (id BIGINT PRIMARY KEY, balance BIGINT NOT NULL CHECK (balance >= 0))"])).unwrap();
    db.execute_sql(sql(&["INSERT INTO accounts VALUES (1, 100), (2, 100)"]))
        .unwrap();
    assert!(
        db.execute_sql(sql(&[
            "UPDATE accounts SET balance = 50 WHERE id = 1",
            "UPDATE accounts SET balance = -1 WHERE id = 2",
        ]))
        .is_err()
    );
    let query = "SELECT id, balance FROM accounts ORDER BY id";
    assert_eq!(
        integers(db.execute_sql(sql(&[query])).unwrap()),
        vec![vec![1, 100], vec![2, 100]]
    );
    let ctx = audit::AuditContext::embedded();
    let reader = db.begin_sql_transaction(&ctx).unwrap();
    let writer = db.begin_sql_transaction(&ctx).unwrap();
    db.execute_sql_transaction(
        &writer.handle,
        sql(&["UPDATE accounts SET balance = 75 WHERE id = 1"]),
        &ctx,
    )
    .unwrap();
    assert_eq!(
        integers(db.execute_sql(sql(&[query])).unwrap()),
        vec![vec![1, 100], vec![2, 100]]
    );
    db.commit_sql_transaction(&writer.handle, &ctx).unwrap();
    assert_eq!(
        integers(
            db.execute_sql_transaction(&reader.handle, sql(&[query]), &ctx)
                .unwrap()
        ),
        vec![vec![1, 100], vec![2, 100]]
    );
    db.rollback_sql_transaction(&reader.handle, &ctx).unwrap();
    let discarded = db.begin_sql_transaction(&ctx).unwrap();
    db.execute_sql_transaction(&discarded.handle, sql(&["DELETE FROM accounts"]), &ctx)
        .unwrap();
    db.rollback_sql_transaction(&discarded.handle, &ctx)
        .unwrap();
    drop(db);
    for _ in 0..2 {
        let db = Db::open(tmp.path()).unwrap();
        assert_eq!(
            integers(db.execute_sql(sql(&[query])).unwrap()),
            vec![vec![1, 75], vec![2, 100]]
        );
    }
}

#[test]
fn snapshot_isolation_allows_disjoint_write_skew() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path()).unwrap();
    db.execute_sql(sql(&[
        "CREATE TABLE duty (id BIGINT PRIMARY KEY, active BIGINT NOT NULL)",
    ]))
    .unwrap();
    db.execute_sql(sql(&["INSERT INTO duty VALUES (1, 1), (2, 1)"]))
        .unwrap();
    let ctx = audit::AuditContext::embedded();
    let first = db.begin_sql_transaction(&ctx).unwrap();
    let second = db.begin_sql_transaction(&ctx).unwrap();
    for handle in [&first.handle, &second.handle] {
        assert_eq!(
            integers(
                db.execute_sql_transaction(handle, sql(&["SELECT SUM(active) FROM duty"]), &ctx)
                    .unwrap()
            ),
            vec![vec![2]]
        );
    }
    db.execute_sql_transaction(
        &first.handle,
        sql(&["UPDATE duty SET active = 0 WHERE id = 1"]),
        &ctx,
    )
    .unwrap();
    db.execute_sql_transaction(
        &second.handle,
        sql(&["UPDATE duty SET active = 0 WHERE id = 2"]),
        &ctx,
    )
    .unwrap();
    db.commit_sql_transaction(&first.handle, &ctx).unwrap();
    db.commit_sql_transaction(&second.handle, &ctx).unwrap();
    // This is a capability boundary, not proof of serializable isolation. An
    // application invariant across these rows needs stronger coordination.
    assert_eq!(
        integers(
            db.execute_sql(sql(&["SELECT SUM(active) FROM duty"]))
                .unwrap()
        ),
        vec![vec![0]]
    );
}
