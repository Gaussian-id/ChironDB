#![no_main]

use chirondb_core::{Db, RelationalEngine, SqlExecutionRequest, SqlStatementRequest};
use libfuzzer_sys::fuzz_target;

const MAX_SQL_BYTES: usize = 1024 * 1024;

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

// Arbitrary SQL text through the native relational parser, guards,
// authorization analysis, and executor against a fresh small table, so a
// reproducer does not depend on earlier inputs (RT-40 stack-depth class).
fuzz_target!(|data: &[u8]| {
    let Ok(sql) = std::str::from_utf8(&data[..data.len().min(MAX_SQL_BYTES)]) else {
        return;
    };
    let _ = RelationalEngine::analyze_statement(sql);
    let Ok(temp) = tempfile::tempdir() else {
        return;
    };
    let Ok(db) = Db::open(temp.path()) else {
        return;
    };
    for setup in [
        "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT, score BIGINT)",
        "INSERT INTO items VALUES (1, 'a', 10), (2, 'b', NULL), (3, NULL, 30)",
    ] {
        db.execute_sql(request(setup)).expect("fuzz fixture");
    }
    let _ = db.execute_sql(request(sql));
    let _ = db.execute_sql(request("SELECT id, name, score FROM items ORDER BY id"));
});
