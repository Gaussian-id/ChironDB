use super::*;
use crate::response_buffer::{ResponseBuffer, ResponseReservation};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};

fn raw(columns: &[&str], types: Vec<RelationalType>, rows: Vec<Value>) -> ChironQlResponse {
    let mut value = rows_response(
        "owned-query",
        columns.iter().map(|s| (*s).into()).collect(),
        rows,
    );
    value.column_types = types;
    value
}
fn qualified(alias: &str, rows: Vec<Value>, memory: &mut QueryMemory) -> PipelineRows {
    let value = raw(
        &["id", "payload"],
        vec![RelationalType::Integer, RelationalType::Text],
        rows,
    );
    memory.response(&value).unwrap();
    qualify_pipeline_rows(alias, value, None, memory).unwrap()
}
fn pipeline(kind: &str) -> Pipeline {
    let query = format!(
        "PIPELINE VECTOR v {{ SEARCH chunks NEAR [1,0] LIMIT 1 }} RELATIONAL r {{ SQL SELECT id, payload FROM documents }}\n {kind} JOIN r ON r.id = v.id\n RETURN r.id, v.id, r.payload\n ORDER BY r.id ASC\n LIMIT 100;"
    );
    let Statement::Pipeline(value) = chironql_parser::parse(&query).unwrap() else {
        panic!("pipeline")
    };
    value
}

#[test]
fn qualification_moves_payload_and_reference_preserves_namespace() {
    let text = "日本語\n".repeat(2048);
    let pointer = text.as_ptr();
    let value = raw(
        &["id", "payload"],
        vec![RelationalType::Text, RelationalType::Text],
        vec![Value::Object(
            [
                ("id".into(), Value::String("chunk-1".into())),
                ("payload".into(), Value::String(text)),
            ]
            .into_iter()
            .collect(),
        )],
    );
    let mut memory = QueryMemory::new().unwrap();
    memory.response(&value).unwrap();
    let rows = qualify_pipeline_rows("v", value, Some("docs"), &mut memory).unwrap();
    assert_eq!(
        rows.rows[0]["v.payload"].as_str().unwrap().as_ptr(),
        pointer
    );
    assert_eq!(
        rows.rows[0]["v.record_ref"],
        json!({"namespace":"docs","id":"chunk-1"})
    );
    assert_eq!(
        rows.types["v.record_ref"],
        RelationalType::RecordRef {
            namespace: "docs".into()
        }
    );
}

#[test]
fn randomized_join_sort_projection_matches_independent_nested_loop() {
    let mut seed = 0x159d_873a_u64;
    for kind in ["INNER", "LEFT"] {
        let plan = pipeline(kind);
        for round in 0..48 {
            let mut next = || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as usize
            };
            let left = (0..(next() % 15 + 1))
                .map(|n| {
                    let id = if n % 4 == 0 {
                        Value::Null
                    } else {
                        json!(next() % 6)
                    };
                    json!({"id":id,"payload":format!("left-{round}-{n}")})
                })
                .collect::<Vec<_>>();
            let right = (0..(next() % 15 + 1))
                .map(|n| {
                    let id = if n % 5 == 0 {
                        Value::Null
                    } else {
                        json!(next() % 6)
                    };
                    json!({"id":id,"payload":format!("right-{round}-{n}")})
                })
                .collect::<Vec<_>>();
            let mut expected = Vec::new();
            for l in &left {
                let matches = right
                    .iter()
                    .filter(|r| !l["id"].is_null() && l["id"].as_i64() == r["id"].as_i64())
                    .collect::<Vec<_>>();
                if matches.is_empty() && kind == "LEFT" {
                    expected.push(json!({"id":null,"v.id":l["id"],"payload":null}));
                }
                for r in matches {
                    expected.push(json!({"id":r["id"],"v.id":l["id"],"payload":r["payload"]}));
                }
            }
            expected.sort_by_key(|row| (row["id"].is_null(), row["id"].as_i64()));
            expected.truncate(100);
            let mut memory = QueryMemory::new().unwrap();
            let v = qualified("v", left, &mut memory);
            let r = qualified("r", right, &mut memory);
            let result = assemble_pipeline_response(
                &plan,
                v,
                None,
                r,
                "random-oracle",
                &mut QueryTrace::new("random-oracle"),
                Role::ReadOnly,
                &mut memory,
            )
            .unwrap();
            assert_eq!(result.rows, expected, "{kind}, seed {seed}, round {round}");
            assert_eq!(result.columns, ["id", "v.id", "payload"]);
        }
    }
}

#[test]
fn pipeline_sort_keeps_large_integer_order_and_duplicate_projection() {
    let mut plan = pipeline("INNER");
    plan.projection = vec![
        PipelineField {
            alias: "r".into(),
            field: "id".into(),
        },
        PipelineField {
            alias: "r".into(),
            field: "id".into(),
        },
    ];
    let ids = [
        9_007_199_254_740_993_i64,
        9_007_199_254_740_992,
        i64::MAX,
        i64::MAX - 1,
    ];
    let source = || {
        ids.iter()
            .map(|id| json!({"id":id,"payload":"text"}))
            .collect()
    };
    let mut memory = QueryMemory::new().unwrap();
    let v = qualified("v", source(), &mut memory);
    let r = qualified("r", source(), &mut memory);
    let result = assemble_pipeline_response(
        &plan,
        v,
        None,
        r,
        "integer-oracle",
        &mut QueryTrace::new("integer-oracle"),
        Role::ReadOnly,
        &mut memory,
    )
    .unwrap();
    let mut sorted = ids;
    sorted.sort();
    assert_eq!(
        result.rows,
        sorted
            .into_iter()
            .map(|id| json!({"id":id,"r.id":id}))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        compare_json(&json!(-1), &json!(u64::MAX), "", ""),
        Ordering::Less
    );
    assert_eq!(
        compare_json(&json!(u64::MAX), &json!(i64::MAX), "", ""),
        Ordering::Greater
    );
}

#[test]
fn canceled_join_conversion_and_queued_consumer_never_publish() {
    let mut memory = QueryMemory::new().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    memory.cancel_with(flag.clone());
    let v = qualified("v", vec![json!({"id":1,"payload":"left"})], &mut memory);
    let r = qualified("r", vec![json!({"id":1,"payload":"right"})], &mut memory);
    flag.store(true, AtomicOrdering::Release);
    assert_eq!(
        join_pipeline_rows(v, r, &pipeline("INNER").joins[0], "canceled", &mut memory)
            .err()
            .unwrap()
            .code,
        "chironql.invalid_request"
    );
    let output = QueryResult::new(raw(&[], vec![], vec![]), memory);
    let mut published = false;
    assert!(output.consume(|_| published = true).is_err());
    assert!(!published);
}

#[test]
fn query_owner_retains_receiving_memory_during_handoff_and_unwind() {
    let flag = Arc::new(AtomicBool::new(false));
    let weak = Arc::downgrade(&flag);
    let mut memory = QueryMemory::new().unwrap();
    memory.cancel_with(flag);
    memory.ql(32768, "lease").unwrap();
    let output = QueryResult::new(raw(&[], vec![], vec![json!({"value":-0.0})]), memory);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output
            .consume(|_| {
                assert!(weak.upgrade().is_some());
                panic!("consumer unwind")
            })
            .unwrap();
    }));
    assert!(result.is_err());
    assert!(weak.upgrade().is_none());
}

#[test]
fn protected_query_epoch_revoke_precedes_json_publication() {
    let (_dir, authority, key) = crate::chironql_protected::tests::identity_fixture();
    let identity = authority.authenticate(&key.secret).unwrap();
    let mut memory = QueryMemory::new().unwrap();
    memory.cancel_identity(&identity);
    let raw = raw(
        &["secret"],
        vec![RelationalType::Text],
        vec![json!({"secret":"forbidden"})],
    );
    memory.response(&raw).unwrap();
    memory.metadata(&raw).unwrap();
    let queued = crate::chironql_protected::Output::Query(
        crate::chironql_protected::PublicationGuard::Identity(identity.clone()),
        QueryResult::new(raw, memory),
    );
    authority
        .revoke_credential(&identity, identity.revision(), &key.id)
        .unwrap();
    assert!(identity.cancellation().is_cancelled());
    let mut encoded = false;
    assert!(queued.publish(|_| encoded = true).is_err());
    assert!(!encoded);
}

#[test]
fn receiving_budget_refuses_before_growth_and_releases_after_last_frame() {
    const CHILD: &str = "CHIRON_TEST_QUERY_MEMORY_SMALL_POOL";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","chironql_exec::query_ownership_tests::receiving_budget_refuses_before_growth_and_releases_after_last_frame","--nocapture"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let mut profile = crate::resource_profile::ResourceProfile::from_limits(1 << 30, 1);
    profile.sql_pool_bytes = 256 * 1024;
    crate::resource_profile::install(profile);
    let mut memory = QueryMemory::new().unwrap();
    memory.admit(90 * 1024).unwrap();
    let before = memory.bytes_for_test();
    assert!(memory.admit(256 * 1024).is_err());
    assert_eq!(memory.bytes_for_test(), before);
    let output = QueryResult::new(raw(&[], vec![], vec![]), memory);
    output
        .consume(|_| {
            assert!(ResponseReservation::new(64 * 1024).is_err());
        })
        .unwrap();
    let slot = ResponseReservation::new(120 * 1024).unwrap();
    drop(slot);
    let mut owner = ResponseBuffer::allocate(90 * 1024, 128 * 1024).unwrap();
    owner.as_mut()[0] = 42;
    let bytes = axum::body::Bytes::from_owner(owner);
    let last = bytes.slice(..1);
    drop(bytes);
    assert!(ResponseReservation::new(64 * 1024).is_err());
    assert_eq!(last[0], 42);
    drop(last);
    assert!(ResponseReservation::new(120 * 1024).is_ok());
}

#[test]
fn typed_sql_to_query_moves_text_and_preserves_json_numeric_values() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let request = |sql: &str, parameters: Vec<RelationalValue>| SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters,
        }],
        idempotency_key: None,
        retry_id: None,
    };
    db.execute_sql(request(
        "CREATE TABLE ownership (id INTEGER PRIMARY KEY, note TEXT, data JSONB)",
        vec![],
    ))
    .unwrap();
    let numbers = json!({"integer":i64::MAX,"float":-0.0,"nested":["日本語",true,null]});
    db.execute_sql(request(
        "INSERT INTO ownership (id, note, data) VALUES ($1, $2, $3)",
        vec![
            RelationalValue::Integer(1),
            RelationalValue::Text("owned note".repeat(2048)),
            RelationalValue::Json(numbers.clone()),
        ],
    ))
    .unwrap();
    let result = db
        .execute_sql_owned(request("SELECT note, data FROM ownership", vec![]))
        .unwrap();
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        panic!("rows")
    };
    let RelationalValue::Text(note) = &rows[0][0] else {
        panic!("text")
    };
    let pointer = note.as_ptr();
    let mut memory = QueryMemory::new().unwrap();
    let result = sql_execution_admitted(result, "sql-owner", &mut memory).unwrap();
    assert_eq!(result.rows[0]["note"].as_str().unwrap().as_ptr(), pointer);
    assert_eq!(result.rows[0]["data"], numbers);
    memory.metadata(&result).unwrap();
    let output = QueryResult::new(result, memory);
    let (message, admission) = output
        .consume(crate::response_output::chironql)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&message.rows_json[0]).unwrap()["data"],
        numbers
    );
    let weak = Arc::downgrade(&admission);
    use prost::Message;
    let bytes = crate::response_output::retain_frame(
        axum::body::Bytes::from(message.encode_to_vec()),
        admission,
    );
    let last = bytes.slice(..1);
    drop(bytes);
    drop(message);
    assert!(weak.upgrade().is_some());
    drop(last);
    assert!(weak.upgrade().is_none());
}

#[test]
fn refused_sql_conversion_keeps_committed_key_and_reopen_decision() {
    let directory = tempfile::tempdir().unwrap();
    let request = |sql: &str, key: Option<&str>| SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: key.map(str::to_owned),
        retry_id: None,
    };
    let transaction_id;
    {
        let db = Db::open(directory.path()).unwrap();
        db.execute_sql(request(
            "CREATE TABLE decisions (id INTEGER PRIMARY KEY)",
            None,
        ))
        .unwrap();
        let sql = "INSERT INTO decisions (id) VALUES (1)";
        let committed = db
            .execute_sql_owned(request(sql, Some("conversion-key")))
            .unwrap();
        assert!(committed.committed);
        transaction_id = committed.transaction_id.clone().unwrap();
        let mut memory = QueryMemory::new().unwrap();
        let flag = Arc::new(AtomicBool::new(true));
        memory.cancel_with(flag);
        assert!(sql_execution_admitted(committed, "refused-receiver", &mut memory).is_err());
        let replay = db
            .execute_sql_owned(request(sql, Some("conversion-key")))
            .unwrap();
        assert_eq!(
            replay.transaction_id.as_deref(),
            Some(transaction_id.as_str())
        );
        let mut memory = QueryMemory::new().unwrap();
        let response = sql_execution_admitted(replay, "reconcile", &mut memory).unwrap();
        assert_eq!(
            response.transaction_id.as_deref(),
            Some(transaction_id.as_str())
        );
    }
    let db = Db::open(directory.path()).unwrap();
    let result = db
        .execute_sql_owned(request(
            "INSERT INTO decisions (id) VALUES (1)",
            Some("conversion-key"),
        ))
        .unwrap();
    assert_eq!(
        result.transaction_id.as_deref(),
        Some(transaction_id.as_str())
    );
    let result = db
        .execute_sql_owned(request("SELECT id FROM decisions", None))
        .unwrap();
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        panic!("rows")
    };
    assert_eq!(rows, &[vec![RelationalValue::Integer(1)]]);
}
