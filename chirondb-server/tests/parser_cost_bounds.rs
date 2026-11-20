//! Parsing untrusted SQL must not repeat nested argument work exponentially.
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn in_bounded_child(name: &str, check: impl FnOnce()) {
    if std::env::var("CHIRON_PARSER_COST_CHILD").ok().as_deref() != Some(name) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("CHIRON_PARSER_COST_CHILD", name)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "bounded parser child failed: {status}");
                return;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("small SQL corpus exceeded the five-second process deadline");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    check();
}

#[test]
fn sql_parser_cost_is_bounded() {
    in_bounded_child("sql_parser_cost_is_bounded", || {
        for input in [
            include_str!("../../fuzz/corpus/query_decoders/sql_nested_calls_1"),
            include_str!("../../fuzz/corpus/query_decoders/sql_nested_calls_2"),
            include_str!("../../fuzz/corpus/query_decoders/sql_nested_calls_3"),
        ] {
            assert!(chirondb::chironql_parser::parse(input).is_err());
            let sql = input.trim().strip_prefix("SQL").unwrap().trim();
            assert!(chirondb::RelationalEngine::analyze_statement(sql).is_err());
            assert!(chirondb::pgvector_parser::parse(sql).is_err());
        }
        // Preserve legitimate nesting rather than lowering an accepted depth limit.
        let sql = format!("SELECT {}1{}", "abs(".repeat(24), ")".repeat(24));
        assert!(chirondb::RelationalEngine::analyze_statement(&sql).is_ok());
        assert!(chirondb::chironql_parser::parse(&format!("SQL {sql}")).is_ok());
    });
}

#[test]
fn pgvector_expression_depth_is_bounded() {
    in_bounded_child("pgvector_expression_depth_is_bounded", || {
        // Model a small worker stack; any regression aborts only the child.
        thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                for sql in [
                    include_str!("../../fuzz/corpus/query_decoders/pgvector_nested_parentheses")
                        .to_owned(),
                    format!("SELECT {}true FROM points", "NOT ".repeat(4000)),
                    format!("SELECT {}true FROM points", "true AND ".repeat(4000)),
                    format!("SELECT {}true FROM points", "true OR ".repeat(4000)),
                    format!(
                        "SELECT {}id{} FROM points",
                        "f(".repeat(2000),
                        ")".repeat(2000)
                    ),
                    format!(
                        "SELECT {}id{} FROM points",
                        "id IN (".repeat(2000),
                        ")".repeat(2000)
                    ),
                ] {
                    let error = chirondb::pgvector_parser::parse(&sql).unwrap_err();
                    assert_eq!(error.sqlstate(), "54001");
                }
                for depth in [24, 32, 33] {
                    for expr in [
                        format!("{}id{}", "(".repeat(depth), ")".repeat(depth)),
                        format!("{}id{}", "f(".repeat(depth), ")".repeat(depth)),
                        format!("{}true", "NOT ".repeat(depth)),
                        format!("{}true", "true AND ".repeat(depth)),
                        format!("{}true", "true OR ".repeat(depth)),
                        format!("{}id{}", "id IN (".repeat(depth), ")".repeat(depth)),
                    ] {
                        let parsed =
                            chirondb::pgvector_parser::parse(&format!("SELECT {expr} FROM points"));
                        if depth <= 32 {
                            let parsed = parsed.unwrap();
                            assert_eq!(parsed, parsed.clone());
                            assert!(!format!("{parsed:?}").is_empty());
                        } else {
                            assert_eq!(parsed.unwrap_err().sqlstate(), "54001");
                        }
                    }
                }
                // Independent shallow expressions and quoted punctuation are not nesting.
                for sql in [
                    format!(
                        "INSERT INTO points VALUES {}",
                        vec!["(1,'value')"; 1000].join(",")
                    ),
                    format!(
                        "SELECT id FROM points WHERE id IN ({})",
                        vec!["1"; 1000].join(",")
                    ),
                    format!("SELECT '{}' FROM points", "(".repeat(5000)),
                ] {
                    assert!(chirondb::pgvector_parser::parse(&sql).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    });
}

#[test]
fn native_sql_expression_depth_is_bounded() {
    in_bounded_child("native_sql_expression_depth_is_bounded", || {
        thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                for sql in [
                    format!(
                        "SELECT id FROM points WHERE {}true",
                        "true AND ".repeat(4000)
                    ),
                    format!(
                        "SELECT id FROM points WHERE {}true",
                        "true OR ".repeat(4000)
                    ),
                    format!("SELECT {}true FROM points", "NOT ".repeat(4000)),
                    format!(
                        "SELECT {}id{} FROM points",
                        "f(".repeat(2000),
                        ")".repeat(2000)
                    ),
                    format!(
                        "SELECT {}id{} FROM points",
                        "(".repeat(2000),
                        ")".repeat(2000)
                    ),
                    format!("SELECT 1 {}", "UNION SELECT 1 ".repeat(4000)),
                    format!("CREATE TABLE points(v INTEGER{})", "[]".repeat(4000)),
                ] {
                    assert!(chirondb::RelationalEngine::analyze_statement(&sql).is_err());
                    assert!(chirondb::chironql_parser::parse(&format!("SQL {sql}")).is_err());
                }
                for sql in [
                    format!("SELECT {}id{} FROM points", "f(".repeat(24), ")".repeat(24)),
                    format!("SELECT {}true FROM points", "true AND ".repeat(24)),
                    format!(
                        "INSERT INTO points VALUES {}",
                        vec!["(1,'value')"; 1000].join(",")
                    ),
                    "SELECT '[UNION INTERSECT EXCEPT]' FROM points".to_owned(),
                ] {
                    assert!(chirondb::RelationalEngine::analyze_statement(&sql).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    });
}
