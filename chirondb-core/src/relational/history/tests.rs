use super::*;
use crate::relational::{RelationalEngine, TransactionJournal, with_sql_cancellation};
use crate::{RelationalValue, SqlResult, audit::AuditContext};
use std::sync::{Arc, atomic::AtomicBool};

fn statement(sql: &str) -> SqlStatementRequest {
    SqlStatementRequest {
        sql: sql.into(),
        parameters: Vec::new(),
    }
}

fn request(sql: &str) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![statement(sql)],
        retry_id: None,
        idempotency_key: None,
    }
}

#[test]
fn local_limit_refuses_savepoints_and_cleanup_reuses_exact_capacity() {
    memory::with_history_pool(64 * 1024, |pool| {
        let mut history = History::new().unwrap();
        history.limit = 8192;
        let base = pool.used();
        let mut admitted = 0;
        loop {
            let before = pool.used();
            if let Err(error) = history.push_savepoint("x".repeat(1000)) {
                assert!(matches!(error, GaussError::ResourceExhausted(_)));
                assert_eq!(pool.used(), before);
                break;
            }
            admitted += 1;
        }
        assert!((1..8).contains(&admitted));
        assert_eq!(history.savepoints().len(), admitted);
        history.truncate_savepoints(0);
        assert_eq!(pool.used(), base);
        for _ in 0..1000 {
            history.push_savepoint("x".repeat(1000)).unwrap();
            history.truncate_savepoints(0);
            assert_eq!(pool.used(), base);
        }
        drop(history);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn shared_limit_rejects_another_session_and_expanded_json_replay_is_reserved() {
    memory::with_history_pool(4096 + memory::LEASE_ROOT_BYTES, |pool| {
        let first = History::new().unwrap();
        assert!(matches!(
            History::new(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 4096 + memory::LEASE_ROOT_BYTES);
        drop(first);
        assert_eq!(pool.used(), 0);
    });
    memory::with_history_pool(2 * 1024 * 1024, |pool| {
        let mut history = History::new().unwrap();
        history.limit = 1024 * 1024;
        let mut item = statement("INSERT INTO items VALUES ($1)");
        item.parameters
            .push(RelationalValue::Json(serde_json::json!({
                "array": vec![serde_json::Value::Null; 4096], "unicode": "雪☕"
            })));
        let serialized = serde_json::to_vec(&item).unwrap().len() as u64;
        history.push_statement(item).unwrap();
        let retained = pool.used();
        assert!(retained > serialized * 2, "decoded heap, not wire length");
        let (copy, charge) = history.copy_request(Some("audit-only")).unwrap();
        assert_eq!(copy.statements, history.statements);
        let copying = pool.used();
        assert!(copying > retained);
        drop(history);
        assert_eq!(pool.used(), copying - retained);
        drop(copy);
        drop(charge);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn cancelled_or_refused_replay_leaves_history_and_budget_unchanged() {
    memory::with_history_pool(64 * 1024, |pool| {
        let mut history = History::new().unwrap();
        history.push_statement(statement("SELECT 1")).unwrap();
        let before = pool.used();
        let cancelled = Arc::new(AtomicBool::new(false));
        let result = with_sql_cancellation(cancelled.clone(), || {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            history.copy_request(None)
        });
        assert!(result.unwrap_err().to_string().contains("query canceled"));
        assert_eq!(pool.used(), before);
        history.limit = before;
        assert!(matches!(
            history.copy_request(None),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), before);
        assert_eq!(history.statements()[0].sql, "SELECT 1");
    });
}

#[test]
fn engine_overload_rolls_back_to_savepoint_and_commit_releases_history() {
    memory::with_history_pool(32 * 1024, |pool| {
        let root = tempfile::tempdir().unwrap();
        let engine =
            RelationalEngine::open(root.path(), TransactionJournal::open(root.path()).unwrap())
                .unwrap();
        engine
            .execute(request(
                "CREATE TABLE items (id BIGINT PRIMARY KEY, value JSONB)",
            ))
            .unwrap();
        let owner = AuditContext::embedded();
        let handle = engine.begin_interactive(&owner).unwrap().handle;
        engine
            .execute_interactive(
                &handle,
                request("INSERT INTO items VALUES (1, NULL)"),
                &owner,
            )
            .unwrap();
        engine
            .execute_interactive(&handle, request("SAVEPOINT anchor"), &owner)
            .unwrap();
        let mut large = request("INSERT INTO items VALUES (2, $1)");
        large.statements[0]
            .parameters
            .push(RelationalValue::Json(serde_json::json!(vec![0; 10000])));
        assert!(matches!(
            engine.execute_interactive(&handle, large, &owner),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(engine.commit_interactive(&handle, &owner).is_err());
        engine
            .execute_interactive(&handle, request("ROLLBACK TO anchor"), &owner)
            .unwrap();
        // SAVEPOINT calls are not part of the 32-statement replay limit. Byte
        // admission must still stop repeated names from growing without bound.
        let savepoint = request(&format!("SAVEPOINT \"{}\"", "s".repeat(8192)));
        let mut admitted = 0;
        loop {
            match engine.execute_interactive(&handle, savepoint.clone(), &owner) {
                Ok(_) => admitted += 1,
                Err(GaussError::ResourceExhausted(_)) => break,
                Err(error) => panic!("unexpected error: {error}"),
            }
            assert!(admitted < 4);
        }
        assert!(admitted > 0);
        engine
            .execute_interactive(&handle, request("ROLLBACK TO anchor"), &owner)
            .unwrap();
        engine
            .execute_interactive(
                &handle,
                request("INSERT INTO items VALUES (2, NULL)"),
                &owner,
            )
            .unwrap();
        engine.commit_interactive(&handle, &owner).unwrap();
        assert_eq!(pool.used(), 0);
        let response = engine
            .execute(request("SELECT id FROM items ORDER BY id"))
            .unwrap()
            .response;
        let SqlResult::Rows { rows, .. } = &response.results[0] else {
            panic!("rows")
        };
        assert_eq!(
            rows,
            &vec![
                vec![RelationalValue::Integer(1)],
                vec![RelationalValue::Integer(2)]
            ]
        );
        let handle = engine.begin_interactive(&owner).unwrap().handle;
        assert!(pool.used() > 0);
        engine.rollback_interactive(&handle, &owner).unwrap();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn expired_session_returns_history_budget() {
    memory::with_history_pool(16 * 1024, |pool| {
        let root = tempfile::tempdir().unwrap();
        let engine =
            RelationalEngine::open(root.path(), TransactionJournal::open(root.path()).unwrap())
                .unwrap();
        let owner = AuditContext::embedded();
        let handle = engine.begin_interactive(&owner).unwrap().handle;
        engine
            .execute_interactive(&handle, request("SAVEPOINT held"), &owner)
            .unwrap();
        let entry = engine.interactive.get(&handle, &owner).unwrap();
        entry.lock(&handle).unwrap().as_mut().unwrap().last_activity -=
            super::super::INTERACTIVE_TRANSACTION_TTL;
        assert!(pool.used() > 0);
        engine.interactive.expire().unwrap();
        assert_eq!(pool.used(), 0);
        assert!(engine.commit_interactive(&handle, &owner).is_err());
    });
}
