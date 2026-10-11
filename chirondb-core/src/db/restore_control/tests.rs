use super::super::*;

fn sql(db: &Db, text: &str) -> crate::SqlExecutionResponse {
    db.execute_sql(
        serde_json::from_value(serde_json::json!({
            "statements": [{"sql": text}],
        }))
        .unwrap(),
    )
    .unwrap()
}

fn ids(db: &Db) -> Vec<i64> {
    let response = sql(db, "SELECT id FROM documents ORDER BY id");
    let crate::SqlResult::Rows { rows, .. } = &response.results[0] else {
        panic!("expected rows")
    };
    rows.iter()
        .map(|row| match row[0] {
            crate::RelationalValue::Integer(id) => id,
            _ => panic!("expected BIGINT"),
        })
        .collect()
}

fn live(root: &Path, generations: bool) -> Db {
    if generations {
        crate::storage_layout::initialize_empty(root).unwrap();
    }
    let db = Db::open(root).unwrap();
    sql(&db, "CREATE TABLE documents (id BIGINT PRIMARY KEY)");
    sql(&db, "INSERT INTO documents (id) VALUES (1)");
    db
}

#[test]
fn restore_activates_sql_snapshot_in_every_existing_db_clone() {
    for generation in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = live(&temp.path().join("live"), generation);
        let cloned = db.clone();
        let snapshot = temp.path().join("snapshot");
        db.snapshot(&snapshot).unwrap();
        sql(&db, "INSERT INTO documents (id) VALUES (2)");
        db.restore(&snapshot).unwrap();
        assert_eq!(ids(&db), [1], "generation={generation}");
        assert_eq!(ids(&cloned), [1], "generation={generation}");
    }
}

#[test]
fn acknowledged_sql_after_generation_restore_survives_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("live");
    let db = live(&data, true);
    let snapshot = temp.path().join("snapshot");
    db.snapshot(&snapshot).unwrap();
    sql(&db, "INSERT INTO documents (id) VALUES (2)");
    db.restore(&snapshot).unwrap();
    let response = sql(&db, "INSERT INTO documents (id) VALUES (3)");
    assert!(response.committed);
    drop(db);
    let db = Db::open(&data).unwrap();
    assert_eq!(ids(&db), [1, 3]);
}

#[test]
fn content_restore_preserves_consumed_keys_and_invalidates_optimistic_reads() {
    for generation in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("live");
        let db = live(&data, generation);
        let snapshot = temp.path().join("snapshot");
        db.snapshot(&snapshot).unwrap();
        let request: crate::SqlExecutionRequest = serde_json::from_value(serde_json::json!({
            "statements": [{"sql": "INSERT INTO documents (id) VALUES (2)"}],
            "idempotency_key": "after-snapshot",
        }))
        .unwrap();
        let original = db.execute_sql(request.clone()).unwrap();
        let before = db.multimodel_visibility_frontier().unwrap().unwrap();
        db.restore(&snapshot).unwrap();
        let after = db.multimodel_visibility_frontier().unwrap().unwrap();
        assert_ne!(before, after, "generation={generation}");
        assert_eq!(ids(&db), [1]);
        let replay = db.execute_sql(request.clone()).unwrap();
        assert_eq!(original.transaction_id, replay.transaction_id);
        assert_eq!(
            ids(&db),
            [1],
            "a content rollback never permits a second commit"
        );
        drop(db);
        let db = Db::open(&data).unwrap();
        assert_eq!(
            db.execute_sql(request).unwrap().transaction_id,
            original.transaction_id
        );
        assert_eq!(ids(&db), [1]);
    }
}

#[test]
fn restore_refuses_active_interactive_transactions_without_changing_sql_root() {
    for generation in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = live(&temp.path().join("live"), generation);
        let snapshot = temp.path().join("snapshot");
        db.snapshot(&snapshot).unwrap();
        let audit = audit::AuditContext::embedded();
        let handle = db.begin_sql_transaction(&audit).unwrap();
        assert!(
            matches!(db.restore(&snapshot), Err(GaussError::InvalidRequest(message)) if message.contains("SQL transactions"))
        );
        assert_eq!(ids(&db), [1]);
        db.rollback_sql_transaction(&handle.handle, &audit).unwrap();
        db.restore(&snapshot).unwrap();
        assert_eq!(ids(&db), [1]);
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn restore_sql_refusal_and_publication_failure_keep_old_root_writable() {
    for generation in [false, true] {
        for boundary in [
            "restore.after_relational_validation",
            "restore.before_relational_publication",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("live");
            let db = live(&data, generation);
            let snapshot = temp.path().join("snapshot");
            db.snapshot(&snapshot).unwrap();
            sql(&db, "INSERT INTO documents (id) VALUES (2)");
            let old_root = crate::storage_layout::resolve(&data).unwrap().active_root;
            {
                let _env = crate::failpoint::test_env(
                    &format!("error:{boundary}"),
                    &temp.path().join("marker"),
                    &temp.path().join("release"),
                );
                assert!(matches!(db.restore(&snapshot), Err(GaussError::Io(_))));
            }
            assert_eq!(
                crate::storage_layout::resolve(&data).unwrap().active_root,
                old_root
            );
            assert_eq!(
                ids(&db),
                [1, 2],
                "generation={generation}, boundary={boundary}"
            );
            sql(&db, "INSERT INTO documents (id) VALUES (3)");
            // A second restore must not encounter a stale control journal.
            db.restore(&snapshot).unwrap();
            assert_eq!(ids(&db), [1]);
            sql(&db, "INSERT INTO documents (id) VALUES (4)");
            drop(db);
            assert_eq!(ids(&Db::open(&data).unwrap()), [1, 4]);
        }
    }
}

#[test]
fn corrupt_sql_snapshot_is_rejected_before_content_activation() {
    for generation in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("live");
        let db = live(&data, generation);
        db.relational.read().checkpoint().unwrap();
        let snapshot = temp.path().join("snapshot");
        db.snapshot(&snapshot).unwrap();
        sql(&db, "INSERT INTO documents (id) VALUES (2)");
        let old_root = crate::storage_layout::resolve(&data).unwrap().active_root;
        let checkpoint = snapshot.join("relational/checkpoint.gdx");
        let mut corrupt = fs::read(&checkpoint).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&checkpoint, &corrupt).unwrap();
        let restored = db.restore(&snapshot);
        assert!(
            matches!(&restored, Err(GaussError::SegmentCorruption { .. })),
            "{restored:?}"
        );
        assert_eq!(
            fs::read(&checkpoint).unwrap(),
            corrupt,
            "restore changed its source"
        );
        assert_eq!(
            crate::storage_layout::resolve(&data).unwrap().active_root,
            old_root
        );
        assert_eq!(ids(&db), [1, 2]);
        sql(&db, "INSERT INTO documents (id) VALUES (3)");
        drop(db);
        assert_eq!(ids(&Db::open(&data).unwrap()), [1, 2, 3]);
    }
}
