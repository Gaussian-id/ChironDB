use super::*;

fn request(sql: &str) -> SqlExecutionRequest {
    SqlExecutionRequest {
        statements: vec![crate::SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        }],
        idempotency_key: None,
        retry_id: None,
    }
}

fn open(path: &Path) -> Arc<RelationalEngine> {
    RelationalEngine::open(path, TransactionJournal::open(path).unwrap()).unwrap()
}

fn seed(engine: &RelationalEngine) {
    engine
        .execute(request(
            "CREATE TABLE source (id INTEGER PRIMARY KEY, value INTEGER)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO source VALUES (2, 20), (1, 10)"))
        .unwrap();
}

fn revision(engine: &RelationalEngine) -> MlSourceRevision {
    engine
        .ml_source_revision("source")
        .unwrap()
        .unwrap()
        .revision
}

#[test]
fn revisions_track_committed_affected_tables_and_ignore_noops_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let original = revision(&engine);
    for sql in [
        "CREATE TABLE unrelated (id INTEGER PRIMARY KEY)",
        "INSERT INTO unrelated VALUES (1)",
        "UPDATE source SET value = 100 WHERE id = 999",
        "DELETE FROM source WHERE id = 999",
        "UPDATE source SET value = 10 WHERE id = 1",
    ] {
        engine.execute(request(sql)).unwrap();
        assert_eq!(revision(&engine), original, "{sql}");
    }
    let audit = AuditContext::embedded();
    let tx = engine.begin_interactive(&audit).unwrap();
    engine
        .execute_interactive(
            &tx.handle,
            request("UPDATE source SET value = 99 WHERE id = 1"),
            &audit,
        )
        .unwrap();
    assert_eq!(revision(&engine), original);
    engine.rollback_interactive(&tx.handle, &audit).unwrap();
    assert_eq!(revision(&engine), original);
    assert!(
        engine
            .execute(request("INSERT INTO source VALUES (1, 99)"))
            .is_err()
    );
    assert_eq!(revision(&engine), original);
    engine
        .execute(request("UPDATE source SET value = 11 WHERE id = 1"))
        .unwrap();
    let updated = revision(&engine);
    assert!(updated.data_revision > original.data_revision);
    assert_eq!(updated.schema_revision, original.schema_revision);
    engine
        .execute(request("ALTER TABLE source ADD COLUMN extra INTEGER"))
        .unwrap();
    let altered = revision(&engine);
    assert!(altered.schema_revision > updated.schema_revision);
    assert_eq!(altered.table_id, original.table_id);
}

#[test]
fn source_watermarks_replay_checkpoint_and_preserve_nonreused_identity() {
    for checkpoint in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        seed(&engine);
        engine
            .execute(request("DELETE FROM source WHERE id = 2"))
            .unwrap();
        let expected = revision(&engine);
        if checkpoint {
            engine.checkpoint().unwrap();
        }
        drop(engine);
        let engine = open(directory.path());
        assert_eq!(revision(&engine), expected);
        engine.execute(request("DROP TABLE source")).unwrap();
        if checkpoint {
            engine.checkpoint().unwrap();
        }
        drop(engine);
        let engine = open(directory.path());
        seed(&engine);
        assert!(revision(&engine).table_id > expected.table_id);
    }
}

#[test]
fn legacy_checkpoint_revisions_are_conservative_and_upgrade_is_explicit() {
    for version in [2, 3, 4] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path());
        seed(&engine);
        engine
            .execute(request("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"))
            .unwrap();
        let sequence = engine.checkpoint().unwrap();
        let mut legacy = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        legacy.version = version;
        legacy.source_lineage = None;
        for table in &mut legacy.tables {
            table.source_revision = None;
            if version == 2 {
                table.row_segment = table.row_segments.pop();
                table.index_segment = table.index_segments.pop();
            }
        }
        write_relational_checkpoint(&engine.checkpoint_path, &legacy).unwrap();
        drop(engine);
        let engine = open(directory.path());
        let expected = revision(&engine);
        assert_eq!(expected.data_revision, sequence);
        assert_eq!(expected.schema_revision, sequence);
        assert_eq!(
            read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap()
                .version,
            version
        );
        engine.ensure_ml_source_format().unwrap();
        let upgraded = fs::read(&engine.checkpoint_path).unwrap();
        assert_eq!(
            read_relational_checkpoint(&engine.checkpoint_path)
                .unwrap()
                .unwrap()
                .version,
            5
        );
        engine.ensure_ml_source_format().unwrap();
        assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), upgraded);
        drop(engine);
        assert_eq!(revision(&open(directory.path())), expected);
    }
}

#[test]
fn source_snapshot_pins_values_schema_identity_and_revisions_together() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let uppercase = engine
        .ml_source_snapshot("SOURCE", &["VALUE".into()], 10000)
        .unwrap();
    assert_eq!(uppercase.selected_columns, ["id", "VALUE"]);
    assert_eq!(
        engine
            .ml_source_revision("SOURCE")
            .unwrap()
            .unwrap()
            .revision,
        revision(&engine)
    );
    let base = engine.state.read().clone();
    let expected = revision(&engine);
    engine
        .execute(request("ALTER TABLE source RENAME TO renamed"))
        .unwrap();
    engine
        .execute(request(
            "CREATE TABLE source (id INTEGER PRIMARY KEY, value TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO source VALUES (1, 'replacement')"))
        .unwrap();
    let captured = snapshot(base, "source", &["value".into()], 10000).unwrap();
    assert_eq!(captured.metadata.revision, expected);
    assert_eq!(captured.selected_columns, ["id", "value"]);
    assert_eq!(
        captured.rows,
        vec![
            vec![RelationalValue::Integer(1), RelationalValue::Integer(10)],
            vec![RelationalValue::Integer(2), RelationalValue::Integer(20)]
        ]
    );
    assert_ne!(
        captured.metadata.revision.table_id,
        revision(&engine).table_id
    );
    assert!(
        engine
            .ml_source_snapshot("source", &["value".into()], 0)
            .is_err()
    );
    assert!(
        engine
            .ml_source_snapshot("source", &["value".into()], 10001)
            .is_err()
    );
    assert!(
        engine
            .ml_source_snapshot("source", &["missing".into()], 10000)
            .is_err()
    );
    assert!(matches!(
        engine.ml_source_snapshot("renamed", &["value".into()], 1),
        Err(GaussError::SqlLimitExceeded(_))
    ));
}

#[test]
fn publication_checks_source_fence_at_commit_and_allows_newer_data() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("CREATE TABLE published (id INTEGER PRIMARY KEY)"))
        .unwrap();
    let expected = engine.ml_source_revision("source").unwrap().unwrap();
    engine
        .execute(request("UPDATE source SET value = 21 WHERE id = 2"))
        .unwrap();
    engine
        .execute_ml_publication(
            request("INSERT INTO published VALUES (1)"),
            &AuditContext::embedded(),
            &expected,
            None,
        )
        .unwrap();
    let base = engine.state.read().clone();
    let mut prepared = prepare_execution(
        base,
        request("INSERT INTO published VALUES (2)"),
        true,
        true,
        None,
        None,
        true,
    )
    .unwrap();
    prepared.ml_source_fence = Some(expected.clone());
    engine
        .execute(request("ALTER TABLE source ADD COLUMN extra INTEGER"))
        .unwrap();
    let error = engine
        .commit_prepared_under_reference_gate(prepared, &AuditContext::embedded(), 1, None, None)
        .err()
        .unwrap();
    assert!(error.to_string().contains("schema changed"), "{error}");
    let result = engine
        .execute(request("SELECT id FROM published"))
        .unwrap()
        .response;
    assert!(matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
    engine.execute(request("DROP TABLE source")).unwrap();
    seed(&engine);
    assert!(
        engine
            .execute_ml_publication(
                request("INSERT INTO published VALUES (3)"),
                &AuditContext::embedded(),
                &expected,
                None
            )
            .is_err()
    );
}

#[test]
fn current_checkpoint_requires_complete_valid_source_revisions() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine.checkpoint().unwrap();
    let mut checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    checkpoint.tables[0].source_revision = None;
    write_relational_checkpoint(&engine.checkpoint_path, &checkpoint).unwrap();
    assert!(read_relational_checkpoint(&engine.checkpoint_path).is_err());
    checkpoint.tables[0].source_revision = Some(MlSourceRevision {
        table_id: u64::MAX,
        data_revision: 1,
        schema_revision: 1,
    });
    write_relational_checkpoint(&engine.checkpoint_path, &checkpoint).unwrap();
    assert!(read_relational_checkpoint(&engine.checkpoint_path).is_err());
}

#[test]
fn db_publication_rejects_lineage_mismatch_without_writes() {
    let directory = tempfile::tempdir().unwrap();
    let db = crate::Db::open(directory.path()).unwrap();
    db.execute_sql(request("CREATE TABLE source (id INTEGER PRIMARY KEY)"))
        .unwrap();
    db.execute_sql(request("CREATE TABLE published (id INTEGER PRIMARY KEY)"))
        .unwrap();
    let mut metadata = db.ml_source_revision("source").unwrap().unwrap();
    assert!(!metadata.lineage.is_empty());
    metadata.lineage.push_str("-old-generation");
    assert!(
        db.execute_ml_publication(
            request("INSERT INTO published VALUES (1)"),
            &AuditContext::embedded(),
            &metadata,
            None
        )
        .is_err()
    );
    let result = db.execute_sql(request("SELECT id FROM published")).unwrap();
    assert!(matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()));
}

#[test]
fn publication_fences_exact_durable_schedule_claim() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let mut audit = AuditContext::embedded();
    audit.transport = "chironql-ml".into();
    for sql in [
        "CREATE TABLE __chiron_ml_schedule (name TEXT PRIMARY KEY, state TEXT NOT NULL)",
        "INSERT INTO __chiron_ml_schedule VALUES ('forecast', 'epoch-1')",
        "CREATE TABLE published (id INTEGER PRIMARY KEY)",
    ] {
        engine.execute_with_audit(request(sql), &audit).unwrap();
    }
    let expected = engine.ml_source_revision("source").unwrap().unwrap();
    let fence = MlPublicationFence {
        schedule_name: "forecast".into(),
        schedule_state: "epoch-1".into(),
    };
    engine
        .execute_ml_publication(
            request("INSERT INTO published VALUES (1)"),
            &audit,
            &expected,
            Some(&fence),
        )
        .unwrap();
    let base = engine.state.read().clone();
    let mut prepared = prepare_execution(
        base,
        request("INSERT INTO published VALUES (2)"),
        true,
        true,
        None,
        None,
        true,
    )
    .unwrap();
    prepared.ml_source_fence = Some(expected);
    prepared.ml_schedule_fence = Some(fence);
    engine
        .execute_with_audit(
            request("UPDATE __chiron_ml_schedule SET state = 'epoch-2' WHERE name = 'forecast'"),
            &audit,
        )
        .unwrap();
    let error = engine
        .commit_prepared_under_reference_gate(prepared, &audit, 1, None, None)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("epoch or claim changed"),
        "{error}"
    );
    let result = engine
        .execute(request("SELECT id FROM published"))
        .unwrap()
        .response;
    assert!(matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows.len() == 1));
}

#[test]
fn concurrent_snapshot_values_always_match_their_committed_revision() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE source (id INTEGER PRIMARY KEY, value INTEGER)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO source VALUES (1, 2)"))
        .unwrap();
    let writer = Arc::clone(&engine);
    let thread = std::thread::spawn(move || {
        for sequence in 3..53 {
            writer
                .execute(request(&format!(
                    "UPDATE source SET value = {sequence} WHERE id = 1"
                )))
                .unwrap();
        }
    });
    for _ in 0..100 {
        let snapshot = engine
            .ml_source_snapshot("source", &["value".into()], 10000)
            .unwrap();
        assert_eq!(
            snapshot.rows[0][1],
            RelationalValue::Integer(snapshot.metadata.revision.data_revision as i64)
        );
    }
    thread.join().unwrap();
}

#[test]
fn db_source_lineage_survives_reopen_changes_on_fork_and_fences_restore() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("db");
    let backup = directory.path().join("snapshot");
    let db = crate::Db::open(&root).unwrap();
    db.execute_sql(request(
        "CREATE TABLE source (id INTEGER PRIMARY KEY, value INTEGER)",
    ))
    .unwrap();
    db.execute_sql(request("INSERT INTO source VALUES (1, 10)"))
        .unwrap();
    db.execute_sql(request("CREATE TABLE published (id INTEGER PRIMARY KEY)"))
        .unwrap();
    db.ensure_ml_source_format().unwrap();
    let expected = db.ml_source_revision("source").unwrap().unwrap();
    db.snapshot(&backup).unwrap();
    drop(db);
    let db = crate::Db::open(&root).unwrap();
    assert_eq!(db.ml_source_revision("source").unwrap().unwrap(), expected);
    let fork = crate::Db::open(&backup).unwrap();
    assert_ne!(
        fork.ml_source_revision("source").unwrap().unwrap().lineage,
        expected.lineage
    );
    drop(fork);
    assert!(db.restore(directory.path().join("missing")).is_err());
    assert_eq!(db.ml_source_revision("source").unwrap().unwrap(), expected);
    db.execute_sql(request("UPDATE source SET value = 20 WHERE id = 1"))
        .unwrap();
    db.restore(&backup).unwrap();
    let restored = db.ml_source_revision("source").unwrap().unwrap();
    assert_eq!(restored.revision, expected.revision);
    assert_ne!(restored.lineage, expected.lineage);
    assert!(
        db.execute_ml_publication(
            request("INSERT INTO published VALUES (1)"),
            &AuditContext::embedded(),
            &expected,
            None
        )
        .is_err()
    );
    assert_eq!(
        db.ml_source_snapshot("source", &["value".into()], 10000)
            .unwrap()
            .rows[0][1],
        RelationalValue::Integer(10)
    );
    drop(db);
    let reopened = crate::Db::open(&root).unwrap();
    assert_eq!(
        reopened.ml_source_revision("source").unwrap().unwrap(),
        restored
    );
}

/// Qualification fixture: run with an immutable pre-v5 ChironDB server binary.
/// Ordinary unit tests cannot manufacture a previous release's reader.
#[test]
#[ignore = "requires CHIRONDB_PRE_V5_BINARY pointing to a frozen previous server"]
fn frozen_pre_v5_binary_rejects_source_format_without_mutating_sql_storage() {
    use std::process::{Command, Stdio};
    let binary =
        std::env::var_os("CHIRONDB_PRE_V5_BINARY").expect("provide the frozen pre-v5 server");
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("db");
    let db = crate::Db::open(&root).unwrap();
    db.execute_sql(request("CREATE TABLE source (id INTEGER PRIMARY KEY)"))
        .unwrap();
    db.execute_sql(request("INSERT INTO source VALUES (1)"))
        .unwrap();
    db.ensure_ml_source_format().unwrap();
    let expected = db.ml_source_revision("source").unwrap().unwrap();
    drop(db);
    fn files(directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, result);
            } else {
                result.insert(path.clone(), fs::read(path).unwrap());
            }
        }
    }
    let mut before = BTreeMap::new();
    files(&root.join("relational"), &mut before);
    let mut child = Command::new(binary)
        .args(["--data-dir"])
        .arg(&root)
        .args([
            "--listen-http",
            "127.0.0.1:0",
            "--listen-grpc",
            "127.0.0.1:0",
            "--listen-wire",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("previous binary did not reject the v5 database before startup");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let evidence = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{evidence}");
    assert!(
        evidence.contains("unknown field `source_lineage`")
            || evidence.contains("unknown field `source_revision`")
            || evidence.contains("unsupported relational checkpoint version 5"),
        "{evidence}"
    );
    let mut after = BTreeMap::new();
    files(&root.join("relational"), &mut after);
    assert_eq!(before, after, "old reader must not modify SQL storage");
    let reopened = crate::Db::open(&root).unwrap();
    assert_eq!(
        reopened.ml_source_revision("source").unwrap().unwrap(),
        expected
    );
    println!("Frozen previous binary rejected v5 without SQL storage mutations: {evidence}");
}

#[test]
fn catalog_lineage_fences_reads_and_writes_across_concurrent_restore() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("db");
    let backup = directory.path().join("snapshot");
    let db = crate::Db::open(root).unwrap();
    db.execute_sql(request("CREATE TABLE published (id INTEGER PRIMARY KEY)"))
        .unwrap();
    db.ensure_ml_source_format().unwrap();
    db.snapshot(&backup).unwrap();
    for _ in 0..10 {
        let old_lineage = db.ml_catalog_lineage().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                barrier.wait();
                db.execute_ml_catalog(
                    request("INSERT INTO published VALUES (1)"),
                    &AuditContext::embedded(),
                    &old_lineage,
                )
            });
            barrier.wait();
            db.restore(&backup).unwrap();
            if let Err(error) = writer.join().unwrap() {
                // Restore may close write admission before the operation can
                // acquire the lifecycle guard and check its expected lineage.
                let message = error.to_string();
                assert!(
                    message.contains("lineage changed")
                        || message.contains("storage maintenance is active"),
                    "{error}"
                );
            }
        });
        assert_ne!(db.ml_catalog_lineage().unwrap(), old_lineage);
        assert!(
            db.execute_ml_catalog(
                request("SELECT id FROM published"),
                &AuditContext::embedded(),
                &old_lineage
            )
            .is_err()
        );
        assert!(
            db.execute_ml_catalog(
                request("INSERT INTO published VALUES (2)"),
                &AuditContext::embedded(),
                &old_lineage
            )
            .is_err()
        );
        let current = db.ml_catalog_lineage().unwrap();
        let result = db
            .execute_ml_catalog(
                request("SELECT id FROM published"),
                &AuditContext::embedded(),
                &current,
            )
            .unwrap();
        assert!(
            matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows.is_empty()),
            "a stale catalog write must never reach the restored root"
        );
    }
}

#[test]
fn source_snapshot_refuses_held_budget_and_recovers_after_release() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let expected_revision = revision(&engine);
    let columns = vec!["value".into()];
    // Use the existing production storage capacity in an isolated test pool.
    // The held reservation consumes accounting budget, not an OS-sized buffer.
    let capacity = (crate::resource_profile::current().sql_pool_bytes / 2).max(1);
    wal_decode::with_test_storage_pool(capacity, |used| {
        assert_eq!(used(), 0);
        let mut held = wal_decode::MetadataCharge::default();
        held.prepare(
            capacity
                .checked_sub(wal_decode::lease_root_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(used(), capacity);
        assert!(matches!(
            engine.ml_source_snapshot("source", &columns, 10_000),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(used(), capacity, "refused snapshot must not leak a charge");
        assert_eq!(revision(&engine), expected_revision);
        drop(held);
        assert_eq!(used(), 0);
        let snapshot = engine
            .ml_source_snapshot("source", &columns, 10_000)
            .unwrap();
        assert_eq!(snapshot.metadata.revision, expected_revision);
        assert_eq!(snapshot.selected_columns, ["id", "value"]);
        assert_eq!(
            snapshot.rows,
            vec![
                vec![RelationalValue::Integer(1), RelationalValue::Integer(10)],
                vec![RelationalValue::Integer(2), RelationalValue::Integer(20)],
            ]
        );
        assert!(
            used() > 0,
            "successful snapshot must retain its reservation"
        );
        drop(snapshot);
        assert_eq!(used(), 0, "dropping the snapshot releases its reservation");
    });
}
