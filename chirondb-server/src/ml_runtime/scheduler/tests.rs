use super::*;

fn fixture() -> Schedule {
    let definition = MlMaterialize {
        view: "forecast".into(),
        source: "prices".into(),
        target: "target".into(),
        features: vec!["feature".into()],
        task: MlTask::Regression,
        model: MlModel::DecisionTree,
    };
    let mut record = Schedule::new("forecast", canonical_definition(&definition), 0);
    record.mode = MlRefreshMode::Auto;
    record
}

fn rev(data: u64) -> MlSourceRevision {
    MlSourceRevision {
        table_id: 7,
        data_revision: data,
        schema_revision: 1,
    }
}

#[test]
fn job_provenance_describes_current_attempt_and_recovery_trigger() {
    let mut record = fixture();
    record.worker_identity = Some(json!({"script_sha256_at_dispatch":"previous-worker"}));
    record.requested_revision = Some(rev(2));
    record.desired = Some(rev(9));
    let details = |record: &Schedule, source| {
        let statement = provenance_statement(record, "abc", source, false);
        serde_json::from_str::<Value>(one_text(&statement.parameters[1]).unwrap()).unwrap()
    };
    let queued = details(&record, None);
    assert_eq!(queued["trigger"], "automatic");
    assert!(queued["worker_identity"].is_null());
    assert!(queued["source_revision"].is_null());
    record.error_code = Some("chironql.ml_interrupted".into());
    assert_eq!(details(&record, None)["trigger"], "recovery");
    record.manual = true;
    assert_eq!(details(&record, None)["trigger"], "manual");
    record.manual = false;
    record.worker_identity = Some(json!({"script_sha256_at_dispatch":"current-worker"}));
    let dispatched = details(&record, Some(rev(9)));
    assert_eq!(
        dispatched["worker_identity"],
        record.worker_identity.clone().unwrap()
    );
    assert_eq!(dispatched["source_revision"], json!({"data":9,"schema":1}));

    // A failure before dispatch must persist this attempt's requested revision,
    // without borrowing the prior generation's worker identity or source capture.
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    execute_sql(
        &db,
        vec![insert_statement(&record).unwrap()],
        &audit("test", None, None),
    )
    .unwrap();
    fail_before_spawn(
        &db,
        &mut record,
        MlError::new("chironql.ml_invalid_schema", "preflight failed"),
        100,
    )
    .unwrap();
    let response = execute_sql(
        &db,
        vec![statement(format!("SELECT id FROM {JOBS_TABLE}"), vec![])],
        &audit("test", None, None),
    )
    .unwrap();
    let job_id = one_text(&rows(&response.results[0]).unwrap().1[0][0]).unwrap();
    let job = super::super::get_job(&db, job_id).unwrap();
    assert_eq!(job["status"], "failed");
    assert_eq!(job["trigger"], "recovery");
    assert_eq!(job["requested_revision"], json!({"data":9,"schema":1}));
    assert!(job["source_version"].is_null());
    assert!(job["source_revision"].is_null());
    assert!(job["worker_identity"].is_null());
}

#[test]
fn thousand_changes_coalesce_and_sustained_writes_have_a_deadline() {
    let mut burst = fixture();
    for tick in 0..1000 {
        burst.dirty(rev(tick + 1), tick);
    }
    assert!(burst.pending);
    assert_eq!(burst.desired, Some(rev(1000)));
    assert_eq!(burst.first_dirty, Some(0));
    assert_eq!(burst.eligible_at(), 5999);
    assert!(serde_json::to_vec(&burst).unwrap().len() < 2048);
    let mut continuous = fixture();
    for tick in 0..1000 {
        continuous.dirty(rev(tick + 1), tick * 100);
    }
    assert_eq!(continuous.eligible_at(), MAX_COALESCE_MS);
    // Duplicate metadata observations cannot delay dispatch or create intent.
    continuous.dirty(rev(1000), 200_000);
    assert_eq!(continuous.eligible_at(), MAX_COALESCE_MS);
}

#[test]
fn running_changes_create_one_followup_without_losing_first_dirty() {
    let mut record = fixture();
    record.desired = Some(rev(1));
    record.claim = Some("active".into());
    for tick in 1..1001 {
        record.dirty(rev(tick + 1), tick);
    }
    assert_eq!(record.claim.as_deref(), Some("active"));
    assert_eq!(record.first_dirty, Some(1));
    assert_eq!(record.desired, Some(rev(1001)));
    record.published = Some(rev(1));
    assert!(record.pending);
    assert_ne!(record.desired, record.published);
}

#[test]
fn failures_keep_backoff_across_source_writes_and_block_permanent_errors() {
    let mut record = fixture();
    let transient = MlError {
        code: "chironql.ml_worker_timeout",
        message: "deadline".into(),
        transient: true,
    };
    for (attempt, delay) in [(1, 5000), (2, 30000), (3, 300000), (4, 300000)] {
        record.fail(&transient, 1000);
        assert_eq!(record.failures, attempt);
        assert_eq!(record.retry_at, Some(1000 + delay));
        record.dirty(rev(u64::from(attempt)), 1001);
        assert_eq!(record.retry_at, Some(1000 + delay));
        assert!(record.eligible_at() >= 1000 + delay);
    }
    record.fail(
        &MlError::new("chironql.ml_unavailable", "install worker"),
        2000,
    );
    assert!(record.blocked);
    assert!(!record.pending);
    assert_eq!(record.retry_at, None);
    record.dirty(rev(20), 3000);
    assert!(!record.blocked);
    assert!(record.pending);
}

#[test]
fn restart_clamps_future_timestamps_without_resetting_cooldown() {
    let mut record = fixture();
    record.first_dirty = Some(1_000_000);
    record.last_dirty = Some(2_000_000);
    record.retry_at = Some(3_000_000);
    record.clamp_recovered_clock(100);
    assert_eq!(record.first_dirty, Some(100));
    assert_eq!(record.last_dirty, Some(100));
    assert_eq!(record.retry_at, Some(300_100));
}

#[test]
fn repeated_reads_do_not_recover_or_mutate_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    execute_sql(
        &db,
        vec![statement(
            format!(
                "INSERT INTO {JOBS_TABLE} (id,view_name,status) VALUES ('abc','missing','running')"
            ),
            vec![],
        )],
        &audit("test", None, None),
    )
    .unwrap();
    let before = db.ml_source_revision(JOBS_TABLE).unwrap().unwrap().revision;
    for _ in 0..20 {
        assert_eq!(
            super::super::get_job(&db, "abc").unwrap()["status"],
            "running"
        );
    }
    let after = db.ml_source_revision(JOBS_TABLE).unwrap().unwrap().revision;
    assert_eq!(before, after);
}

#[test]
fn scheduler_owner_releases_database_and_recovers_only_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    {
        let db = Db::open(directory.path()).unwrap();
        let runtime = state_for(&db);
        ensure_catalog_for_test(&db, &runtime).unwrap();
        let mut record = fixture();
        record.claim = Some("old-claim".into());
        record.job = Some("abc".into());
        execute_sql(&db, vec![
            statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version) VALUES ($1,$2,'prices',0)"), vec![text(&record.name),text(&record.definition)]),
            insert_statement(&record).unwrap(),
            statement(format!("INSERT INTO {JOBS_TABLE} (id,view_name,status) VALUES ('abc','forecast','running')"), vec![]),
        ], &audit("test", None, None)).unwrap();
    }
    let reopened = Db::open(directory.path()).unwrap();
    initialize(&reopened).unwrap();
    let job = super::super::get_job(&reopened, "abc").unwrap();
    assert_eq!(job["status"], "failed");
    let runtime = state_for(&reopened);
    let inner = runtime.shared.inner.lock().unwrap();
    let record = &inner.records["forecast"];
    assert!(record.claim.is_none());
    assert_eq!(record.failures, 1);
}

#[test]
fn first_embedded_get_after_reopen_does_not_recover_jobs() {
    let directory = tempfile::tempdir().unwrap();
    {
        let db = Db::open(directory.path()).unwrap();
        let runtime = state_for(&db);
        ensure_catalog_for_test(&db, &runtime).unwrap();
        execute_sql(&db, vec![statement(format!("INSERT INTO {JOBS_TABLE} (id,view_name,status) VALUES ('abc','missing','running')"), vec![])], &audit("test", None, None)).unwrap();
    }
    let reopened = Db::open(directory.path()).unwrap();
    let before = reopened
        .ml_source_revision(JOBS_TABLE)
        .unwrap()
        .unwrap()
        .revision;
    assert!(super::super::get_job(&reopened, "abc").is_err());
    let response = execute_sql(
        &reopened,
        vec![statement(
            format!("SELECT status FROM {JOBS_TABLE} WHERE id = 'abc'"),
            vec![],
        )],
        &audit("test", None, None),
    )
    .unwrap();
    assert_eq!(
        one_text(&rows(&response.results[0]).unwrap().1[0][0]).unwrap(),
        "running"
    );
    assert_eq!(
        before,
        reopened
            .ml_source_revision(JOBS_TABLE)
            .unwrap()
            .unwrap()
            .revision
    );
}

#[test]
fn legacy_catalog_larger_than_sql_statement_limit_migrates_as_manual() {
    let directory = tempfile::tempdir().unwrap();
    {
        let db = Db::open(directory.path()).unwrap();
        let runtime = state_for(&db);
        ensure_catalog_for_test(&db, &runtime).unwrap();
        for id in 0..61 {
            let name = format!("legacy_{id}");
            execute_sql(&db, vec![statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version) VALUES ($1,$2,'prices',3)"), vec![text(name),text(&fixture().definition)])], &audit("test", None, None)).unwrap();
        }
    }
    let reopened = Db::open(directory.path()).unwrap();
    initialize(&reopened).unwrap();
    let runtime = state_for(&reopened);
    let inner = runtime.shared.inner.lock().unwrap();
    assert_eq!(inner.records.len(), 61);
    assert!(
        inner
            .records
            .values()
            .all(|record| record.mode == MlRefreshMode::Manual
                && record.source_id.is_none()
                && record.published.is_none()
                && record.version == 3)
    );
}

#[test]
fn lost_publication_ack_reconciles_receipt_without_second_generation() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    let context = audit("receipt-test", None, None);
    execute_sql(&db, vec![
        statement("CREATE TABLE prices (id INTEGER PRIMARY KEY, feature DOUBLE PRECISION, target DOUBLE PRECISION)", vec![]),
        statement("INSERT INTO prices VALUES (1,1.0,2.0),(2,2.0,4.0),(3,3.0,NULL)", vec![]),
    ], &context).unwrap();
    db.ensure_ml_source_format().unwrap();
    let mut record = fixture();
    record.mode = MlRefreshMode::Manual;
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    record.bind(&db.ml_source_revision("prices").unwrap().unwrap(), 1);
    record.claim = Some("receipt-claim".into());
    record.job = Some("abc".into());
    let definition = record.definition().unwrap();
    let snapshot = read_snapshot(&db, &definition).unwrap();
    execute_sql(&db, vec![
        statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version) VALUES ('forecast',$1,'prices',0)"), vec![text(&record.definition)]),
        insert_statement(&record).unwrap(), queued_job(&record,"abc"),
        provenance_statement(&record,"abc",Some(snapshot.source.metadata.revision),false),
    ], &context).unwrap();
    let result =
        json!({"predictions":[2.0,4.0,4.0],"confidence":[null,null,null],"context_rows":2});
    let mut committed = record.clone();
    committed.claim = None;
    committed.job = None;
    committed.published = Some(snapshot.source.metadata.revision);
    committed.track_freshness(100);
    committed.version = 1;
    committed.finished_at = Some(100);
    publish(
        &db,
        &result,
        Publication {
            definition: &definition,
            snapshot: &snapshot,
            job_id: "abc",
            audit: &context,
            duration_ms: 1,
            schedule: &committed,
        },
    )
    .unwrap();
    // The SQL commit is durable, but the process still has its old lease and
    // worker result, as after losing a completion acknowledgement.
    let mut inner = runtime.shared.inner.lock().unwrap();
    inner.records.insert(record.name.clone(), record.clone());
    let (_, receiver) = mpsc::sync_channel(1);
    let mut active = Active {
        _permit: test_permit(),
        name: record.name.clone(),
        epoch: record.epoch,
        claim: "receipt-claim".into(),
        job: "abc".into(),
        definition,
        snapshot,
        started: Instant::now(),
        receiver,
        thread: None,
        outcome: Some(Ok(result)),
        cancel: Arc::new(AtomicBool::new(false)),
        operation: None,
    };
    complete(&db, &mut inner, &mut active, 101).unwrap();
    assert_eq!(inner.records["forecast"].version, 1);
    assert_eq!(
        inner.records["forecast"].observed_freshness_lag_ms(101),
        Some(0)
    );
    assert!(inner.records["forecast"].claim.is_none());
    assert!(
        !inner.recovery_required,
        "an applied success receipt resolves the acknowledgement"
    );
    drop(inner);
    let page = super::super::get_view(&db, "forecast", 100, None).unwrap();
    assert_eq!(page["version"], 1);
    assert_eq!(page["row_count"], 3);
    assert_eq!(
        super::super::get_job(&db, "abc").unwrap()["status"],
        "succeeded"
    );
}

fn test_permit() -> WorkerPermit {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(permit) = WorkerPermit::acquire() {
            return permit;
        }
        assert!(
            Instant::now() < deadline,
            "test worker permit remained occupied"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn permanent_completion_preserves_only_a_newer_pending_auto_intent() {
    for (label, newer, mode, pending, expected_pending) in [
        ("newer", true, MlRefreshMode::Auto, true, true),
        ("same", false, MlRefreshMode::Auto, true, false),
        ("cancelled", true, MlRefreshMode::Auto, false, false),
        ("manual", true, MlRefreshMode::Manual, true, false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        let runtime = state_for(&db);
        ensure_catalog_for_test(&db, &runtime).unwrap();
        let context = audit("permanent-followup-test", None, None);
        let source_context = AuditContext {
            transport: "test".into(),
            ..context.clone()
        };
        execute_sql(&db, vec![
            statement("CREATE TABLE prices (id INTEGER PRIMARY KEY, feature DOUBLE PRECISION, target DOUBLE PRECISION)", vec![]),
            statement("INSERT INTO prices VALUES (1,1.0,2.0),(2,2.0,4.0),(3,3.0,NULL)", vec![]),
        ], &source_context).unwrap();
        db.ensure_ml_source_format().unwrap();
        let mut record = fixture();
        record.catalog_lineage = db.ml_catalog_lineage().unwrap();
        record.bind(&db.ml_source_revision("prices").unwrap().unwrap(), 1);
        record.claim = Some("failed-claim".into());
        record.job = Some("abc".into());
        let definition = record.definition().unwrap();
        let snapshot = read_snapshot(&db, &definition).unwrap();
        if newer {
            execute_sql(
                &db,
                vec![statement(
                    "UPDATE prices SET feature = 9.0 WHERE id = 3",
                    vec![],
                )],
                &source_context,
            )
            .unwrap();
            record.dirty(
                db.ml_source_revision("prices").unwrap().unwrap().revision,
                100,
            );
        }
        record.mode = mode;
        record.pending = pending;
        record.failures = 1;
        assert!(!metadata(&db, &record).unwrap().table.managed_by_ml);
        let desired = record.desired;
        execute_sql(&db, vec![
            statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version) VALUES ('forecast',$1,'prices',0)"), vec![text(&record.definition)]),
            insert_statement(&record).unwrap(), queued_job(&record,"abc"),
            provenance_statement(&record,"abc",Some(snapshot.source.metadata.revision),false),
            statement(format!("UPDATE {JOBS_TABLE} SET status = 'running' WHERE id = 'abc'"),vec![]),
        ], &context).unwrap();
        let mut inner = runtime.shared.inner.lock().unwrap();
        inner.records.insert(record.name.clone(), record.clone());
        let (_, receiver) = mpsc::sync_channel(1);
        let mut active = Active {
            _permit: test_permit(),
            name: record.name.clone(),
            epoch: record.epoch,
            claim: "failed-claim".into(),
            job: "abc".into(),
            definition,
            snapshot,
            started: Instant::now(),
            receiver,
            thread: None,
            outcome: Some(Err(MlError::new(
                "chironql.ml_invalid_rows",
                "captured input invalid",
            ))),
            cancel: Arc::new(AtomicBool::new(false)),
            operation: None,
        };
        complete(&db, &mut inner, &mut active, 120).unwrap();
        // Re-observing the already-known current revision must neither erase
        // the newer intent nor unblock a same-revision permanent failure.
        reconcile(&db, &mut inner, 121).unwrap();
        let completed = &inner.records["forecast"];
        assert_eq!(completed.pending, expected_pending, "{label}");
        assert_eq!(completed.blocked, !expected_pending, "{label}");
        assert_eq!(completed.desired, desired, "{label}");
        assert_eq!(completed.failures, 2, "{label}");
        assert_eq!(completed.retry_at, None, "{label}");
        assert!(
            completed.claim.is_none() && completed.job.is_none(),
            "{label}"
        );
        if expected_pending {
            assert_eq!(completed.first_dirty, Some(100));
            assert_eq!(completed.last_dirty, Some(100));
            assert_eq!(completed.eligible_at(), 5_100);
        }
        let persisted: Schedule = serde_json::from_str(
            &stored_state(&db, "forecast", &completed.catalog_lineage).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.pending, expected_pending, "{label}");
        assert_eq!(persisted.blocked, !expected_pending, "{label}");
        assert_eq!(persisted.desired, desired, "{label}");
        drop(inner);
        assert_eq!(
            super::super::get_job(&db, "abc").unwrap()["status"],
            "failed"
        );
    }
}

#[test]
fn failed_worker_start_keeps_claim_until_failure_is_durable() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    let context = audit("worker-start-test", None, None);
    execute_sql(&db, vec![
        statement("CREATE TABLE prices (id INTEGER PRIMARY KEY, feature DOUBLE PRECISION, target DOUBLE PRECISION)", vec![]),
        statement("INSERT INTO prices VALUES (1,1.0,2.0),(2,2.0,4.0),(3,3.0,NULL)", vec![]),
    ], &context).unwrap();
    db.ensure_ml_source_format().unwrap();
    let mut record = fixture();
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    record.bind(&db.ml_source_revision("prices").unwrap().unwrap(), 1);
    record.claim = Some("unstarted-claim".into());
    record.job = Some("def".into());
    record.pending = false;
    let definition = record.definition().unwrap();
    let snapshot = read_snapshot(&db, &definition).unwrap();
    execute_sql(&db, vec![
        statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version) VALUES ('forecast',$1,'prices',0)"), vec![text(&record.definition)]),
        insert_statement(&record).unwrap(), queued_job(&record,"def"),
        provenance_statement(&record,"def",Some(snapshot.source.metadata.revision),false),
        statement(format!("UPDATE {JOBS_TABLE} SET status = 'running' WHERE id = 'def'"),vec![]),
    ], &context).unwrap();
    let mut inner = runtime.shared.inner.lock().unwrap();
    inner.records.insert(record.name.clone(), record.clone());
    let (_, receiver) = mpsc::sync_channel(1);
    let mut active = Active {
        _permit: test_permit(),
        name: record.name.clone(),
        epoch: record.epoch,
        claim: "unstarted-claim".into(),
        job: "def".into(),
        definition,
        snapshot,
        started: Instant::now(),
        receiver,
        thread: None,
        outcome: Some(Err(MlError {
            code: "chironql.ml_worker_resource",
            message: "thread creation refused".into(),
            transient: true,
        })),
        cancel: Arc::new(AtomicBool::new(false)),
        operation: None,
    };
    // Refuse the catalog write/read boundary, then restore it. The owned
    // failure and durable claim must survive until completion can be recorded.
    inner.records.get_mut("forecast").unwrap().catalog_lineage = "unavailable-root".into();
    assert!(complete(&db, &mut inner, &mut active, 100).is_err());
    assert_eq!(
        inner.records["forecast"].claim.as_deref(),
        Some("unstarted-claim")
    );
    assert!(active.outcome.as_ref().unwrap().is_err());
    inner.records.get_mut("forecast").unwrap().catalog_lineage = db.ml_catalog_lineage().unwrap();
    complete(&db, &mut inner, &mut active, 101).unwrap();
    let completed = &inner.records["forecast"];
    assert!(completed.claim.is_none());
    assert!(completed.pending);
    assert_eq!(completed.retry_at, Some(5_101));
    assert_eq!(
        completed.error_code.as_deref(),
        Some("chironql.ml_worker_resource")
    );
    assert_eq!(completed.version, 0);
    let persisted: Schedule =
        serde_json::from_str(&stored_state(&db, "forecast", &completed.catalog_lineage).unwrap())
            .unwrap();
    assert!(persisted.claim.is_none());
    assert_eq!(persisted.failures, 1);
    drop(inner);
    assert_eq!(
        super::super::get_job(&db, "def").unwrap()["status"],
        "failed"
    );
}

#[test]
fn unknown_unprojected_commit_blocks_root_until_reopen_and_preserves_reads() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    let context = audit("unknown-commit-test", None, None);
    execute_sql(&db, vec![
        statement("CREATE TABLE prices (id INTEGER PRIMARY KEY, feature DOUBLE PRECISION, target DOUBLE PRECISION)", vec![]),
        statement("INSERT INTO prices VALUES (1,1.0,2.0),(2,2.0,4.0),(3,3.0,NULL)", vec![]),
        statement("CREATE TABLE forecast (id INTEGER PRIMARY KEY, prediction DOUBLE PRECISION, refresh_version BIGINT)", vec![]),
        statement("INSERT INTO forecast VALUES (1,2.0,1)", vec![]),
    ], &context).unwrap();
    db.ensure_ml_source_format().unwrap();
    let mut record = fixture();
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    record.bind(&db.ml_source_revision("prices").unwrap().unwrap(), 1);
    record.published = record.desired;
    record.version = 1;
    record.claim = Some("unknown-claim".into());
    record.job = Some("abc".into());
    let definition = record.definition().unwrap();
    let snapshot = read_snapshot(&db, &definition).unwrap();
    execute_sql(&db, vec![
        statement(format!("INSERT INTO {VIEWS_TABLE} (name,definition,source,version,source_version,row_count) VALUES ('forecast',$1,'prices',1,1,1)"), vec![text(&record.definition)]),
        insert_statement(&record).unwrap(), queued_job(&record,"abc"),
        provenance_statement(&record,"abc",Some(snapshot.source.metadata.revision),false),
        statement(format!("UPDATE {JOBS_TABLE} SET status = 'running' WHERE id = 'abc'"),vec![]),
    ], &context).unwrap();
    let before = db
        .ml_source_revision(SCHEDULE_TABLE)
        .unwrap()
        .unwrap()
        .revision;
    let mut inner = runtime.shared.inner.lock().unwrap();
    inner.records.insert(record.name.clone(), record.clone());
    let (_, receiver) = mpsc::sync_channel(1);
    let mut active = Active {
        _permit: test_permit(),
        name: record.name.clone(),
        epoch: record.epoch,
        claim: "unknown-claim".into(),
        job: "abc".into(),
        definition: definition.clone(),
        snapshot,
        started: Instant::now(),
        receiver,
        thread: None,
        // The journal cannot yet confirm its COMMIT. Current SQL still has
        // the old generation and a running receipt, so absence of a success
        // must never authorize publication or claim replacement.
        outcome: Some(Err(engine_error(
            chirondb_core::GaussError::CommitOutcomeUnknown {
                transaction_id: "unprojected-transaction".into(),
            },
        ))),
        cancel: Arc::new(AtomicBool::new(false)),
        operation: None,
    };
    assert_eq!(
        complete(&db, &mut inner, &mut active, 100)
            .unwrap_err()
            .code,
        "chironql.ml_commit_unknown"
    );
    assert!(inner.recovery_required);
    assert_eq!(
        inner.records["forecast"].claim.as_deref(),
        Some("unknown-claim")
    );
    assert_eq!(inner.records["forecast"].job.as_deref(), Some("abc"));
    for now in [101, 10_000, 1_000_000] {
        assert_eq!(
            complete(&db, &mut inner, &mut active, now)
                .unwrap_err()
                .code,
            RECOVERY_REQUIRED_CODE
        );
        assert_eq!(
            reconcile(&db, &mut inner, now).unwrap_err().code,
            RECOVERY_REQUIRED_CODE
        );
        assert_eq!(
            dispatch(&db, &mut inner, &runtime.shared, now)
                .err()
                .unwrap()
                .code,
            RECOVERY_REQUIRED_CODE
        );
        assert_eq!(
            ensure_catalog(&db, &mut inner, now, &context)
                .unwrap_err()
                .code,
            RECOVERY_REQUIRED_CODE
        );
    }
    // Another view in this database is blocked too, even though its own
    // source/claim had no error. The unknown decision belongs to the root.
    let mut other = inner.records["forecast"].clone();
    other.name = "other".into();
    other.claim = None;
    other.job = None;
    inner.records.insert(other.name.clone(), other);
    drop(inner);
    execute_sql(
        &db,
        vec![statement(
            "UPDATE prices SET feature = 5.0 WHERE id = 1",
            vec![],
        )],
        &context,
    )
    .unwrap();
    for name in ["forecast", "other"] {
        let state = get_refresh_status(&db, name).unwrap();
        assert_eq!(state.activity, Activity::Blocked);
        assert_eq!(state.availability, Availability::Available);
        assert_eq!(state.error_code.as_deref(), Some(RECOVERY_REQUIRED_CODE));
        assert!(state.blocked_reason.unwrap().contains("reopen"));
        assert_eq!(state.retry_at_ms, None);
    }
    assert_eq!(
        set_refresh_policy(&db, "forecast", MlRefreshMode::Auto, "test", None)
            .unwrap_err()
            .code,
        RECOVERY_REQUIRED_CODE
    );
    assert_eq!(
        set_refresh_policy(&db, "forecast", MlRefreshMode::Manual, "test", None)
            .unwrap_err()
            .code,
        RECOVERY_REQUIRED_CODE
    );
    assert_eq!(
        submit(&db, &definition, "test", None).unwrap_err().code,
        RECOVERY_REQUIRED_CODE
    );
    assert_eq!(
        drop_view(&db, "forecast", "test", None).unwrap_err().code,
        RECOVERY_REQUIRED_CODE
    );
    let page = super::super::get_view(&db, "forecast", 100, None).unwrap();
    assert_eq!(page["version"], 1);
    assert_eq!(page["rows"][0]["prediction"], 2.0);
    assert_eq!(
        super::super::get_job(&db, "abc").unwrap()["status"],
        "running"
    );
    assert_eq!(
        db.ml_source_revision(SCHEDULE_TABLE)
            .unwrap()
            .unwrap()
            .revision,
        before
    );
    drop(active);
    drop(runtime);
    drop(db);
    let reopened = Db::open(directory.path()).unwrap();
    initialize(&reopened).unwrap();
    let recovered = state_for(&reopened);
    assert!(!recovered.shared.inner.lock().unwrap().recovery_required);
    assert_eq!(
        super::super::get_job(&reopened, "abc").unwrap()["status"],
        "failed"
    );
    assert_eq!(
        super::super::get_view(&reopened, "forecast", 100, None).unwrap()["rows"],
        page["rows"]
    );
}

#[test]
fn completed_busy_view_rejoins_after_an_already_waiting_manual_view() {
    let mut busy = fixture();
    busy.name = "busy".into();
    busy.dirty(rev(1), 1_000);
    busy.dirty(rev(2), 90_000);
    busy.finished_at = Some(100_000);
    let mut waiting = fixture();
    waiting.name = "waiting".into();
    waiting.manual = true;
    waiting.dirty(rev(1), 90_000);
    assert_eq!(busy.eligible_at(), 31_000);
    assert_eq!(waiting.eligible_at(), 90_000);
    let records = [busy, waiting];
    let selected = records
        .iter()
        .filter(|record| record.pending && record.eligible_at() <= 100_000)
        .min_by_key(|record| (record.queue_priority(), record.first_dirty, &record.name))
        .unwrap();
    assert_eq!(selected.name, "waiting");
    assert_eq!(
        records[0].eligible_at(),
        31_000,
        "fairness must not start a new debounce"
    );
}

#[test]
fn changed_revision_after_permanent_failure_starts_a_new_debounce_intent() {
    let mut record = fixture();
    record.dirty(rev(1), 0);
    record.fail(
        &MlError::new("chironql.ml_limit_exceeded", "hard row limit"),
        1_000,
    );
    assert!(record.blocked);
    assert!(!record.pending);
    assert_eq!(record.failures, 1);
    record.dirty(rev(2), 100_000);
    assert!(!record.blocked);
    assert!(record.pending);
    assert_eq!(record.first_dirty, Some(100_000));
    assert_eq!(record.eligible_at(), 105_000);
    record.dirty(rev(3), 101_000);
    assert_eq!(record.first_dirty, Some(100_000));
    assert_eq!(record.eligible_at(), 106_000);
    assert_eq!(record.failures, 1);
    assert_eq!(record.retry_at, None);
}

#[test]
fn recovery_clamps_queue_finish_clock_without_rewriting_job_provenance() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    let context = audit("recovered-queue-clock-test", None, None);
    let mut record = fixture();
    record.mode = MlRefreshMode::Manual;
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    record.first_dirty = Some(10);
    record.last_dirty = Some(20);
    record.finished_at = Some(5_000_000);
    let provenance = provenance_statement(&record, "abc", None, false);
    let original = provenance.parameters[1].clone();
    execute_sql(
        &db,
        vec![insert_statement(&record).unwrap(), provenance],
        &context,
    )
    .unwrap();
    let mut inner = runtime.shared.inner.lock().unwrap();
    inner.initialized = false;
    ensure_catalog(&db, &mut inner, 100, &context).unwrap();
    let recovered = &inner.records["forecast"];
    assert_eq!(recovered.finished_at, Some(100));
    assert_eq!(recovered.queue_priority(), 5_020);
    let response = execute_sql(
        &db,
        vec![statement(
            format!("SELECT details FROM {PROVENANCE_TABLE} WHERE id = 'abc'"),
            vec![],
        )],
        &context,
    )
    .unwrap();
    assert_eq!(rows(&response.results[0]).unwrap().1[0][0], original);
    let persisted: Schedule =
        serde_json::from_str(&stored_state(&db, "forecast", &record.catalog_lineage).unwrap())
            .unwrap();
    assert_eq!(persisted.finished_at, Some(100));
}

#[derive(Default)]
struct LagSamples(Mutex<Vec<f64>>);

impl metrics::HistogramFn for LagSamples {
    fn record(&self, value: f64) {
        self.0.lock().unwrap().push(value);
    }
}

#[derive(Default)]
struct ObservationRecorder {
    changed: Arc<metrics::atomics::AtomicU64>,
    coalesced: Arc<metrics::atomics::AtomicU64>,
    lag: Arc<LagSamples>,
}

impl ObservationRecorder {
    fn counts(&self) -> (u64, u64) {
        (
            self.changed.load(Ordering::Acquire),
            self.coalesced.load(Ordering::Acquire),
        )
    }
}

impl metrics::Recorder for ObservationRecorder {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let value = match key.name() {
            "chirondb_ml_observed_source_revision_changes_total" => &self.changed,
            "chirondb_ml_coalesced_revision_observations_total" => &self.coalesced,
            _ => return metrics::Counter::noop(),
        };
        assert_eq!(key.labels().count(), 0);
        metrics::Counter::from_arc(Arc::clone(value))
    }

    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        if key.name() == "chirondb_ml_observed_freshness_lag_seconds" {
            assert_eq!(key.labels().count(), 0);
            metrics::Histogram::from_arc(Arc::clone(&self.lag))
        } else {
            metrics::Histogram::noop()
        }
    }
}

#[test]
fn revision_observation_metrics_require_a_known_durable_schedule_save() {
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(directory.path()).unwrap();
    let runtime = state_for(&db);
    ensure_catalog_for_test(&db, &runtime).unwrap();
    let context = audit("observation-test", None, None);
    let source_context = AuditContext {
        transport: "test".into(),
        ..context.clone()
    };
    execute_sql(&db, vec![
        statement("CREATE TABLE prices (id INTEGER PRIMARY KEY, feature DOUBLE PRECISION, target DOUBLE PRECISION)", vec![]),
        statement("INSERT INTO prices VALUES (1,1.0,2.0)", vec![]),
    ], &source_context).unwrap();
    db.ensure_ml_source_format().unwrap();
    let mut record = fixture();
    record.catalog_lineage = db.ml_catalog_lineage().unwrap();
    execute_sql(&db, vec![insert_statement(&record).unwrap()], &context).unwrap();
    let mut inner = runtime.shared.inner.lock().unwrap();
    inner.records.insert(record.name.clone(), record.clone());
    let recorder = ObservationRecorder::default();
    metrics::with_local_recorder(&recorder, || {
        // Initial binding is an observation, not a revision transition.
        reconcile(&db, &mut inner, 100).unwrap();
        assert_eq!(recorder.counts(), (0, 0));
        let mut fresh = inner.records["forecast"].clone();
        assert!(fresh.source_id.is_some());
        fresh.published = fresh.desired;
        fresh.pending = false;
        fresh.track_freshness(100);
        catalog_sql(
            &db,
            vec![save_statement(&fresh).unwrap()],
            &context,
            &inner.lineage,
        )
        .unwrap();
        inner.records.insert(fresh.name.clone(), fresh);
        reconcile(&db, &mut inner, 200).unwrap();
        assert_eq!(recorder.counts(), (0, 0));
        for (index, now) in [(1, 1_000), (2, 2_000)] {
            execute_sql(
                &db,
                vec![statement(
                    format!("UPDATE prices SET feature = {}.0 WHERE id = 1", index + 1),
                    vec![],
                )],
                &source_context,
            )
            .unwrap();
            reconcile(&db, &mut inner, now).unwrap();
            assert_eq!(recorder.counts(), (index, index - 1));
            reconcile(&db, &mut inner, now + 1).unwrap();
            assert_eq!(recorder.counts(), (index, index - 1));
        }
        let lineage = inner.lineage.clone();
        let before = stored_state(&db, "forecast", &lineage).unwrap();
        execute_sql(
            &db,
            vec![statement(
                "UPDATE prices SET feature = 4.0 WHERE id = 1",
                vec![],
            )],
            &source_context,
        )
        .unwrap();
        // Real catalog fence refusal: source is newer but no schedule save.
        inner.lineage = "retired-root".into();
        assert!(reconcile(&db, &mut inner, 3_000).is_err());
        assert_eq!(recorder.counts(), (2, 1));
        assert_eq!(stored_state(&db, "forecast", &lineage).unwrap(), before);
        inner.lineage = lineage;
        // Unknown outcomes cannot count or retry the transition while latched.
        let unknown = engine_error(chirondb_core::GaussError::CommitOutcomeUnknown {
            transaction_id: "observation-unknown".into(),
        });
        assert!(inner.observe::<()>(Err(unknown)).is_err());
        assert!(reconcile(&db, &mut inner, 3_001).is_err());
        assert_eq!(recorder.counts(), (2, 1));
        // Model an owner recovered from durable SQL; recovery itself emits none.
        inner.recovery_required = false;
        inner.initialized = false;
        ensure_catalog(&db, &mut inner, 3_002, &context).unwrap();
        assert_eq!(recorder.counts(), (2, 1));
        reconcile(&db, &mut inner, 3_003).unwrap();
        assert_eq!(recorder.counts(), (3, 2));
        record_freshness_lag(&inner, 4_000);
        assert_eq!(*recorder.lag.0.lock().unwrap(), vec![3.0]);
    });
}

#[test]
fn observed_freshness_lag_survives_work_failure_and_durable_recovery() {
    let mut record = fixture();
    record.published = Some(rev(1));
    record.desired = record.published;
    assert_eq!(record.observed_freshness_lag_ms(500), Some(0));
    record.dirty(rev(2), 1_000);
    assert_eq!(record.observed_freshness_lag_ms(6_000), Some(5_000));
    // Dispatch consumes the intent, but does not make its result current.
    record.pending = false;
    record.first_dirty = None;
    record.last_dirty = None;
    record.claim = Some("running".into());
    assert_eq!(record.observed_freshness_lag_ms(7_000), Some(6_000));
    record.fail(
        &MlError {
            code: "chironql.ml_worker_timeout",
            message: "deadline".into(),
            transient: true,
        },
        8_000,
    );
    assert_eq!(record.observed_freshness_lag_ms(9_000), Some(8_000));
    record.dirty(rev(3), 10_000);
    record.published = Some(rev(2));
    record.track_freshness(11_000);
    assert_eq!(record.observed_freshness_lag_ms(12_000), Some(11_000));

    let directory = tempfile::tempdir().unwrap();
    {
        let db = Db::open(directory.path()).unwrap();
        let mut inner = Inner::default();
        ensure_catalog(&db, &mut inner, 12_000, &audit("lag-test", None, None)).unwrap();
        record.catalog_lineage = inner.lineage;
        execute_sql(
            &db,
            vec![insert_statement(&record).unwrap()],
            &record.audit(None),
        )
        .unwrap();
    }
    let reopened = Db::open(directory.path()).unwrap();
    let mut inner = Inner::default();
    ensure_catalog(
        &reopened,
        &mut inner,
        20_000,
        &audit("lag-test", None, None),
    )
    .unwrap();
    let recovered = inner.records.get_mut("forecast").unwrap();
    assert_eq!(recovered.stale_since, Some(1_000));
    assert_eq!(recovered.observed_freshness_lag_ms(20_000), Some(19_000));
    recovered.clamp_recovered_clock(500);
    assert_eq!(recovered.stale_since, Some(500));
    assert_eq!(recovered.observed_freshness_lag_ms(500), Some(0));
    let mut legacy = serde_json::to_value(&*recovered).unwrap();
    legacy.as_object_mut().unwrap().remove("stale_since");
    let mut legacy: Schedule = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.observed_freshness_lag_ms(900), None);
    legacy.clamp_recovered_clock(900);
    assert_eq!(legacy.stale_since, Some(900));
    recovered.published = recovered.desired;
    recovered.track_freshness(25_000);
    assert_eq!(recovered.stale_since, None);
    let recorder = ObservationRecorder::default();
    metrics::with_local_recorder(&recorder, || record_freshness_lag(&inner, 30_000));
    assert_eq!(*recorder.lag.0.lock().unwrap(), vec![0.0]);
    for code in [
        "chironql.ml_invalid_source",
        "chironql.ml_invalid_schema",
        "chironql.ml_storage_failed",
    ] {
        inner.records.get_mut("forecast").unwrap().error_code = Some(code.into());
        metrics::with_local_recorder(&recorder, || record_freshness_lag(&inner, 31_000));
    }
    assert_eq!(*recorder.lag.0.lock().unwrap(), vec![0.0]);
}
