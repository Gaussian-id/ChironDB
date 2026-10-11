use super::*;
use tempfile::tempdir;

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

fn ids(engine: &RelationalEngine, sql: &str) -> Vec<i64> {
    let result = engine.execute(request(sql)).unwrap().response;
    let SqlResult::Rows { rows, .. } = &result.results[0] else {
        unreachable!()
    };
    rows.iter()
        .map(|row| match row[0] {
            RelationalValue::Integer(id) => id,
            _ => unreachable!(),
        })
        .collect()
}

fn record(id: u32, bytes: usize) -> SegmentRecord {
    SegmentRecord {
        key: (id.to_be_bytes().to_vec()).into(),
        value: (vec![b'x'; bytes]).into(),
    }
}

fn assert_empty(path: &Path) {
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn bounded_batches_and_binary_merges_match_an_independent_sort() {
    let directory = tempdir().unwrap();
    let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 7).unwrap();
    sorter.byte_limit = 64 * 1024;
    let mut expected = Vec::new();
    // Coprime permutation crosses all sort batches; no input order assumption.
    for n in 0..4099 {
        let row = record((n * 71) % 4099, 32);
        expected.push(row.clone());
        sorter.push(row).unwrap();
        assert!(sorter.levels.iter().flatten().count() <= 13);
    }
    assert!(sorter.peak_rows <= BATCH_ROWS);
    assert!(sorter.peak_bytes <= sorter.byte_limit);
    assert!(sorter.serial > 2);
    expected.sort_by(|a, b| a.key.cmp(&b.key));
    let sorted = sorter.finish().unwrap();
    assert_eq!(
        sorted
            .cursor()
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap(),
        expected
    );
    assert_eq!(fs::read_dir(sorted._directory.path()).unwrap().count(), 1);
    drop(sorted);
    assert_empty(directory.path());
}

#[test]
fn row_limit_and_oversized_single_record_are_handled_without_full_batches() {
    let directory = tempdir().unwrap();
    let mut sorter = Sorter::new(directory.path(), SegmentKind::Index, 1).unwrap();
    sorter.byte_limit = usize::MAX;
    for id in (0..2050).rev() {
        sorter.push(record(id, 1)).unwrap();
    }
    assert_eq!(sorter.peak_rows, 1024);
    drop(sorter.finish().unwrap());
    assert_empty(directory.path());
    let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1).unwrap();
    sorter.byte_limit = 1024;
    sorter.push(record(1, 800)).unwrap();
    sorter.push(record(2, 4096)).unwrap();
    assert_eq!(sorter.peak_rows, 1);
    assert!(sorter.buffer.is_empty());
    let sorted = sorter.finish().unwrap();
    assert_eq!(sorted.cursor().unwrap().count(), 2);
    drop(sorted);
    assert_empty(directory.path());
}

#[test]
fn duplicates_in_one_batch_or_across_runs_fail_without_scratch_leaks() {
    for byte_limit in [64, 64 * 1024] {
        let directory = tempdir().unwrap();
        let result = (|| -> Result<SortedRun> {
            let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1)?;
            sorter.byte_limit = byte_limit;
            sorter.push(record(7, 256))?;
            sorter.push(record(7, 256))?;
            sorter.finish()
        })();
        assert!(result.is_err());
        assert_empty(directory.path());
    }
}

#[test]
fn cancellation_and_failed_write_remove_private_runs() {
    let directory = tempdir().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let result = with_sql_cancellation(Arc::clone(&cancelled), || {
        let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1)?;
        sorter.byte_limit = 128;
        sorter.push(record(1, 256))?;
        assert_eq!(fs::read_dir(sorter.directory.path())?.count(), 1);
        cancelled.store(true, AtomicOrdering::Release);
        sorter.push(record(2, 256))
    });
    assert!(result.unwrap_err().to_string().contains("canceled"));
    assert_empty(directory.path());
    let result = (|| -> Result<SortedRun> {
        let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1)?;
        sorter.push(record(1, 1))?;
        // Deterministic destination failure, not claimed as physical ENOSPC.
        fs::create_dir(sorter.directory.path().join("1.rseg"))?;
        sorter.finish()
    })();
    assert!(result.is_err());
    assert_empty(directory.path());
}

#[test]
fn corrupt_sort_input_is_reported_instead_of_publishing_a_partial_merge() {
    let directory = tempdir().unwrap();
    let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1).unwrap();
    sorter.byte_limit = 64;
    sorter.push(record(1, 256)).unwrap();
    let path = &sorter.levels[0].as_ref().unwrap().path;
    let mut bytes = fs::read(path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(sorter.push(record(2, 256)).is_err());
    drop(sorter);
    assert_empty(directory.path());
}

#[test]
fn full_and_delta_projections_match_the_prior_encoders_byte_for_byte() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE, n INTEGER, body TEXT)",
        ))
        .unwrap();
    let values = (0..257)
        .map(|i| {
            let id = (i * 73) % 257;
            let code = if id % 3 == 0 {
                "NULL".to_owned()
            } else {
                format!("'code-{id}'")
            };
            format!("({id}, {code}, {}, 'escaped '' row {id}')", id % 11)
        })
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO items VALUES {values}")))
        .unwrap();
    engine
        .execute(request("CREATE INDEX n_code ON items (n, code)"))
        .unwrap();
    let compare = |delta| {
        let state = engine.state.read();
        let table = &state.tables["items"];
        let expected = if delta {
            delta_records(table).unwrap()
        } else {
            (
                row_segment_records(table).unwrap(),
                index_segment_records(table).unwrap(),
            )
        };
        for (kind, expected) in [
            (SegmentKind::Row, expected.0),
            (SegmentKind::Index, expected.1),
        ] {
            let sorted = project(
                table,
                &directory.path().join(RELATIONAL_SEGMENT_DIR),
                kind,
                state.sequence,
                delta,
            )
            .unwrap();
            assert_eq!(
                sorted
                    .cursor()
                    .unwrap()
                    .collect::<Result<Vec<_>>>()
                    .unwrap(),
                expected
            );
            // Existing frozen version-2 writer must produce identical bytes.
            let old = directory.path().join("old.rseg");
            let new = directory.path().join("new.rseg");
            write_segment(&old, kind, state.sequence, &expected).unwrap();
            segment::write_segment_stream(&new, kind, state.sequence, || sorted.cursor()).unwrap();
            assert_eq!(fs::read(old).unwrap(), fs::read(new).unwrap());
        }
    };
    compare(false);
    engine.checkpoint().unwrap();
    engine
        .execute(request(
            "UPDATE items SET id = 1000, code = 'new' WHERE id = 1",
        ))
        .unwrap();
    engine
        .execute(request("DELETE FROM items WHERE id = 2"))
        .unwrap();
    engine.collect_mvcc_garbage().unwrap();
    compare(true);
    compare(false);
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'new'"),
        [1000]
    );
}

#[test]
fn startup_removes_interrupted_scratch_and_preserves_other_namespaces() {
    let directory = tempdir().unwrap();
    let segments = directory.path().join(RELATIONAL_SEGMENT_DIR);
    fs::create_dir_all(&segments).unwrap();
    let stale = segments.join(format!("{SCRATCH_PREFIX}orphan"));
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("partial.rseg"), b"abandoned").unwrap();
    let unrelated = segments.join("other-directory");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("keep"), b"keep").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&unrelated, segments.join(format!("{SCRATCH_PREFIX}link"))).unwrap();
    let engine = open(directory.path());
    assert!(!stale.exists());
    assert_eq!(fs::read(unrelated.join("keep")).unwrap(), b"keep");
    drop(engine);
}

#[test]
fn encrypted_scratch_and_final_projection_never_write_plaintext_payloads() {
    const CHILD: &str = "CHIRONDB_PROJECTION_SORT_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relational::checkpoint::sort::tests::encrypted_scratch_and_final_projection_never_write_plaintext_payloads", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use base64::Engine as _;
    let mut key = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([12u8;32])}]})).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let mut sorter = Sorter::new(directory.path(), SegmentKind::Row, 1).unwrap();
    sorter.byte_limit = 8 * 1024;
    for id in (1..=33).rev() {
        sorter.push(record(id, 2048)).unwrap();
        for entry in fs::read_dir(sorter.directory.path()).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(bytes.starts_with(b"CHIRENC1"));
            assert!(!bytes.windows(64).any(|part| part == [b'x'; 64]));
        }
    }
    let sorted = sorter.finish().unwrap();
    assert_eq!(
        sorted
            .cursor()
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap(),
        (1..=33).map(|id| record(id, 2048)).collect::<Vec<_>>()
    );
    let final_path = directory.path().join("final.rseg");
    segment::write_segment_stream(&final_path, SegmentKind::Row, 1, || sorted.cursor()).unwrap();
    let bytes = fs::read(final_path).unwrap();
    assert!(bytes.starts_with(b"CHIRENC1"));
    assert!(!bytes.windows(64).any(|part| part == [b'x'; 64]));
    drop(sorted);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
#[cfg(feature = "fault-injection")]
fn killed_sort_preserves_the_checkpoint_and_replays_acknowledged_writes() {
    const CHILD: &str = "CHIRONDB_PROJECTION_SORT_KILL_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = Path::new(&path);
        let engine = open(path);
        // Startup also sorts derived row locators. Arm the checkpoint fault
        // only after recovery so this test still interrupts its intended phase.
        let boundary = std::env::var("CHIRONDB_PROJECTION_SORT_KILL_BOUNDARY").unwrap();
        let _fault = crate::failpoint::test_env(
            &format!("pause:relational_sort.{boundary}"),
            &path.join("paused"),
            &path.join("release"),
        );
        engine.checkpoint().unwrap();
        panic!("parent should terminate the paused sorter");
    }
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for boundary in ["after_batch", "after_merge"] {
        let directory = tempdir().unwrap();
        let engine = open(directory.path());
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO items VALUES (0, 'base')"))
            .unwrap();
        engine.checkpoint().unwrap();
        let values = (1..=2200)
            .map(|id| format!("({id}, '{}')", "x".repeat(128)))
            .collect::<Vec<_>>()
            .join(",");
        engine
            .execute(request(&format!("INSERT INTO items VALUES {values}")))
            .unwrap();
        let checkpoint_path = engine.checkpoint_path.clone();
        let before = fs::read(&checkpoint_path).unwrap();
        drop(engine);
        let marker = directory.path().join("paused");
        let mut child = KillOnDrop(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relational::checkpoint::sort::tests::killed_sort_preserves_the_checkpoint_and_replays_acknowledged_writes", "--nocapture"])
            .env(CHILD, directory.path())
            .env("CHIRONDB_PROJECTION_SORT_KILL_BOUNDARY", boundary)
            .env_remove("CHIRONDB_FAILPOINT")
            .env_remove("CHIRONDB_FAILPOINT_RELEASE")
            .stdout(std::process::Stdio::null())
            .spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() && Instant::now() < deadline {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "sort child exited before {boundary}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "sort child did not reach {boundary}");
        let segments = directory.path().join(RELATIONAL_SEGMENT_DIR);
        assert!(fs::read_dir(&segments).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(SCRATCH_PREFIX)
        }));
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        assert_eq!(fs::read(checkpoint_path).unwrap(), before);
        let engine = open(directory.path());
        assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [2201]);
        engine.checkpoint().unwrap();
        assert!(fs::read_dir(&segments).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(SCRATCH_PREFIX)
        }));
        drop(engine);
        assert_eq!(
            ids(&open(directory.path()), "SELECT COUNT(*) FROM items"),
            [2201]
        );
    }
}
