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
fn seed(engine: &RelationalEngine, count: usize) {
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    let values = (1..=count)
        .rev()
        .map(|id| format!("({id}, 'value-{id}')"))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO items VALUES {values}")))
        .unwrap();
    engine.checkpoint().unwrap();
}
fn ids(engine: &RelationalEngine, sql: &str) -> Vec<i64> {
    let response = engine.execute(request(sql)).unwrap().response;
    let SqlResult::Rows { rows, .. } = &response.results[0] else {
        unreachable!()
    };
    rows.iter()
        .map(|row| match row[0] {
            RelationalValue::Integer(id) => id,
            _ => unreachable!(),
        })
        .collect()
}
fn directories(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root.join(RELATIONAL_SEGMENT_DIR))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".chiron-relational-locator-")
        })
        .collect()
}

#[test]
fn ordered_primary_rows_stream_one_locator_without_external_merge() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    let values = (1..=128)
        .map(|id| format!("({id}, 'value-{id}')"))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO items VALUES {values}")))
        .unwrap();
    engine.checkpoint().unwrap();
    let snapshot = engine.state.read().clone();
    let locator = &snapshot.tables["items"].rows.base.as_ref().unwrap().locator;
    assert!(
        locator
            .scratch_directory()
            .unwrap()
            .join("ordered.rseg")
            .exists()
    );
    assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [128]);
    drop(snapshot);
    drop(engine);
    let reopened = open(directory.path());
    assert_eq!(ids(&reopened, "SELECT COUNT(*) FROM items"), [128]);
}

#[test]
fn locator_runs_replace_per_version_ram_entries_and_scan_in_hidden_id_order() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 2049);
    let snapshot = engine.state.read().clone();
    let rows = &snapshot.tables["items"].rows;
    let base = rows.base.as_ref().unwrap();
    assert_eq!(base.version_count(), 2049);
    assert_eq!(base.sources.len(), 1);
    assert!(rows.delta.is_empty());
    assert_eq!(rows.retained_bytes(), 0);
    assert!(base.locator.scratch_directory().unwrap().is_dir());
    assert!(
        !base
            .locator
            .scratch_directory()
            .unwrap()
            .join("ordered.rseg")
            .exists()
    );
    assert_eq!(
        rows.visible(1, snapshot.sequence).unwrap().unwrap().values[0],
        RelationalValue::Integer(2049)
    );
    let scanned = rows
        .visible_rows(snapshot.sequence)
        .map(|row| {
            let (internal, values) = row.unwrap();
            (internal, values[0].clone())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scanned,
        (1..=2049)
            .map(|internal| (internal, RelationalValue::Integer(2050 - internal as i64)))
            .collect::<Vec<_>>()
    );
    engine
        .execute(request(
            "UPDATE items SET id = 4096, body = 'new' WHERE id = 2049",
        ))
        .unwrap();
    engine
        .execute(request("DELETE FROM items WHERE id = 2048"))
        .unwrap();
    assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 4096"), [4096]);
    assert_eq!(
        rows.visible(1, snapshot.sequence).unwrap().unwrap().values[0],
        RelationalValue::Integer(2049)
    );
    engine.checkpoint().unwrap();
    drop(snapshot);
    drop(engine);
    assert!(directories(directory.path()).is_empty());
    let engine = open(directory.path());
    assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [2048]);
    assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 4096"), [4096]);
}

#[test]
fn locator_validation_rejects_overlaps_and_duplicate_logical_versions() {
    for same_begin in [false, true] {
        let directory = tempdir().unwrap();
        let engine = open(directory.path());
        seed(&engine, 1);
        let mut table = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap()
            .tables
            .remove(0);
        drop(engine);
        let versions = [
            RowVersion {
                begin: 1,
                end: Some(3),
                values: RowValues::adopt(vec![
                    RelationalValue::Integer(1),
                    RelationalValue::Text("a".into()),
                ])
                .unwrap(),
            },
            RowVersion {
                begin: if same_begin { 1 } else { 2 },
                end: None,
                values: RowValues::adopt(vec![
                    RelationalValue::Integer(2),
                    RelationalValue::Text("b".into()),
                ])
                .unwrap(),
            },
        ];
        let mut records = versions
            .into_iter()
            .map(|version| SegmentRecord {
                key: (row_segment_key(&table.definition, 1, &version).unwrap()).into(),
                value: (serde_json::to_vec(&PersistedRowVersion { row_id: 1, version }).unwrap())
                    .into(),
            })
            .collect::<Vec<_>>();
        records.sort_by(|a, b| a.key.cmp(&b.key));
        let segments = directory.path().join(RELATIONAL_SEGMENT_DIR);
        let metadata = write_segment(
            &segments.join("invalid.rseg"),
            SegmentKind::Row,
            3,
            &records,
        )
        .unwrap();
        table.row_segments = vec![segment_reference("invalid.rseg".into(), &metadata)];
        let error = build(&table, 3, &segments).unwrap_err();
        assert!(
            error.to_string().contains(if same_begin {
                "unique ascending"
            } else {
                "overlapping"
            }),
            "{error}"
        );
        assert!(directories(directory.path()).is_empty());
    }
}

#[test]
fn disk_version_chains_retain_metadata_quota_after_readers_drop() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 1);
    let mut table = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap()
        .tables
        .remove(0);
    drop(engine);
    let mut records = (2..=33)
        .map(|begin| {
            let version = RowVersion {
                begin,
                end: (begin < 33).then_some(begin + 1),
                values: RowValues::copy(&[
                    RelationalValue::Integer(1),
                    RelationalValue::Text("payload".into()),
                ])
                .unwrap(),
            };
            SegmentRecord {
                key: row_segment_key(&table.definition, 1, &version)
                    .unwrap()
                    .into(),
                value: serde_json::to_vec(&PersistedRowVersion { row_id: 1, version })
                    .unwrap()
                    .into(),
            }
        })
        .collect::<Vec<_>>();
    records.sort_by(|a, b| a.key.cmp(&b.key));
    let segments = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let metadata = write_segment(
        &segments.join("history.rseg"),
        SegmentKind::Row,
        33,
        &records,
    )
    .unwrap();
    table.row_segments = vec![segment_reference("history.rseg".into(), &metadata)];
    let disk = build(&table, 33, &segments).unwrap();
    memory::with_storage_pool(1024 * 1024, |pool| {
        let one = disk.visible(1, 0, 33).unwrap().unwrap();
        let payload = pool.used();
        assert!(payload > 0);
        drop(one);
        assert_eq!(pool.used(), 0);
        let chain = disk.get(1, 0).unwrap();
        assert_eq!(chain.len(), 32);
        assert!(
            pool.used() > 32 * payload,
            "chain metadata must have its own reservation"
        );
        let held = pool.used();
        let shadows = imbl::OrdMap::new();
        let mut scan = disk.scan(0, Some(33), &shadows);
        let (_, visible) = scan.next().unwrap().unwrap();
        drop(scan);
        assert_eq!(visible.len(), 1);
        assert!(
            pool.used() > held + payload,
            "scan ownership includes metadata after its cursor drops"
        );
        drop(visible);
        assert_eq!(pool.used(), held);
        drop(disk);
        assert_eq!(pool.used(), held, "owned chain outlives the disk reader");
        drop(chain);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn corrupt_derived_locator_fails_reads_and_is_rebuilt_from_authoritative_rows() {
    use std::io::{Seek, SeekFrom, Write};
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 257);
    let before = fs::read(&engine.checkpoint_path).unwrap();
    let path = {
        let state = engine.state.read();
        let base = state.tables["items"].rows.base.as_ref().unwrap();
        let mut wrong = base.entries().next().unwrap().unwrap();
        wrong.row_id += 1;
        assert!(matches!(
            base.load(&wrong),
            Err(GaussError::SegmentCorruption { .. })
        ));
        wrong.source = base.sources.len();
        assert!(matches!(
            base.decode(SegmentRecord {
                key: key(wrong.row_id, wrong.begin).to_vec().into(),
                value: (serde_json::to_vec(&wrong).unwrap()).into(),
            }),
            Err(GaussError::SegmentCorruption { .. })
        ));
        let mut outside = base.entries().next().unwrap().unwrap();
        outside.offset = usize::MAX;
        assert!(matches!(
            base.load(&outside),
            Err(GaussError::SegmentCorruption { .. })
        ));
        fs::read_dir(base.locator.scratch_directory().unwrap())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
    };
    let length = fs::metadata(&path).unwrap().len();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(length > 100);
    assert!(
        engine
            .execute(request("SELECT id FROM items WHERE id = 1"))
            .is_err()
    );
    assert!(
        engine
            .execute(request("SELECT COUNT(*) FROM items"))
            .is_err()
    );
    assert!(
        engine.state.read().tables["items"]
            .rows
            .contains_key(&257)
            .is_err()
    );
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), before);
    assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [257]);
    assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 1"), [1]);
}

#[test]
fn locator_cursor_keeps_its_directory_alive_until_the_last_mapping_drops() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 8);
    let (path, mut cursor) = {
        let state = engine.state.read();
        let base = state.tables["items"].rows.base.as_ref().unwrap();
        (
            base.locator.scratch_directory().unwrap().to_path_buf(),
            base.locator.cursor(),
        )
    };
    drop(engine);
    assert!(path.exists());
    assert!(cursor.next().unwrap().is_ok());
    assert_eq!(cursor.collect::<Result<Vec<_>>>().unwrap().len(), 7);
    assert!(!path.exists());
}

#[test]
#[cfg(feature = "fault-injection")]
fn post_decision_gc_failure_does_not_change_durable_sql_or_terminal_outcomes() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 1);
    let owner = AuditContext::embedded();
    let handle = engine.begin_interactive(&owner).unwrap().handle;
    engine
        .execute_interactive(
            &handle,
            request("INSERT INTO items VALUES (3, 'interactive')"),
            &owner,
        )
        .unwrap();
    let rollback = engine.begin_interactive(&owner).unwrap().handle;
    let mut once = request("INSERT INTO items VALUES (2, 'standalone')");
    once.idempotency_key = Some("locator-gc-receipt".into());
    {
        let _fault = crate::failpoint::test_env(
            "error:relational_gc.after_decision",
            &directory.path().join("marker"),
            &directory.path().join("release"),
        );
        let result = engine.execute(once.clone()).unwrap();
        assert!(result.response.committed);
        assert!(
            engine
                .commit_interactive(&handle, &owner)
                .unwrap()
                .response
                .committed
        );
        assert_eq!(
            engine
                .rollback_interactive(&rollback, &owner)
                .unwrap()
                .state,
            SqlTransactionState::RolledBack
        );
        assert_eq!(
            engine.execute(once).unwrap().response.transaction_id,
            result.response.transaction_id
        );
    }
    assert_eq!(ids(&engine, "SELECT id FROM items ORDER BY id"), [1, 2, 3]);
    drop(engine);
    assert_eq!(
        ids(&open(directory.path()), "SELECT id FROM items ORDER BY id"),
        [1, 2, 3]
    );
}

#[test]
fn derived_locator_uses_encrypted_storage_and_survives_reopen() {
    const CHILD: &str = "CHIRONDB_LOCATOR_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "relational::rows::locator::tests::derived_locator_uses_encrypted_storage_and_survives_reopen",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
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
    serde_json::to_writer(
        &mut key,
        &serde_json::json!({
            "version": 1,
            "active_key_id": "test",
            "keys": [{
                "id": "test",
                "key_base64": base64::engine::general_purpose::STANDARD.encode([14u8;32]),
            }],
        }),
    )
    .unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 1025);
    for path in directories(directory.path()) {
        for entry in fs::read_dir(path).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(bytes.starts_with(b"CHIRENC1"));
            assert!(!bytes.windows(8).any(|part| part == b"\"row_id\""));
        }
    }
    assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 1025"), [1025]);
    drop(engine);
    assert_eq!(
        ids(&open(directory.path()), "SELECT COUNT(*) FROM items"),
        [1025]
    );
}

#[test]
#[cfg(feature = "fault-injection")]
fn killed_locator_build_leaves_checkpoint_authority_and_rebuilds_on_restart() {
    const CHILD: &str = "CHIRONDB_LOCATOR_KILL_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let _engine = open(Path::new(&path));
        panic!("parent should kill the paused locator build");
    }
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 1025);
    let checkpoint = engine.checkpoint_path.clone();
    let before = fs::read(&checkpoint).unwrap();
    drop(engine);
    let marker = directory.path().join("paused");
    let mut child = KillOnDrop(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "relational::rows::locator::tests::killed_locator_build_leaves_checkpoint_authority_and_rebuilds_on_restart",
                "--nocapture",
            ])
            .env(CHILD, directory.path())
            .env("CHIRONDB_FAILPOINT", "pause:relational_locator.before_install")
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env_remove("CHIRONDB_FAILPOINT_RELEASE")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() && Instant::now() < deadline {
        assert!(child.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.exists());
    let abandoned = directories(directory.path());
    assert!(!abandoned.is_empty());
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
    }
    assert_eq!(fs::read(checkpoint).unwrap(), before);
    let engine = open(directory.path());
    assert!(abandoned.iter().all(|path| !path.exists()));
    assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [1025]);
    drop(engine);
    assert!(directories(directory.path()).is_empty());
}
