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

fn seed(engine: &RelationalEngine) {
    seed_count(engine, 64, 2048);
}

fn seed_count(engine: &RelationalEngine, count: usize, body_bytes: usize) {
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT, body TEXT)",
        ))
        .unwrap();
    let values = (1..=count)
        .map(|id| format!("({id}, 'code-{id}', '{}')", "x".repeat(body_bytes)))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO items VALUES {values}")))
        .unwrap();
    engine.checkpoint().unwrap();
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

#[test]
fn large_live_ddl_rebuild_succeeds_without_retained_scalar_maps() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    drop(engine);
    memory::with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
            .unwrap();
        assert_eq!(
            ids(&engine, "SELECT id FROM items WHERE code = 'code-64'"),
            [64]
        );
        engine
            .execute(request("ALTER TABLE items RENAME COLUMN code TO label"))
            .unwrap();
        engine
            .execute(request("ALTER TABLE items RENAME TO renamed"))
            .unwrap();
        assert_eq!(
            ids(&engine, "SELECT id FROM renamed WHERE label = 'code-64'"),
            [64]
        );
        assert_eq!(pool.used(), 0);
        engine.checkpoint().unwrap();
        drop(engine);
        assert_eq!(
            ids(&open(directory.path()), "SELECT COUNT(*) FROM renamed"),
            [64]
        );
    });
}

#[test]
fn committed_create_index_replays_below_the_old_rebuild_memory_requirement() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
        .unwrap();
    drop(engine);
    memory::with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(
            ids(&engine, "SELECT id FROM items WHERE code = 'code-32'"),
            [32]
        );
        assert_eq!(pool.used(), 0);
        engine.checkpoint().unwrap();
        drop(engine);
        assert_eq!(
            ids(&open(directory.path()), "SELECT COUNT(*) FROM items"),
            [64]
        );
    });
}

#[test]
fn multi_batch_ddl_rebuild_preserves_fk_binding_across_renames() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed_count(&engine, 1280, 8);
    drop(engine);
    memory::with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
            .unwrap();
        assert_eq!(
            engine.state.read().tables["items"].index_segments[0]
                .reader
                .metadata()
                .record_count,
            2560
        );
        assert_eq!(pool.used(), 0);
        engine
            .execute(request(
                "CREATE TABLE refs (id INTEGER PRIMARY KEY, item_code TEXT REFERENCES items(code))",
            ))
            .unwrap();
        engine
            .execute(request("INSERT INTO refs VALUES (1, 'code-1280')"))
            .unwrap();
        engine.checkpoint().unwrap();
        engine
            .execute(request("ALTER TABLE items RENAME COLUMN code TO label"))
            .unwrap();
        engine
            .execute(request("ALTER TABLE items RENAME TO inventory"))
            .unwrap();
        assert_eq!(
            ids(
                &engine,
                "SELECT id FROM inventory WHERE label = 'code-1280'"
            ),
            [1280]
        );
        assert!(
            engine
                .execute(request(
                    "UPDATE inventory SET label = 'forbidden' WHERE id = 1280"
                ))
                .err()
                .expect("foreign key must reject a key update")
                .to_string()
                .contains("foreign key")
        );
        assert_eq!(ids(&engine, "SELECT COUNT(*) FROM refs"), [1]);
        assert_eq!(pool.used(), 0);
        engine.checkpoint().unwrap();
        assert!(scratch_paths(directory.path()).is_empty());
        drop(engine);
        let engine = open(directory.path());
        assert_eq!(
            ids(
                &engine,
                "SELECT id FROM inventory WHERE label = 'code-1280'"
            ),
            [1280]
        );
        assert!(
            engine
                .execute(request("INSERT INTO refs VALUES (2, 'missing')"))
                .err()
                .expect("foreign key must reject a missing parent")
                .to_string()
                .contains("foreign key")
        );
    });
}

fn scratch_paths(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root.join(RELATIONAL_SEGMENT_DIR))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".chiron-relational-sort-")
        })
        .collect()
}

#[test]
#[cfg(feature = "fault-injection")]
fn failed_unique_and_failed_install_leave_catalog_journal_and_scratch_unchanged() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("UPDATE items SET code = 'code-1' WHERE id = 2"))
        .unwrap();
    engine.checkpoint().unwrap();
    let commits = engine.journal.committed().unwrap().len();
    let sequence = engine.state.read().sequence;
    let error = engine
        .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
        .err()
        .expect("duplicate values must refuse a unique index");
    assert!(error.to_string().contains("unique constraint"), "{error}");
    assert!(
        engine.state.read().tables["items"]
            .definition
            .indexes
            .is_empty()
    );
    assert_eq!(engine.state.read().sequence, sequence);
    assert_eq!(engine.journal.committed().unwrap().len(), commits);
    assert!(scratch_paths(directory.path()).is_empty());
    {
        let _fault = crate::failpoint::test_env(
            "error:relational_index_rebuild.before_install",
            &directory.path().join("marker"),
            &directory.path().join("release"),
        );
        assert!(
            engine
                .execute(request("CREATE INDEX code_index ON items (code)"))
                .is_err()
        );
    }
    assert!(
        engine.state.read().tables["items"]
            .definition
            .indexes
            .is_empty()
    );
    assert_eq!(engine.journal.committed().unwrap().len(), commits);
    assert!(scratch_paths(directory.path()).is_empty());
    engine
        .execute(request("CREATE INDEX code_index ON items (code)"))
        .unwrap();
    assert_eq!(
        ids(
            &engine,
            "SELECT id FROM items WHERE code = 'code-1' ORDER BY id"
        ),
        [1, 2]
    );
}

#[test]
fn old_reader_pins_private_index_until_rollback_after_a_new_checkpoint() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("CREATE INDEX code_index ON items (code)"))
        .unwrap();
    let old_path = engine.state.read().tables["items"].index_segments[0]
        .path
        .clone();
    let owner = AuditContext::embedded();
    let handle = engine.begin_interactive(&owner).unwrap().handle;
    engine.execute(request("DROP INDEX code_index")).unwrap();
    engine.checkpoint().unwrap();
    assert!(old_path.exists());
    let response = engine
        .execute_interactive(
            &handle,
            request("SELECT id FROM items WHERE code = 'code-32'"),
            &owner,
        )
        .unwrap();
    assert!(
        matches!(&response.results[0], SqlResult::Rows{rows,..} if rows == &vec![vec![RelationalValue::Integer(32)]])
    );
    engine.rollback_interactive(&handle, &owner).unwrap();
    assert!(!old_path.exists());
    assert!(scratch_paths(directory.path()).is_empty());
}

#[test]
fn index_cursor_itself_pins_the_temporary_directory_after_the_table_drops() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("CREATE INDEX code_index ON items (code)"))
        .unwrap();
    let (path, mut cursor) = {
        let state = engine.state.read();
        let table = &state.tables["items"];
        let key = table.indexes[&vec!["code".to_owned()]]
            .key(&[&RelationalValue::Text("code-64".into())])
            .unwrap()
            .unwrap();
        let backing = &table.index_segments[0];
        (
            backing.path.clone(),
            backing.reader.prefix_cursor(&key).unwrap(),
        )
    };
    drop(engine);
    assert!(path.exists());
    let row: PersistedIndexVersion =
        serde_json::from_slice(&cursor.next().unwrap().unwrap().value).unwrap();
    assert_eq!(row.row_id, 64);
    assert!(cursor.next().is_none());
    drop(cursor);
    assert!(!path.exists());
    assert!(scratch_paths(directory.path()).is_empty());
}

#[test]
fn ddl_between_mutations_keeps_current_memberships_and_replays_exactly() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let mut batch = request("INSERT INTO items VALUES (65, 'code-65', 'new')");
    for sql in [
        "CREATE UNIQUE INDEX code_index ON items (code)",
        "UPDATE items SET code = 'changed' WHERE id = 64",
        "DELETE FROM items WHERE id = 1",
    ] {
        batch.statements.push(crate::SqlStatementRequest {
            sql: sql.into(),
            parameters: vec![],
        });
    }
    engine.execute(batch).unwrap();
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'changed'"),
        [64]
    );
    assert!(ids(&engine, "SELECT id FROM items WHERE code = 'code-1'").is_empty());
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'code-65'"),
        [65]
    );
    drop(engine);
    memory::with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(
            ids(&engine, "SELECT id FROM items WHERE code = 'changed'"),
            [64]
        );
        assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [64]);
        assert!(
            engine
                .execute(request(
                    "INSERT INTO items VALUES (66, 'changed', 'duplicate')"
                ))
                .is_err()
        );
        engine.checkpoint().unwrap();
        assert_eq!(pool.used(), 0);
        assert!(scratch_paths(directory.path()).is_empty());
        drop(engine);
        assert_eq!(
            ids(&open(directory.path()), "SELECT COUNT(*) FROM items"),
            [64]
        );
    });
}

#[test]
fn legacy_inline_checkpoint_builds_disk_indexes_and_reuses_them_safely() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    let mut legacy = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    legacy.version = RELATIONAL_CHECKPOINT_LEGACY_VERSION;
    legacy.tables[0].rows = engine.state.read().tables["items"]
        .rows
        .iter()
        .map(|row| {
            let (id, versions) = row.unwrap();
            let mut versions = versions.to_vec();
            for version in &mut versions {
                let mut values = version.values.to_vec();
                values[2] = RelationalValue::Text("legacy".into());
                version.values = RowValues::adopt(values).unwrap();
            }
            (id, versions)
        })
        .collect();
    legacy.tables[0].row_segments.clear();
    legacy.tables[0].index_segments.clear();
    write_relational_checkpoint(&engine.checkpoint_path, &legacy).unwrap();
    drop(engine);
    memory::with_pool(256 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 64"), [64]);
        assert!(
            engine.state.read().tables["items"]
                .indexes
                .values()
                .all(|index| index.retained_bytes() == 0)
        );
        assert!(pool.used() < 128 * 1024); // Only legacy inline rows are retained.
        engine.checkpoint().unwrap();
        assert_eq!(ids(&engine, "SELECT id FROM items WHERE id = 64"), [64]);
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert!(scratch_paths(directory.path()).is_empty());
    });
}

#[test]
fn protected_rebuilt_indexes_are_encrypted_and_recover() {
    const CHILD: &str = "CHIRONDB_DDL_INDEX_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relational::indexes::rebuild_tests::protected_rebuilt_indexes_are_encrypted_and_recover", "--nocapture"])
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
    serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([13u8;32])}]})).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine);
    engine
        .execute(request("CREATE INDEX body_index ON items (body)"))
        .unwrap();
    let path = engine.state.read().tables["items"].index_segments[0]
        .path
        .clone();
    let bytes = fs::read(path).unwrap();
    assert!(bytes.starts_with(b"CHIRENC1"));
    assert!(!bytes.windows(64).any(|part| part == [b'x'; 64]));
    drop(engine);
    memory::with_pool(128 * 1024, |_| {
        let engine = open(directory.path());
        assert_eq!(
            ids(
                &engine,
                &format!(
                    "SELECT COUNT(*) FROM items WHERE body = '{}'",
                    "x".repeat(2048)
                )
            ),
            [64]
        );
        engine.checkpoint().unwrap();
        assert!(scratch_paths(directory.path()).is_empty());
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn killed_private_rebuild_preserves_uncommitted_and_committed_ddl_outcomes() {
    const CHILD: &str = "CHIRONDB_DDL_INDEX_KILL_CHILD";
    const REPLAY: &str = "CHIRONDB_DDL_INDEX_KILL_REPLAY";
    if let Some(path) = std::env::var_os(CHILD) {
        let engine = open(Path::new(&path));
        if std::env::var_os(REPLAY).is_none() {
            engine
                .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
                .unwrap();
        }
        panic!("parent should terminate the paused index build");
    }
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for committed in [false, true] {
        let directory = tempdir().unwrap();
        let engine = open(directory.path());
        seed(&engine);
        if committed {
            engine
                .execute(request("CREATE UNIQUE INDEX code_index ON items (code)"))
                .unwrap();
        }
        let commits = engine.journal.committed().unwrap().len();
        let checkpoint_path = engine.checkpoint_path.clone();
        let before = fs::read(&checkpoint_path).unwrap();
        drop(engine);
        let marker = directory.path().join("paused");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "relational::indexes::rebuild_tests::killed_private_rebuild_preserves_uncommitted_and_committed_ddl_outcomes", "--nocapture"])
            .env(CHILD, directory.path())
            .env("CHIRONDB_FAILPOINT", "pause:relational_index_rebuild.before_install")
            .env("CHIRONDB_FAILPOINT_MARKER", &marker)
            .env_remove("CHIRONDB_FAILPOINT_RELEASE")
            .stdout(std::process::Stdio::null());
        if committed {
            command.env(REPLAY, "1");
        } else {
            command.env_remove(REPLAY);
        }
        let mut child = KillOnDrop(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() && Instant::now() < deadline {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before pause"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists());
        assert!(!scratch_paths(directory.path()).is_empty());
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
        assert_eq!(engine.journal.committed().unwrap().len(), commits);
        assert_eq!(
            !engine.state.read().tables["items"]
                .definition
                .indexes
                .is_empty(),
            committed
        );
        assert_eq!(ids(&engine, "SELECT COUNT(*) FROM items"), [64]);
        engine.checkpoint().unwrap();
        assert!(scratch_paths(directory.path()).is_empty());
        drop(engine);
        assert_eq!(
            ids(
                &open(directory.path()),
                "SELECT id FROM items WHERE code = 'code-64'"
            ),
            [64]
        );
    }
}
