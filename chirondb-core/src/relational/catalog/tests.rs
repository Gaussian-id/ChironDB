use super::*;
use crate::relational::memory::with_storage_pool;

fn table() -> Arc<TableState> {
    let definition: TableDefinition = serde_json::from_value(serde_json::json!({
        "table_id":1,"name":"items","columns":[
            {"name":"id","data_type":{"kind":"integer"},"nullable":false}],
        "primary_key":["id"],"primary_key_index_id":2
    }))
    .unwrap();
    Arc::new(TableState::empty(definition, Arc::new(PathBuf::new())).unwrap())
}
fn request(sql: &str) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap()
}
fn open(path: &Path) -> Arc<RelationalEngine> {
    RelationalEngine::open(path, TransactionJournal::open(path).unwrap()).unwrap()
}

#[test]
fn snapshots_share_table_names_and_roots_then_charge_only_independent_tree_owners() {
    let source = table();
    let (pool, old, mut current) = with_storage_pool(128 * 1024, |pool| {
        let mut old = Catalog::empty().unwrap();
        old.insert("zeta", source.clone()).unwrap();
        old.insert("alpha", source.clone()).unwrap();
        let held = pool.used();
        let mut current = old.clone();
        assert!(old.entries.ptr_eq(&current.entries));
        assert_eq!(pool.used(), held);
        let original_name = old.entries.get_key_value("alpha").unwrap().0;
        Arc::make_mut(current.get_mut("alpha").unwrap().unwrap()).next_row_id = 42;
        assert!(!old.entries.ptr_eq(&current.entries));
        assert!(pool.used() >= held + map_bytes(2).unwrap());
        assert!(Arc::ptr_eq(
            &original_name.0,
            &current.entries.get_key_value("alpha").unwrap().0.0
        ));
        assert_eq!(old["alpha"].next_row_id, 1);
        assert_eq!(current["alpha"].next_row_id, 42);
        assert_eq!(
            current.keys().map(String::as_str).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
        (pool, old, current)
    });
    drop(old);
    current.remove("zeta").unwrap();
    assert!(
        pool.used() > 0,
        "surviving root owns shared name allocations"
    );
    drop(current);
    assert_eq!(pool.used(), 0);
}

#[test]
fn long_name_refusal_and_partial_candidate_cleanup_leave_catalog_unchanged() {
    let source = table();
    with_storage_pool(16 * 1024, |pool| {
        let mut catalog = Catalog::empty().unwrap();
        catalog.insert("items", source.clone()).unwrap();
        let snapshot = catalog.clone();
        let held = pool.used();
        assert!(matches!(
            catalog.insert(&"x".repeat(32 * 1024), source.clone()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(catalog.entries.ptr_eq(&snapshot.entries));
        assert_eq!(catalog.len(), 1);
        assert_eq!(pool.used(), held);
    });
    with_storage_pool(0, |pool| {
        assert!(matches!(
            Catalog::empty(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn refused_or_cancelled_mutation_preserves_shared_names_and_table_state() {
    let source = table();
    with_storage_pool(9 * 1024, |pool| {
        let mut catalog = Catalog::empty().unwrap();
        catalog.insert("items", source.clone()).unwrap();
        let snapshot = catalog.clone();
        let held = pool.used();
        assert!(matches!(
            catalog.get_mut("items"),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(matches!(
            catalog.remove("items"),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), held);
        assert!(catalog.entries.ptr_eq(&snapshot.entries));
        assert!(Arc::ptr_eq(&catalog["items"], &source));
        assert!(catalog.get_mut("missing").unwrap().is_none());
    });
    let mut catalog = Catalog::empty().unwrap();
    catalog.insert("items", source.clone()).unwrap();
    let snapshot = catalog.clone();
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    with_sql_cancellation(cancelled.clone(), || {
        cancelled.store(true, std::sync::atomic::Ordering::Release);
        assert!(catalog.get_mut("items").is_err());
        assert!(catalog.insert("other", source).is_err());
        assert!(catalog.remove("items").is_err());
        assert!(catalog.prepare_install().is_err());
        Ok(())
    })
    .unwrap();
    assert!(catalog.entries.ptr_eq(&snapshot.entries));
}

#[test]
fn bulk_update_failure_never_publishes_partial_table_roots() {
    let source = table();
    let mut catalog = Catalog::empty().unwrap();
    catalog.insert("alpha", source.clone()).unwrap();
    catalog.insert("zeta", source).unwrap();
    let old = catalog.clone();
    let mut count = 0;
    assert!(
        catalog
            .try_update_all(|table| {
                count += 1;
                if count == 2 {
                    return Err(invalid("stop after first candidate"));
                }
                let mut replacement = table.clone();
                Arc::make_mut(&mut replacement).next_row_id = 8;
                Ok(Some(replacement))
            })
            .is_err()
    );
    assert!(catalog.entries.ptr_eq(&old.entries));
    assert_eq!(catalog["alpha"].next_row_id, 1);
}

#[test]
fn preadmitted_checkpoint_map_keeps_current_writes_and_defers_catalog_growth() {
    let source = table();
    let mut catalog = Catalog::empty().unwrap();
    catalog.insert("items", source.clone()).unwrap();
    let permit = catalog.prepare_install().unwrap();
    let old = catalog.clone();
    Arc::make_mut(catalog.get_mut("items").unwrap().unwrap()).next_row_id = 73;
    let current = with_storage_pool(0, |pool| {
        let mut candidate = catalog.begin_prepared(permit).unwrap();
        assert_eq!(candidate.get_mut("items").unwrap().next_row_id, 73);
        Arc::make_mut(candidate.get_mut("items").unwrap()).next_row_id = 74;
        assert_eq!(pool.used(), 0);
        candidate.finish()
    });
    assert_eq!(current["items"].next_row_id, 74);
    assert_eq!(catalog["items"].next_row_id, 73);
    assert_eq!(old["items"].next_row_id, 1);
    let permit = catalog.prepare_install().unwrap();
    catalog.insert("new_table", source).unwrap();
    let before = catalog.clone();
    assert!(catalog.begin_prepared(permit).is_none());
    assert!(catalog.entries.ptr_eq(&before.entries));
    assert!(catalog.contains_key("new_table"));
}

#[test]
fn prepared_conflict_catalog_shares_snapshot_and_reopen_preserves_rename_drop_and_rows() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1)"))
        .unwrap();
    let old = engine.state.read().clone();
    let prepared = prepare_execution(
        old.clone(),
        request("UPDATE items SET id = 2 WHERE id = 1"),
        false,
        true,
        None,
        None,
        false,
    )
    .unwrap();
    assert!(old.tables.entries.ptr_eq(&prepared.catalog.entries));
    assert!(Arc::ptr_eq(
        &old.tables["items"],
        &prepared.catalog["items"]
    ));
    engine
        .execute(request("ALTER TABLE items RENAME TO renamed"))
        .unwrap();
    let current = engine.state.read().clone();
    assert!(validate_rebase(&prepared, &current).is_err());
    assert!(old.tables.contains_key("items"));
    assert!(!current.tables.contains_key("items"));
    engine
        .execute(request("CREATE TABLE discarded (id INTEGER)"))
        .unwrap();
    engine.execute(request("DROP TABLE discarded")).unwrap();
    engine.checkpoint().unwrap();
    drop(prepared);
    drop(engine);
    let engine = open(directory.path());
    let response = engine
        .execute(request("SELECT id FROM renamed"))
        .unwrap()
        .response;
    let SqlResult::Rows { rows, .. } = &response.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(1)]]);
    assert_eq!(engine.state.read().tables.len(), 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn catalog_growth_after_manifest_defers_install_and_wal_reclaim_then_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request("CREATE TABLE items (id INTEGER PRIMARY KEY)"))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1)"))
        .unwrap();
    let captured = capture_relational_checkpoint(
        &engine.state.read(),
        engine.wal.lock().unwrap().len().unwrap(),
    )
    .unwrap();
    let watermark = engine.wal.lock().unwrap().len().unwrap();
    let marker = directory.path().join("marker");
    let release = directory.path().join("release");
    let fault = crate::failpoint::test_env(
        "pause:relational_checkpoint.after_manifest",
        &marker,
        &release,
    );
    let worker_engine = engine.clone();
    let worker = std::thread::spawn(move || worker_engine.publish_checkpoint(&captured));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Always release the publisher even when the assertion below fails.
    struct Release(PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = fs::write(&self.0, b"release");
        }
    }
    let unblock = Release(release.clone());
    assert!(
        marker.exists(),
        "checkpoint must reach durable manifest boundary"
    );
    engine
        .execute(request("CREATE TABLE added (id INTEGER PRIMARY KEY)"))
        .unwrap();
    engine
        .execute(request("INSERT INTO added VALUES (2)"))
        .unwrap();
    let after = engine.wal.lock().unwrap().len().unwrap();
    assert!(after > watermark);
    drop(unblock);
    worker.join().unwrap().unwrap();
    drop(fault);
    assert_eq!(
        engine.wal.lock().unwrap().len().unwrap(),
        after,
        "deferred activation must keep WAL prefix"
    );
    assert!(
        engine.state.read().tables["items"]
            .rows
            .checkpoint_delta()
            .next()
            .is_some()
    );
    drop(engine);
    let engine = open(directory.path());
    for (name, id) in [("items", 1), ("added", 2)] {
        let result = engine
            .execute(request(&format!("SELECT id FROM {name}")))
            .unwrap()
            .response;
        let SqlResult::Rows { rows, .. } = &result.results[0] else {
            panic!("rows expected")
        };
        assert_eq!(rows, &vec![vec![RelationalValue::Integer(id)]]);
    }
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(engine.state.read().tables.len(), 2);
}
