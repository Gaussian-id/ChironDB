use super::*;
use crate::relational::memory::with_storage_pool;

fn request(sql: &str) -> SqlExecutionRequest {
    serde_json::from_value(serde_json::json!({"statements":[{"sql":sql}]})).unwrap()
}

fn open(path: &Path) -> Arc<RelationalEngine> {
    RelationalEngine::open(path, TransactionJournal::open(path).unwrap()).unwrap()
}

fn definition() -> TableDefinition {
    serde_json::from_value(serde_json::json!({
        "table_id":1,"name":"items","columns":[
            {"name":"id","data_type":{"kind":"integer"},"nullable":false},
            {"name":"code","data_type":{"kind":"text"},"nullable":false},
            {"name":"ref","data_type":{"kind":"record_ref","namespace":"documents"},"nullable":true}],
        "primary_key":["id"],"primary_key_index_id":2,
        "unique_constraints":[{"index_id":3,"columns":["code"]}],
        "foreign_keys":[{"index_id":3,"columns":["code"],"referenced_table":"parents","referenced_columns":["code"]}],
        "indexes":[{"index_id":3,"name":"by_code","columns":["code"],"unique":false}],
        "reference_index_ids":{"ref":4}
    })).unwrap()
}

#[test]
fn catalog_shares_map_and_types_then_admits_independent_keys_before_fork() {
    let source = definition();
    let (pool, original, forked) = with_storage_pool(128 * 1024, |pool| {
        let original = Catalog::new(&source).unwrap();
        assert_eq!(original.len(), 3, "same physical columns are deduplicated");
        let held = pool.used();
        assert!(held >= memory::tree_bytes(3));
        let mut forked = original.clone();
        assert!(Arc::ptr_eq(&original.0, &forked.0));
        assert_eq!(pool.used(), held);
        for (_, index) in forked.iter_mut().unwrap() {
            assert!(index.delta.is_empty());
        }
        assert!(!Arc::ptr_eq(&original.0, &forked.0));
        assert!(pool.used() >= held + memory::tree_bytes(3));
        for (columns, index) in original.iter() {
            let (copied_columns, copied_index) = forked.get_key_value(columns).unwrap();
            assert_ne!(columns.as_ptr(), copied_columns.as_ptr());
            assert_ne!(columns[0].as_ptr(), copied_columns[0].as_ptr());
            assert!(Arc::ptr_eq(&index.types.0, &copied_index.types.0));
        }
        let code = [String::from("code")];
        assert_eq!(original.get(code.as_slice()).unwrap().id, 3);
        let index = original.get(code.as_slice()).unwrap();
        assert_eq!(
            index.key(&[&RelationalValue::Text("x".into())]).unwrap(),
            Some(
                encode_index_prefix_v1(
                    3,
                    &[(&RelationalType::Text, &RelationalValue::Text("x".into()))]
                )
                .unwrap()
            )
        );
        (pool, original, forked)
    });
    drop(source);
    drop(original);
    assert!(pool.used() > 0, "fork retains types and independent keys");
    drop(forked);
    assert_eq!(pool.used(), 0);
}

#[test]
fn type_namespace_admission_precedes_copy_and_survives_all_source_owners() {
    let source = RelationalType::RecordRef {
        namespace: "n".repeat(32 * 1024),
    };
    with_storage_pool(16 * 1024, |pool| {
        assert!(matches!(
            Types::copy(std::iter::once(&source).map(Ok)),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    let (pool, original, shared) = with_storage_pool(64 * 1024, |pool| {
        let original = Types::copy(std::iter::once(&source).map(Ok)).unwrap();
        let held = pool.used();
        assert!(held > 32 * 1024);
        let shared = original.clone();
        assert!(Arc::ptr_eq(&original.0, &shared.0));
        assert_eq!(pool.used(), held);
        (pool, original, shared)
    });
    drop(source);
    drop(original);
    assert!(pool.used() > 32 * 1024);
    assert!(
        matches!(&shared[0], RelationalType::RecordRef { namespace } if namespace.len() == 32 * 1024)
    );
    drop(shared);
    assert_eq!(pool.used(), 0);
}

#[test]
fn refused_or_cancelled_fork_keeps_the_original_catalog_and_its_memberships() {
    let mut original = Catalog::new(&definition()).unwrap();
    original
        .iter_mut()
        .unwrap()
        .find(|(columns, _)| columns[0] == "id")
        .unwrap()
        .1
        .set(7, &[&RelationalValue::Integer(7)], true)
        .unwrap();
    let mut forked = original.clone();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            forked.iter_mut(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(Arc::ptr_eq(&original.0, &forked.0));
        assert_eq!(pool.used(), 0);
    });
    with_storage_pool(128 * 1024, |pool| {
        let result = with_sql_cancellation(Arc::new(AtomicBool::new(true)), || {
            let _ = forked.iter_mut()?;
            Ok(())
        });
        assert!(result.unwrap_err().to_string().contains("query canceled"));
        assert!(Arc::ptr_eq(&original.0, &forked.0));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(
        forked
            .get(["id".into()].as_slice())
            .unwrap()
            .lookup(&[], 1, &[&RelationalValue::Integer(7)])
            .unwrap(),
        BTreeSet::from([7])
    );
}

#[test]
fn partial_construction_failure_releases_keys_types_and_nodes() {
    let mut source = definition();
    source.columns[2].data_type = RelationalType::RecordRef {
        namespace: "n".repeat(32 * 1024),
    };
    with_storage_pool(16 * 1024, |pool| {
        assert!(matches!(
            Catalog::new(&source),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    source.primary_key_index_id = None;
    with_storage_pool(128 * 1024, |pool| {
        assert!(
            Catalog::new(&source)
                .unwrap_err()
                .to_string()
                .contains("physical identity")
        );
        assert_eq!(pool.used(), 0);
    });
    // Preserve the previous constructor's physical identity resolution: an
    // old PK without its own ID can use a matching unique owner's stable ID.
    source.unique_constraints.push(UniqueConstraint {
        index_id: 2,
        name: None,
        columns: vec!["id".into()],
    });
    with_storage_pool(128 * 1024, |pool| {
        let catalog = Catalog::new(&source).unwrap();
        assert_eq!(catalog.get(["id".into()].as_slice()).unwrap().id, 2);
        assert_eq!(catalog.len(), 3);
        drop(catalog);
        assert_eq!(pool.used(), 0);
    });
    source.primary_key_index_id = Some(2);
    source.indexes.push(ScalarIndexDefinition {
        index_id: 5,
        name: "bad".into(),
        columns: vec!["missing".into()],
        unique: false,
    });
    with_storage_pool(128 * 1024, |pool| {
        assert!(Catalog::new(&source).is_err());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn mutation_catalog_refusal_preserves_acknowledged_rows_and_retries_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let columns = (0..8)
        .map(|i| format!("c{i} INTEGER"))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, {columns})"
        )))
        .unwrap();
    for i in 0..8 {
        engine
            .execute(request(&format!("CREATE INDEX by_c{i} ON items (c{i})")))
            .unwrap();
    }
    engine
        .execute(request("INSERT INTO items VALUES (1,0,0,0,0,0,0,0,0)"))
        .unwrap();
    let old = engine.state.read().clone();
    let watermark = engine.wal.lock().unwrap().len().unwrap();
    assert!(old.tables["items"].indexes.0._memory.bytes() > 8192);
    with_storage_pool(8192, |pool| {
        assert!(matches!(
            engine.execute(request("UPDATE items SET c0 = 9 WHERE id = 1")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert!(Arc::ptr_eq(
        &old.tables["items"].indexes.0,
        &engine.state.read().tables["items"].indexes.0
    ));
    assert_eq!(engine.state.read().sequence, old.sequence);
    assert_eq!(engine.wal.lock().unwrap().len().unwrap(), watermark);
    drop(engine);
    let engine = open(directory.path());
    let result = engine
        .execute(request("SELECT id FROM items WHERE c0 = 0"))
        .unwrap();
    let SqlResult::Rows { rows, .. } = &result.response.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(1)]]);
    engine
        .execute(request("UPDATE items SET c0 = 9 WHERE id = 1"))
        .unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = open(directory.path());
    let result = engine
        .execute(request("SELECT id FROM items WHERE c0 = 9"))
        .unwrap();
    let SqlResult::Rows { rows, .. } = &result.response.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Integer(1)]]);
}

#[test]
fn checkpoint_installs_preadmitted_empty_index_catalog_with_no_new_storage_quota() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'old')"))
        .unwrap();
    let old = engine.state.read().clone();
    let captured =
        capture_relational_checkpoint(&old, engine.wal.lock().unwrap().len().unwrap()).unwrap();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let persisted = checkpoint::materialize(&captured, None, &segment_dir).unwrap();
    let (pool, backings) = with_storage_pool(2 * 1024 * 1024, |pool| {
        let backings =
            prepare_live_checkpoint_backings(&persisted, &captured, None, &segment_dir).unwrap();
        assert!(pool.used() > 0);
        assert!(
            backings[0]
                .scalar_indexes
                .values()
                .all(|index| index.delta.is_empty())
        );
        (pool, backings)
    });
    let prepared = backings[0].scalar_indexes.clone();
    let mut current = old.clone();
    let permit = current.tables.prepare_install().unwrap();
    with_storage_pool(0, |pool| {
        assert!(install_checkpoint_backings(
            &mut current,
            &persisted,
            backings,
            permit
        ));
        assert_eq!(pool.used(), 0);
    });
    assert!(Arc::ptr_eq(&prepared.0, &current.tables["items"].indexes.0));
    assert!(!Arc::ptr_eq(
        &old.tables["items"].indexes.0,
        &current.tables["items"].indexes.0
    ));
    assert!(
        old.tables["items"]
            .indexes
            .values()
            .any(|index| !index.delta.is_empty())
    );
    let index = current.tables["items"]
        .indexes
        .get(["code".into()].as_slice())
        .unwrap();
    assert_eq!(
        index
            .lookup(
                &current.tables["items"].index_segments,
                current.sequence,
                &[&RelationalValue::Text("old".into())]
            )
            .unwrap(),
        BTreeSet::from([1])
    );
    drop(current);
    assert!(
        pool.used() > 0,
        "independent prepared catalog retains its reservation"
    );
    drop(prepared);
    assert_eq!(pool.used(), 0);
}
