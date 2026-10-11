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
        "table_id":1,"creator_principal_id":"creator","tenant_id":"acme",
        "name":"items","columns":[
            {"name":"id","data_type":{"kind":"integer"},"nullable":false},
            {"name":"ref","data_type":{"namespace":"documents","kind":"record_ref"},
             "nullable":true,"default":{"type":"json","value":{"nested":["value",[0,1,2]]}}}],
        "primary_key":["id"],"primary_key_name":"items_pkey","primary_key_index_id":2,
        "unique_constraints":[{"index_id":3,"name":"ref_unique","columns":["ref"]}],
        "check_constraints":[{"name":"positive","expression":"id > 0"}],
        "foreign_keys":[{"index_id":4,"name":"parent_fk","columns":["id"],
            "referenced_table":"parent","referenced_columns":["id"],
            "referenced_key_kind":"primary_key","referenced_key_name":"parent_pkey"}],
        "indexes":[{"index_id":5,"name":"by_ref","columns":["ref"],"unique":false}],
        "reference_index_ids":{"ref":6}
    }))
    .unwrap()
}

#[test]
fn schema_copy_preserves_fields_and_lifetime_without_recharging_snapshots() {
    let source = definition();
    let expected = serde_json::to_value(&source).unwrap();
    let (pool, copy, shared) = with_storage_pool(1024 * 1024, |pool| {
        let copy = Schema::copy(&source).unwrap();
        let held = pool.used();
        assert!(held > size_of::<TableDefinition>() as u64);
        let shared = copy.clone();
        assert!(std::ptr::eq(copy.as_ref(), shared.as_ref()));
        assert_eq!(pool.used(), held);
        (pool, copy, shared)
    });
    drop(source);
    assert_eq!(serde_json::to_value(copy.as_ref()).unwrap(), expected);
    drop(copy);
    assert!(pool.used() > 0);
    assert_eq!(serde_json::to_value(shared.as_ref()).unwrap(), expected);
    drop(shared);
    assert_eq!(pool.used(), 0);
}

#[test]
fn adoption_accounts_unused_capacity_while_copy_only_allocates_used_slots() {
    let mut source = definition();
    source.columns.reserve_exact(1000);
    source.primary_key.reserve_exact(1000);
    source.unique_constraints.reserve_exact(1000);
    source.check_constraints.reserve_exact(1000);
    source.foreign_keys.reserve_exact(1000);
    source.indexes.reserve_exact(1000);
    source.unique_constraints[0].columns.reserve_exact(1000);
    source.foreign_keys[0]
        .referenced_columns
        .reserve_exact(1000);
    source.indexes[0].columns.reserve_exact(1000);
    let expected = serde_json::to_value(&source).unwrap();
    let capacity_bytes = source.columns.capacity() * size_of::<RelationalColumn>()
        + source.primary_key.capacity() * size_of::<String>()
        + source.unique_constraints.capacity() * size_of::<UniqueConstraint>()
        + source.check_constraints.capacity() * size_of::<CheckConstraintDefinition>()
        + source.foreign_keys.capacity() * size_of::<ForeignKeyDefinition>()
        + source.indexes.capacity() * size_of::<ScalarIndexDefinition>()
        + source.unique_constraints[0].columns.capacity() * size_of::<String>()
        + source.foreign_keys[0].referenced_columns.capacity() * size_of::<String>()
        + source.indexes[0].columns.capacity() * size_of::<String>();
    with_storage_pool(2 * 1024 * 1024, |pool| {
        let adopted = Schema::adopt(source).unwrap();
        let retained = pool.used();
        assert!(retained >= capacity_bytes as u64 + size_of::<Allocation>() as u64);
        let copied = Schema::copy(&adopted).unwrap();
        assert!(pool.used() - retained < retained / 2);
        assert_eq!(serde_json::to_value(copied.as_ref()).unwrap(), expected);
        drop(adopted);
        assert!(pool.used() > 0);
        drop(copied);
        assert_eq!(pool.used(), 0);
    });
    let mut empty_capacity = definition();
    empty_capacity.indexes = Vec::with_capacity(1000);
    with_storage_pool(16 * 1024, |pool| {
        assert!(matches!(
            Schema::adopt(empty_capacity),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn copy_refusal_and_cancellation_preserve_the_source_and_release_memory() {
    let source = definition();
    let expected = serde_json::to_value(&source).unwrap();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            Schema::copy(&source),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    with_storage_pool(1024 * 1024, |pool| {
        let error =
            with_sql_cancellation(Arc::new(AtomicBool::new(true)), || Schema::copy(&source))
                .unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(serde_json::to_value(&source).unwrap(), expected);
}

#[test]
fn dml_and_prepared_catalog_share_schema_and_old_ddl_snapshots_retain_their_owner() {
    let directory = tempfile::tempdir().unwrap();
    let (pool, old, prepared) = with_storage_pool(8 * 1024 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request(&format!(
                "CREATE TABLE items (id INTEGER, body TEXT DEFAULT '{}')",
                "s".repeat(64 * 1024)
            )))
            .unwrap();
        let old = engine.state.read().clone();
        let prepared = prepare_execution(
            old.clone(),
            request("SELECT id FROM items"),
            false,
            true,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(std::ptr::eq(
            old.tables["items"].definition.as_ref(),
            prepared.catalog["items"].definition.as_ref()
        ));
        engine
            .execute(request("INSERT INTO items VALUES (1, 'old')"))
            .unwrap();
        engine
            .execute(request("UPDATE items SET body = 'new' WHERE id = 1"))
            .unwrap();
        assert!(!Arc::ptr_eq(
            &old.tables["items"],
            &engine.state.read().tables["items"]
        ));
        assert!(std::ptr::eq(
            old.tables["items"].definition.as_ref(),
            engine.state.read().tables["items"].definition.as_ref()
        ));
        engine
            .execute(request(
                "ALTER TABLE items ALTER COLUMN body SET DEFAULT 'changed'",
            ))
            .unwrap();
        assert!(!std::ptr::eq(
            old.tables["items"].definition.as_ref(),
            engine.state.read().tables["items"].definition.as_ref()
        ));
        assert_eq!(
            engine.table_definitions()[0].columns[1].default,
            Some(RelationalValue::Text("changed".into()))
        );
        drop(engine);
        assert!(pool.used() >= 64 * 1024);
        (pool, old, prepared)
    });
    drop(old);
    assert!(
        pool.used() >= 64 * 1024,
        "prepared catalog still owns the old schema"
    );
    drop(prepared);
    assert_eq!(pool.used(), 0);
}

#[test]
fn failed_schema_replacement_or_create_preserves_live_and_reopened_state() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER, body TEXT DEFAULT 'old')",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'retained')"))
        .unwrap();
    let old = engine.state.read().clone();
    let wal_len = engine.wal.lock().unwrap().len().unwrap();
    with_storage_pool(32 * 1024, |pool| {
        for sql in [
            format!(
                "ALTER TABLE items ALTER COLUMN body SET DEFAULT '{}'",
                "s".repeat(64 * 1024)
            ),
            format!(
                "CREATE TABLE refused (body TEXT DEFAULT '{}')",
                "s".repeat(64 * 1024)
            ),
        ] {
            assert!(matches!(
                engine.execute(request(&sql)),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(pool.used(), 0);
        }
    });
    assert_eq!(engine.state.read().sequence, old.sequence);
    assert_eq!(engine.state.read().tables.len(), 1);
    assert!(std::ptr::eq(
        engine.state.read().tables["items"].definition.as_ref(),
        old.tables["items"].definition.as_ref()
    ));
    assert_eq!(engine.wal.lock().unwrap().len().unwrap(), wal_len);
    drop(engine);
    let reopened = open(directory.path());
    assert_eq!(
        reopened.table_definitions(),
        vec![old.tables["items"].definition.as_ref().clone()]
    );
    let result = reopened.execute(request("SELECT body FROM items")).unwrap();
    let SqlResult::Rows { rows, .. } = &result.response.results[0] else {
        panic!("rows expected")
    };
    assert_eq!(rows, &vec![vec![RelationalValue::Text("retained".into())]]);
}

#[test]
fn restored_schema_keeps_admission_after_manifest_consumption_and_failed_restore_is_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(&format!(
            "CREATE TABLE items (body TEXT DEFAULT '{}')",
            "s".repeat(64 * 1024)
        )))
        .unwrap();
    engine.checkpoint().unwrap();
    let path = engine.checkpoint_path.clone();
    drop(engine);
    let bytes = fs::read(&path).unwrap();
    let manifest = read_relational_checkpoint(&path).unwrap().unwrap();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    with_storage_pool(32 * 1024, |pool| {
        assert!(matches!(
            restore_relational_checkpoint(manifest, &segment_dir),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let manifest = read_relational_checkpoint(&path).unwrap().unwrap();
    let (pool, state) = with_storage_pool(1024 * 1024, |pool| {
        let (state, _) = restore_relational_checkpoint(manifest, &segment_dir).unwrap();
        assert!(pool.used() >= 64 * 1024);
        (pool, state)
    });
    drop(state);
    assert_eq!(pool.used(), 0);
    assert_eq!(
        open(directory.path()).table_definitions()[0].columns[0].default,
        Some(RelationalValue::Text("s".repeat(64 * 1024)))
    );
}
