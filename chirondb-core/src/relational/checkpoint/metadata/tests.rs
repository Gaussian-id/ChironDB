use super::*;
use crate::relational::memory::{with_pool, with_storage_pool};

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

fn fixture() -> RelationalCheckpoint {
    // All current heap-bearing catalog fields, legacy values and run metadata.
    // This tests copying DTOs; physical segment validation is exercised elsewhere.
    let definition: TableDefinition = serde_json::from_value(serde_json::json!({
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
    .unwrap();
    let reference = RelationalSegmentReference {
        file_name: "row-example.rseg".into(),
        kind: SegmentKind::Row,
        sequence: 1,
        record_count: 1,
        min_key: Some(vec![1; 1024]),
        max_key: Some(vec![2; 2048]),
    };
    RelationalCheckpoint {
        version: RELATIONAL_CHECKPOINT_VERSION,
        sequence: 1,
        next_catalog_id: 7,
        wal_watermark: 0,
        tables: vec![RelationalCheckpointTable {
            definition,
            rows: BTreeMap::from([(
                1,
                vec![RowVersion {
                    begin: 1,
                    end: None,
                    values: RowValues::adopt(vec![RelationalValue::Text("legacy".repeat(1024))])
                        .unwrap(),
                }],
            )]),
            next_row_id: 2,
            row_segment: Some(reference.clone()),
            index_segment: None,
            row_segments: vec![reference],
            index_segments: vec![],
        }],
        applied_transactions: (0..1000).map(|_| TransactionId::new()).collect(),
        owned_memory: memory::Charge::default(),
    }
}

#[test]
fn copied_metadata_owns_independent_admission_and_preserves_every_field() {
    let source = fixture();
    let expected = serde_json::to_value(&source).unwrap();
    let (pool, copy) = with_storage_pool(1024 * 1024, |pool| {
        let copied = source.try_clone().unwrap();
        assert_eq!(serde_json::to_value(&copied).unwrap(), expected);
        assert!(pool.used() > 16_000);
        (pool, copied)
    });
    drop(source);
    assert!(pool.used() > 16_000);
    assert_eq!(serde_json::to_value(&copy).unwrap(), expected);
    drop(copy);
    assert_eq!(pool.used(), 0);
}

#[test]
fn projection_omits_inline_rows_and_history_without_losing_schema_or_refs() {
    let source = fixture();
    let mut expected = serde_json::to_value(&source).unwrap();
    expected["applied_transactions"] = serde_json::json!([]);
    expected["tables"][0]["rows"] = serde_json::json!({});
    with_storage_pool(1024 * 1024, |pool| {
        let full = source.try_clone().unwrap();
        let projected = projection_manifest(&source).unwrap();
        assert_eq!(serde_json::to_value(&projected).unwrap(), expected);
        assert!(projected.owned_memory.bytes() < full.owned_memory.bytes());
        assert_eq!(
            pool.used(),
            full.owned_memory.bytes()
                + projected.owned_memory.bytes()
                + 2 * memory::LEASE_ROOT_BYTES
        );
        drop(full);
        assert_eq!(
            pool.used(),
            projected.owned_memory.bytes() + memory::LEASE_ROOT_BYTES
        );
        drop(projected);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn clone_quota_and_cancellation_preserve_source_and_release_reservations() {
    let source = fixture();
    let expected = serde_json::to_value(&source).unwrap();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            source.try_clone(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(matches!(
            projection_manifest(&source),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    with_storage_pool(1024 * 1024, |pool| {
        let error = with_sql_cancellation(Arc::new(AtomicBool::new(true)), || source.try_clone())
            .unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(serde_json::to_value(&source).unwrap(), expected);
}

#[test]
fn capture_pins_and_metadata_share_one_reservation_until_both_drop() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT DEFAULT 'default')",
        ))
        .unwrap();
    let (pool, captured) = with_storage_pool(1024 * 1024, |pool| {
        let captured = capture(&engine.state.read(), 0).unwrap();
        assert_eq!(
            pool.used(),
            captured.manifest.owned_memory.bytes() + memory::LEASE_ROOT_BYTES
        );
        (pool, captured)
    });
    drop(engine);
    assert!(pool.used() > 0);
    let CapturedRelationalCheckpoint {
        manifest,
        tables,
        _owned_memory,
    } = captured;
    drop(manifest);
    assert!(pool.used() > 0);
    assert_eq!(tables[0].definition.name, "items");
    drop(tables);
    drop(_owned_memory);
    assert_eq!(pool.used(), 0);
}

#[test]
fn copied_run_bounds_remain_charged_after_the_source_drops() {
    let mut source = fixture();
    let borrowed = checkpoint_row_references(&source.tables[0]);
    assert_eq!(borrowed.as_ptr(), source.tables[0].row_segments.as_ptr());
    let expected = borrowed.to_vec();
    let (pool, refs, charge) = with_storage_pool(64 * 1024, |pool| {
        let mut charge = memory::Charge::storage();
        let refs = references(borrowed, None, &mut charge).unwrap();
        assert!(pool.used() >= 3072);
        (pool, refs, charge)
    });
    source.tables[0].row_segments.clear();
    assert_eq!(
        checkpoint_row_references(&source.tables[0]).as_ptr(),
        source.tables[0].row_segment.as_slice().as_ptr()
    );
    drop(source);
    assert_eq!(refs, expected);
    assert!(pool.used() >= 3072);
    drop(refs);
    drop(charge);
    assert_eq!(pool.used(), 0);
}

#[test]
fn refused_capture_after_commit_keeps_receipt_and_recovers_acknowledged_write() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(&format!(
            "CREATE TABLE items (id INTEGER, body TEXT DEFAULT '{}')",
            "d".repeat(40 * 1024)
        )))
        .unwrap();
    let mut mutation = request(&format!(
        "INSERT INTO items VALUES (1, '{}')",
        "x".repeat(10 * 1024)
    ));
    mutation.idempotency_key = Some("capture-pressure".into());
    // Journal preflight is now admitted before COMMIT. Apply checkpoint pressure
    // after the real durable decision, then exercise the production post-commit
    // failure handler under the original unchanged maintenance quota.
    let decision = engine.execute(mutation.clone()).unwrap().response;
    assert!(decision.committed);
    let pool = with_pool(64 * 1024, |_| {
        with_storage_pool(48 * 1024, |pool| {
            assert!(engine.state.read().checkpoint_required());
            // A long reader retains a charged copy of the acknowledged row.
            // The same 48 KiB pool must admit that owner and checkpoint capture.
            let state = engine.state.read();
            let row = state.tables["items"]
                .rows
                .visible(1, state.sequence)
                .unwrap()
                .unwrap();
            let reader = RowValues::copy(&row.values).unwrap();
            let captured = capture(&state, 0);
            drop(state);
            assert!(matches!(captured, Err(GaussError::ResourceExhausted(_))));
            engine.checkpoint_after_commit(captured, "relational");
            assert!(!engine.checkpoint_path.exists());
            assert_eq!(
                engine
                    .journal
                    .status(decision.transaction_id.as_ref().unwrap().parse().unwrap())
                    .state,
                crate::transaction_journal::TransactionState::Committed
            );
            drop(reader);
            pool
        })
    });
    drop(engine);
    assert_eq!(pool.used(), 0);
    let reopened = open(directory.path());
    let replay = reopened.execute(mutation).unwrap().response;
    assert_eq!(replay.transaction_id, decision.transaction_id);
    assert!(replay.committed);
    let selected = reopened
        .execute(request("SELECT id FROM items"))
        .unwrap()
        .response;
    assert!(
        matches!(&selected.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1)]])
    );
}
