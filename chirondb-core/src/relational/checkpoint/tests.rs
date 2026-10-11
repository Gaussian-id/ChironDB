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

fn seed(engine: &RelationalEngine, count: usize, body_bytes: usize) {
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE, body TEXT)",
        ))
        .unwrap();
    let body = "x".repeat(body_bytes);
    let values = (1..=count)
        .map(|id| format!("({id}, 'code-{id}', '{body}')"))
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
fn live_checkpoint_carries_unchanged_table_without_revalidating_its_runs() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE stable (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("CREATE TABLE active (id INTEGER PRIMARY KEY)"))
        .unwrap();
    let values = (1..=256)
        .map(|id| format!("({id}, 'value-{id}')"))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO stable VALUES {values}")))
        .unwrap();
    engine
        .execute(request("INSERT INTO active VALUES (1)"))
        .unwrap();
    engine.checkpoint().unwrap();
    let previous = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    let old_stable = previous
        .tables
        .iter()
        .find(|table| table.definition.name == "stable")
        .unwrap();
    let old_rows = checkpoint_row_references(old_stable);
    let old_indexes = checkpoint_index_references(old_stable);
    let reader = Arc::clone(&engine.state.read().tables["stable"].index_segments[0].reader);

    engine
        .execute(request("INSERT INTO active VALUES (2)"))
        .unwrap();
    engine.checkpoint().unwrap();
    let current = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    let stable = current
        .tables
        .iter()
        .find(|table| table.definition.name == "stable")
        .unwrap();
    assert_eq!(checkpoint_row_references(stable), old_rows);
    assert_eq!(checkpoint_index_references(stable), old_indexes);
    assert!(Arc::ptr_eq(
        &reader,
        &engine.state.read().tables["stable"].index_segments[0].reader
    ));

    drop(engine);
    let reopened = open(directory.path());
    assert_eq!(
        ids(&reopened, "SELECT id FROM active ORDER BY id"),
        vec![1, 2]
    );
    assert_eq!(
        ids(&reopened, "SELECT id FROM stable ORDER BY id"),
        (1..=256).collect::<Vec<_>>()
    );
}

#[test]
fn offline_migration_writes_distinct_runs_for_an_unchanged_table() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 16, 8);
    let previous = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    let captured =
        capture_relational_checkpoint(&engine.state.read(), previous.wal_watermark).unwrap();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let migrated = materialize_migration(&captured, Some(&previous), &segment_dir).unwrap();
    assert_ne!(
        checkpoint_row_references(&migrated.tables[0]),
        checkpoint_row_references(&previous.tables[0])
    );
    assert_ne!(
        checkpoint_index_references(&migrated.tables[0]),
        checkpoint_index_references(&previous.tables[0])
    );
    prepare_checkpoint_backings(&migrated, &segment_dir).unwrap();
    drop(engine);
    assert_eq!(
        ids(&open(directory.path()), "SELECT id FROM items ORDER BY id"),
        (1..=16).collect::<Vec<_>>()
    );
}

#[test]
fn live_delta_validation_rejects_a_missing_index_record_before_publication() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 16, 8);
    let original = fs::read(&engine.checkpoint_path).unwrap();
    let previous = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    engine
        .execute(request("UPDATE items SET code = 'new' WHERE id = 1"))
        .unwrap();
    let captured =
        capture_relational_checkpoint(&engine.state.read(), previous.wal_watermark).unwrap();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let mut persisted = materialize(&captured, Some(&previous), &segment_dir).unwrap();
    let source = &captured.tables[0];
    assert!(
        validate_appended_generation(
            source,
            &persisted.tables[0],
            &previous.tables[0],
            previous.sequence,
            &segment_dir,
            persisted.sequence,
        )
        .unwrap()
    );
    assert!(
        !validate_appended_generation(
            source,
            &persisted.tables[0],
            &previous.tables[0],
            previous.sequence + 1,
            &segment_dir,
            persisted.sequence,
        )
        .unwrap()
    );

    let appended = persisted.tables[0].index_segments.last_mut().unwrap();
    let path = segment_dir.join(&appended.file_name);
    let mut records = segment::read_segment(&path).unwrap().records;
    records.pop();
    let metadata = write_segment(&path, SegmentKind::Index, persisted.sequence, &records).unwrap();
    *appended = segment_reference(appended.file_name.clone(), &metadata);
    assert!(
        validate_appended_generation(
            source,
            &persisted.tables[0],
            &previous.tables[0],
            previous.sequence,
            &segment_dir,
            persisted.sequence,
        )
        .is_err()
    );
    assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), original);
    drop(engine);
    assert_eq!(
        ids(
            &open(directory.path()),
            "SELECT id FROM items WHERE code = 'new'"
        ),
        vec![1]
    );
}

#[test]
fn ordinary_checkpoint_projects_only_changed_versions_and_retains_gc_closures() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 1024, 2048);
    engine
        .execute(request("UPDATE items SET code = 'changed' WHERE id = 1"))
        .unwrap();
    engine.collect_mvcc_garbage().unwrap();
    {
        let state = engine.state.read();
        let table = &state.tables["items"];
        assert_eq!(
            table.rows.get(&1).unwrap().unwrap().len(),
            1,
            "logical GC hides the closed version"
        );
        let (rows, indexes) = delta_records(table).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "only the close and new version, not 1024 rows"
        );
        assert_eq!(indexes.len(), 4);
        assert!(
            rows.iter().any(
                |record| serde_json::from_slice::<PersistedRowVersion>(&record.value)
                    .unwrap()
                    .version
                    .end
                    .is_some()
            ),
            "GC must retain the unflushed closing record"
        );
    }
    engine.checkpoint().unwrap();
    let manifest = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    assert_eq!(manifest.tables[0].row_segments.len(), 2);
    assert_eq!(manifest.tables[0].row_segments[1].record_count, 2);
    assert_eq!(manifest.tables[0].index_segments[1].record_count, 4);
    assert_eq!(
        engine.state.read().tables["items"]
            .rows
            .checkpoint_delta()
            .count(),
        0
    );
    engine
        .execute(request("DELETE FROM items WHERE id = 2"))
        .unwrap();
    engine
        .execute(request("DELETE FROM items WHERE id = 3"))
        .unwrap();
    engine.collect_mvcc_garbage().unwrap();
    let (rows, indexes) = delta_records(&engine.state.read().tables["items"]).unwrap();
    assert_eq!((rows.len(), indexes.len()), (2, 4));
    assert!(rows.iter().all(|record| {
        serde_json::from_slice::<PersistedRowVersion>(&record.value)
            .unwrap()
            .version
            .end
            .is_some()
    }));
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'changed'"),
        vec![1]
    );
    assert!(ids(&engine, "SELECT id FROM items WHERE code = 'code-2'").is_empty());
    assert!(ids(&engine, "SELECT id FROM items WHERE code = 'code-3'").is_empty());
    engine
        .execute(request(
            "INSERT INTO items VALUES (2000, 'code-2', 'reused')",
        ))
        .unwrap();
}

#[test]
fn index_byte_pressure_compacts_row_and_index_generations_together() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 128, 16 * 1024);
    let long_code = "k".repeat(100 * 1024);
    engine
        .execute(request(&format!(
            "UPDATE items SET code = '{long_code}' WHERE id = 1"
        )))
        .unwrap();
    engine.collect_mvcc_garbage().unwrap();
    let prior = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    let state = engine.state.read();
    let table = &state.tables["items"];
    let (rows, indexes) = delta_records(table).unwrap();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let writer = RunWriter {
        directory: &segment_dir,
        sequence: state.sequence,
        table_id: table.definition.table_id,
    };
    let mode = RunMode::Delta {
        reclaim_before: table.rows.retention_frontier(),
    };
    assert!(
        !writer
            .needs_compaction(SegmentKind::Row, &rows, &prior.tables[0].row_segments, mode)
            .unwrap()
    );
    assert!(
        writer
            .needs_compaction(
                SegmentKind::Index,
                &indexes,
                &prior.tables[0].index_segments,
                mode
            )
            .unwrap(),
        "index size must trigger before the four-run bound"
    );
    drop(state);
    engine.checkpoint().unwrap();
    let current = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    assert_eq!(current.tables[0].row_segments.len(), 1);
    assert_eq!(current.tables[0].index_segments.len(), 1);
    assert_eq!(current.tables[0].row_segments[0].record_count, 128);
    assert_eq!(current.tables[0].index_segments[0].record_count, 256);
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(
        ids(
            &engine,
            &format!("SELECT id FROM items WHERE code = '{long_code}'")
        ),
        vec![1]
    );
}

#[test]
fn preparation_refuses_mismatched_projections_before_manifest_publication() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 16, 8);
    let original = fs::read(&engine.checkpoint_path).unwrap();
    let mut candidate = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    let mut records = index_segment_records(&engine.state.read().tables["items"]).unwrap();
    records.pop();
    let segment_dir = directory.path().join(RELATIONAL_SEGMENT_DIR);
    let name = "bad-projection.rseg";
    let metadata = write_segment(
        &segment_dir.join(name),
        SegmentKind::Index,
        candidate.sequence,
        &records,
    )
    .unwrap();
    candidate.tables[0].index_segments = vec![segment_reference(name.into(), &metadata)];
    assert!(prepare_checkpoint_backings(&candidate, &segment_dir).is_err());
    assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), original);
    drop(engine);
    assert_eq!(
        ids(&open(directory.path()), "SELECT id FROM items WHERE id = 1"),
        vec![1]
    );
}

#[test]
fn reusing_an_inline_legacy_checkpoint_preserves_scalar_memberships() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    seed(&engine, 2, 8);
    let mut legacy = read_relational_checkpoint(&engine.checkpoint_path)
        .unwrap()
        .unwrap();
    legacy.version = RELATIONAL_CHECKPOINT_LEGACY_VERSION;
    legacy.tables[0].rows = engine.state.read().tables["items"]
        .rows
        .iter()
        .map(|entry| {
            let (id, versions) = entry.unwrap();
            (id, versions.to_vec())
        })
        .collect();
    legacy.tables[0].row_segments.clear();
    legacy.tables[0].index_segments.clear();
    write_relational_checkpoint(&engine.checkpoint_path, &legacy).unwrap();
    drop(engine);
    let engine = open(directory.path());
    engine.checkpoint().unwrap(); // Same sequence: reuse instead of creating a generation.
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'code-1'"),
        vec![1]
    );
    assert!(
        engine
            .execute(request(
                "INSERT INTO items VALUES (3, 'code-1', 'duplicate')"
            ))
            .is_err()
    );
    engine
        .execute(request("INSERT INTO items VALUES (3, 'three', 'new')"))
        .unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = open(directory.path());
    assert_eq!(
        ids(&engine, "SELECT id FROM items WHERE code = 'three'"),
        vec![3]
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn delta_checkpoint_interruptions_recover_deletes_and_changed_primary_keys() {
    for boundary in ["after_segments", "after_manifest", "after_wal_reclaim"] {
        let directory = tempdir().unwrap();
        let engine = open(directory.path());
        seed(&engine, 128, 128);
        engine
            .execute(request("DELETE FROM items WHERE id = 1"))
            .unwrap();
        engine
            .execute(request(
                "UPDATE items SET id = 2000, code = 'moved' WHERE id = 2",
            ))
            .unwrap();
        {
            let _fault = crate::failpoint::test_env(
                &format!("error:relational_checkpoint.{boundary}"),
                &directory.path().join("marker"),
                &directory.path().join("release"),
            );
            assert!(engine.checkpoint().is_err(), "{boundary}");
        }
        drop(engine);
        let engine = open(directory.path());
        assert!(
            ids(&engine, "SELECT id FROM items WHERE id = 1").is_empty(),
            "{boundary}"
        );
        assert!(
            ids(&engine, "SELECT id FROM items WHERE id = 2").is_empty(),
            "{boundary}"
        );
        assert_eq!(
            ids(&engine, "SELECT id FROM items WHERE code = 'moved'"),
            vec![2000],
            "{boundary}"
        );
        assert_eq!(
            ids(&engine, "SELECT id FROM items").len(),
            127,
            "{boundary}"
        );
        engine.checkpoint().unwrap();
        drop(engine);
        assert_eq!(
            ids(
                &open(directory.path()),
                "SELECT id FROM items WHERE code = 'moved'"
            ),
            vec![2000]
        );
    }
}
