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

fn select_ids(state: &RelationalState, sql: &str) -> Vec<i64> {
    let Statement::Query(query) = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .unwrap()
        .remove(0)
    else {
        unreachable!()
    };
    let SqlResult::Rows { rows, .. } = execute_query(state, state.sequence, &query, &[]).unwrap()
    else {
        unreachable!()
    };
    rows.into_iter()
        .map(|row| match row[0] {
            RelationalValue::Integer(id) => id,
            _ => unreachable!(),
        })
        .collect()
}

#[test]
fn disk_indexes_reopen_without_membership_hydration_and_preserve_snapshots() {
    let directory = tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let engine = RelationalEngine::open(directory.path(), journal).unwrap();
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE, bucket INTEGER)",
        ))
        .unwrap();
    engine
        .execute(request("CREATE INDEX by_bucket ON items (bucket)"))
        .unwrap();
    let values = (1..=1024)
        .map(|id| format!("({id}, 'code-{id}', {})", id % 4))
        .collect::<Vec<_>>()
        .join(",");
    engine
        .execute(request(&format!("INSERT INTO items VALUES {values}")))
        .unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    let old = engine.state.read().clone();
    let table = &old.tables["items"];
    assert_eq!(table.indexes.len(), 3);
    assert!(
        table.indexes.values().all(|index| index.delta.is_empty()),
        "disk memberships must not hydrate into scalar maps"
    );
    assert_eq!(
        select_ids(&old, "SELECT COUNT(*) FROM items WHERE bucket = 0"),
        vec![256]
    );
    assert_eq!(
        select_ids(
            &old,
            "SELECT id FROM items WHERE bucket = 0 LIMIT 3 OFFSET 251"
        ),
        vec![1008, 1012, 1016]
    );
    assert_eq!(
        select_ids(
            &old,
            "SELECT id FROM items WHERE bucket = 0 ORDER BY id DESC LIMIT 3 OFFSET 20",
        ),
        vec![944, 940, 936]
    );
    let generation = Arc::clone(&table.index_segments[0].reader);
    engine
        .execute(request(
            "UPDATE items SET code = 'moved', bucket = 7 WHERE id = 1",
        ))
        .unwrap();
    {
        let state = engine.state.read();
        let table = &state.tables["items"];
        assert!(Arc::ptr_eq(&generation, &table.index_segments[0].reader));
        assert_eq!(
            table
                .indexes
                .values()
                .flat_map(|index| index.delta.values())
                .map(|members| members.len())
                .sum::<usize>(),
            5
        );
        assert_eq!(
            select_ids(&state, "SELECT id FROM items WHERE code = 'code-1'"),
            Vec::<i64>::new()
        );
        assert_eq!(
            select_ids(&state, "SELECT id FROM items WHERE bucket = 7"),
            vec![1]
        );
    }
    assert_eq!(
        select_ids(&old, "SELECT id FROM items WHERE code = 'code-1'"),
        vec![1]
    );
    assert!(
        engine
            .execute(request("INSERT INTO items VALUES (2000, 'moved', 7)"))
            .is_err()
    );
    engine
        .execute(request("INSERT INTO items VALUES (2000, 'code-1', 7)"))
        .unwrap();
    engine
        .execute(request("DELETE FROM items WHERE id = 2"))
        .unwrap();
    engine.checkpoint().unwrap();
    assert!(
        engine.state.read().tables["items"]
            .indexes
            .values()
            .all(|index| index.delta.is_empty())
    );
    // A stale snapshot still owns its original index run after publication.
    assert_eq!(
        select_ids(&old, "SELECT id FROM items WHERE code = 'code-1'"),
        vec![1]
    );
    drop(old);
    drop(engine);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    let state = engine.state.read();
    assert!(
        state.tables["items"]
            .indexes
            .values()
            .all(|index| index.delta.is_empty())
    );
    assert_eq!(
        select_ids(&state, "SELECT id FROM items WHERE code = 'code-1'"),
        vec![2000]
    );
    assert_eq!(
        select_ids(&state, "SELECT id FROM items WHERE code = 'code-2'"),
        Vec::<i64>::new()
    );
    assert_eq!(
        select_ids(&state, "SELECT id FROM items WHERE bucket = 7 ORDER BY id"),
        vec![1, 2000]
    );
}

#[test]
#[ignore = "explicit large indexed-query acceptance fixture"]
fn indexed_count_and_deep_page_stream_past_old_candidate_cap_after_reopen() {
    const ROWS: usize = 100_001;
    let directory = tempdir().unwrap();
    let journal = TransactionJournal::open(directory.path()).unwrap();
    let engine = RelationalEngine::open(directory.path(), journal.clone()).unwrap();
    let audit = crate::audit::AuditWriter::open(directory.path()).unwrap();
    // Complete the same durable audit lifecycle as Db::execute_sql_owned.
    // Leaving low-level executions unaudited deliberately retains PREPAREs.
    let execute = |sql: &str| {
        let execution = engine.execute(request(sql)).unwrap();
        assert!(execution.projection_error.is_none());
        let transaction = execution.committed.as_ref().unwrap();
        let id = transaction.prepare.transaction_id;
        let before = journal.status(id);
        assert!(before.storage_projected);
        assert!(!before.audit_projected);
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
        audit
            .project_committed_transaction(id, &transaction.prepare.audit)
            .unwrap();
        journal.mark_projected(id, ProjectionKind::Audit).unwrap();
        let after = journal.status(id);
        assert!(after.storage_projected && after.audit_projected);
        assert_eq!(
            journal.completed_commit_frontier().unwrap(),
            after.commit_sequence
        );
    };
    execute("CREATE TABLE candidate_scale (id INTEGER PRIMARY KEY, bucket INTEGER)");
    execute("CREATE INDEX candidate_scale_bucket ON candidate_scale (bucket)");
    for start in (0..ROWS).step_by(512) {
        let values = (start..(start + 512).min(ROWS))
            .map(|id| format!("({id}, 1)"))
            .collect::<Vec<_>>()
            .join(", ");
        execute(&format!("INSERT INTO candidate_scale VALUES {values}"));
        if start % 8192 == 0 {
            engine.checkpoint().unwrap();
        }
    }
    engine.checkpoint().unwrap();
    assert_eq!(
        journal.completed_commit_frontier().unwrap(),
        Some(2 + ROWS.div_ceil(512) as u64)
    );
    crate::audit::verify_hash_chain(directory.path()).unwrap();
    audit.flush_and_shutdown().unwrap();
    drop(audit);
    drop(engine);
    drop(journal);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    let state = engine.state.read();
    assert_eq!(
        select_ids(
            &state,
            "SELECT COUNT(*) FROM candidate_scale WHERE bucket = 1"
        ),
        vec![ROWS as i64]
    );
    assert_eq!(
        select_ids(
            &state,
            "SELECT id FROM candidate_scale WHERE bucket = 1 LIMIT 1 OFFSET 100000"
        ),
        vec![100_000]
    );
}

#[test]
fn membership_deltas_match_independent_randomized_oracle_and_share_untouched_keys() {
    let directory = tempdir().unwrap();
    let mut index = ScalarIndex {
        id: 9,
        types: catalog::Types::copy(std::iter::once(&RelationalType::Integer).map(Ok)).unwrap(),
        delta: imbl::OrdMap::new(),
        memory: memory::Charge::default(),
    };
    let mut expected = (0..4).map(|_| BTreeSet::new()).collect::<Vec<_>>();
    let mut records = (1..=8192_u64)
        .map(|id| {
            let bucket = (id % 4) as usize;
            expected[bucket].insert(id);
            SegmentRecord {
                key: (encode_index_key_v1(
                    9,
                    &[(
                        &RelationalType::Integer,
                        &RelationalValue::Integer(bucket as i64),
                    )],
                    id,
                    1,
                )
                .unwrap())
                .into(),
                value: (serde_json::to_vec(&PersistedIndexVersion {
                    row_id: id,
                    begin: 1,
                    end: None,
                })
                .unwrap())
                .into(),
            }
        })
        .collect::<Vec<_>>();
    records.sort_by(|a, b| a.key.cmp(&b.key));
    let name = "base.rseg";
    let meta = write_segment(
        &directory.path().join(name),
        SegmentKind::Index,
        1,
        &records,
    )
    .unwrap();
    let backings = vec![
        TableSegmentBacking::open(directory.path(), &segment_reference(name.into(), &meta))
            .unwrap(),
    ];
    drop(records);
    index
        .set(4, &[&RelationalValue::Integer(0)], false)
        .unwrap();
    expected[0].remove(&4);
    assert_eq!(
        index
            .delta
            .values()
            .map(|members| members.len())
            .sum::<usize>(),
        1,
        "deleting one hot-key member must not copy its 2048 base postings"
    );
    let mut snapshot = index.clone();
    snapshot
        .set(2, &[&RelationalValue::Integer(2)], false)
        .unwrap();
    let zero_key = index.key(&[&RelationalValue::Integer(0)]).unwrap().unwrap();
    assert!(snapshot.delta[&zero_key].ptr_eq(&index.delta[&zero_key]));
    let frozen = index.clone();
    let frozen_expected = expected.clone();
    let mut random = 41_u64;
    for step in 0..1024 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let bucket = ((random >> 16) % 4) as usize;
        let id = (random >> 24) % 11_000 + 1;
        let present = random & 0x100 != 0;
        index
            .set(id, &[&RelationalValue::Integer(bucket as i64)], present)
            .unwrap();
        if present {
            expected[bucket].insert(id);
        } else {
            expected[bucket].remove(&id);
        }
        if step % 64 == 0 {
            for (bucket, expected) in expected.iter().enumerate() {
                assert_eq!(
                    &index
                        .lookup(&backings, 1, &[&RelationalValue::Integer(bucket as i64)])
                        .unwrap(),
                    expected
                );
            }
        }
    }
    assert!(index.has_duplicates(&backings, 1).unwrap());
    assert!(
        index
            .has_duplicate_key(&backings, 1, &[&RelationalValue::Integer(0)])
            .unwrap()
    );
    assert!(
        !index
            .has_duplicate_key(&backings, 1, &[&RelationalValue::Integer(9)])
            .unwrap()
    );
    assert!(
        !index
            .has_duplicate_key(&backings, 1, &[&RelationalValue::Null])
            .unwrap()
    );
    for (bucket, expected) in frozen_expected.iter().enumerate() {
        assert_eq!(
            &frozen
                .lookup(&backings, 1, &[&RelationalValue::Integer(bucket as i64)])
                .unwrap(),
            expected
        );
    }
    assert!(index.delta.len() <= 4);
    assert!(
        index
            .delta
            .values()
            .map(|members| members.len())
            .sum::<usize>()
            <= 1025
    );
    let actual_count = index
        .entries(&backings, 1, None)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap()
        .len();
    assert_eq!(
        actual_count,
        expected.iter().map(BTreeSet::len).sum::<usize>()
    );
}

#[test]
fn large_overlay_forks_share_keys_and_preserve_hot_key_membership() {
    let mut index = ScalarIndex {
        id: 9,
        types: catalog::Types::copy(std::iter::once(&RelationalType::Text).map(Ok)).unwrap(),
        delta: imbl::OrdMap::new(),
        memory: memory::Charge::default(),
    };
    let hot = RelationalValue::Text("hot".into());
    let cold = RelationalValue::Text(format!("cold:{}", "x".repeat(32 * 1024)));
    for id in 1..=16_384 {
        index.set(id, &[&hot], true).unwrap();
    }
    index.set(20_000, &[&cold], true).unwrap();
    for id in 30_000..31_024 {
        index
            .set(id, &[&RelationalValue::Text(format!("key-{id}"))], true)
            .unwrap();
    }
    let hot_key = index.key(&[&hot]).unwrap().unwrap();
    let cold_key = index.key(&[&cold]).unwrap().unwrap();
    let key_owner = Arc::downgrade(index.delta.get_key_value(&cold_key).unwrap().0);
    let frozen = index.clone();
    assert!(frozen.delta.ptr_eq(&index.delta));
    index.set(8192, &[&hot], false).unwrap();
    index.set(16_385, &[&hot], true).unwrap();
    assert!(!frozen.delta.ptr_eq(&index.delta));
    assert!(!frozen.delta[&hot_key].ptr_eq(&index.delta[&hot_key]));
    assert!(frozen.delta[&cold_key].ptr_eq(&index.delta[&cold_key]));
    for (key, members) in &frozen.delta {
        let (other_key, other_members) = index.delta.get_key_value(key).unwrap();
        assert!(Arc::ptr_eq(key, other_key));
        if key.as_ref() != &hot_key {
            assert!(members.ptr_eq(other_members));
        }
    }
    let expected: BTreeSet<_> = (1..=16_384).collect();
    assert_eq!(frozen.lookup(&[], 0, &[&hot]).unwrap(), expected);
    let mut changed = expected;
    changed.remove(&8192);
    changed.insert(16_385);
    assert_eq!(index.lookup(&[], 0, &[&hot]).unwrap(), changed);
    assert_eq!(
        index.lookup(&[], 0, &[&cold]).unwrap(),
        BTreeSet::from([20_000])
    );
    drop(index);
    assert!(key_owner.upgrade().is_some());
    drop(frozen);
    assert!(key_owner.upgrade().is_none());
}

#[test]
fn stale_checkpoint_cannot_discard_scalar_tombstones_or_install_old_ddl_indexes() {
    let directory = tempdir().unwrap();
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'old'), (2, 'two')"))
        .unwrap();
    engine.checkpoint().unwrap();
    let captured = capture_relational_checkpoint(
        &engine.state.read(),
        engine.wal.lock().unwrap().len().unwrap(),
    )
    .unwrap();
    engine
        .execute(request("UPDATE items SET code = 'new' WHERE id = 1"))
        .unwrap();
    engine
        .execute(request("DELETE FROM items WHERE id = 2"))
        .unwrap();
    engine.publish_checkpoint(&captured).unwrap();
    {
        let state = engine.state.read();
        assert_eq!(
            select_ids(&state, "SELECT id FROM items WHERE code = 'old'"),
            Vec::<i64>::new()
        );
        assert_eq!(
            select_ids(&state, "SELECT id FROM items WHERE code = 'two'"),
            Vec::<i64>::new()
        );
        assert_eq!(
            select_ids(&state, "SELECT id FROM items WHERE code = 'new'"),
            vec![1]
        );
        assert!(
            state.tables["items"]
                .indexes
                .values()
                .any(|index| !index.delta.is_empty())
        );
    }
    engine
        .execute(request("ALTER TABLE items RENAME COLUMN code TO label"))
        .unwrap();
    let (rebuilt_sequence, rebuilt_readers) = {
        let state = engine.state.read();
        let table = &state.tables["items"];
        assert!(!table.index_segments.is_empty());
        (
            table.index_snapshot,
            table
                .index_segments
                .iter()
                .map(|backing| Arc::downgrade(&backing.reader))
                .collect::<Vec<_>>(),
        )
    };
    engine.publish_checkpoint(&captured).unwrap();
    {
        let state = engine.state.read();
        let table = &state.tables["items"];
        assert_eq!(table.index_snapshot, rebuilt_sequence);
        assert_eq!(table.index_segments.len(), rebuilt_readers.len());
        for (backing, rebuilt) in table.index_segments.iter().zip(rebuilt_readers) {
            assert!(
                std::sync::Weak::ptr_eq(&Arc::downgrade(&backing.reader), &rebuilt),
                "stale catalog must preserve the exact rebuilt disk generation"
            );
        }
    }
    assert_eq!(
        select_ids(
            &engine.state.read(),
            "SELECT id FROM items WHERE label = 'new'"
        ),
        vec![1]
    );
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        select_ids(
            &engine.state.read(),
            "SELECT id FROM items WHERE label = 'new'"
        ),
        vec![1]
    );
}

#[test]
fn streaming_projection_validation_refuses_missing_extra_and_misbound_records() {
    let directory = tempdir().unwrap();
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
        ))
        .unwrap();
    engine
        .execute(request(
            "INSERT INTO items VALUES (1, 'one'), (2, 'two'), (3, NULL)",
        ))
        .unwrap();
    engine.checkpoint().unwrap();
    let state = engine.state.read();
    let table = &state.tables["items"];
    let records = index_segment_records(table).unwrap();
    assert_eq!(records.len(), 5);
    for case in 0..7 {
        let mut changed = records.clone();
        match case {
            0 => {
                changed.pop();
            }
            1 => {
                changed[0].key = changed[0]
                    .key
                    .test_edit(|key| key[3..11].copy_from_slice(&u64::MAX.to_be_bytes()));
            }
            2 => {
                changed[0].value = serde_json::to_vec(&PersistedIndexVersion {
                    row_id: 999,
                    begin: state.sequence,
                    end: None,
                })
                .unwrap()
                .into();
            }
            3 => {
                changed[0].value = changed[0].value.test_edit(|value| value.push(b' '));
            }
            4 => {
                let len = changed[0].key.len();
                changed[0].key = changed[0].key.test_edit(|key| key[len - 17] ^= 1);
            }
            5 => {
                let len = changed[0].key.len();
                changed[0].key = changed[0].key.test_edit(|key| key[len - 1] ^= 1);
            }
            6 => {
                let mut extra = records[0].clone();
                let len = extra.key.len();
                extra.key = extra.key.test_edit(|key| {
                    key[len - 16..len - 8].copy_from_slice(&999_u64.to_be_bytes())
                });
                extra.value = serde_json::to_vec(&PersistedIndexVersion {
                    row_id: 999,
                    begin: state.sequence,
                    end: None,
                })
                .unwrap()
                .into();
                changed.push(extra);
            }
            _ => unreachable!(),
        }
        changed.sort_by(|a, b| a.key.cmp(&b.key));
        let name = format!("invalid-{case}.rseg");
        let meta = write_segment(
            &directory.path().join(&name),
            SegmentKind::Index,
            state.sequence,
            &changed,
        )
        .unwrap();
        let reference = segment_reference(name, &meta);
        assert!(
            validate_projection(table, directory.path(), &[reference], state.sequence).is_err(),
            "case {case}"
        );
    }
    let name = "valid.rseg";
    let meta = write_segment(
        &directory.path().join(name),
        SegmentKind::Index,
        state.sequence,
        &records,
    )
    .unwrap();
    validate_projection(
        table,
        directory.path(),
        &[segment_reference(name.into(), &meta)],
        state.sequence,
    )
    .unwrap();
}

#[test]
fn cancelled_disk_index_stream_is_terminal() {
    let index = ScalarIndex {
        id: 9,
        types: catalog::Types::copy(std::iter::once(&RelationalType::Integer).map(Ok)).unwrap(),
        delta: imbl::OrdMap::new(),
        memory: memory::Charge::default(),
    };
    let cancellation = Arc::new(AtomicBool::new(false));
    with_sql_cancellation(Arc::clone(&cancellation), || {
        let mut entries = index.entries(&[], 0, None)?;
        cancellation.store(true, AtomicOrdering::Release);
        assert!(entries.next().unwrap().is_err());
        assert!(entries.next().is_none());
        Ok(())
    })
    .unwrap();
}

#[test]
fn disk_composite_constraints_preserve_canonical_equality_nulls_and_cascade() {
    let directory = tempdir().unwrap();
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    engine
        .execute(request(
            "CREATE TABLE parent (a TEXT, b NUMERIC(8,2), UNIQUE (a,b))",
        ))
        .unwrap();
    engine.execute(request("CREATE TABLE child (id INTEGER PRIMARY KEY, a TEXT, b NUMERIC(8,2), FOREIGN KEY (a,b) REFERENCES parent(a,b) ON UPDATE CASCADE ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED)")).unwrap();
    engine
        .execute(request(
            "CREATE TABLE moments (id INTEGER PRIMARY KEY, moment TIMESTAMPTZ UNIQUE)",
        ))
        .unwrap();
    engine
        .execute(request(
            "INSERT INTO parent VALUES ('alpha', 1.00), ('beta', 1), ('alpha', NULL)",
        ))
        .unwrap();
    engine
        .execute(request(
            "INSERT INTO child VALUES (1, 'alpha', 1.0), (2, 'alpha', NULL)",
        ))
        .unwrap();
    engine
        .execute(request(
            "INSERT INTO moments VALUES (1, '2026-09-25T00:00:00.000+00:00')",
        ))
        .unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    assert!(
        engine
            .execute(request("INSERT INTO parent VALUES ('alpha', 1.0)"))
            .is_err()
    );
    assert!(
        engine
            .execute(request("INSERT INTO child VALUES (3, 'missing', 1.0)"))
            .is_err()
    );
    assert!(
        engine
            .execute(request(
                "INSERT INTO moments VALUES (2, '2026-09-25T00:00:00Z')"
            ))
            .is_err()
    );
    engine
        .execute(request(
            "UPDATE parent SET a = 'moved', b = 2 WHERE a = 'alpha' AND b = 1.0",
        ))
        .unwrap();
    assert_eq!(
        select_ids(
            &engine.state.read(),
            "SELECT id FROM child WHERE a = 'moved' AND b = 2"
        ),
        vec![1]
    );
    engine.checkpoint().unwrap();
    drop(engine);
    let engine = RelationalEngine::open(
        directory.path(),
        TransactionJournal::open(directory.path()).unwrap(),
    )
    .unwrap();
    engine
        .execute(request("DELETE FROM parent WHERE a = 'moved'"))
        .unwrap();
    assert_eq!(
        select_ids(&engine.state.read(), "SELECT id FROM child ORDER BY id"),
        vec![2]
    );
}
