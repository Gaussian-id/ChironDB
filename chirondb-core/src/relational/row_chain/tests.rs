use super::*;
use crate::relational::memory::with_storage_pool;

fn version(begin: u64) -> RowVersion {
    RowVersion {
        begin,
        end: None,
        values: RowValues::copy(&[RelationalValue::Integer(1)]).unwrap(),
    }
}

#[test]
fn growth_reserves_both_blocks_and_refusal_preserves_the_chain() {
    let row = version(1);
    let slot = std::mem::size_of::<RowVersion>() as u64;
    // A four-slot result fits, but the old two-slot allocation must still be
    // admitted while the allocator grows it. Refuse before altering the chain.
    with_storage_pool(OWNER_BYTES + 5 * slot, |pool| {
        let mut chain = VersionChain::single(row.clone()).unwrap();
        chain.push(row.clone()).unwrap();
        let before = pool.used();
        let pointer = chain.as_ptr();
        assert!(matches!(
            chain.push(row.clone()),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(chain.as_ptr(), pointer);
        assert_eq!(chain.len(), 2);
        assert_eq!(pool.used(), before);
        drop(chain);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn snapshots_share_metadata_and_private_copies_keep_separate_reservations() {
    let row = version(1);
    with_storage_pool(64 * 1024, |pool| {
        let mut rows = RowStore::default();
        rows.insert(1, VersionChain::single(row.clone()).unwrap())
            .unwrap();
        let first = pool.used();
        let frozen = rows.clone();
        assert_eq!(pool.used(), first);
        let mut copied = rows.get(&1).unwrap().unwrap().into_owned().unwrap();
        copied[0].end = Some(2);
        copied.push(version_in_same_payload(&row, 2)).unwrap();
        rows.insert(1, copied).unwrap();
        assert!(pool.used() > first);
        assert_eq!(frozen.get(&1).unwrap().unwrap()[0].end, None);
        assert_eq!(rows.get(&1).unwrap().unwrap()[0].end, Some(2));
        drop(rows);
        assert_eq!(pool.used(), first);
        let held = frozen.get(&1).unwrap().unwrap().into_owned().unwrap();
        drop(frozen);
        assert_eq!(pool.used(), held.charge.bytes() + memory::LEASE_ROOT_BYTES);
        assert!(!held.is_empty());
        drop(held);
        assert_eq!(pool.used(), 0);
    });
}

fn version_in_same_payload(row: &RowVersion, begin: u64) -> RowVersion {
    RowVersion {
        begin,
        ..row.clone()
    }
}

#[test]
fn cancelled_growth_and_copy_return_all_metadata_quota() {
    let row = version(1);
    with_storage_pool(64 * 1024, |pool| {
        let mut chain = VersionChain::single(row.clone()).unwrap();
        let before = pool.used();
        let cancelled = Arc::new(AtomicBool::new(false));
        with_sql_cancellation(cancelled.clone(), || {
            cancelled.store(true, AtomicOrdering::Release);
            for error in [
                chain.push(row.clone()).unwrap_err(),
                VersionChain::copy(&chain).unwrap_err(),
            ] {
                assert!(error.to_string().contains("query canceled"), "{error}");
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(pool.used(), before);
        drop(chain);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn garbage_collection_refusal_keeps_versions_and_retention_frontier() {
    let mut old = version(1);
    old.end = Some(2);
    let current = RowVersion {
        begin: 2,
        end: None,
        values: old.values.clone(),
    };
    let mut rows = RowStore::default();
    let mut chain = VersionChain::single(old).unwrap();
    chain.push(current).unwrap();
    rows.insert(1, chain).unwrap();
    let before = rows.retained_bytes();
    let pointer = rows.get(&1).unwrap().unwrap().as_ptr();
    with_storage_pool(OWNER_BYTES, |pool| {
        assert!(matches!(
            rows.reclaim(2),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(rows.retention_frontier(), 0);
    assert_eq!(rows.retained_bytes(), before);
    assert_eq!(rows.get(&1).unwrap().unwrap().as_ptr(), pointer);
    assert_eq!(rows.reclaimable(2).unwrap(), 1);
    assert!(rows.visible(1, 1).unwrap().is_some());
    rows.reclaim(2).unwrap();
    assert_eq!(rows.retention_frontier(), 2);
    assert!(rows.visible(1, 1).unwrap().is_none());
    assert!(rows.visible(1, 2).unwrap().is_some());
    assert_eq!(
        rows.checkpoint_delta().count(),
        2,
        "ended physical version still needs its closure"
    );
}

#[test]
fn metadata_refusal_never_publishes_a_partial_mutation_or_index_change() {
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
    let directory = tempfile::tempdir().unwrap();
    let open = || {
        RelationalEngine::open(
            directory.path(),
            TransactionJournal::open(directory.path()).unwrap(),
        )
        .unwrap()
    };
    let engine = open();
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'original')"))
        .unwrap();
    let commits = engine.journal.committed().unwrap().len();
    let journal_file = engine.journal.dir().join("000000.gdwal");
    let journal_before = fs::read(&journal_file).unwrap();
    let before = engine
        .execute(request("SELECT * FROM items"))
        .unwrap()
        .response
        .results;
    with_storage_pool(OWNER_BYTES, |pool| {
        for sql in [
            "UPDATE items SET id = 2, body = 'changed'",
            "DELETE FROM items",
        ] {
            assert!(matches!(
                engine.execute(request(sql)),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(fs::read(&journal_file).unwrap(), journal_before);
            assert_eq!(pool.used(), 0);
        }
    });
    assert_eq!(engine.journal.committed().unwrap().len(), commits);
    assert_eq!(
        engine
            .execute(request("SELECT * FROM items WHERE id = 1"))
            .unwrap()
            .response
            .results,
        before
    );
    engine
        .execute(request("UPDATE items SET id = 2, body = 'changed'"))
        .unwrap();
    let after = engine
        .execute(request("SELECT * FROM items WHERE id = 2"))
        .unwrap()
        .response
        .results;
    drop(engine);
    let engine = open();
    assert_eq!(
        engine
            .execute(request("SELECT * FROM items WHERE id = 2"))
            .unwrap()
            .response
            .results,
        after
    );
}
