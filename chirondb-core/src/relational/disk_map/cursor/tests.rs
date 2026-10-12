use super::*;

#[test]
fn ordered_snapshot_survives_merges_and_map_drop_with_bounded_heads() {
    memory::with_storage_pool(8 * 1024 * 1024, |pool| {
        let parent = tempfile::tempdir().unwrap();
        let mut map = DiskMap::new(parent.path()).unwrap();
        let mut oracle = std::collections::BTreeMap::new();
        for batch_id in 0..7 {
            map.insert_batch(|batch| {
                for index in (0..33).rev() {
                    let key = format!("order-{index:03}-{batch_id}");
                    let value = index * 7 + batch_id;
                    batch.insert(key.as_bytes(), &value)?;
                    oracle.insert(key, value);
                }
                batch.insert(format!("other-{batch_id}").as_bytes(), &999_u64)
            })
            .unwrap();
        }
        let root = map.directory.path().to_path_buf();
        let mut cursor = map.prefix_cursor(b"order-").unwrap();
        map.insert_batch(|batch| batch.insert(b"order-new", &999_u64))
            .unwrap();
        map.publish_checkpoint(&8_u64).unwrap();
        drop(map);
        assert!(root.exists(), "scratch parent must remain pinned");
        let mut seen = std::collections::BTreeMap::new();
        for row in cursor.by_ref() {
            let row = row.unwrap();
            seen.insert(
                String::from_utf8(row.key().to_vec()).unwrap(),
                *row.decode::<u64>().unwrap(),
            );
        }
        assert_eq!(seen, oracle);
        assert!(cursor.next().is_none());
        assert!(!root.exists(), "EOF closes the last scratch layouts");
        drop(cursor);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn duplicate_keys_in_distinct_runs_fail_closed_and_fuse() {
    let parent = tempfile::tempdir().unwrap();
    let mut map = DiskMap::new(parent.path()).unwrap();
    map.insert_batch(|batch| batch.insert(b"key-1", &1_u64))
        .unwrap();
    map.insert_batch(|batch| batch.insert(b"key-2", &2_u64))
        .unwrap();
    // Level zero is now free, so this malformed insertion cannot meet the
    // earlier physical key until the snapshot merges its heads.
    map.insert_batch(|batch| batch.insert(b"key-1", &3_u64))
        .unwrap();
    let mut cursor = map.prefix_cursor(b"key-").unwrap();
    assert!(matches!(
        cursor.next().unwrap(),
        Err(GaussError::WalCorruption { .. })
    ));
    assert!(cursor.next().is_none());
}

#[test]
fn snapshot_admission_refuses_before_retaining_readers_and_preserves_map() {
    let parent = tempfile::tempdir().unwrap();
    let mut map = DiskMap::new(parent.path()).unwrap();
    map.insert_batch(|batch| batch.insert(b"one", &1_u64))
        .unwrap();
    memory::with_storage_pool(1, |pool| {
        assert!(matches!(
            map.prefix_cursor(b"one"),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
}

#[test]
fn cancellation_closes_shared_generations_and_fuses_without_a_temp_leak() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let parent = tempfile::tempdir().unwrap();
    let mut map = DiskMap::new(parent.path()).unwrap();
    map.insert_batch(|batch| batch.insert(b"one", &1_u64))
        .unwrap();
    let root = map.directory.path().to_path_buf();
    let mut cursor = map.prefix_cursor(b"one").unwrap();
    drop(map);
    assert!(root.exists());
    let cancel = Arc::new(AtomicBool::new(false));
    super::super::super::with_sql_cancellation(Arc::clone(&cancel), || {
        cancel.store(true, Ordering::Release);
        assert!(cursor.next().unwrap().is_err());
        assert!(cursor.next().is_none());
        assert!(!root.exists());
        Ok(())
    })
    .unwrap();
}
