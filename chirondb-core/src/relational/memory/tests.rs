use super::super::*;
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

fn count(engine: &RelationalEngine) -> i64 {
    let response = engine
        .execute(request("SELECT COUNT(*) FROM items"))
        .unwrap()
        .response;
    let SqlResult::Rows { rows, .. } = &response.results[0] else {
        unreachable!()
    };
    let RelationalValue::Integer(value) = rows[0][0] else {
        unreachable!()
    };
    value
}

#[test]
fn storage_reader_reservation_follows_shared_cursor_lifetime() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    let records = vec![SegmentRecord {
        key: (vec![1]).into(),
        value: (vec![2; 4096]).into(),
    }];
    write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
    with_storage_pool(1024 * 1024, |pool| {
        let reader = segment::SegmentReader::open(&path).unwrap();
        let used = pool.used();
        assert!(
            used > 0,
            "persisted metadata must retain an aggregate reservation"
        );
        let mut cursor = reader.cursor();
        let prefix = reader.prefix_cursor(&[1]).unwrap();
        let with_prefix = pool.used();
        assert!(
            with_prefix > used,
            "prefix bytes own a separate reservation"
        );
        drop(reader);
        assert_eq!(pool.used(), with_prefix);
        assert!(cursor.next().unwrap().is_ok());
        drop(cursor);
        assert_eq!(pool.used(), with_prefix);
        drop(prefix);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn storage_writer_metadata_remains_reserved_until_result_drop() {
    let directory = tempdir().unwrap();
    let records = vec![SegmentRecord {
        key: (vec![1]).into(),
        value: (vec![2]).into(),
    }];
    with_storage_pool(1024 * 1024, |pool| {
        let metadata = write_segment(
            &directory.path().join("rows.rseg"),
            SegmentKind::Row,
            1,
            &records,
        )
        .unwrap();
        assert!(
            pool.used() > 0,
            "returned writer metadata must own its reservation"
        );
        assert_eq!(metadata.record_count, 1);
        drop(metadata);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn storage_admission_rejects_before_metadata_allocation_and_retries_cleanly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    let output = directory.path().join("refused.rseg");
    let records = vec![SegmentRecord {
        key: (vec![1]).into(),
        value: (vec![2; 4096]).into(),
    }];
    write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
    let before = fs::read(&path).unwrap();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            segment::SegmentReader::open(&path),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
        assert!(matches!(
            write_segment(&output, SegmentKind::Row, 1, &records),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
        assert!(!output.exists());
    });
    assert_eq!(fs::read(&path).unwrap(), before);
    with_storage_pool(1024 * 1024, |pool| {
        let cursor = segment::SegmentCursor::open(&path).unwrap();
        assert_eq!(cursor.collect::<Result<Vec<_>>>().unwrap(), records);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn storage_concurrent_readers_share_one_aggregate_budget() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("rows.rseg");
    write_segment(
        &path,
        SegmentKind::Row,
        1,
        &[SegmentRecord {
            key: (vec![1]).into(),
            value: (vec![2]).into(),
        }],
    )
    .unwrap();
    with_storage_pool(32 * 1024, |pool| {
        let start = Arc::new(std::sync::Barrier::new(16));
        let held = Arc::new(std::sync::Barrier::new(16));
        let workers = (0..16)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let path = path.clone();
                let start = Arc::clone(&start);
                let held = Arc::clone(&held);
                std::thread::spawn(move || {
                    TEST_STORAGE_POOL.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&pool)));
                    start.wait();
                    let result = segment::SegmentReader::open(&path);
                    assert!(pool.used() <= 32 * 1024);
                    held.wait();
                    match result {
                        Ok(reader) => {
                            assert_eq!(
                                reader.cursor().collect::<Result<Vec<_>>>().unwrap().len(),
                                1
                            );
                            true
                        }
                        Err(GaussError::ResourceExhausted(_)) => false,
                        Err(error) => panic!("unexpected reader error: {error}"),
                    }
                })
            })
            .collect::<Vec<_>>();
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert!(accepted > 0 && accepted < 16);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn storage_sort_refusal_preserves_buffer_and_releases_after_spill() {
    let directory = tempdir().unwrap();
    with_storage_pool(64 * 1024, |pool| {
        let mut sorter = checkpoint::sort::Sorter::locator(directory.path(), 1).unwrap();
        sorter
            .push(SegmentRecord {
                key: (vec![1]).into(),
                value: (vec![1; 1024]).into(),
            })
            .unwrap();
        let retained = pool.used();
        assert!(retained >= 1024 * std::mem::size_of::<SegmentRecord>() as u64 + 1024);
        assert!(matches!(
            SegmentRecord::json(vec![2], &"x".repeat(64 * 1024)),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), retained);
        sorter
            .push(SegmentRecord {
                key: (vec![3]).into(),
                value: (vec![3; 1024]).into(),
            })
            .unwrap();
        let sorted = sorter.finish().unwrap();
        assert_eq!(
            pool.used(),
            0,
            "sort buffers and writer metadata have dropped"
        );
        let reader = sorted.into_reader().unwrap();
        assert!(pool.used() > 0);
        assert_eq!(
            reader
                .cursor()
                .map(|record| record.unwrap().key)
                .collect::<Vec<_>>(),
            [vec![1], vec![3]]
        );
        drop(reader);
        assert_eq!(pool.used(), 0);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    });
}

#[test]
fn storage_failure_preserves_ddl_checkpoint_and_reopen_authority() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'one')"))
        .unwrap();
    engine.checkpoint().unwrap();
    let before = fs::read(&engine.checkpoint_path).unwrap();
    let commits = engine.journal.committed().unwrap().len();
    let journal_file = engine.journal.dir().join("000000.gdwal");
    let journal_before = fs::read(&journal_file).unwrap();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            engine.execute(request("CREATE INDEX by_body ON items (body)")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(fs::read(&journal_file).unwrap(), journal_before);
        assert!(matches!(
            engine.execute(request("SELECT COUNT(*) FROM items")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(engine.journal.committed().unwrap().len(), commits);
    assert_eq!(count(&engine), 1);
    engine
        .execute(request("INSERT INTO items VALUES (2, 'two')"))
        .unwrap();
    with_storage_pool(1, |pool| {
        assert!(matches!(
            engine.checkpoint(),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(fs::read(&engine.checkpoint_path).unwrap(), before);
        assert!(matches!(
            engine.execute(request("SELECT COUNT(*) FROM items")),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(count(&engine), 2);
    drop(engine);
    with_storage_pool(1, |pool| {
        assert!(matches!(
            TransactionJournal::open(directory.path())
                .and_then(|journal| RelationalEngine::open(directory.path(), journal)),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(
            fs::read(directory.path().join(RELATIONAL_CHECKPOINT_FILE)).unwrap(),
            before
        );
        assert_eq!(pool.used(), 0);
    });
    let engine = open(directory.path());
    assert_eq!(count(&engine), 2);
    engine
        .execute(request("CREATE INDEX by_body ON items (body)"))
        .unwrap();
    engine.checkpoint().unwrap();
    drop(engine);
    assert_eq!(count(&open(directory.path())), 2);
}

#[test]
fn storage_metadata_errors_release_reader_and_writer_reservations() {
    use std::io::{Seek, SeekFrom, Write};
    let directory = tempdir().unwrap();
    let path = directory.path().join("bad.rseg");
    let records = vec![SegmentRecord {
        key: (vec![1]).into(),
        value: (vec![2]).into(),
    }];
    write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(56)).unwrap();
    file.write_all(b"!").unwrap();
    file.sync_all().unwrap();
    drop(file);
    with_storage_pool(1024 * 1024, |pool| {
        assert!(matches!(
            segment::SegmentReader::open(&path),
            Err(GaussError::SegmentCorruption { .. })
        ));
        assert_eq!(pool.used(), 0);
        let output = directory.path().join("duplicate.rseg");
        let duplicate = [records[0].clone(), records[0].clone()];
        assert!(write_segment(&output, SegmentKind::Row, 1, &duplicate).is_err());
        assert!(!output.exists());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn storage_admission_preserves_enforced_encryption_and_releases_on_refusal() {
    const CHILD: &str = "CHIRONDB_STORAGE_ADMISSION_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "relational::memory::tests::storage_admission_preserves_enforced_encryption_and_releases_on_refusal",
                "--nocapture",
            ])
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
    serde_json::to_writer(&mut key, &serde_json::json!({
        "version": 1, "active_key_id": "test",
        "keys": [{"id": "test", "key_base64": base64::engine::general_purpose::STANDARD.encode([17u8; 32])}],
    })).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let path = directory.path().join("encrypted.rseg");
    let records = vec![SegmentRecord {
        key: (b"private-key-marker".to_vec()).into(),
        value: (vec![2; 4096]).into(),
    }];
    with_storage_pool(1024 * 1024, |pool| {
        let written = write_segment(&path, SegmentKind::Row, 1, &records).unwrap();
        assert!(pool.used() > 0);
        drop(written);
        assert_eq!(pool.used(), 0);
        let reader = segment::SegmentReader::open(&path).unwrap();
        assert!(pool.used() > 0);
        assert_eq!(
            reader.cursor().collect::<Result<Vec<_>>>().unwrap(),
            records
        );
        drop(reader);
        assert_eq!(pool.used(), 0);
    });
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"CHIRENC1"));
    assert!(
        !bytes
            .windows(records[0].key.len())
            .any(|part| part == records[0].key.as_slice())
    );
    with_storage_pool(1, |pool| {
        assert!(matches!(
            segment::SegmentReader::open(&path),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(pool.used(), 0);
    });
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn shared_reservations_refuse_same_size_forks_and_release_on_drop() {
    with_pool(128 + LEASE_ROOT_BYTES, |pool| {
        let mut charge = Charge::default();
        charge.prepare(96).unwrap();
        let frozen = charge.clone();
        assert_eq!(pool.used(), 96 + LEASE_ROOT_BYTES);
        assert!(matches!(
            charge.prepare(96),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert_eq!(charge.bytes(), 96);
        assert_eq!(pool.used(), 96 + LEASE_ROOT_BYTES);
        drop(frozen);
        charge.prepare(128).unwrap();
        assert!(charge.prepare(u64::MAX).is_err());
        assert_eq!(pool.used(), 128 + LEASE_ROOT_BYTES);
        charge.prepare(32).unwrap();
        assert_eq!(pool.used(), 32 + LEASE_ROOT_BYTES);
        charge.clear();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn concurrent_reservations_never_oversubscribe_capacity() {
    let pool = Arc::new(Pool::new(64));
    let start = Arc::new(std::sync::Barrier::new(16));
    let finish = Arc::new(std::sync::Barrier::new(16));
    let workers = (0..16)
        .map(|_| {
            let pool = Arc::clone(&pool);
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            std::thread::spawn(move || {
                start.wait();
                let lease = pool.acquire(64).ok().map(|()| Lease {
                    pool: Arc::clone(&pool),
                    bytes: 64,
                    root: 0,
                });
                assert!(pool.used() <= 64);
                finish.wait();
                usize::from(lease.is_some())
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .sum::<usize>(),
        1
    );
    assert_eq!(pool.used(), 0);
}

#[test]
fn row_admission_failure_preserves_values_and_gc_frontier() {
    with_pool(64 * 1024, |pool| {
        let mut rows = RowStore::default();
        rows.insert(
            1,
            VersionChain::single(RowVersion {
                begin: 1,
                end: None,
                values: RowValues::adopt(vec![RelationalValue::Text("x".repeat(32 * 1024))])
                    .unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
        let frozen = rows.clone();
        let before = pool.used();
        assert!(matches!(
            rows.insert(
                1,
                VersionChain::single(RowVersion {
                    begin: 2,
                    end: None,
                    values: RowValues::adopt(vec![RelationalValue::Text("y".repeat(32 * 1024))])
                        .unwrap()
                })
                .unwrap()
            ),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(rows.can_install_base(1));
        assert_eq!(pool.used(), before);
        assert!(rows.reclaim(2).is_err());
        assert_eq!(rows.retention_frontier(), 0);
        assert_eq!(
            rows.visible(1, 1).unwrap().unwrap().values,
            frozen.visible(1, 1).unwrap().unwrap().values
        );
        drop(frozen);
        rows.insert(
            1,
            VersionChain::single(RowVersion {
                begin: 2,
                end: None,
                values: RowValues::adopt(vec![RelationalValue::Text("small".into())]).unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(pool.used() < before);
        drop(rows);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn byte_trigger_flushes_before_commit_count_interval_and_reopens() {
    let directory = tempdir().unwrap();
    with_pool(1024 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        for id in 1..=32 {
            engine
                .execute(request(&format!(
                    "INSERT INTO items VALUES ({id}, '{}')",
                    "x".repeat(2048)
                )))
                .unwrap();
            assert!(engine.state.read().retained_bytes() < flush_threshold());
        }
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert!(checkpoint.sequence < RELATIONAL_CHECKPOINT_INTERVAL);
        assert!(checkpoint.sequence > 1);
        assert_eq!(count(&engine), 32);
        drop(engine);
        assert_eq!(pool.used(), 0);
        let reopened = open(directory.path());
        assert_eq!(count(&reopened), 32);
        drop(reopened);
        assert_eq!(pool.used(), 0);
    });
}

fn seed_uncheckpointed(path: &Path, batch: bool) {
    let engine = open(path);
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    let body = "x".repeat(2048);
    if batch {
        let values = (1..=64)
            .map(|id| format!("({id}, '{body}')"))
            .collect::<Vec<_>>()
            .join(",");
        engine
            .execute(request(&format!("INSERT INTO items VALUES {values}")))
            .unwrap();
    } else {
        for id in 1..=64 {
            engine
                .execute(request(&format!(
                    "INSERT INTO items VALUES ({id}, '{body}')"
                )))
                .unwrap();
        }
    }
    assert!(!engine.checkpoint_path.exists());
}

#[test]
fn restart_flushes_a_wal_tail_larger_than_the_retained_pool() {
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), false);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        assert!(engine.state.read().retained_bytes() < flush_threshold());
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert!(checkpoint.sequence > 1);
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 64);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn restart_stages_one_committed_batch_larger_than_the_retained_pool() {
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), true);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        assert!(engine.state.read().retained_bytes() < flush_threshold());
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 64);
    });
}

#[test]
fn staged_batch_replaces_keys_and_deletes_rows_created_in_the_same_commit() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    let values = (1..=64)
        .map(|id| format!("({id}, '{}')", "x".repeat(2048)))
        .collect::<Vec<_>>()
        .join(",");
    let sql = [
        format!("INSERT INTO items VALUES {values}"),
        "UPDATE items SET id = 1064 WHERE id = 64".into(),
        "UPDATE items SET body = 'changed' WHERE id > 32".into(),
        "DELETE FROM items WHERE id <= 32".into(),
    ];
    let batch_request = SqlExecutionRequest {
        statements: sql
            .into_iter()
            .map(|sql| crate::SqlStatementRequest {
                sql,
                parameters: vec![],
            })
            .collect(),
        idempotency_key: None,
        retry_id: None,
    };
    engine.execute(batch_request).unwrap();
    drop(engine);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 32);
        let response = engine
            .execute(request("SELECT id, body FROM items ORDER BY id"))
            .unwrap()
            .response;
        let SqlResult::Rows { rows, .. } = &response.results[0] else {
            unreachable!()
        };
        assert_eq!(
            rows,
            &(33..=63)
                .chain([1064])
                .map(|id| vec![
                    RelationalValue::Integer(id),
                    RelationalValue::Text("changed".into())
                ])
                .collect::<Vec<_>>()
        );
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 32);
    });
}

#[test]
fn interactive_snapshots_cause_precommit_refusal_and_release_capacity_on_rollback() {
    let directory = tempdir().unwrap();
    with_pool(512 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        let body = "x".repeat(2048);
        engine.execute(request(&format!("INSERT INTO items VALUES (1, '{body}'), (2, '{body}'), (3, '{body}'), (4, '{body}')"))).unwrap();
        let owner = AuditContext::embedded();
        let mut handles = Vec::new();
        let mut refused = false;
        for step in 0..40 {
            handles.push(engine.begin_interactive(&owner).unwrap().handle);
            let before_sequence = engine.state.read().sequence;
            let before_commits = engine.journal.committed().unwrap().len();
            let result = engine.execute(request(&format!(
                "UPDATE items SET body = '{step}:{body}' WHERE id = 1"
            )));
            if matches!(result, Err(GaussError::ResourceExhausted(_))) {
                assert_eq!(engine.state.read().sequence, before_sequence);
                assert_eq!(engine.journal.committed().unwrap().len(), before_commits);
                refused = true;
                break;
            }
            result.unwrap();
        }
        assert!(
            refused,
            "old snapshots must remain admitted until explicitly retired"
        );
        let reserved = pool.used();
        for handle in handles {
            engine.rollback_interactive(&handle, &owner).unwrap();
        }
        assert!(pool.used() < reserved);
        engine
            .execute(request(
                "UPDATE items SET body = 'after release' WHERE id = 1",
            ))
            .unwrap();
        engine.checkpoint().unwrap();
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&engine), 4);
        drop(engine);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn checkpoint_failure_preserves_acknowledged_writes_and_eventually_applies_backpressure() {
    let directory = tempdir().unwrap();
    with_pool(512 * 1024, |pool| {
        let engine = open(directory.path());
        engine
            .execute(request(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
            ))
            .unwrap();
        let mut acknowledged = 0;
        {
            let _fault = crate::failpoint::test_env(
                "error:relational_checkpoint.after_segments",
                &directory.path().join("marker"),
                &directory.path().join("release"),
            );
            for id in 1..=128 {
                let before_commits = engine.journal.committed().unwrap().len();
                match engine.execute(request(&format!(
                    "INSERT INTO items VALUES ({id}, '{}')",
                    "x".repeat(2048)
                ))) {
                    Ok(execution) => {
                        assert!(execution.response.committed);
                        acknowledged += 1;
                    }
                    Err(GaussError::ResourceExhausted(_)) => {
                        assert_eq!(engine.journal.committed().unwrap().len(), before_commits);
                        break;
                    }
                    Err(error) => panic!("unexpected rejection: {error}"),
                }
            }
        }
        assert!(acknowledged > 4 && acknowledged < 128);
        assert_eq!(count(&engine), acknowledged);
        drop(engine);
        assert_eq!(pool.used(), 0);
        let engine = open(directory.path());
        assert_eq!(count(&engine), acknowledged);
        engine
            .execute(request("INSERT INTO items VALUES (1000, 'after restart')"))
            .unwrap();
        assert_eq!(count(&engine), acknowledged + 1);
        drop(engine);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn staged_batch_failure_never_publishes_a_partial_transaction_and_cleans_orphans() {
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), true);
    with_pool(128 * 1024, |pool| {
        {
            let _fault = crate::failpoint::test_env(
                "error:relational_recovery.after_staged_segments",
                &directory.path().join("marker"),
                &directory.path().join("release"),
            );
            assert!(
                RelationalEngine::open(
                    directory.path(),
                    TransactionJournal::open(directory.path()).unwrap()
                )
                .is_err()
            );
        }
        assert!(!directory.path().join(RELATIONAL_CHECKPOINT_FILE).exists());
        assert_eq!(pool.used(), 0);
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        let checkpoint = read_relational_checkpoint(&engine.checkpoint_path)
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.sequence, 2);
        let files = fs::read_dir(directory.path().join(RELATIONAL_SEGMENT_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".rseg"))
            .collect::<HashSet<_>>();
        assert_eq!(files, checkpoint_segment_names(&checkpoint));
        drop(engine);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn committed_row_rewrite_replays_in_private_chunks() {
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), true);
    let engine = open(directory.path());
    engine
        .execute(request(
            "ALTER TABLE items ADD COLUMN state TEXT NOT NULL DEFAULT 'ready'",
        ))
        .unwrap();
    assert!(!engine.checkpoint_path.exists());
    drop(engine);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        let result = engine
            .execute(request("SELECT state FROM items WHERE id = 64"))
            .unwrap()
            .response;
        assert!(
            matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Text("ready".into())]])
        );
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 64);
    });
}

#[test]
fn recovery_spills_use_encrypted_runs_and_reopen_without_plaintext() {
    const CHILD: &str = "CHIRONDB_RETAINED_MEMORY_ENCRYPTED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relational::memory::tests::recovery_spills_use_encrypted_runs_and_reopen_without_plaintext", "--nocapture"])
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
    serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([11u8;32])}]})).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(key.path()).unwrap(),
        true,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), true);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        let mut paths = fs::read_dir(directory.path().join(RELATIONAL_SEGMENT_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        while let Some(path) = paths.pop() {
            if path.is_dir() {
                paths.extend(
                    fs::read_dir(path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
                continue;
            }
            let bytes = fs::read(path).unwrap();
            assert!(bytes.starts_with(b"CHIRENC1"));
            assert!(!bytes.windows(64).any(|window| window == [b'x'; 64]));
        }
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 64);
    });
}

#[test]
fn legacy_add_column_update_image_replays_as_one_schema_generation() {
    let directory = tempdir().unwrap();
    seed_uncheckpointed(directory.path(), true);
    let engine = open(directory.path());
    let state = engine.state.read();
    let table = &state.tables["items"];
    let mut definition = table.definition.as_ref().clone();
    let mut column = definition.columns[1].clone();
    column.name = "state".into();
    column.nullable = false;
    column.default = Some(RelationalValue::Text("ready".into()));
    definition.columns.push(column);
    let rows = table
        .rows
        .visible_rows(state.sequence)
        .map(|row| {
            let (row_id, source) = row.unwrap();
            let mut values = source.to_vec();
            values.push(RelationalValue::Text("ready".into()));
            StoredRow { row_id, values }
        })
        .collect();
    let mutation = WalEntry::RelationalBatch {
        batch: RelationalBatch {
            sequence: state.sequence + 1,
            mutations: vec![
                RelationalMutation::AlterTable { definition },
                RelationalMutation::Update {
                    table: "items".into(),
                    rows,
                },
            ],
        },
    };
    drop(state);
    let committed = engine
        .journal
        .commit(
            TransactionTarget::Relational,
            mutation.clone(),
            TransactionAudit::mutation(
                "sql_transaction",
                None,
                &AuditContext::embedded(),
                serde_json::json!({"fixture":"legacy-add-column"}),
            ),
        )
        .unwrap();
    engine
        .wal
        .lock()
        .unwrap()
        .append(&WalEntry::TransactionApply {
            transaction_id: committed.prepare.transaction_id,
            entry: Box::new(mutation),
        })
        .unwrap();
    engine
        .journal
        .mark_projected(committed.prepare.transaction_id, ProjectionKind::Storage)
        .unwrap();
    drop(engine);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 64);
        let result = engine
            .execute(request("SELECT state FROM items WHERE id = 64"))
            .unwrap()
            .response;
        assert!(
            matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Text("ready".into())]])
        );
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 64);
    });
}

#[test]
fn added_column_checkpoint_keeps_an_old_reader_on_its_original_schema() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    engine
        .execute(request("INSERT INTO items VALUES (1, 'old')"))
        .unwrap();
    let owner = AuditContext::embedded();
    let handle = engine.begin_interactive(&owner).unwrap().handle;
    engine
        .execute(request(
            "ALTER TABLE items ADD COLUMN state TEXT NOT NULL DEFAULT 'ready'",
        ))
        .unwrap();
    engine.checkpoint().unwrap();
    let old = engine
        .execute_interactive(&handle, request("SELECT id, body FROM items"), &owner)
        .unwrap();
    assert!(
        matches!(&old.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Integer(1), RelationalValue::Text("old".into())]])
    );
    engine.rollback_interactive(&handle, &owner).unwrap();
    drop(engine);
    let engine = open(directory.path());
    let result = engine
        .execute(request("SELECT state FROM items"))
        .unwrap()
        .response;
    assert!(
        matches!(&result.results[0], SqlResult::Rows { rows, .. } if rows == &vec![vec![RelationalValue::Text("ready".into())]])
    );
}

#[test]
fn staged_insert_then_delete_all_does_not_resurrect_and_keeps_row_id_frontier() {
    let directory = tempdir().unwrap();
    let engine = open(directory.path());
    engine
        .execute(request(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)",
        ))
        .unwrap();
    let values = (1..=64)
        .map(|id| format!("({id}, '{}')", "x".repeat(2048)))
        .collect::<Vec<_>>()
        .join(",");
    let mut batch = request(&format!("INSERT INTO items VALUES {values}"));
    batch.statements.push(crate::SqlStatementRequest {
        sql: "DELETE FROM items".into(),
        parameters: vec![],
    });
    engine.execute(batch).unwrap();
    drop(engine);
    with_pool(128 * 1024, |pool| {
        let engine = open(directory.path());
        assert_eq!(count(&engine), 0);
        assert_eq!(engine.state.read().tables["items"].next_row_id, 65);
        engine
            .execute(request("INSERT INTO items VALUES (1, 'reused public key')"))
            .unwrap();
        assert_eq!(count(&engine), 1);
        engine.checkpoint().unwrap();
        drop(engine);
        assert_eq!(pool.used(), 0);
        assert_eq!(count(&open(directory.path())), 1);
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn interrupted_recovery_keeps_a_complete_prefix_and_replays_the_suffix() {
    for boundary in ["after_segments", "after_manifest"] {
        let directory = tempdir().unwrap();
        seed_uncheckpointed(directory.path(), false);
        with_pool(128 * 1024, |pool| {
            {
                let _fault = crate::failpoint::test_env(
                    &format!("error:relational_recovery.{boundary}"),
                    &directory.path().join("marker"),
                    &directory.path().join("release"),
                );
                assert!(
                    RelationalEngine::open(
                        directory.path(),
                        TransactionJournal::open(directory.path()).unwrap()
                    )
                    .is_err()
                );
            }
            assert_eq!(pool.used(), 0);
            let engine = open(directory.path());
            assert_eq!(count(&engine), 64, "{boundary}");
            assert!(engine.state.read().retained_bytes() < flush_threshold());
            drop(engine);
            assert_eq!(pool.used(), 0);
        });
    }
}

#[test]
fn empty_controllers_allocate_no_lease_and_refuse_before_first_root() {
    with_storage_pool(LEASE_ROOT_BYTES, |pool| {
        let mut empty = Charge::storage();
        let clone = empty.clone();
        assert!(empty.lease.is_none() && clone.lease.is_none());
        empty.prepare(0).unwrap();
        assert!(empty.lease.is_none());
        assert!(matches!(
            empty.prepare(1),
            Err(GaussError::ResourceExhausted(_))
        ));
        assert!(empty.lease.is_none());
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn controller_root_is_shared_and_zero_payload_releases_only_its_owner() {
    with_storage_pool(LEASE_ROOT_BYTES + 10, |pool| {
        let mut charge = Charge::storage();
        charge.prepare(10).unwrap();
        assert_eq!(pool.used(), LEASE_ROOT_BYTES + 10);
        let shared = charge.clone();
        assert_eq!(pool.used(), LEASE_ROOT_BYTES + 10);
        assert!(charge.prepare(10).is_err());
        charge.prepare(0).unwrap();
        assert!(charge.lease.is_none());
        assert_eq!(pool.used(), LEASE_ROOT_BYTES + 10);
        drop(shared);
        assert_eq!(pool.used(), 0);
        charge.prepare(1).unwrap();
        assert_eq!(pool.used(), LEASE_ROOT_BYTES + 1);
        charge.prepare(0).unwrap();
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn empty_controller_preserves_its_original_pool_after_scope_exit() {
    let (mut charge, pool) =
        with_storage_pool(LEASE_ROOT_BYTES + 1, |pool| (Charge::storage(), pool));
    assert!(charge.lease.is_none());
    with_storage_pool(1, |other| {
        charge.prepare(1).unwrap();
        assert_eq!(pool.used(), LEASE_ROOT_BYTES + 1);
        assert_eq!(other.used(), 0);
        let mut fresh = charge.empty_in_same_pool();
        assert!(fresh.prepare(1).is_err());
        drop(charge);
        fresh.prepare(1).unwrap();
        drop(fresh);
        assert_eq!(pool.used(), 0);
    });
}

#[test]
fn initial_controller_admission_overflow_preserves_empty_state() {
    with_storage_pool(u64::MAX, |pool| {
        let mut charge = Charge::storage();
        assert!(charge.prepare(u64::MAX).is_err());
        assert!(charge.lease.is_none());
        assert_eq!(charge.bytes(), 0);
        assert_eq!(pool.used(), 0);
    });
}
