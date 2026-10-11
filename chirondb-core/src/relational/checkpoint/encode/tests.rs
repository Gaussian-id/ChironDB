use super::*;
use crate::relational::memory::with_storage_pool;

fn fixture(count: usize) -> RelationalCheckpoint {
    RelationalCheckpoint {
        version: RELATIONAL_CHECKPOINT_VERSION,
        sequence: 1,
        next_catalog_id: 1,
        wal_watermark: 0,
        tables: Vec::new(),
        applied_transactions: (0..count).map(|_| TransactionId::new()).collect(),
        owned_memory: memory::Charge::default(),
    }
}

// Independent copy of the old plaintext representation, including its header.
fn legacy_bytes(checkpoint: &RelationalCheckpoint) -> Vec<u8> {
    let payload = serde_json::to_vec(checkpoint).unwrap();
    let mut output = RELATIONAL_CHECKPOINT_MAGIC.to_vec();
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    output.extend_from_slice(&payload);
    output
}

#[test]
fn bounded_output_preserves_checkpoint_bytes_across_multiple_chunks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    let mut checkpoint = fixture(4_000);
    let expected = legacy_bytes(&checkpoint);
    assert!(expected.len() > 2 * DEFAULT_CHUNK_SIZE);
    for version in [
        RELATIONAL_CHECKPOINT_LEGACY_VERSION,
        RELATIONAL_CHECKPOINT_RUNS_VERSION,
        RELATIONAL_CHECKPOINT_VERSION,
    ] {
        checkpoint.version = version;
        with_storage_pool(2 * 1024 * 1024, |pool| {
            write(&path, &checkpoint).unwrap();
            assert_eq!(pool.used(), 0);
        });
        let file = PersistentFile::open(&path).unwrap();
        assert_eq!(
            file.read_range(0..file.len()).unwrap(),
            legacy_bytes(&checkpoint)
        );
        let decoded = read_relational_checkpoint(&path).unwrap().unwrap();
        assert!(decoded.applied_transactions.is_empty());
        assert_eq!(decoded.sequence, checkpoint.sequence);
    }
}

#[test]
fn output_quota_refusal_preserves_existing_file_and_leaves_no_staging_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    let checkpoint = fixture(20_000);
    for existing in [false, true] {
        if existing {
            fs::write(&path, b"previous generation").unwrap();
        }
        for capacity in [STREAM_SCRATCH_BYTES - 1, STREAM_SCRATCH_BYTES + 8192] {
            with_storage_pool(capacity, |pool| {
                assert!(matches!(
                    write(&path, &checkpoint),
                    Err(GaussError::ResourceExhausted(_))
                ));
                assert_eq!(pool.used(), 0);
            });
            if existing {
                assert_eq!(fs::read(&path).unwrap(), b"previous generation");
            } else {
                assert!(!path.exists());
            }
            assert_eq!(
                fs::read_dir(directory.path()).unwrap().count(),
                usize::from(existing)
            );
        }
    }
}

#[test]
fn cancelled_checkpoint_does_not_replace_the_file_or_reserve_memory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    fs::write(&path, b"previous generation").unwrap();
    let checkpoint = fixture(1);
    with_storage_pool(1, |pool| {
        let error = with_sql_cancellation(Arc::new(AtomicBool::new(true)), || {
            write(&path, &checkpoint)
        })
        .unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert_eq!(pool.used(), 0);
        assert_eq!(fs::read(&path).unwrap(), b"previous generation");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    });
}

#[test]
fn cancellation_is_checked_between_persistence_chunks() {
    let data = vec![7; 3 * DEFAULT_CHUNK_SIZE];
    let mut output = vec![0; data.len()];
    let cancel = Arc::new(AtomicBool::new(false));
    with_sql_cancellation(cancel.clone(), || {
        let mut input = CancelReader(data.as_slice());
        let first = input.read(&mut output).unwrap();
        assert_eq!(first, DEFAULT_CHUNK_SIZE);
        cancel.store(true, AtomicOrdering::Release);
        let error = input.read(&mut output[first..]).unwrap_err();
        assert!(error.to_string().contains("query canceled"));
        assert!(output[first..].iter().all(|byte| *byte == 0));
        Ok(())
    })
    .unwrap();
}

#[cfg(feature = "fault-injection")]
#[test]
fn publication_faults_preserve_complete_old_or_new_checkpoint_and_release_quota() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    let old = fixture(1);
    let new = fixture(4_000);
    for (point, expected) in [
        ("atomic.before_temp_sync", &old),
        ("atomic.after_temp_sync", &old),
        ("atomic.after_rename_before_dir_sync", &new),
    ] {
        write(&path, &old).unwrap();
        let fault = crate::failpoint::test_env(
            &format!("error:{point}"),
            &directory.path().join("unused-marker"),
            &directory.path().join("unused-release"),
        );
        with_storage_pool(2 * 1024 * 1024, |pool| {
            let error = write(&path, &new).unwrap_err();
            assert!(error.to_string().contains(point), "{error}");
            assert_eq!(pool.used(), 0);
        });
        drop(fault);
        assert_eq!(fs::read(&path).unwrap(), legacy_bytes(expected));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        let checkpoint = read_relational_checkpoint(&path).unwrap().unwrap();
        assert!(checkpoint.applied_transactions.is_empty());
        assert_eq!(checkpoint.sequence, expected.sequence);
    }
}
