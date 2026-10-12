use super::*;

fn generation(parent: &Path) -> PathBuf {
    let root = parent.join(DIRECTORY);
    let bytes = fs::read(root.join("CURRENT")).unwrap();
    let manifest: Manifest<u64> =
        serde_json::from_slice(crate::security::storage::decode_metadata(MAGIC, &bytes).unwrap())
            .unwrap();
    root.join(manifest.generation)
}

#[test]
#[cfg(unix)]
fn publication_reuses_the_immutable_run_inode_instead_of_rewriting_it() {
    use std::os::unix::fs::MetadataExt;
    let parent = tempfile::tempdir().unwrap();
    let mut map = DiskMap::new(parent.path()).unwrap();
    map.insert_batch(|batch| batch.insert(b"one", &1_u64))
        .unwrap();
    let source = fs::read_dir(map.directory.path())
        .unwrap()
        .flat_map(|entry| fs::read_dir(entry.unwrap().path()).unwrap())
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rseg")
        })
        .unwrap();
    let before = fs::metadata(&source).unwrap();
    map.publish_checkpoint(&1_u64).unwrap();
    let published = fs::metadata(generation(parent.path()).join("level-0.rseg")).unwrap();
    assert_eq!(
        (before.dev(), before.ino()),
        (published.dev(), published.ino())
    );
    assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
}

#[test]
fn an_old_reader_pins_its_generation_until_the_last_cursor_drops() {
    memory::with_storage_pool(4 * 1024 * 1024, |pool| {
        let parent = tempfile::tempdir().unwrap();
        let mut map = DiskMap::new(parent.path()).unwrap();
        map.insert_batch(|batch| batch.insert(b"one", &1_u64))
            .unwrap();
        map.publish_checkpoint(&1_u64).unwrap();
        let old = generation(parent.path());
        let mut cursor = map.levels[0].as_ref().unwrap().cursor();
        map.insert_batch(|batch| batch.insert(b"two", &2_u64))
            .unwrap();
        map.publish_checkpoint(&2_u64).unwrap();
        let current = generation(parent.path());
        assert_ne!(old, current);
        assert!(old.exists(), "reader must retain the retired directory");
        let record = cursor.next().unwrap().unwrap();
        assert_eq!(record.key.as_slice(), b"one");
        drop(record);
        assert!(cursor.next().is_none());
        drop(map);
        assert!(old.exists());
        assert!(
            current.exists(),
            "CURRENT remains durable after normal close"
        );
        drop(cursor);
        assert!(!old.exists(), "retired directory must be reclaimed");
        assert_eq!(pool.used(), 0);
        let mut map = DiskMap::new(parent.path()).unwrap();
        assert_eq!(*map.load_checkpoint::<u64>().unwrap().unwrap(), 2);
        assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
        assert_eq!(map.get::<u64>(b"two").unwrap(), Some(2));
    });
}

#[test]
#[cfg(feature = "fault-injection")]
fn uncertain_publication_cleanup_preserves_live_pins_and_reclaims_orphans_on_retry() {
    for point in [
        "transaction_checkpoint.before_link",
        "transaction_checkpoint.before_publish",
        "transaction_checkpoint.after_manifest",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let mut map = DiskMap::new(parent.path()).unwrap();
        map.insert_batch(|batch| batch.insert(b"one", &1_u64))
            .unwrap();
        map.publish_checkpoint(&1_u64).unwrap();
        let old = generation(parent.path());
        let mut held = map.prefix_cursor(b"one").unwrap();
        map.insert_batch(|batch| batch.insert(b"two", &2_u64))
            .unwrap();
        let root = parent.path().join(DIRECTORY);
        let before = fs::read(root.join("CURRENT")).unwrap();
        let fault =
            crate::failpoint::test_env(&format!("error:{point}"), parent.path(), parent.path());
        assert!(map.publish_checkpoint(&2_u64).is_err());
        drop(fault);
        let uncertain = generation(parent.path());
        if point.ends_with("after_manifest") {
            assert_ne!(old, uncertain);
        } else {
            assert_eq!(fs::read(root.join("CURRENT")).unwrap(), before);
        }
        map.publish_checkpoint(&3_u64).unwrap();
        assert!(old.exists());
        if uncertain != old {
            assert!(!uncertain.exists());
        }
        assert_eq!(held.next().unwrap().unwrap().key(), b"one");
        drop(held);
        assert!(!old.exists());
        assert_eq!(
            fs::read_dir(&root)
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
                .count(),
            1
        );
        drop(map);
        let mut recovered = DiskMap::new(parent.path()).unwrap();
        assert_eq!(*recovered.load_checkpoint::<u64>().unwrap().unwrap(), 3);
        assert_eq!(recovered.get::<u64>(b"one").unwrap(), Some(1));
        assert_eq!(recovered.get::<u64>(b"two").unwrap(), Some(2));
    }
}

#[test]
#[cfg(feature = "fault-injection")]
fn last_reader_unlink_and_generation_sweep_are_idempotent_in_both_orders() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Warnings(Arc<AtomicUsize>);
    impl tracing::Subscriber for Warnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    for reader_first in [true, false] {
        let parent = tempfile::tempdir().unwrap();
        let mut map = DiskMap::new(parent.path()).unwrap();
        map.insert_batch(|batch| batch.insert(b"one", &1_u64))
            .unwrap();
        map.publish_checkpoint(&1_u64).unwrap();
        let old = generation(parent.path());
        let held = map.prefix_cursor(b"one").unwrap();
        map.insert_batch(|batch| batch.insert(b"two", &2_u64))
            .unwrap();
        map.publish_checkpoint(&2_u64).unwrap();
        let current = generation(parent.path());
        assert!(old.exists());
        let marker = parent.path().join("gc-marker");
        let release = parent.path().join("gc-release");
        let point = if reader_first {
            "transaction_checkpoint.before_gc_pin_check"
        } else {
            "transaction_generation.before_unlink"
        };
        let fault = crate::failpoint::test_env(&format!("pause:{point}"), &marker, &release);
        let warnings = Arc::new(AtomicUsize::new(0));
        let counts = Arc::clone(&warnings);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        if reader_first {
            let worker = std::thread::spawn(move || {
                let result = map.cleanup_checkpoint_generations();
                (map, result)
            });
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let reached = marker.exists();
            tracing::subscriber::with_default(Warnings(counts), || drop(held));
            fs::write(&release, b"continue").unwrap();
            let (recovered, result) = worker.join().unwrap();
            map = recovered;
            assert!(reached, "sweep did not reach the cached-entry barrier");
            assert!(
                result.is_ok(),
                "sweep must accept a directory removed by its last reader: {result:?}"
            );
        } else {
            let worker = std::thread::spawn(move || {
                tracing::subscriber::with_default(Warnings(counts), || drop(held))
            });
            while !marker.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let reached = marker.exists();
            let result = map.cleanup_checkpoint_generations();
            fs::write(&release, b"continue").unwrap();
            worker.join().unwrap();
            assert!(reached, "reader did not reach the unlink barrier");
            assert!(result.is_ok());
        }
        drop(fault);
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            0,
            "already completed unlink is not a cleanup failure"
        );
        assert!(!old.exists());
        assert!(current.exists());
        assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
        assert_eq!(map.get::<u64>(b"two").unwrap(), Some(2));
        map.cleanup_checkpoint_generations().unwrap();
        drop(map);
        let mut reopened = DiskMap::new(parent.path()).unwrap();
        assert_eq!(*reopened.load_checkpoint::<u64>().unwrap().unwrap(), 2);
        assert_eq!(reopened.get::<u64>(b"one").unwrap(), Some(1));
        assert_eq!(reopened.get::<u64>(b"two").unwrap(), Some(2));
    }
}

#[test]
fn generation_cleanup_propagates_other_io_errors_and_keeps_current_intact() {
    let parent = tempfile::tempdir().unwrap();
    let mut map = DiskMap::new(parent.path()).unwrap();
    map.insert_batch(|batch| batch.insert(b"one", &1_u64))
        .unwrap();
    map.publish_checkpoint(&1_u64).unwrap();
    let current = parent.path().join(DIRECTORY).join("CURRENT");
    let before = fs::read(&current).unwrap();
    let obstruction = parent.path().join(DIRECTORY).join("generation-obstruction");
    fs::write(&obstruction, b"not a directory").unwrap();
    assert!(
        matches!(map.cleanup_checkpoint_generations(), Err(GaussError::Io(error)) if error.kind() != std::io::ErrorKind::NotFound)
    );
    assert_eq!(fs::read(&current).unwrap(), before);
    assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
    fs::remove_file(obstruction).unwrap();
    map.cleanup_checkpoint_generations().unwrap();
    drop(map);
    let mut reopened = DiskMap::new(parent.path()).unwrap();
    assert_eq!(*reopened.load_checkpoint::<u64>().unwrap().unwrap(), 1);
    assert_eq!(reopened.get::<u64>(b"one").unwrap(), Some(1));
}
