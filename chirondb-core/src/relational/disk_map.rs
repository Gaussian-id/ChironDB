//! Append-only lookup over the engine's accounted encrypted runs.
//! Each key is inserted once. Failed merges leave all installed runs intact.
//! The owner validates versioned metadata before using a published generation.

use super::{checkpoint::sort, segment, *};
use serde::de::DeserializeOwned;
const SCRATCH_PREFIX: &str = ".chiron-decisions-";
mod checkpoint;
mod cursor;
pub(crate) use cursor::Cursor;

#[derive(Debug)]
pub(crate) struct DiskMap {
    // Runs drop before the parent directory. Each reader owns its child run.
    levels: [Option<Arc<segment::SegmentReader>>; 64],
    directory: Arc<tempfile::TempDir>,
    checkpoint_generation: Option<Arc<segment::Generation>>,
    generation_pins: Vec<std::sync::Weak<segment::Generation>>,
    _pins_memory: wal_decode::MetadataCharge,
    // Last: directory/generation paths and their owners drop before admission.
    _memory: wal_decode::MetadataCharge,
}

pub(crate) struct Batch {
    sorter: sort::Sorter,
    count: usize,
}

impl Batch {
    pub(crate) fn insert(&mut self, key: &[u8], value: &impl Serialize) -> Result<()> {
        self.sorter.push(segment::SegmentRecord::json_admitted(
            segment::RecordBytes::copy(key)?,
            value,
        )?)?;
        self.count += 1;
        Ok(())
    }
}

impl DiskMap {
    pub(crate) fn new(parent: &Path) -> Result<Self> {
        let mut memory = wal_decode::MetadataCharge::default();
        memory.prepare(
            (parent.as_os_str().len() as u64)
                .checked_mul(8)
                .and_then(|n| n.checked_add(4096))
                .ok_or_else(sql_overloaded)?,
        )?;
        fs::create_dir_all(parent)?;
        Ok(Self {
            levels: std::array::from_fn(|_| None),
            directory: Arc::new(
                tempfile::Builder::new()
                    .prefix(SCRATCH_PREFIX)
                    .tempdir_in(parent)?,
            ),
            checkpoint_generation: None,
            generation_pins: Vec::new(),
            _pins_memory: wal_decode::MetadataCharge::default(),
            _memory: memory,
        })
    }

    #[cfg(test)]
    pub(crate) fn get<V: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<V>> {
        self.get_owned::<V>(key)?
            .map(|value| value.consume(Ok))
            .transpose()
    }

    pub(crate) fn get_owned<V: DeserializeOwned>(
        &self,
        key: &[u8],
    ) -> Result<Option<wal_decode::Owned<V>>> {
        for reader in self.levels.iter().flatten() {
            let metadata = reader.metadata();
            if metadata.min_key.as_deref().is_none_or(|min| key < min)
                || metadata.max_key.as_deref().is_none_or(|max| key > max)
                || !metadata.may_contain(key)
            {
                continue;
            }
            let mut cursor = reader.prefix_cursor(key)?;
            if let Some(record) = cursor.next().transpose()?
                && record.key.as_slice() == key
            {
                return Ok(Some(wal_decode::decode(&record.value)?));
            }
        }
        Ok(None)
    }

    pub(crate) fn insert_batch(
        &mut self,
        fill: impl FnOnce(&mut Batch) -> Result<()>,
    ) -> Result<()> {
        let mut batch = Batch {
            sorter: sort::Sorter::new(self.directory.path(), segment::SegmentKind::Index, 1)?,
            count: 0,
        };
        fill(&mut batch)?;
        if batch.count == 0 {
            return Ok(());
        }
        let mut reader = Arc::new(
            batch
                .sorter
                .finish()?
                .into_reader()?
                .with_scratch_parent(Arc::clone(&self.directory)),
        );
        let mut slot = 0;
        while let Some(previous) = self.levels.get(slot).and_then(Option::as_ref) {
            let directory = tempfile::Builder::new()
                .prefix("merge-")
                .tempdir_in(self.directory.path())?;
            let path = directory.path().join("index.rseg");
            segment::write_segment_stream(&path, segment::SegmentKind::Index, 1, || {
                sort::Merge::readers(previous, &reader)
            })?;
            reader = Arc::new(
                segment::SegmentReader::open_scratch(&path, directory)?
                    .with_scratch_parent(Arc::clone(&self.directory)),
            );
            slot += 1;
        }
        if slot == self.levels.len() {
            return Err(sql_overloaded());
        }
        crate::failpoint::check("transaction_decisions.before_publish")?;
        // Publish only after every replacement file is written and authenticated.
        self.levels[slot] = Some(reader);
        self.levels[..slot].fill(None);
        Ok(())
    }

    pub(crate) fn cleanup_interrupted(parent: &Path) -> Result<()> {
        if !parent.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(SCRATCH_PREFIX)
            {
                // remove_dir_all does not follow a directory symlink.
                fs::remove_dir_all(entry.path())?;
            }
        }
        Ok(())
    }

    pub(crate) fn is_journal_scratch(path: &Path) -> bool {
        path.parent().is_some_and(|parent| {
            parent.ends_with(crate::transaction_journal::TRANSACTION_JOURNAL_DIR)
        }) && path.file_name().is_some_and(|name| {
            name.to_string_lossy().starts_with(SCRATCH_PREFIX) || name == checkpoint::DIRECTORY
        }) || path.parent().is_some_and(|parent| {
            parent.ends_with(crate::transaction_journal::TRANSACTION_AUTHORITY_DIR)
        }) && path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(SCRATCH_PREFIX))
            || path
                .parent()
                .is_some_and(|parent| parent.ends_with("audit"))
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with(SCRATCH_PREFIX)
                        || name == checkpoint::DIRECTORY
                })
    }

    /// Replace the live runs only after a bounded ordered rewrite succeeds.
    /// The caller publishes metadata afterwards; CURRENT and pinned generations
    /// remain intact on a failed rewrite. Existing cursors own their old runs.
    pub(crate) fn retain(
        &mut self,
        mut keep: impl FnMut(&cursor::Record) -> Result<bool>,
    ) -> Result<()> {
        let mut input = self.cursor()?;
        let mut replacement = Self::new(self.directory.path().parent().expect("map parent"))?;
        loop {
            let mut visited = 0;
            replacement.insert_batch(|batch| {
                for record in input.by_ref().take(512) {
                    let record = record?;
                    visited += 1;
                    if keep(&record)? {
                        batch.sorter.push(record.into_inner())?;
                        batch.count += 1;
                    }
                }
                Ok(())
            })?;
            if visited == 0 {
                break;
            }
        }
        self.levels = std::mem::replace(&mut replacement.levels, std::array::from_fn(|_| None));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_metadata_refuses_without_activation_and_survives_map_drop() {
        memory::with_storage_pool(4 * 1024 * 1024, |pool| {
            let parent = tempfile::tempdir().unwrap();
            let mut map = DiskMap::new(parent.path()).unwrap();
            map.insert_batch(|batch| batch.insert(b"one", &1)).unwrap();
            let metadata = serde_json::json!({"note":"x".repeat(20_000)});
            map.publish_checkpoint(&metadata).unwrap();
            let current = parent.path().join(checkpoint::DIRECTORY).join("CURRENT");
            let before = fs::read(&current).unwrap();
            let used = pool.used();
            let mut pressure = memory::Charge::storage();
            pressure
                .prepare(4 * 1024 * 1024 - used - memory::LEASE_ROOT_BYTES)
                .unwrap();
            assert!(matches!(
                map.load_checkpoint::<serde_json::Value>(),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(fs::read(&current).unwrap(), before);
            drop(pressure);
            assert_eq!(pool.used(), used);
            let recovered = map.load_checkpoint::<serde_json::Value>().unwrap().unwrap();
            drop(map);
            assert!(pool.used() >= 20_000);
            assert_eq!(*recovered, metadata);
            drop(recovered);
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn merge_failure_retains_every_installed_run_and_releases_scratch() {
        memory::with_storage_pool(1024 * 1024, |pool| {
            let parent = tempfile::tempdir().unwrap();
            let mut map = DiskMap::new(parent.path()).unwrap();
            map.insert_batch(|batch| batch.insert(b"one", &1)).unwrap();
            // Duplicate keys are rejected by the immutable merge. Its inputs
            // remain queryable and the failed replacement directory is dropped.
            assert!(map.insert_batch(|batch| batch.insert(b"one", &2)).is_err());
            assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
            assert_eq!(fs::read_dir(map.directory.path()).unwrap().count(), 1);
            map.insert_batch(|batch| batch.insert(b"two", &2)).unwrap();
            assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
            assert_eq!(map.get::<u64>(b"two").unwrap(), Some(2));
            assert_eq!(map.get::<u64>(b"missing").unwrap(), None);
            drop(map);
            assert_eq!(pool.used(), 0);
            assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        });
    }

    #[test]
    fn admission_failure_keeps_old_keys_and_releases_all_reservations() {
        memory::with_storage_pool(128 * 1024, |pool| {
            let parent = tempfile::tempdir().unwrap();
            let mut map = DiskMap::new(parent.path()).unwrap();
            map.insert_batch(|batch| batch.insert(b"one", &1)).unwrap();
            let before = pool.used();
            let large = "x".repeat(256 * 1024);
            assert!(
                map.insert_batch(|batch| batch.insert(b"two", &large))
                    .is_err()
            );
            assert_eq!(pool.used(), before);
            assert_eq!(map.get::<u64>(b"one").unwrap(), Some(1));
            assert!(map.get::<String>(b"two").unwrap().is_none());
            drop(map);
            assert_eq!(pool.used(), 0);
        });
    }

    #[test]
    fn encrypted_batches_and_merges_never_stage_plaintext_decisions() {
        const CHILD: &str = "CHIRONDB_DECISION_MAP_ENCRYPTED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "relational::disk_map::tests::encrypted_batches_and_merges_never_stage_plaintext_decisions", "--nocapture"])
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
        serde_json::to_writer(&mut key, &serde_json::json!({"version":1,"active_key_id":"test","keys":[{"id":"test","key_base64":base64::engine::general_purpose::STANDARD.encode([29u8;32])}]})).unwrap();
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(key.path()).unwrap(),
            true,
        )
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut map = DiskMap::new(parent.path()).unwrap();
        let sensitive_value = "protected-principal-and-consumed-idempotency-key".repeat(16);
        fn verify(path: &Path, plaintext: &[u8]) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    verify(&entry.path(), plaintext)
                } else {
                    let bytes = fs::read(entry.path()).unwrap();
                    assert!(bytes.starts_with(b"CHIRENC1"));
                    assert!(!bytes.windows(plaintext.len()).any(|part| part == plaintext));
                }
            }
        }
        for batch_id in 0..5 {
            map.insert_batch(|batch| {
                for index in 0..128 {
                    batch.insert(
                        format!("key-{batch_id}-{index:03}").as_bytes(),
                        &sensitive_value,
                    )?;
                }
                Ok(())
            })
            .unwrap();
            verify(map.directory.path(), sensitive_value.as_bytes());
        }
        for batch_id in 0..5 {
            assert_eq!(
                map.get::<String>(format!("key-{batch_id}-127").as_bytes())
                    .unwrap(),
                Some(sensitive_value.clone())
            );
        }
        map.publish_checkpoint(&512_u64).unwrap();
        verify(
            &parent.path().join(checkpoint::DIRECTORY),
            sensitive_value.as_bytes(),
        );
        drop(map);
        let mut map = DiskMap::new(parent.path()).unwrap();
        assert_eq!(
            map.load_checkpoint::<u64>().unwrap().map(|value| *value),
            Some(512)
        );
        assert_eq!(
            map.get::<String>(b"key-4-127").unwrap(),
            Some(sensitive_value)
        );
        drop(map);
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
        // Legacy whole-encrypted WAL files retain plaintext logical LSNs.
        // Verify the checkpoint's range reader authenticates and decodes the suffix.
        let legacy = tempfile::tempdir().unwrap();
        let mut wal = crate::wal::Wal::open_control_journal(legacy.path()).unwrap();
        let entry = crate::wal::WalEntry::DeleteBatch {
            ids: vec!["protected-legacy".into()],
        };
        wal.append(&entry).unwrap();
        let prefix = crate::wal::Wal::checkpoint_prefix(legacy.path(), wal.len().unwrap()).unwrap();
        wal.append(&entry).unwrap();
        drop(wal);
        let path = fs::read_dir(legacy.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|name| name == "gdwal"))
            .unwrap();
        crate::encryption::atomic_write_persistent(
            &path,
            crate::encryption::FileType::Wal,
            &fs::read(&path).unwrap(),
        )
        .unwrap();
        let stats = crate::wal::Wal::recover_checkpoint_suffix(legacy.path(), &prefix, |record| {
            assert!(matches!(
                record.entry,
                crate::wal::WalEntry::DeleteBatch { .. }
            ));
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.records, 1);
    }
}

#[cfg(test)]
mod backing_tests {
    use super::*;
    use serde::ser::SerializeSeq;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn map_root_refusal_precedes_directory_creation() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("missing");
        memory::with_storage_pool(1, |pool| {
            assert!(matches!(
                DiskMap::new(&missing),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(!missing.exists());
            assert_eq!(pool.used(), 0);
        });
        memory::with_storage_pool(32 * 1024, |pool| {
            let map = DiskMap::new(&missing).unwrap();
            assert!(pool.used() >= 4096);
            drop(map);
            assert_eq!(pool.used(), 0);
            assert_eq!(fs::read_dir(&missing).unwrap().count(), 0);
        });
    }

    #[test]
    fn oversized_manifest_stops_serialization_and_preserves_previous_generation() {
        struct Many<'a> {
            visits: &'a AtomicUsize,
            chunk: &'a str,
        }
        impl Serialize for Many<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut seq = serializer.serialize_seq(Some(4096))?;
                for _ in 0..4096 {
                    self.visits.fetch_add(1, Ordering::Relaxed);
                    seq.serialize_element(self.chunk)?;
                }
                seq.end()
            }
        }
        let parent = tempfile::tempdir().unwrap();
        let chunk = "x".repeat(8192);
        memory::with_storage_pool(2 * 1024 * 1024, |pool| {
            let mut map = DiskMap::new(parent.path()).unwrap();
            map.insert_batch(|batch| batch.insert(b"one", &1)).unwrap();
            map.publish_checkpoint(&17).unwrap();
            let root = parent.path().join(checkpoint::DIRECTORY);
            let current = root.join("CURRENT");
            let before = fs::read(&current).unwrap();
            let files = fs::read_dir(&root).unwrap().count();
            let used = pool.used();
            let visits = AtomicUsize::new(0);
            assert!(matches!(
                map.publish_checkpoint(&Many {
                    visits: &visits,
                    chunk: &chunk
                }),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(visits.load(Ordering::Relaxed) < 4096);
            assert_eq!(fs::read(&current).unwrap(), before);
            assert_eq!(fs::read_dir(&root).unwrap().count(), files);
            assert_eq!(pool.used(), used);
            assert_eq!(*map.load_checkpoint::<u64>().unwrap().unwrap(), 17);
            drop(map);
            assert_eq!(pool.used(), 0);
        });
    }
}
