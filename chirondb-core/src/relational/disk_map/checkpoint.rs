//! Private, atomically published lookup generations. The owner validates its
//! metadata and authority/cache contract before installing recovered state.
use super::*;
use sha2::{Digest, Sha256};

pub(super) const DIRECTORY: &str = ".chiron-decision-checkpoint";
const MANIFEST_LIMIT: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"CHIRDEC1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest<V> {
    version: u16,
    generation: String,
    metadata: V,
    runs: Vec<Run>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Run {
    level: usize,
    digest: [u8; 32],
}

impl DiskMap {
    pub(crate) fn publish_checkpoint(&mut self, metadata: &impl Serialize) -> Result<()> {
        let mut manifest_charge = memory::Charge::storage();
        manifest_charge.prepare((MANIFEST_LIMIT as u64) * 8 + 4096)?;
        let root = self
            .directory
            .path()
            .parent()
            .expect("map parent")
            .join(DIRECTORY);
        fs::create_dir_all(&root)?;
        regular(&root, true)?;
        let staging = tempfile::Builder::new()
            .prefix("generation-")
            .tempdir_in(&root)?;
        let mut runs = Vec::new();
        let mut levels = std::array::from_fn(|_| None);
        let generation_pin = segment::Generation::new(staging.path())?;
        for (level, reader) in self.levels.iter().enumerate() {
            let Some(reader) = reader else {
                continue;
            };
            let path = staging.path().join(format!("level-{level}.rseg"));
            // Validate the immutable input without creating another body or
            // encryption envelope. Links preserve its authenticated bytes.
            for record in reader.cursor() {
                record?;
            }
            regular(reader.path(), false)?;
            crate::failpoint::check("transaction_checkpoint.before_link")?;
            fs::hard_link(reader.path(), &path)?;
            runs.push(Run {
                level,
                digest: file_digest(&path)?,
            });
            levels[level] = Some(Arc::new(segment::SegmentReader::open_generation(
                &path,
                Arc::clone(&generation_pin),
            )?));
        }
        crate::fs_util::sync_tree(staging.path())?;
        crate::fs_util::sync_directory(&root)?;
        let generation = staging
            .path()
            .file_name()
            .expect("generation name")
            .to_string_lossy()
            .into_owned();
        let manifest = Manifest {
            version: 1,
            generation,
            metadata,
            runs,
        };
        // Bound serialization during growth, before keeping the staged generation.
        // The fixed manifest lease covers paths/runs/envelope/encryption overlap;
        // this buffer separately admits each JSON reallocation.
        let payload = segment::EncodedBuffer::encode(&manifest, MANIFEST_LIMIT - 52)?;
        let bytes = crate::security::storage::encode_metadata(MAGIC, &payload.bytes);
        self.register_generation(&generation_pin)?;
        crate::failpoint::check("transaction_checkpoint.before_publish")?;
        // An error after manifest rename may already expose this generation.
        // Preserve it even if the caller cannot prove directory fsync succeeded.
        let _ = staging.keep();
        crate::encryption::atomic_write_persistent(
            &root.join("CURRENT"),
            crate::encryption::FileType::Metadata,
            &bytes,
        )?;
        crate::failpoint::check("transaction_checkpoint.after_manifest")?;
        self.levels = levels;
        if let Some(previous) = self.checkpoint_generation.replace(generation_pin) {
            previous.retire();
        }
        self.cleanup_checkpoint_generations()?;
        metrics::counter!("chirondb_transaction_decision_checkpoints_total").increment(1);
        Ok(())
    }

    /// Validate authority metadata without creating scratch files or pins.
    pub(crate) fn inspect_checkpoint<V: DeserializeOwned>(
        parent: &Path,
    ) -> Result<wal_decode::Owned<V>> {
        let root = parent.join(DIRECTORY);
        regular(parent, true)?;
        regular(&root, true)?;
        let current = root.join("CURRENT");
        regular(&current, false)?;
        let file = crate::encryption::PersistentFile::open(&current)?;
        if file.len() > MANIFEST_LIMIT {
            return Err(sql_overloaded());
        }
        let mut charge = memory::Charge::storage();
        charge.prepare(file.len() as u64 * 8 + 4096)?;
        let bytes = file.read_range_admitted(0..file.len())?;
        let manifest: wal_decode::Owned<Manifest<V>> =
            wal_decode::decode(crate::security::storage::decode_metadata(MAGIC, &bytes)?)?;
        if manifest.version != 1
            || manifest.runs.len() > 64
            || !manifest
                .generation
                .strip_prefix("generation-")
                .is_some_and(|name| {
                    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
        {
            return Err(invalid_checkpoint(&root));
        }
        let generation = root.join(&manifest.generation);
        regular(&generation, true)?;
        let mut seen = [false; 64];
        for run in &manifest.runs {
            if run.level >= seen.len() || seen[run.level] {
                return Err(invalid_checkpoint(&generation));
            }
            seen[run.level] = true;
            let path = generation.join(format!("level-{}.rseg", run.level));
            regular(&path, false)?;
            if file_digest(&path)? != run.digest {
                return Err(invalid_checkpoint(&path));
            }
        }
        manifest.try_map(|manifest| Ok(manifest.metadata))
    }

    pub(crate) fn load_checkpoint<V: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<wal_decode::Owned<V>>> {
        let root = self
            .directory
            .path()
            .parent()
            .expect("map parent")
            .join(DIRECTORY);
        let current = root.join("CURRENT");
        if !current.try_exists()? {
            return Ok(None);
        }
        regular(&current, false)?;
        let file = crate::encryption::PersistentFile::open(&current)?;
        if file.len() > MANIFEST_LIMIT {
            return Err(sql_overloaded());
        }
        let mut manifest_charge = memory::Charge::storage();
        manifest_charge.prepare((file.len() as u64) * 8 + 4096)?;
        let bytes = file.read_range_admitted(0..file.len())?;
        let manifest: wal_decode::Owned<Manifest<V>> =
            wal_decode::decode(crate::security::storage::decode_metadata(MAGIC, &bytes)?)?;
        if manifest.version != 1
            || manifest.runs.len() > self.levels.len()
            || !manifest
                .generation
                .strip_prefix("generation-")
                .is_some_and(|name| {
                    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
        {
            return Err(invalid_checkpoint(&root));
        }
        regular(&root, true)?;
        let generation = root.join(&manifest.generation);
        regular(&generation, true)?;
        let generation_pin = match &self.checkpoint_generation {
            Some(pin) if pin.path() == generation => Arc::clone(pin),
            _ => segment::Generation::new(&generation)?,
        };
        let mut levels = std::array::from_fn(|_| None);
        for run in &manifest.runs {
            if run.level >= levels.len() || levels[run.level].is_some() {
                return Err(invalid_checkpoint(&generation));
            }
            let path = generation.join(format!("level-{}.rseg", run.level));
            regular(&path, false)?;
            if file_digest(&path)? != run.digest {
                return Err(invalid_checkpoint(&path));
            }
            levels[run.level] = Some(Arc::new(segment::SegmentReader::open_generation(
                &path,
                Arc::clone(&generation_pin),
            )?));
        }
        self.register_generation(&generation_pin)?;
        self.levels = levels;
        if let Some(previous) = self.checkpoint_generation.replace(generation_pin)
            && previous.path() != generation
        {
            previous.retire();
        }
        Ok(Some(manifest.try_map(|manifest| Ok(manifest.metadata))?))
    }

    fn register_generation(&mut self, pin: &Arc<segment::Generation>) -> Result<()> {
        self.generation_pins.retain(|pin| pin.strong_count() != 0);
        if self
            .generation_pins
            .iter()
            .any(|existing| existing.ptr_eq(&Arc::downgrade(pin)))
        {
            return Ok(());
        }
        if self.generation_pins.len() == self.generation_pins.capacity() {
            let capacity = self
                .generation_pins
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(sql_overloaded)?;
            // Weak registry entries can retain an Arc control block after the
            // generation's own reservation drops. Cover that lifetime here.
            let size = std::mem::size_of::<std::sync::Weak<segment::Generation>>() as u64 + 32;
            self._pins_memory.prepare(
                (capacity as u64)
                    .checked_add(self.generation_pins.capacity() as u64)
                    .and_then(|count| count.checked_mul(size))
                    .and_then(|bytes| bytes.checked_add(1024))
                    .ok_or_else(sql_overloaded)?,
            )?;
            self.generation_pins
                .try_reserve_exact(capacity - self.generation_pins.len())
                .map_err(|_| sql_overloaded())?;
            self._pins_memory
                .reduce(self.generation_pins.capacity() as u64 * size + 1024);
        }
        self.generation_pins.push(Arc::downgrade(pin));
        Ok(())
    }

    /// Startup has no escaping readers. Live sweeps also preserve every shared
    /// pin, including older generations and files from uncertain publication.
    pub(crate) fn cleanup_checkpoint_generations(&mut self) -> Result<()> {
        let root = self
            .directory
            .path()
            .parent()
            .expect("map parent")
            .join(DIRECTORY);
        if !root.try_exists()? {
            return Ok(());
        }
        regular(&root, true)?;
        self.generation_pins.retain(|pin| pin.strong_count() != 0);
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".CURRENT.") && name.ends_with(".tmp") {
                fs::remove_file(entry.path())?;
                continue;
            }
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("generation-")
                && self.checkpoint_generation.as_ref().map(|pin| pin.path())
                    != Some(entry.path().as_path())
            {
                crate::failpoint::check("transaction_checkpoint.before_gc_pin_check")?;
                if self
                    .generation_pins
                    .iter()
                    .any(|pin| pin.upgrade().is_some_and(|pin| pin.path() == entry.path()))
                {
                    continue;
                }
                match fs::remove_dir_all(entry.path()) {
                    Ok(()) => {}
                    // The final reader may have unlinked this cached entry
                    // after the pin check. Both paths completed the same GC.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        crate::fs_util::sync_directory(&root)
    }
}

fn file_digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        super::super::check_sql_cancelled()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

fn regular(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(invalid_checkpoint(path));
    }
    Ok(())
}

fn invalid_checkpoint(path: &Path) -> GaussError {
    GaussError::WalCorruption {
        path: path.display().to_string(),
        message: "invalid decision checkpoint".into(),
    }
}

#[cfg(test)]
mod tests;
