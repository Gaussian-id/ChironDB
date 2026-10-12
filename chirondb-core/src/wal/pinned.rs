//! Same-filesystem links retain captured WAL bytes through source-prefix cleanup.
//! These are transient reader pins, never replay or checkpoint authority.
use super::*;

pub(super) const PREFIX: &str = ".chiron-wal-pins-";

#[derive(Debug)]
pub(super) struct DirectoryPin {
    directory: Option<tempfile::TempDir>,
    // Last: the TempDir path and its allocation stay admitted through cleanup.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl DirectoryPin {
    pub(super) fn new(parent: &Path) -> Result<Self> {
        crate::relational::check_sql_cancelled()?;
        let memory = layout::root(parent, std::mem::size_of::<Self>() + 256)?;
        Ok(Self {
            directory: Some(tempfile::Builder::new().prefix(PREFIX).tempdir_in(parent)?),
            _memory: memory,
        })
    }

    fn path(&self) -> &Path {
        self.directory.as_ref().expect("live WAL pin").path()
    }

    pub(super) fn link(&self, segment: &mut WalSegment) -> Result<()> {
        crate::relational::check_sql_cancelled()?;
        let name = segment.path.file_name().expect("WAL segment name");
        let target_length = self
            .path()
            .as_os_str()
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| GaussError::ResourceExhausted("WAL pin path memory is full".into()))?;
        // Charge both paths before join/replacement; retain the destination's
        // reservation after the original inventory path has been dropped.
        let bytes = (target_length as u64)
            .checked_add(segment.path.as_os_str().len() as u64)
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| n.checked_add(std::mem::size_of::<WalSegment>() as u64 + 256))
            .ok_or_else(|| GaussError::ResourceExhausted("WAL pin path memory is full".into()))?;
        segment.memory.prepare(bytes)?;
        let target = self.path().join(name);
        let metadata = fs::symlink_metadata(&segment.path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(wal_corruption(
                &segment.path,
                "WAL pin requires a regular segment",
            ));
        }
        crate::failpoint::check("wal_pin.before_link")?;
        fs::hard_link(&segment.path, &target)?;
        crate::failpoint::check("wal_pin.after_link")?;
        crate::relational::check_sql_cancelled()?;
        segment.path = target;
        segment
            .memory
            .reduce(target_length as u64 * 4 + std::mem::size_of::<WalSegment>() as u64 + 256);
        Ok(())
    }
}

impl Drop for DirectoryPin {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            tracing::warn!(%error, "WAL file pin cleanup deferred until exclusive startup");
        }
    }
}

impl Wal {
    pub(crate) fn is_snapshot_scratch(path: &Path) -> bool {
        path.parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent == "wal" || parent == "journal" || parent == "catalog_wal")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(PREFIX))
    }

    /// Only the first startup under a newly acquired exclusive data-root lease
    /// may remove pins left by a killed process. Never call from live reload,
    /// checkpoint or Wal::open: another reader may still own this directory.
    pub(crate) fn cleanup_pins_on_exclusive_startup(data_dir: &Path, root: &Path) -> Result<()> {
        let _memory = layout::root(data_dir, 8192)?;
        layout::cleanup_snapshot_pins(
            &data_dir.join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR),
        )?;
        layout::cleanup_snapshot_pins(&root.join("catalog_wal"))?;
        layout::cleanup_snapshot_pins(&root.join("relational/wal"))?;
        layout::cleanup_child_snapshot_pins(&root.join("collections"))
    }
}

#[cfg(test)]
mod tests;
