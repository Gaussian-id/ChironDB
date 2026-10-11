//! Retired immutable directories live until their final reader/cursor closes.
//! The current manifest's generation survives an ordinary database close.
use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub(in crate::relational) struct Generation {
    path: PathBuf,
    retired: AtomicBool,
    // Last: path/Arc allocation dies before its reservation.
    _memory: super::super::wal_decode::MetadataCharge,
}

impl Generation {
    pub(in crate::relational) fn new(path: &Path) -> Result<Arc<Self>> {
        let mut memory = super::super::wal_decode::MetadataCharge::default();
        memory.prepare(
            (path.as_os_str().len() as u64)
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(1024))
                .ok_or_else(super::super::sql_overloaded)?,
        )?;
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            retired: AtomicBool::new(false),
            _memory: memory,
        }))
    }

    pub(in crate::relational) fn path(&self) -> &Path {
        &self.path
    }

    pub(in crate::relational) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        if !self.retired.load(Ordering::Acquire) {
            return;
        }
        let result = crate::failpoint::check("transaction_generation.before_unlink")
            .map_err(std::io::Error::other)
            .and_then(|()| match fs::remove_dir_all(&self.path) {
                Ok(()) => Ok(()),
                // A concurrent sweep can win after the final Arc disappears.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            })
            .and_then(|()| {
                self.path.parent().map_or(Ok(()), |parent| {
                    crate::fs_util::sync_directory(parent).map_err(std::io::Error::other)
                })
            });
        if let Err(error) = result {
            // Startup cleanup retries failed unlink/fsync after the exclusive
            // root lease is acquired. A reclamation failure cannot undo CURRENT.
            tracing::warn!(%error, path = %self.path.display(), "retired decision generation cleanup deferred");
        }
    }
}
