//! Coordinate the SQL engine with a restored content root.

use super::*;

pub(super) type RelationalRoot =
    Arc<crate::relational::wal_decode::Owned<RwLock<Arc<crate::RelationalEngine>>>>;

pub(super) fn root(engine: Arc<crate::RelationalEngine>) -> Result<RelationalRoot> {
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    memory.prepare(std::mem::size_of::<RwLock<Arc<crate::RelationalEngine>>>() as u64 + 256)?;
    Ok(Arc::new(crate::relational::wal_decode::Owned::from_parts(
        RwLock::new(engine),
        memory.into_reservation(),
    )))
}

pub(super) fn prepare(db: &Db, content: &Path) -> Result<Arc<crate::RelationalEngine>> {
    crate::relational::RelationalEngine::ensure_storage(content)?;
    let engine =
        crate::relational::RelationalEngine::open(content, Arc::clone(&db.transaction_journal))?;
    Ok(engine)
}

pub(super) fn validate_staging(db: &Db, staging: &Path) -> Result<()> {
    drop(prepare(db, staging)?);
    crate::failpoint::check("restore.after_relational_validation")
}

pub(super) fn open_installed(db: &Db, content: &Path) -> Result<Arc<crate::RelationalEngine>> {
    let engine = prepare(db, content)?;
    crate::failpoint::check("restore.before_relational_publication")?;
    Ok(engine)
}

/// Installation decisions and consumed keys outlive a content rollback. The
/// lifecycle gate and checkpoint pause freeze this control copy before a flat
/// root swap; generation restores already keep control at the installation.
pub(super) fn preserve_journal(db: &Db, staging: &Path) -> Result<()> {
    if db
        .transaction_journal
        .completed_commit_frontier()?
        .is_none()
    {
        return Err(GaussError::WalUnavailable(
            "restore has unfinished commit projections".into(),
        ));
    }
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    memory.prepare(
        (db.data_dir.as_os_str().len() as u64 + staging.as_os_str().len() as u64)
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| {
                GaussError::ResourceExhausted("restore control paths are too large".into())
            })?,
    )?;
    let source = db.data_dir.join("transactions");
    let target = staging.join("transactions");
    if target.exists() {
        durable_remove_dir_all(&target)?;
    }
    durable_create_dir(&target)?;
    copy_dir_contents(&source, &target)
}

pub(super) fn publish(db: &Db, engine: Arc<crate::RelationalEngine>) {
    let lease: Arc<dyn Send + Sync + std::fmt::Debug> = db._data_dir_lock.clone();
    engine.enable_background_checkpoints(lease);
    *db.relational.write() = engine;
}

#[cfg(test)]
mod tests;
