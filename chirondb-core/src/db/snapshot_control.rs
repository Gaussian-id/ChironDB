//! Snapshot the installation transaction control alongside the active content
//! generation while the caller holds the exclusive lifecycle gate.
use super::*;

/// Restore keeps the live installation's control journal in generation mode,
/// but the supplied backup must still be usable for a cold restore. Validate
/// every retained frame strictly before recovery can repair a torn final tail.
/// Recovery may rebuild derived caches only in the private staging copy.
pub(super) fn validate_transactions(staging: &Path) -> Result<()> {
    TransactionJournal::validate_existing_format(staging)?;
    if !staging.join("transactions").exists() {
        return Ok(()); // A pre-transaction-format backup.
    }
    let dir = staging.join(crate::transaction_journal::TRANSACTION_JOURNAL_DIR);
    Wal::validate_existing(&dir)?;
    Wal::scan_from(&dir, 0, |_| Ok(()))?;
    drop(TransactionJournal::open(staging)?);
    Ok(())
}

pub(super) fn stage_transactions(
    data_dir: &Path,
    content_root: &Path,
    staging: &Path,
) -> Result<()> {
    if data_dir == content_root {
        return Ok(());
    }
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    memory.prepare(
        (data_dir.as_os_str().len() as u64 + staging.as_os_str().len() as u64)
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| GaussError::ResourceExhausted("snapshot control paths".into()))?,
    )?;
    let source = data_dir.join("transactions");
    let destination = staging.join("transactions");
    // A legacy imported content generation can contain its old control copy.
    // The current installation's control is the source of this snapshot.
    if destination.exists() {
        durable_remove_dir_all(&destination)?;
    }
    durable_create_dir(&destination)?;
    snapshot_dir_contents(data_dir, &source, &destination)
}
