//! Non-mutating authority checks precede recovery and orphan cleanup.
use super::*;

pub(super) fn preflight(data_dir: &Path) -> Result<()> {
    crate::encryption::require_rotation_complete(data_dir)?;
    let layout = crate::storage_layout::resolve(data_dir)?;
    if layout.active_root != data_dir {
        crate::encryption::require_rotation_complete(&layout.active_root)?;
    }
    let catalog = read_catalog(&layout.active_root)?;
    for config in catalog.collections {
        validate_config(&config)?;
        let wal = collection_dir(&layout.active_root, &config.name).join("wal");
        if let Err(error) = Wal::validate_existing(&wal) {
            // DROP may have durably moved/removed the collection before its
            // catalog checkpoint. Normal journal recovery still validates and
            // applies the decision; this preflight must not resurrect its WAL.
            if collection_was_dropped(
                data_dir,
                &layout.active_root,
                catalog.wal_watermark,
                &config.name,
            )? {
                continue;
            }
            if matches!(error, GaussError::ResourceExhausted(_)) {
                return Err(error);
            }
            return Err(GaussError::WalCorruption {
                path: wal.display().to_string(),
                message: format!(
                    "collection '{}' requires its existing WAL: {error}; restore a verified backup before restarting; do not create an empty replacement",
                    config.name
                ),
            });
        }
    }
    Ok(())
}

fn collection_was_dropped(
    data_dir: &Path,
    root: &Path,
    watermark: u64,
    name: &str,
) -> Result<bool> {
    if data_dir
        .join(crate::transaction_journal::TRANSACTION_FORMAT_MARKER)
        .try_exists()?
    {
        return crate::transaction_journal::retained_collection_was_dropped(data_dir, name);
    }
    // Alpha layouts used the raw catalog WAL as their lifecycle authority.
    TransactionJournal::validate_existing_format(data_dir)?;
    let mut dropped = false;
    Wal::inspect_recovery_prefix(&root.join(CATALOG_WAL_DIR), watermark, |record| {
        match record.entry {
            WalEntry::DropCollection { name: found } if found == name => dropped = true,
            WalEntry::CreateCollection { config } if config.name == name => dropped = false,
            _ => {}
        }
        Ok(())
    })?;
    Ok(dropped)
}

pub(super) fn cleanup_and_verify(data_dir: &Path) -> Result<()> {
    crate::fs_util::cleanup_atomic_temps(data_dir)?;
    crate::encryption::verify_process_tree(data_dir)
}
