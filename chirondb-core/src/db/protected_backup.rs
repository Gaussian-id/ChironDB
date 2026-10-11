//! Offline protected backup assembly. The exported data remains fenced until
//! a restore has reconciled an independently trusted current authority.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Db;
use crate::{
    GaussError, Result, audit,
    data_dir_lock::DataDirLock,
    encryption,
    fs_util::{atomic_write, durable_rename, sync_directory, sync_tree},
    security::onboarding,
    storage_layout,
    transaction_journal::{TRANSACTION_FORMAT_MARKER, TRANSACTION_JOURNAL_DIR},
    wal::Wal,
};

pub(super) mod replay;

const MANIFEST: &str = "backup.manifest";
const JOURNAL_MANIFEST: &str = "journal.manifest";
const BACKUP_FORMAT_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBackupManifest {
    version: u8,
    installation: uuid::Uuid,
    identity_revision: u64,
    completed_commit_frontier: u64,
    active_generation: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    common_frontier: bool,
    files: BTreeMap<String, BackupFile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRestoreReceipt {
    pub installation: uuid::Uuid,
    pub backup_identity_revision: u64,
    pub active_identity_revision: u64,
    pub backup_commit_frontier: u64,
    pub completed_commit_frontier: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedJournalArchiveManifest {
    version: u8,
    installation: uuid::Uuid,
    identity_revision: u64,
    completed_commit_frontier: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    common_frontier: bool,
    files: BTreeMap<String, BackupFile>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    bytes: u64,
    sha256: String,
}

/// Build an encrypted, atomic backup while the installation is offline.
/// This function opens its own exclusive Db lease; it cannot copy a running
/// server. The returned artifact is intentionally not a runnable data dir:
/// its installation marker is raised to version 3 until trusted authority
/// reconciliation during restore.
pub fn create_offline_protected_backup(
    source: &Path,
    destination: &Path,
    keyring: &encryption::Keyring,
) -> Result<ProtectedBackupManifest> {
    if !encryption::encryption_enforced() {
        return Err(GaussError::InvalidRequest(
            "protected backup requires an enforced process keyring".into(),
        ));
    }
    let source = fs::canonicalize(source)?;
    let destination = normalized_destination(destination)?;
    if destination.starts_with(&source) || source.starts_with(&destination) {
        return Err(GaussError::InvalidRequest(
            "protected backup destination overlaps the data directory".into(),
        ));
    }
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(GaussError::InvalidRequest(
            "protected backup destination already exists".into(),
        ));
    }
    let db = Db::open_for_offline_maintenance(&source)?;
    let authority = db.identity_authority().ok_or_else(|| {
        GaussError::InvalidRequest("protected backup requires an installed authority".into())
    })?;
    let installation = authority.installation_id().ok_or_else(|| {
        GaussError::InvalidRequest("protected backup requires an installation ID".into())
    })?;
    let revision = authority.revision();
    let _lifecycle = db.lifecycle_gate.write();
    let _maintenance = db.maintenance_barrier.read();
    db.wait_for_storage_idle()?;
    db.flush_wals()?;
    let frontier = db
        .transaction_journal
        .completed_commit_frontier()?
        .ok_or_else(|| {
            GaussError::WalUnavailable("protected backup has an incomplete commit decision".into())
        })?;
    audit::verify_hash_chain(&source)?;
    encryption::verify_tree(keyring, &source)?;
    let external_files = crate::segment::external_cold_object_file_count(&source, keyring)?;
    if external_files != 0 {
        return Err(GaussError::InvalidRequest(format!(
            "protected backup omits {external_files} external cold-object files"
        )));
    }
    storage_layout::resolve(&source)?
        .generation
        .ok_or_else(|| GaussError::InvalidRequest("protected backup needs generations".into()))?;

    let parent = destination
        .parent()
        .expect("normalized destination has parent");
    let name = destination
        .file_name()
        .expect("normalized destination has name");
    let staging = parent.join(format!(
        ".{}.backup-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&staging)?;
    private_dir(&staging)?;
    let result = (|| {
        let staged_data = staging.join("data");
        copy_tree(&source, &staged_data, true)?;
        sync_tree(&staged_data)?;
        crate::failpoint::check("protected_backup.after_copy")?;
        let staged = Db::open_for_offline_maintenance(&staged_data)?;
        let staged_authority = staged.identity_authority().ok_or_else(|| {
            GaussError::InvalidRequest("copied backup lost its identity authority".into())
        })?;
        if staged_authority.installation_id() != Some(installation)
            || staged_authority.revision() != revision
            || staged.transaction_journal.completed_commit_frontier()? != Some(frontier)
        {
            return Err(GaussError::InvalidRequest(
                "copied backup changed its installation or commit frontier".into(),
            ));
        }
        staged.wait_for_storage_idle()?;
        let generation = storage_layout::resolve(&staged_data)?
            .generation
            .ok_or_else(|| GaussError::InvalidRequest("copied backup lost generations".into()))?;
        drop(staged);
        // A worker retaining the copied Db must release its lease before the
        // sibling lock file can be discarded from the artifact.
        drop(DataDirLock::acquire(&staged_data)?);
        let staged_lock = staging.join(".data.chirondb.lock");
        if staged_lock.exists() {
            fs::remove_file(&staged_lock)?;
        }
        audit::verify_hash_chain(&staged_data)?;
        // Version 3 is reserved for backup artifacts. Current and historical
        // readers reject it before journal or projection recovery.
        atomic_write(
            &staged_data.join(onboarding::MARKER),
            format!("CHRNINSTALL3\n{installation}\n").as_bytes(),
        )?;
        let manifest = ProtectedBackupManifest {
            version: BACKUP_FORMAT_VERSION,
            installation,
            identity_revision: revision,
            completed_commit_frontier: frontier,
            active_generation: generation,
            common_frontier: onboarding::has_common_frontier(&source)?,
            files: hash_files(&staged_data, &staged_data)?,
        };
        encryption::atomic_write_persistent(
            &staging.join(MANIFEST),
            encryption::FileType::Metadata,
            &serde_json::to_vec(&manifest)?,
        )?;
        verify_offline_protected_backup(&staging, keyring)?;
        sync_tree(&staging)?;
        crate::failpoint::check("protected_backup.after_stage_sync")?;
        durable_rename(&staging, &destination)?;
        Ok(manifest)
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
        let _ = sync_directory(parent);
    }
    result
}

/// Verify a fenced backup artifact before any restore operation can consume
/// it. The file inventory is authenticated by the encrypted manifest; the
/// individual source files remain encrypted with the installation keyring.
pub fn verify_offline_protected_backup(
    backup: &Path,
    keyring: &encryption::Keyring,
) -> Result<ProtectedBackupManifest> {
    let manifest_path = backup.join(MANIFEST);
    let manifest_metadata = fs::symlink_metadata(&manifest_path)?;
    let data = backup.join("data");
    let data_metadata = fs::symlink_metadata(&data)?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || manifest_metadata.len() > MAX_MANIFEST_BYTES
        || !data_metadata.is_dir()
        || data_metadata.file_type().is_symlink()
    {
        return Err(GaussError::InvalidRequest(
            "invalid protected backup artifact entries".into(),
        ));
    }
    for entry in fs::read_dir(backup)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != MANIFEST && name != "data" && name != ".data.chirondb.lock" {
            return Err(GaussError::InvalidRequest(
                "protected backup contains an unexpected root entry".into(),
            ));
        }
        if entry.file_type()?.is_symlink() {
            return Err(GaussError::InvalidRequest(
                "protected backup contains a symbolic link".into(),
            ));
        }
    }
    encryption::verify_file(keyring, &manifest_path)?;
    let manifest: ProtectedBackupManifest =
        serde_json::from_slice(&encryption::read_persistent(&manifest_path)?)?;
    let actual_files = hash_files(&data, &data)?;
    if manifest.version != BACKUP_FORMAT_VERSION
        || manifest.installation.is_nil()
        || manifest.identity_revision == 0
        || manifest.files.is_empty()
        || actual_files != manifest.files
        || storage_layout::resolve(&data)?.generation.as_deref()
            != Some(manifest.active_generation.as_str())
    {
        return Err(GaussError::InvalidRequest(
            "invalid protected backup manifest".into(),
        ));
    }
    if fs::read_to_string(data.join(onboarding::MARKER))?
        != format!("CHRNINSTALL3\n{}\n", manifest.installation)
    {
        return Err(GaussError::InvalidRequest(
            "protected backup contents do not match the manifest".into(),
        ));
    }
    encryption::verify_tree(keyring, &data)?;
    audit::verify_hash_chain(&data)?;
    Ok(manifest)
}

/// Export the encrypted decision journal and latest authority/audit without a
/// second copy of content. The artifact is fenced from direct server startup.
pub fn create_offline_protected_journal_archive(
    source: &Path,
    destination: &Path,
    keyring: &encryption::Keyring,
) -> Result<ProtectedJournalArchiveManifest> {
    if !encryption::encryption_enforced() {
        return Err(GaussError::InvalidRequest(
            "protected journal archive requires an enforced process keyring".into(),
        ));
    }
    let source = fs::canonicalize(source)?;
    let destination = normalized_destination(destination)?;
    if destination.starts_with(&source) || source.starts_with(&destination) {
        return Err(GaussError::InvalidRequest(
            "protected journal archive destination overlaps source".into(),
        ));
    }
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(GaussError::InvalidRequest(
            "protected journal archive destination already exists".into(),
        ));
    }
    let db = Db::open_for_offline_maintenance(&source)?;
    let authority = db.identity_authority().ok_or_else(|| {
        GaussError::InvalidRequest("protected journal archive requires an authority".into())
    })?;
    let installation = authority.installation_id().ok_or_else(|| {
        GaussError::InvalidRequest("protected journal archive requires an installation ID".into())
    })?;
    let _lifecycle = db.lifecycle_gate.write();
    let _maintenance = db.maintenance_barrier.read();
    db.wait_for_storage_idle()?;
    db.flush_wals()?;
    let frontier = db
        .transaction_journal
        .completed_commit_frontier()?
        .ok_or_else(|| {
            GaussError::WalUnavailable("journal archive has incomplete commits".into())
        })?;
    audit::verify_hash_chain(&source)?;
    encryption::verify_tree(keyring, &source)?;

    let parent = destination
        .parent()
        .expect("normalized destination has parent");
    let name = destination
        .file_name()
        .expect("normalized destination has name");
    let staging = parent.join(format!(
        ".{}.journal-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&staging)?;
    private_dir(&staging)?;
    let result = (|| {
        let data = staging.join("data");
        fs::create_dir(&data)?;
        private_dir(&data)?;
        for directory in ["security", "audit", "transactions"] {
            copy_tree(&source.join(directory), &data.join(directory), false)?;
        }
        if onboarding::has_common_frontier(&source)? {
            copy_tree(
                &source.join(crate::graph_identity::GRAPH_IDENTITY_FILE),
                &data.join(crate::graph_identity::GRAPH_IDENTITY_FILE),
                false,
            )?;
        }
        atomic_write(
            &data.join(onboarding::MARKER),
            format!("CHRNINSTALL3\n{installation}\n").as_bytes(),
        )?;
        let manifest = ProtectedJournalArchiveManifest {
            version: 1,
            installation,
            identity_revision: authority.revision(),
            completed_commit_frontier: frontier,
            common_frontier: onboarding::has_common_frontier(&source)?,
            files: hash_files(&data, &data)?,
        };
        encryption::atomic_write_persistent(
            &staging.join(JOURNAL_MANIFEST),
            encryption::FileType::Metadata,
            &serde_json::to_vec(&manifest)?,
        )?;
        verify_offline_protected_journal_archive(&staging, keyring)?;
        sync_tree(&staging)?;
        crate::failpoint::check("protected_journal_archive.after_stage_sync")?;
        durable_rename(&staging, &destination)?;
        Ok(manifest)
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
        let _ = sync_directory(parent);
    }
    result
}

pub fn verify_offline_protected_journal_archive(
    archive: &Path,
    keyring: &encryption::Keyring,
) -> Result<ProtectedJournalArchiveManifest> {
    let manifest_path = archive.join(JOURNAL_MANIFEST);
    let metadata = fs::symlink_metadata(&manifest_path)?;
    let data = archive.join("data");
    let data_metadata = fs::symlink_metadata(&data)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
        || !data_metadata.is_dir()
        || data_metadata.file_type().is_symlink()
    {
        return Err(GaussError::InvalidRequest(
            "invalid protected journal archive entries".into(),
        ));
    }
    for entry in fs::read_dir(archive)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != JOURNAL_MANIFEST && name != "data" && name != ".data.chirondb.lock" {
            return Err(GaussError::InvalidRequest(
                "protected journal archive contains unexpected entry".into(),
            ));
        }
        if entry.file_type()?.is_symlink() {
            return Err(GaussError::InvalidRequest(
                "protected journal archive contains symbolic link".into(),
            ));
        }
    }
    encryption::verify_file(keyring, &manifest_path)?;
    let manifest: ProtectedJournalArchiveManifest =
        serde_json::from_slice(&encryption::read_persistent(&manifest_path)?)?;
    let actual = hash_files(&data, &data)?;
    if manifest.version != 1
        || manifest.installation.is_nil()
        || manifest.identity_revision == 0
        || actual != manifest.files
        || !actual.contains_key(onboarding::MARKER)
        || !actual.contains_key(TRANSACTION_FORMAT_MARKER)
        || !actual.keys().any(|name| name.starts_with("security/"))
        || !actual.keys().any(|name| name.starts_with("audit/"))
        || !actual
            .keys()
            .any(|name| name.starts_with(TRANSACTION_JOURNAL_DIR))
        || (manifest.common_frontier
            && !actual.contains_key(crate::graph_identity::GRAPH_IDENTITY_FILE))
        || actual.keys().any(|name| {
            name != onboarding::MARKER
                && !(manifest.common_frontier && name == crate::graph_identity::GRAPH_IDENTITY_FILE)
                && !["security/", "audit/", "transactions/"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
        })
        || fs::read_to_string(data.join(onboarding::MARKER))?
            != format!("CHRNINSTALL3\n{}\n", manifest.installation)
    {
        return Err(GaussError::InvalidRequest(
            "invalid protected journal archive manifest".into(),
        ));
    }
    encryption::verify_tree(keyring, &data)?;
    audit::verify_hash_chain(&data)?;
    Wal::scan_from(&data.join(TRANSACTION_JOURNAL_DIR), 0, |_| Ok(()))?;
    Ok(manifest)
}

/// Restore a fenced backup to a new data directory using an independently
/// selected, offline installation or verified backup as the authority source.
/// A strict journal prefix permits replay of later mutations, including
/// collection lifecycle changes, while preserving consumed idempotency keys.
pub fn restore_offline_protected_backup(
    backup: &Path,
    authority_source: &Path,
    destination: &Path,
    keyring: &encryption::Keyring,
) -> Result<ProtectedRestoreReceipt> {
    if !encryption::encryption_enforced() {
        return Err(GaussError::InvalidRequest(
            "protected restore requires an enforced process keyring".into(),
        ));
    }
    let backup = fs::canonicalize(backup)?;
    let authority_source = fs::canonicalize(authority_source)?;
    let destination = normalized_destination(destination)?;
    if [backup.as_path(), authority_source.as_path()]
        .iter()
        .any(|source| destination.starts_with(source) || source.starts_with(&destination))
    {
        return Err(GaussError::InvalidRequest(
            "protected restore destination overlaps an input".into(),
        ));
    }
    let _destination_lease = DataDirLock::acquire(&destination)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(GaussError::InvalidRequest(
            "protected restore destination already exists".into(),
        ));
    }
    let manifest = verify_offline_protected_backup(&backup, keyring)?;
    if authority_source == backup {
        return Err(GaussError::InvalidRequest(
            "protected restore needs a separate authority source".into(),
        ));
    }
    let _backup_lease = DataDirLock::acquire(&backup.join("data"))?;
    let authority_backup = authority_source.join(MANIFEST).is_file();
    let authority_journal = authority_source.join(JOURNAL_MANIFEST).is_file();
    let _authority_backup_lease = if authority_backup || authority_journal {
        Some(DataDirLock::acquire(&authority_source.join("data"))?)
    } else {
        None
    };
    let (authority_data, active_revision, active_installation, active_frontier, source) =
        if authority_backup {
            let current = verify_offline_protected_backup(&authority_source, keyring)?;
            (
                authority_source.join("data"),
                current.identity_revision,
                current.installation,
                current.completed_commit_frontier,
                None,
            )
        } else if authority_journal {
            let current = verify_offline_protected_journal_archive(&authority_source, keyring)?;
            (
                authority_source.join("data"),
                current.identity_revision,
                current.installation,
                current.completed_commit_frontier,
                None,
            )
        } else {
            let source = Db::open_for_offline_maintenance(&authority_source)?;
            let authority = source.identity_authority().ok_or_else(|| {
                GaussError::InvalidRequest("protected restore requires a current authority".into())
            })?;
            let active_revision = authority.revision();
            let active_installation = authority.installation_id().ok_or_else(|| {
                GaussError::InvalidRequest("current authority has no installation ID".into())
            })?;
            let active_frontier = source.transaction_journal.completed_commit_frontier()?;
            (
                authority_source.clone(),
                active_revision,
                active_installation,
                active_frontier.ok_or_else(|| {
                    GaussError::WalUnavailable("current authority has incomplete commits".into())
                })?,
                Some(source),
            )
        };
    if active_installation != manifest.installation
        || active_revision < manifest.identity_revision
        || active_frontier < manifest.completed_commit_frontier
    {
        return Err(GaussError::InvalidRequest(
            "protected restore authority installation, revision or frontier mismatch".into(),
        ));
    }
    if let Some(source) = &source {
        source.wait_for_storage_idle()?;
        source.flush_wals()?;
        audit::verify_hash_chain(&authority_data)?;
        encryption::verify_tree(keyring, &authority_data)?;
    }
    let backup_data = backup.join("data");
    let restore_common_frontier = manifest.common_frontier
        || if authority_backup {
            verify_offline_protected_backup(&authority_source, keyring)?.common_frontier
        } else if authority_journal {
            verify_offline_protected_journal_archive(&authority_source, keyring)?.common_frontier
        } else {
            onboarding::has_common_frontier(&authority_data)?
        };
    let restore_transaction_authority =
        crate::transaction_journal::TransactionJournal::has_authority_format(&authority_data)?;
    if !audit_is_prefix(&backup_data, &authority_data)? {
        return Err(GaussError::InvalidRequest(
            "protected restore authority does not extend the backup history".into(),
        ));
    }
    let replay = hash_files(&backup_data, &backup_data.join("transactions"))?
        != hash_files(&authority_data, &authority_data.join("transactions"))?;
    if replay && !journal_is_prefix(&backup_data, &authority_data)? {
        return Err(GaussError::InvalidRequest(
            "protected restore journal is not a prefix of current authority".into(),
        ));
    }

    let parent = destination
        .parent()
        .expect("normalized destination has parent");
    let name = destination
        .file_name()
        .expect("normalized destination has name");
    let staging = parent.join(format!(
        ".{}.restore-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let staged_lock = parent.join(format!(
        ".{}.chirondb.lock",
        staging.file_name().unwrap().to_string_lossy()
    ));
    let result = (|| {
        copy_tree(&backup_data, &staging, true)?;
        for directory in ["security", "audit"] {
            fs::remove_dir_all(staging.join(directory))?;
            copy_tree(
                &authority_data.join(directory),
                &staging.join(directory),
                false,
            )?;
        }
        if restore_common_frontier {
            // Allocations are installation authority, never content from an older backup.
            crate::graph_identity::validate_materialized_allocator(&authority_data, &backup_data)?;
            fs::remove_file(staging.join(crate::graph_identity::GRAPH_IDENTITY_FILE))?;
            copy_tree(
                &authority_data.join(crate::graph_identity::GRAPH_IDENTITY_FILE),
                &staging.join(crate::graph_identity::GRAPH_IDENTITY_FILE),
                false,
            )?;
        }
        if replay {
            rebuild_journal_for_replay(
                &authority_data,
                &staging,
                manifest.completed_commit_frontier,
            )?;
        }
        let reader_format = if restore_transaction_authority {
            6
        } else {
            onboarding::restored_installation_format(&staging, manifest.installation)?
        };
        atomic_write(
            &staging.join(onboarding::MARKER),
            format!("CHRNINSTALL{reader_format}\n{}\n", manifest.installation).as_bytes(),
        )?;
        sync_tree(&staging)?;
        crate::failpoint::check("protected_restore.after_stage_sync")?;
        let restored = Db::open_for_offline_maintenance(&staging)?;
        if restore_transaction_authority && replay {
            restored.transaction_journal.migrate_authority_offline()?;
        }
        let restored_authority = restored.identity_authority().ok_or_else(|| {
            GaussError::InvalidRequest("restored installation lost its authority".into())
        })?;
        if restored_authority.installation_id() != Some(manifest.installation)
            || restored_authority.revision() != active_revision
            || restored.transaction_journal.completed_commit_frontier()? != Some(active_frontier)
        {
            return Err(GaussError::InvalidRequest(
                "restored installation changed its authority or frontier".into(),
            ));
        }
        restored.wait_for_storage_idle()?;
        if restore_common_frontier {
            restored.checkpoint_common_frontier_inner(
                std::time::Instant::now() + std::time::Duration::from_secs(300),
                true,
            )?;
        }
        drop(restored);
        crate::failpoint::check("protected_restore.after_validation")?;
        drop(DataDirLock::acquire(&staging)?);
        if staged_lock.exists() {
            fs::remove_file(&staged_lock)?;
        }
        sync_tree(&staging)?;
        durable_rename(&staging, &destination)?;
        Ok(())
    })();
    if result.is_err() {
        if staged_lock.exists() {
            if let Ok(lease) = DataDirLock::acquire(&staging) {
                let removed = !staging.exists() || fs::remove_dir_all(&staging).is_ok();
                drop(lease);
                if removed {
                    let _ = fs::remove_file(&staged_lock);
                }
            }
        } else if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        let _ = sync_directory(parent);
    }
    result.map(|()| ProtectedRestoreReceipt {
        installation: manifest.installation,
        backup_identity_revision: manifest.identity_revision,
        active_identity_revision: active_revision,
        backup_commit_frontier: manifest.completed_commit_frontier,
        completed_commit_frontier: active_frontier,
    })
}

fn journal_is_prefix(backup_data: &Path, authority_data: &Path) -> Result<bool> {
    fn record_hash(hash: &mut Sha256, record: &crate::wal::WalRecord) -> Result<()> {
        let bytes = crate::relational::wal_decode::encode(record)?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(&*bytes);
        Ok(())
    }
    let mut old_hash = Sha256::new();
    let mut old_count = 0_u64;
    Wal::scan_journal_from(&backup_data.join(TRANSACTION_JOURNAL_DIR), 0, |record| {
        record_hash(&mut old_hash, &record)?;
        old_count += 1;
        Ok(())
    })?;
    let mut current_hash = Sha256::new();
    let mut current_count = 0_u64;
    Wal::scan_journal_from(&authority_data.join(TRANSACTION_JOURNAL_DIR), 0, |record| {
        if current_count < old_count {
            record_hash(&mut current_hash, &record)?;
        }
        current_count += 1;
        Ok(())
    })?;
    Ok(current_count >= old_count && current_hash.finalize() == old_hash.finalize())
}

fn rebuild_journal_for_replay(
    authority_data: &Path,
    staging: &Path,
    backup_frontier: u64,
) -> Result<()> {
    if Wal::retained_base_lsn(&authority_data.join(TRANSACTION_JOURNAL_DIR))? != 0 {
        return Err(GaussError::WalUnavailable("restore replay requires complete journal lineage until common-frontier reclamation is qualified".into()));
    }
    let transaction_root = staging.join("transactions");
    let new_journal = transaction_root.join(format!(".replay-{}", uuid::Uuid::new_v4()));
    replay::rebuild(
        &authority_data.join(TRANSACTION_JOURNAL_DIR),
        staging,
        backup_frontier,
        &new_journal,
    )?;
    let format_source = authority_data.join(TRANSACTION_FORMAT_MARKER);
    let format_target = staging.join(TRANSACTION_FORMAT_MARKER);
    fs::copy(format_source, &format_target)?;
    File::open(&format_target)?.sync_all()?;
    if crate::transaction_journal::TransactionJournal::has_authority_format(authority_data)? {
        // This is verified private restore staging, not ordinary recovery.
        // Full source WAL is retained. Rebuild authority only after the staged
        // stores have replayed the deliberately removed projection flags.
        let bytes = encryption::read_persistent(&format_target)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| GaussError::InvalidRequest("invalid replay format".into()))?;
        let id = text
            .strip_prefix("CHIRONTXN3\n")
            .and_then(|text| text.strip_suffix('\n'))
            .ok_or_else(|| GaussError::InvalidRequest("invalid replay format".into()))?;
        let old_authority = staging.join(crate::transaction_journal::TRANSACTION_AUTHORITY_DIR);
        if old_authority.try_exists()? {
            fs::remove_dir_all(old_authority)?;
        }
        encryption::atomic_write_persistent(
            &format_target,
            encryption::FileType::Metadata,
            format!("CHIRONTXN2\n{id}\n").as_bytes(),
        )?;
    }
    fs::remove_dir_all(staging.join(TRANSACTION_JOURNAL_DIR))?;
    durable_rename(&new_journal, &staging.join(TRANSACTION_JOURNAL_DIR))?;
    Ok(())
}

pub(super) fn audit_is_prefix(backup_data: &Path, authority_source: &Path) -> Result<bool> {
    let mut old = AuditBytes::new(backup_data)?;
    let mut current = AuditBytes::new(authority_source)?;
    let mut expected = [0_u8; 64 * 1024];
    let mut actual = [0_u8; 64 * 1024];
    loop {
        let count = old.read(&mut expected)?;
        if count == 0 {
            return Ok(true);
        }
        if let Err(error) = current.read_exact(&mut actual[..count]) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(false);
            }
            return Err(error.into());
        }
        if expected[..count] != actual[..count] {
            return Ok(false);
        }
    }
}

struct AuditBytes {
    paths: Vec<PathBuf>,
    next: usize,
    file: Option<File>,
}

impl AuditBytes {
    fn new(data: &Path) -> Result<Self> {
        let directory = data.join("audit");
        let mut paths = Vec::new();
        let mut active = None;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && crate::relational::disk_map::DiskMap::is_journal_scratch(&entry.path())
            {
                continue;
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| GaussError::InvalidRequest("non-UTF8 audit path".into()))?;
            if !entry.file_type()?.is_file() {
                return Err(GaussError::InvalidRequest("non-file audit entry".into()));
            }
            if name == "audit.jsonl" {
                active = Some(entry.path());
            } else if name.starts_with("audit-") && name.ends_with(".jsonl") {
                paths.push(entry.path());
            } else {
                return Err(GaussError::InvalidRequest("unexpected audit entry".into()));
            }
        }
        paths.sort();
        if let Some(active) = active {
            paths.push(active);
        }
        Ok(Self {
            paths,
            next: 0,
            file: None,
        })
    }
}

impl Read for AuditBytes {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.file.is_none() {
                let Some(path) = self.paths.get(self.next) else {
                    return Ok(0);
                };
                self.file = Some(File::open(path)?);
                self.next += 1;
            }
            let count = self.file.as_mut().unwrap().read(buf)?;
            if count != 0 {
                return Ok(count);
            }
            self.file = None;
        }
    }
}

fn normalized_destination(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        GaussError::InvalidRequest("protected backup destination needs a directory name".into())
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

fn private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, root: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(GaussError::InvalidRequest(format!(
            "protected backup refuses symbolic link {}",
            source.display()
        )));
    }
    if metadata.is_dir() {
        fs::create_dir(destination)?;
        private_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if root && entry.file_name() == ".chirondb.lock" {
                continue;
            }
            if entry.file_type()?.is_dir()
                && (crate::relational::disk_map::DiskMap::is_journal_scratch(&entry.path())
                    || Wal::is_snapshot_scratch(&entry.path()))
            {
                continue;
            }
            copy_tree(&entry.path(), &destination.join(entry.file_name()), false)?;
        }
        fs::set_permissions(destination, metadata.permissions())?;
        sync_directory(destination)?;
    } else if metadata.is_file() {
        fs::copy(source, destination)?;
        File::open(destination)?.sync_all()?;
    } else {
        return Err(GaussError::InvalidRequest(format!(
            "protected backup refuses special file {}",
            source.display()
        )));
    }
    Ok(())
}

fn hash_files(root: &Path, current: &Path) -> Result<BTreeMap<String, BackupFile>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            if crate::relational::disk_map::DiskMap::is_journal_scratch(&path)
                || Wal::is_snapshot_scratch(&path)
            {
                continue;
            }
            files.extend(hash_files(root, &path)?);
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            let name = path
                .strip_prefix(root)
                .expect("descendant path")
                .to_str()
                .ok_or_else(|| GaussError::InvalidRequest("non-UTF8 backup path".into()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let mut file = File::open(&path)?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
            }
            let mut sha256 = String::with_capacity(64);
            for byte in hash.finalize() {
                use std::fmt::Write as _;
                write!(&mut sha256, "{byte:02x}").expect("writing into String cannot fail");
            }
            files.insert(
                name,
                BackupFile {
                    bytes: metadata.len(),
                    sha256,
                },
            );
        } else {
            return Err(GaussError::InvalidRequest(format!(
                "protected backup refuses special file {}",
                path.display()
            )));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use crate::wal::WalEntry;
    #[test]
    fn journal_prefix_checks_are_admitted_strict_and_preserve_inputs_on_refusal() {
        use crate::relational::wal_decode::with_test_storage_pool;
        let temp = tempfile::tempdir().unwrap();
        let backup = temp.path().join("backup");
        let current = temp.path().join("current");
        let mut wal = Wal::open_control_journal(&backup.join(TRANSACTION_JOURNAL_DIR)).unwrap();
        wal.append(&WalEntry::Delete {
            id: "initial".into(),
        })
        .unwrap();
        drop(wal);
        copy_tree(&backup, &current, true).unwrap();
        let mut wal = Wal::open_control_journal(&current.join(TRANSACTION_JOURNAL_DIR)).unwrap();
        wal.append(&WalEntry::Delete {
            id: "suffix".into(),
        })
        .unwrap();
        drop(wal);
        let before = hash_files(&current, &current).unwrap();
        with_test_storage_pool(2 * 1024 * 1024, |used| {
            assert!(journal_is_prefix(&backup, &current).unwrap());
            assert!(!journal_is_prefix(&current, &backup).unwrap());
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(1, |used| {
            assert!(matches!(
                journal_is_prefix(&backup, &current),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(used(), 0);
        });
        assert_eq!(before, hash_files(&current, &current).unwrap());
    }

    #[test]
    fn protected_copy_and_manifest_exclude_live_wal_pins() {
        let root = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let wal_dir = root.path().join("transactions/journal");
        let mut wal = Wal::open(&wal_dir).unwrap();
        wal.append(&WalEntry::Delete { id: "one".into() }).unwrap();
        let mut reader =
            crate::wal::OrderedJournalReader::open(&wal_dir, wal.len().unwrap()).unwrap();
        let output = destination.path().join("copy");
        copy_tree(root.path(), &output, true).unwrap();
        let manifest = hash_files(root.path(), root.path()).unwrap();
        assert!(
            manifest
                .keys()
                .all(|name| !name.contains(".chiron-wal-pins-"))
        );
        assert_eq!(
            manifest.keys().collect::<Vec<_>>(),
            hash_files(&output, &output)
                .unwrap()
                .keys()
                .collect::<Vec<_>>()
        );
        assert!(reader.read(0).is_ok());
        assert_eq!(
            Wal::load(&output.join("transactions/journal"))
                .unwrap()
                .len(),
            1
        );
    }
}
