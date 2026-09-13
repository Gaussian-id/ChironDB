use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    GaussError, Result,
    data_dir_lock::DataDirLock,
    encryption::{self, EncryptionTreeReport, Keyring},
    fs_util::{
        atomic_write, checked_copy, durable_create_dir, durable_remove_file, sync_directory,
        sync_tree,
    },
    graph_identity::GRAPH_IDENTITY_FILE,
};

pub const CURRENT_FILE: &str = "CURRENT";
pub const GENERATIONS_DIR: &str = "generations";
pub const DATA_DIR_LOCK_FILE: &str = ".chirondb.lock";
const MIGRATION_JOURNAL: &str = ".generation-migration.json";
const MAX_CURRENT_BYTES: u64 = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageLayout {
    pub data_dir: PathBuf,
    pub active_root: PathBuf,
    pub generation: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EncryptionMigration {
    pub previous_generation: String,
    pub active_generation: String,
    pub migrated_files: u64,
    pub logical_digest: String,
    pub rebuilt_archive_manifests: usize,
    pub rebuilt_cold_indexes: usize,
    pub verification: EncryptionTreeReport,
}

#[derive(Serialize)]
struct MigrationJournal<'a> {
    schema_version: u8,
    operation: &'a str,
    generation: &'a str,
    phase: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_generation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_digest: Option<&'a str>,
}

#[derive(Deserialize)]
struct OwnedMigrationJournal {
    #[serde(default)]
    schema_version: u8,
    operation: String,
    generation: String,
    phase: String,
    #[serde(default)]
    previous_generation: Option<String>,
    #[serde(default)]
    active_key_id: Option<String>,
    #[serde(default)]
    logical_digest: Option<String>,
}

pub fn resolve(data_dir: impl AsRef<Path>) -> Result<StorageLayout> {
    let data_dir = data_dir.as_ref().to_path_buf();
    let current = data_dir.join(CURRENT_FILE);
    if !current.exists() {
        return Ok(StorageLayout {
            active_root: data_dir.clone(),
            data_dir,
            generation: None,
        });
    }
    let metadata = fs::metadata(&current)?;
    if metadata.len() > MAX_CURRENT_BYTES {
        return Err(invalid("CURRENT exceeds the maximum length"));
    }
    let generation = fs::read_to_string(&current)?.trim().to_string();
    validate_generation_id(&generation)?;
    let active_root = data_dir.join(GENERATIONS_DIR).join(&generation);
    if !active_root.is_dir() {
        return Err(invalid(format!(
            "CURRENT points to missing generation {generation}"
        )));
    }
    Ok(StorageLayout {
        data_dir,
        active_root,
        generation: Some(generation),
    })
}

pub fn is_generation_layout(data_dir: impl AsRef<Path>) -> bool {
    data_dir.as_ref().join(CURRENT_FILE).is_file()
}

/// Initialize a generation layout only when no legacy engine data exists.
pub fn initialize_empty(data_dir: impl AsRef<Path>) -> Result<String> {
    let data_dir = data_dir.as_ref();
    fs::create_dir_all(data_dir)?;
    let _lock = acquire_exclusive(data_dir)?;
    if is_generation_layout(data_dir) {
        return resolve(data_dir)?
            .generation
            .ok_or_else(|| invalid("missing generation"));
    }
    if has_legacy_engine_data(data_dir)? {
        return Err(invalid(
            "legacy storage layout detected; run the offline security migration",
        ));
    }
    create_generation(data_dir, None)
}

/// Offline, crash-safe migration from the alpha root layout to generations.
/// The legacy files are retained until encryption migration has verified the
/// new generation; secure startup must therefore additionally verify that the
/// active generation is encrypted before exposing a public listener.
pub fn migrate_legacy(data_dir: impl AsRef<Path>) -> Result<String> {
    let data_dir = data_dir.as_ref();
    fs::create_dir_all(data_dir)?;
    let _lock = acquire_exclusive(data_dir)?;
    if is_generation_layout(data_dir) {
        return Err(invalid("data directory already uses generation layout"));
    }
    if !has_legacy_engine_data(data_dir)? {
        return create_generation(data_dir, None);
    }
    create_generation(data_dir, Some(data_dir))
}

/// Build and verify an encrypted generation, atomically switch `CURRENT`,
/// then encrypt retained rollback/legacy copies as well. Callers must compact
/// active WALs first; immutable WAL archives can be wrapped as complete
/// encrypted envelopes.
pub fn migrate_encryption(data_dir: &Path, keyring: &Keyring) -> Result<EncryptionMigration> {
    fs::create_dir_all(data_dir)?;
    let _lock = acquire_exclusive(data_dir)?;
    let layout = resolve(data_dir)?;
    let resumed = read_migration_journal(data_dir)?
        .filter(|journal| journal.operation == "encryption_migration");
    let previous_generation = resumed
        .as_ref()
        .and_then(|journal| journal.previous_generation.clone())
        .or(layout.generation.clone())
        .ok_or_else(|| invalid("encryption migration requires generation-based storage"))?;
    let generations = data_dir.join(GENERATIONS_DIR);
    let generation = resumed
        .as_ref()
        .map(|journal| journal.generation.clone())
        .unwrap_or_else(new_generation_id);
    validate_generation_id(&generation)?;
    let staging = generations.join(format!(".{generation}.encryption-staging"));
    let destination = generations.join(&generation);
    let source = generations.join(&previous_generation);
    let logical_digest = encryption::logical_tree_digest(&source, Some(keyring))?;
    if let Some(journal) = &resumed {
        let safe_v1_copy_resume = journal.schema_version == 1
            && journal.phase == "copying"
            && journal.active_key_id.is_none()
            && journal.logical_digest.is_none();
        let matching_v2 = journal.schema_version == 2
            && journal.active_key_id.as_deref() == Some(keyring.active_key_id())
            && journal.logical_digest.as_deref() == Some(logical_digest.as_str());
        if !safe_v1_copy_resume && !matching_v2 {
            return Err(invalid(
                "encryption migration journal does not match the requested key or source generation",
            ));
        }
    }

    let mut migrated_files = 0_u64;
    let mut rebuilt_archive_manifests = 0_usize;
    let mut rebuilt_cold_indexes = 0_usize;
    if !destination.exists() {
        if resumed
            .as_ref()
            .is_none_or(|journal| journal.phase == "copying")
        {
            write_encryption_journal(
                data_dir,
                &generation,
                "copying",
                &previous_generation,
                keyring.active_key_id(),
                &logical_digest,
            )?;
            crate::failpoint::check("migration.after_copy_journal")?;
            durable_create_dir(&staging)?;
            copy_entry(&generations.join(&previous_generation), &staging)?;
            crate::failpoint::check("migration.after_copy")?;
        } else if !staging.is_dir() {
            return Err(invalid(
                "encryption migration journal points to missing staging data",
            ));
        }
        write_encryption_journal(
            data_dir,
            &generation,
            "encrypting",
            &previous_generation,
            keyring.active_key_id(),
            &logical_digest,
        )?;
        migrated_files = encryption::migrate_plain_tree_in_place(keyring, &staging)?;
        rebuilt_archive_manifests = rebuilt_archive_manifests.saturating_add(
            crate::wal::refresh_archive_manifests_for_encryption(&staging, keyring)?,
        );
        rebuilt_cold_indexes = rebuilt_cold_indexes.saturating_add(
            crate::segment::refresh_cold_indexes_for_encryption(&staging, keyring)?,
        );
        let external_objects = crate::segment::external_cold_object_file_count(&staging, keyring)?;
        if external_objects > 0 {
            return Err(invalid(format!(
                "encryption migration found {external_objects} external cold-object files; migrate that external authority explicitly before switching CURRENT"
            )));
        }
        encryption::verify_tree(keyring, &staging)?;
        let staged_digest = encryption::logical_tree_digest(&staging, Some(keyring))?;
        if staged_digest != logical_digest {
            return Err(invalid(format!(
                "encrypted generation changed logical identity: expected {logical_digest}, found {staged_digest}"
            )));
        }
        sync_tree(&staging)?;
        crate::failpoint::check("migration.after_encrypted_sync")?;
        fs::rename(&staging, &destination)?;
        sync_directory(&generations)?;
        crate::failpoint::check("migration.after_generation_publish")?;
    } else {
        encryption::verify_tree(keyring, &destination)?;
        let external_objects =
            crate::segment::external_cold_object_file_count(&destination, keyring)?;
        if external_objects > 0 {
            return Err(invalid(format!(
                "encryption migration found {external_objects} external cold-object files; migrate that external authority explicitly before switching CURRENT"
            )));
        }
        let destination_digest = encryption::logical_tree_digest(&destination, Some(keyring))?;
        if destination_digest != logical_digest {
            return Err(invalid(format!(
                "published encrypted generation changed logical identity: expected {logical_digest}, found {destination_digest}"
            )));
        }
    }

    let audit_path = data_dir.join("audit/audit.jsonl");
    if audit_path.exists() {
        let audit_root = audit_path.parent().expect("audit file has parent");
        if encryption::inspect_tree(audit_root)?.plaintext_files > 0 {
            encryption::migrate_plain_audit_file(keyring, &audit_path)?;
            migrated_files = migrated_files.saturating_add(1);
        }
        encryption::verify_tree(keyring, audit_root)?;
    }

    write_encryption_journal(
        data_dir,
        &generation,
        "switching",
        &previous_generation,
        keyring.active_key_id(),
        &logical_digest,
    )?;
    crate::failpoint::check("migration.before_current_switch")?;
    if resolve(data_dir)?.generation.as_deref() != Some(&generation) {
        switch_current(data_dir, &generation)?;
    }
    crate::failpoint::check("migration.after_current_switch")?;
    // Retain rollback data, but never retain it in plaintext inside the data
    // directory. This also encrypts legacy-root copies left by alpha-layout
    // migration. CURRENT and the lock file are explicit bootstrap metadata.
    migrated_files =
        migrated_files.saturating_add(encryption::migrate_plain_tree_in_place(keyring, data_dir)?);
    rebuilt_archive_manifests = rebuilt_archive_manifests.saturating_add(
        crate::wal::refresh_archive_manifests_for_encryption(data_dir, keyring)?,
    );
    rebuilt_cold_indexes = rebuilt_cold_indexes.saturating_add(
        crate::segment::refresh_cold_indexes_for_encryption(data_dir, keyring)?,
    );
    let verification = encryption::verify_tree(keyring, data_dir)?;
    let referenced = encryption::referenced_key_ids(data_dir)?;
    if referenced != std::collections::HashSet::from([keyring.active_key_id().to_string()]) {
        return Err(invalid(format!(
            "encryption migration retained non-active local key references: {referenced:?}"
        )));
    }
    durable_remove_file(&data_dir.join(MIGRATION_JOURNAL))?;
    Ok(EncryptionMigration {
        previous_generation,
        active_generation: generation,
        migrated_files,
        logical_digest,
        rebuilt_archive_manifests,
        rebuilt_cold_indexes,
        verification,
    })
}

pub(crate) fn new_generation_id() -> String {
    format!("gen-{}", uuid::Uuid::new_v4().simple())
}

pub(crate) fn switch_current(data_dir: &Path, generation: &str) -> Result<()> {
    validate_generation_id(generation)?;
    let root = data_dir.join(GENERATIONS_DIR).join(generation);
    if !root.is_dir() {
        return Err(invalid(format!("generation does not exist: {generation}")));
    }
    atomic_write(
        &data_dir.join(CURRENT_FILE),
        format!("{generation}\n").as_bytes(),
    )
}

fn create_generation(data_dir: &Path, source: Option<&Path>) -> Result<String> {
    let generations = data_dir.join(GENERATIONS_DIR);
    durable_create_dir(&generations)?;
    let generation = new_generation_id();
    let staging = generations.join(format!(".{generation}.staging"));
    let destination = generations.join(&generation);
    write_journal(data_dir, &generation, "copying")?;
    crate::failpoint::check("generation.after_copy_journal")?;
    durable_create_dir(&staging)?;
    if let Some(source) = source {
        copy_legacy_contents(source, &staging)?;
    } else {
        durable_create_dir(&staging.join("collections"))?;
    }
    sync_tree(&staging)?;
    crate::failpoint::check("generation.after_staging_sync")?;
    write_journal(data_dir, &generation, "publishing")?;
    fs::rename(&staging, &destination)?;
    sync_directory(&generations)?;
    crate::failpoint::check("generation.after_publish")?;
    switch_current(data_dir, &generation)?;
    crate::failpoint::check("generation.after_current_switch")?;
    durable_remove_file(&data_dir.join(MIGRATION_JOURNAL))?;
    Ok(generation)
}

fn copy_legacy_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(
                CURRENT_FILE
                    | GENERATIONS_DIR
                    | DATA_DIR_LOCK_FILE
                    | MIGRATION_JOURNAL
                    | GRAPH_IDENTITY_FILE
                    | "audit"
            )
        ) {
            continue;
        }
        copy_entry(&entry.path(), &destination.join(name))?;
    }
    Ok(())
}

fn copy_entry(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "refusing to migrate symbolic link {}",
            source.display()
        )));
    }
    if metadata.is_dir() {
        durable_create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
        sync_directory(destination)?;
    } else if metadata.is_file() {
        checked_copy(source, destination)?;
    } else {
        return Err(invalid(format!(
            "unsupported filesystem entry {}",
            source.display()
        )));
    }
    Ok(())
}

fn write_journal(data_dir: &Path, generation: &str, phase: &str) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&MigrationJournal {
        schema_version: 1,
        operation: "generation_migration",
        generation,
        phase,
        previous_generation: None,
        active_key_id: None,
        logical_digest: None,
    })?;
    atomic_write(&data_dir.join(MIGRATION_JOURNAL), &bytes)
}

fn write_encryption_journal(
    data_dir: &Path,
    generation: &str,
    phase: &str,
    previous_generation: &str,
    active_key_id: &str,
    logical_digest: &str,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&MigrationJournal {
        schema_version: 2,
        operation: "encryption_migration",
        generation,
        phase,
        previous_generation: Some(previous_generation),
        active_key_id: Some(active_key_id),
        logical_digest: Some(logical_digest),
    })?;
    atomic_write(&data_dir.join(MIGRATION_JOURNAL), &bytes)
}

fn read_migration_journal(data_dir: &Path) -> Result<Option<OwnedMigrationJournal>> {
    let path = data_dir.join(MIGRATION_JOURNAL);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let journal = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("invalid migration journal: {error}")))?;
    Ok(Some(journal))
}

fn has_legacy_engine_data(data_dir: &Path) -> Result<bool> {
    let collections = data_dir.join("collections");
    let has_collections = if collections.is_dir() {
        collections.read_dir()?.next().is_some()
    } else {
        false
    };
    Ok(data_dir.join("catalog.json").exists()
        || has_collections
        || data_dir.join("snapshot.marker").exists())
}

/// Opaque process-exclusive lease shared by online and offline storage paths.
pub struct ExclusiveDataDirLock {
    _inner: DataDirLock,
}

pub fn acquire_exclusive(data_dir: &Path) -> Result<ExclusiveDataDirLock> {
    Ok(ExclusiveDataDirLock {
        _inner: DataDirLock::acquire(data_dir)?,
    })
}

fn validate_generation_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 96
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("invalid generation id"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_layout_switches_current_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let generation = initialize_empty(temp.path()).unwrap();
        let layout = resolve(temp.path()).unwrap();
        assert_eq!(layout.generation.as_deref(), Some(generation.as_str()));
        assert!(layout.active_root.join("collections").is_dir());
    }

    #[test]
    fn legacy_layout_migrates_without_copying_audit() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("collections")).unwrap();
        fs::write(temp.path().join("catalog.json"), b"{\"collections\":[]}").unwrap();
        fs::create_dir(temp.path().join("audit")).unwrap();
        fs::write(temp.path().join("audit/audit.jsonl"), b"security-history").unwrap();
        fs::write(
            temp.path().join(GRAPH_IDENTITY_FILE),
            b"installation-identity",
        )
        .unwrap();
        let generation = migrate_legacy(temp.path()).unwrap();
        let active = temp.path().join(GENERATIONS_DIR).join(generation);
        assert!(active.join("catalog.json").exists());
        assert!(!active.join("audit").exists());
        assert!(!active.join(GRAPH_IDENTITY_FILE).exists());
        assert_eq!(
            fs::read(temp.path().join(GRAPH_IDENTITY_FILE)).unwrap(),
            b"installation-identity"
        );
        assert_eq!(
            fs::read(temp.path().join("audit/audit.jsonl")).unwrap(),
            b"security-history"
        );
    }

    #[test]
    fn exclusive_lock_is_stable_when_data_directory_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("database");
        let first = acquire_exclusive(&root).unwrap();
        assert!(!root.exists());
        assert!(acquire_exclusive(&root).is_err());
        drop(first);
        acquire_exclusive(&root).unwrap();
    }
}
