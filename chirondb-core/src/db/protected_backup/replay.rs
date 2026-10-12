//! Private restore staging uses accounted, encrypted decision runs. Neither
//! the trusted source nor its backup manifest is changed by replay planning.
use std::{collections::HashSet, fs, path::Path};

use serde::{Deserialize, Serialize};

use super::super::{CATALOG_WAL_DIR, collection_dir, collections_dir};
use crate::{
    GaussError, Result,
    checkpoint::{CollectionCheckpoint, write_checkpoint},
    fs_util::{sync_directory, sync_tree},
    relational::{disk_map::DiskMap, wal_decode},
    storage_layout,
    transaction_journal::{
        ProjectionKind, TRANSACTION_JOURNAL_DIR, TRANSACTION_JOURNAL_VERSION, TransactionId,
        TransactionPrepare, TransactionProjection, TransactionTarget,
    },
    wal::{Wal, WalEntry},
};

const PREPARE: u8 = 0;
const COMMIT: u8 = 1;
const STORAGE: u8 = 2;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    id: TransactionId,
    sequence: u64,
    lsn: u64,
    catalog: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitReference {
    sequence: u64,
    lsn: u64,
}

fn key(namespace: u8, id: TransactionId) -> [u8; 37] {
    let mut key = [0; 37];
    key[0] = namespace;
    let mut text = [0; 36];
    key[1..].copy_from_slice(id.encode_hyphenated(&mut text).as_bytes());
    key
}

fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_JOURNAL_DIR.into(),
        message: message.into(),
    }
}

fn catalog_name(prepare: &TransactionPrepare) -> Result<&str> {
    match prepare.mutation.as_ref() {
        WalEntry::CreateCollection { config }
        | WalEntry::CreateProtectedCollection { config, .. } => Ok(&config.name),
        WalEntry::DropCollection { name } | WalEntry::DropProtectedCollection { name, .. } => {
            Ok(name)
        }
        _ => Err(corrupt("catalog transaction has a non-catalog mutation")),
    }
}

fn catalog_key(name: &str, sequence: u64) -> Result<wal_decode::Owned<Vec<u8>>> {
    let length = name
        .len()
        .checked_add(16)
        .ok_or_else(|| GaussError::ResourceExhausted("restore catalog key is too large".into()))?;
    let mut memory = wal_decode::MetadataCharge::default();
    memory.prepare(length as u64 + 256)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| GaussError::ResourceExhausted("restore catalog key memory is full".into()))?;
    bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(&(!sequence).to_be_bytes());
    Ok(wal_decode::Owned::from_parts(
        bytes,
        memory.into_reservation(),
    ))
}

fn copy_key(input: &[u8]) -> Result<wal_decode::Owned<Vec<u8>>> {
    let mut memory = wal_decode::MetadataCharge::default();
    memory.prepare(input.len() as u64 + 256)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(input.len())
        .map_err(|_| GaussError::ResourceExhausted("restore key memory is full".into()))?;
    bytes.extend_from_slice(input);
    Ok(wal_decode::Owned::from_parts(
        bytes,
        memory.into_reservation(),
    ))
}

struct Decisions {
    disk: DiskMap,
}

impl Decisions {
    fn build(source: &Path, scratch: &Path) -> Result<Self> {
        let mut disk = DiskMap::new(scratch)?;
        disk.insert_batch(|batch| {
            Wal::scan_journal_from(source, 0, |record| {
                match &record.entry {
                    WalEntry::TransactionPrepare { prepare } => batch.insert(
                        &key(PREPARE, prepare.transaction_id),
                        &Reference {
                            id: prepare.transaction_id,
                            sequence: prepare.commit_sequence,
                            lsn: record.lsn,
                            catalog: matches!(prepare.target, TransactionTarget::Catalog),
                        },
                    )?,
                    WalEntry::TransactionCommit { commit } => batch.insert(
                        &key(COMMIT, commit.transaction_id),
                        &CommitReference {
                            sequence: commit.commit_sequence,
                            lsn: record.lsn,
                        },
                    )?,
                    WalEntry::TransactionProjection { projection }
                        if projection.kind == ProjectionKind::Storage =>
                    {
                        batch.insert(&key(STORAGE, projection.transaction_id), &record.lsn)?;
                    }
                    _ => {}
                }
                Ok(())
            })?;
            Ok(())
        })?;
        let mut commits = disk.prefix_cursor(&[COMMIT])?;
        while let Some(record) = commits.next().transpose()? {
            let mut prepare_key = [0; 37];
            if record.key().len() != prepare_key.len() {
                return Err(corrupt("invalid restore COMMIT key"));
            }
            prepare_key.copy_from_slice(record.key());
            prepare_key[0] = PREPARE;
            let prepare = disk
                .get_owned::<Reference>(&prepare_key)?
                .ok_or_else(|| corrupt("restore COMMIT has no PREPARE"))?;
            let commit = record.decode::<CommitReference>()?;
            if record.key() != key(COMMIT, prepare.id)
                || commit.sequence != prepare.sequence
                || commit.lsn <= prepare.lsn
            {
                return Err(corrupt("restore COMMIT differs from its PREPARE"));
            }
        }
        let mut projections = disk.prefix_cursor(&[STORAGE])?;
        while let Some(record) = projections.next().transpose()? {
            let mut commit_key = [0; 37];
            if record.key().len() != commit_key.len() {
                return Err(corrupt("invalid restore storage key"));
            }
            commit_key.copy_from_slice(record.key());
            commit_key[0] = COMMIT;
            let commit = disk
                .get_owned::<CommitReference>(&commit_key)?
                .ok_or_else(|| corrupt("restore storage projection has no COMMIT"))?;
            if *record.decode::<u64>()? <= commit.lsn {
                return Err(corrupt("restore storage projection precedes its COMMIT"));
            }
        }
        Ok(Self { disk })
    }

    fn committed(&self, prepare: &TransactionPrepare) -> Result<bool> {
        let commit = self
            .disk
            .get_owned::<CommitReference>(&key(COMMIT, prepare.transaction_id))?;
        if let Some(commit) = &commit
            && commit.sequence != prepare.commit_sequence
        {
            return Err(corrupt("restore COMMIT differs from its PREPARE"));
        }
        Ok(commit.is_some())
    }

    fn keep_storage(&self, id: TransactionId, frontier: u64) -> Result<bool> {
        let prepare = self
            .disk
            .get_owned::<Reference>(&key(PREPARE, id))?
            .ok_or_else(|| corrupt("restore storage projection has no PREPARE"))?;
        Ok(prepare.sequence <= frontier || prepare.catalog)
    }
}

fn read_prepare(
    source: &Path,
    reference: &Reference,
) -> Result<wal_decode::Owned<TransactionPrepare>> {
    Wal::read_at_owned(source, reference.lsn)?.try_map(|record| {
        let WalEntry::TransactionPrepare { prepare } = record.entry else {
            return Err(corrupt("restore catalog reference is not a PREPARE"));
        };
        if record.lsn != reference.lsn
            || prepare.transaction_id != reference.id
            || prepare.commit_sequence != reference.sequence
            || !matches!(prepare.target, TransactionTarget::Catalog)
            || !reference.catalog
        {
            return Err(corrupt("restore catalog reference changed"));
        }
        Ok(prepare)
    })
}

/// Rebuild the full retained journal while removing only post-backup content
/// acknowledgements. Catalog acknowledgements stay because their new stores
/// are materialized here; audit is independently copied from current authority.
pub(super) fn rebuild(source: &Path, staging: &Path, frontier: u64, output: &Path) -> Result<()> {
    let mut paths = wal_decode::MetadataCharge::default();
    paths.prepare(
        (source.as_os_str().len() as u64
            + staging.as_os_str().len() as u64
            + output.as_os_str().len() as u64)
            .checked_mul(16)
            .and_then(|bytes| bytes.checked_add(8192))
            .ok_or_else(|| {
                GaussError::ResourceExhausted("restore replay paths are too large".into())
            })?,
    )?;
    let scratch = staging.join("transactions");
    let decisions = Decisions::build(source, &scratch)?;
    crate::failpoint::check("protected_restore.after_replay_index")?;
    let root = storage_layout::resolve(staging)?.active_root;
    let mut catalog = DiskMap::new(&scratch)?;
    let mut catalog_wal = None;
    catalog.insert_batch(|batch| {
        Wal::scan_journal_from(source, 0, |record| {
            if let WalEntry::TransactionPrepare { prepare } = &record.entry
                && prepare.commit_sequence > frontier
                && matches!(prepare.target, TransactionTarget::Catalog)
                && decisions.committed(prepare)?
            {
                batch.insert(
                    &catalog_key(catalog_name(prepare)?, prepare.commit_sequence)?,
                    &Reference {
                        id: prepare.transaction_id,
                        sequence: prepare.commit_sequence,
                        lsn: record.lsn,
                        catalog: true,
                    },
                )?;
                let wal = match &mut catalog_wal {
                    Some(wal) => wal,
                    slot @ None => slot.insert(Wal::open(&root.join(CATALOG_WAL_DIR))?),
                };
                record.consume(|record| {
                    let WalEntry::TransactionPrepare { prepare } = record.entry else {
                        unreachable!()
                    };
                    wal.append_no_sync(&WalEntry::TransactionApply {
                        transaction_id: prepare.transaction_id,
                        entry: prepare.mutation,
                    })?;
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(())
    })?;
    if let Some(wal) = &mut catalog_wal {
        wal.sync()?;
    }
    drop(catalog_wal);

    let mut latest = catalog.cursor()?;
    let mut previous: Option<wal_decode::Owned<Vec<u8>>> = None;
    while let Some(record) = latest.next().transpose()? {
        if record.key().len() < 16 {
            return Err(corrupt("invalid restore catalog key"));
        }
        let prefix = &record.key()[..record.key().len() - 8];
        if previous
            .as_ref()
            .is_some_and(|old| old.as_slice() == prefix)
        {
            continue;
        }
        let reference = record.decode::<Reference>()?;
        let prepare = read_prepare(source, &reference)?;
        if record.key() != catalog_key(catalog_name(&prepare)?, prepare.commit_sequence)?.as_slice()
        {
            return Err(corrupt("restore catalog key differs from its PREPARE"));
        }
        previous = Some(copy_key(prefix)?);
        install_collection(&root, &prepare)?;
    }
    if previous.is_some() {
        sync_directory(&collections_dir(&root))?;
    }

    let mut wal = Wal::open_control_journal(output)?;
    Wal::scan_journal_from(source, 0, |record| {
        if let WalEntry::TransactionProjection { projection } = &record.entry
            && projection.kind == ProjectionKind::Storage
            && !decisions.keep_storage(projection.transaction_id, frontier)?
        {
            return Ok(());
        }
        wal.append_no_sync(&record.entry)?;
        Ok(())
    })?;
    let mut latest = catalog.cursor()?;
    while let Some(record) = latest.next().transpose()? {
        let reference = record.decode::<Reference>()?;
        if decisions
            .disk
            .get_owned::<u64>(&key(STORAGE, reference.id))?
            .is_none()
        {
            wal.append_no_sync(&WalEntry::TransactionProjection {
                projection: TransactionProjection {
                    version: TRANSACTION_JOURNAL_VERSION,
                    transaction_id: reference.id,
                    kind: ProjectionKind::Storage,
                },
            })?;
        }
    }
    wal.sync()?;
    Ok(())
}

pub(in crate::db) fn install_collection(root: &Path, prepare: &TransactionPrepare) -> Result<()> {
    let name = catalog_name(prepare)?;
    let mut paths = wal_decode::MetadataCharge::default();
    paths.prepare(
        (root.as_os_str().len() as u64 + name.len() as u64)
            .checked_mul(16)
            .and_then(|bytes| bytes.checked_add(8192))
            .ok_or_else(|| {
                GaussError::ResourceExhausted("restore collection paths are too large".into())
            })?,
    )?;
    let installed = collection_dir(root, name);
    if installed.exists() {
        fs::remove_dir_all(&installed)?;
    }
    let (config, security) = match prepare.mutation.as_ref() {
        WalEntry::CreateCollection { config } => (config, None),
        WalEntry::CreateProtectedCollection {
            config, security, ..
        } => (config, Some(security)),
        WalEntry::DropCollection { .. } | WalEntry::DropProtectedCollection { .. } => return Ok(()),
        _ => unreachable!("catalog mutation checked above"),
    };
    fs::create_dir_all(installed.join("wal"))?;
    fs::create_dir_all(installed.join("searchers"))?;
    drop(Wal::open(&installed.join("wal"))?);
    write_checkpoint(
        &installed,
        &CollectionCheckpoint::new(config, 1, 0, 0, None)?,
    )?;
    drop(crate::overlay::OverlayStore::open(
        &installed,
        0,
        &HashSet::new(),
        crate::ordinal::SegmentOrdinalSet::new(),
        crate::overlay::OverlayOpenMode::Recover,
    )?);
    if let Some(security) = security {
        wal_decode::copy(security)?.consume(|authority| {
            crate::security::storage::write(
                &installed,
                &crate::security::storage::StoredSecurity {
                    wal_watermark: 0,
                    authority,
                },
            )
        })?;
    }
    sync_tree(&installed)
}

#[cfg(test)]
mod tests;
