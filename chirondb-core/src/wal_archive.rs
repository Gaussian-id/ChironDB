//! WAL archive management: mirroring, restoration, retention pruning, and
//! command execution.  Extracted from `src/db.rs` to keep that module smaller.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::{
    error::{GaussError, Result},
    fs_util::{
        copy_dir_all, count_wal_segment_files, directory_size, durable_remove_dir_all,
        durable_rename, sync_directory, sync_tree,
    },
    segment::{
        ColdObjectStoreConfig, mirror_directory_to_object_store, object_store_child_prefix_names,
        restore_object_store_directory_to_local,
    },
    wal::{
        Wal, WalArchive, WalArchivePrune, WalEntry, prune_archives, prune_archives_older_than,
        prune_archives_over_bytes,
    },
};

// ── Internal result types ─────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalExternalArchive {
    pub(crate) segments: usize,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalArchiveCommand {
    pub(crate) executed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalObjectArchive {
    pub(crate) segments: usize,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalArchiveRestore {
    pub(crate) archives: usize,
    pub(crate) segments: usize,
    pub(crate) bytes: u64,
    pub(crate) restored_archives: Vec<RestoredWalArchive>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RestoredWalArchive {
    pub(crate) collection: String,
    pub(crate) path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WalArchiveReplay {
    pub(crate) archives: usize,
    pub(crate) records: usize,
    pub(crate) schema_records: usize,
}

// ── Retention pruning ─────────────────────────────────────────────────────────

pub(crate) fn apply_wal_archive_retention(
    archive_root: &Path,
    retain_last: Option<usize>,
    max_bytes: Option<u64>,
    max_age: Option<Duration>,
) -> Result<Option<WalArchivePrune>> {
    if retain_last.is_none() && max_bytes.is_none() && max_age.is_none() {
        return Ok(None);
    }

    let mut total = WalArchivePrune {
        retained_archives: 0,
        pruned_archives: 0,
        pruned_bytes: 0,
    };
    if let Some(retain_last) = retain_last {
        let prune = prune_archives(archive_root, retain_last)?;
        total.retained_archives = prune.retained_archives;
        total.pruned_archives += prune.pruned_archives;
        total.pruned_bytes += prune.pruned_bytes;
    }
    if let Some(max_bytes) = max_bytes {
        let prune = prune_archives_over_bytes(archive_root, max_bytes)?;
        total.retained_archives = prune.retained_archives;
        total.pruned_archives += prune.pruned_archives;
        total.pruned_bytes += prune.pruned_bytes;
    }
    if let Some(max_age) = max_age {
        let prune = prune_archives_older_than(archive_root, max_age)?;
        total.retained_archives = prune.retained_archives;
        total.pruned_archives += prune.pruned_archives;
        total.pruned_bytes += prune.pruned_bytes;
    }
    Ok(Some(total))
}

// ── Mirroring ─────────────────────────────────────────────────────────────────

pub(crate) fn mirror_wal_archive(
    external_root: &Path,
    collection_name: &str,
    archive: &WalArchive,
) -> Result<WalExternalArchive> {
    let archive_name = archive.path.file_name().ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "WAL archive path has no final component: {}",
            archive.path.display()
        ))
    })?;
    let collection_root = external_root.join("collections").join(collection_name);
    let archive_name = archive_name.to_string_lossy();
    let mut generation = match fs::read_dir(&collection_root) {
        Ok(mut entries) => entries.try_fold(0_usize, |count, entry| {
            entry?;
            Ok::<_, GaussError>(count + 1)
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let target = loop {
        let candidate = collection_root.join(format!("{generation:06}-{archive_name}"));
        if !candidate.exists() {
            break candidate;
        }
        generation += 1;
    };
    if target.exists() {
        return Err(GaussError::InvalidRequest(format!(
            "external WAL archive target already exists: {}",
            target.display()
        )));
    }
    let tmp = target.with_extension("tmp");
    if tmp.exists() {
        durable_remove_dir_all(&tmp)?;
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    copy_dir_all(&archive.path, &tmp)?;
    durable_rename(&tmp, &target)?;
    Ok(WalExternalArchive {
        segments: archive.segments,
        bytes: archive.bytes,
    })
}

pub(crate) fn mirror_wal_archive_to_object_store(
    object_store: &ColdObjectStoreConfig,
    collection_name: &str,
    archive: &WalArchive,
) -> Result<WalObjectArchive> {
    let archive_name = archive.path.file_name().ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "WAL archive path has no final component: {}",
            archive.path.display()
        ))
    })?;
    let archive_name = archive_name.to_str().ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "WAL archive path is not valid UTF-8: {}",
            archive.path.display()
        ))
    })?;
    let logical_key_prefix = format!("collections/{collection_name}/wal/{archive_name}");
    let write = mirror_directory_to_object_store(object_store, &logical_key_prefix, &archive.path)?;
    Ok(WalObjectArchive {
        // The versioned manifest is an archive file, but not a WAL segment.
        segments: archive.segments,
        bytes: write.bytes,
    })
}

// ── Restoration ───────────────────────────────────────────────────────────────

pub(crate) fn restore_wal_archives_from_external(
    root: &Path,
    external_root: &Path,
    collection_names: &[String],
) -> Result<WalArchiveRestore> {
    if !external_root.exists() {
        return Err(GaussError::InvalidRequest(format!(
            "WAL restore archive directory does not exist: {}",
            external_root.display()
        )));
    }
    let mut restored = WalArchiveRestore {
        archives: 0,
        segments: 0,
        bytes: 0,
        restored_archives: Vec::new(),
    };
    for collection_name in collection_names {
        let source_root = external_root.join("collections").join(collection_name);
        match fs::read_dir(&source_root) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if !entry.file_type()?.is_dir() {
                        continue;
                    }
                    let Some(archive_name) = wal_archive_restore_name(&entry.file_name()) else {
                        continue;
                    };
                    let target = root
                        .join("collections")
                        .join(collection_name)
                        .join("wal/archive")
                        .join(archive_name);
                    if target.exists() {
                        require_same_archive(&entry.path(), &target)?;
                        restored.restored_archives.push(RestoredWalArchive {
                            collection: collection_name.clone(),
                            path: target,
                        });
                        continue;
                    }
                    let tmp = target.with_extension("tmp");
                    if tmp.exists() {
                        durable_remove_dir_all(&tmp)?;
                    }
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    copy_dir_all(&entry.path(), &tmp)?;
                    let segments = count_wal_segment_files(&tmp)?;
                    Wal::load(&tmp)?;
                    let bytes = directory_size(&tmp)?;
                    durable_rename(&tmp, &target)?;
                    restored.archives += 1;
                    restored.segments += segments;
                    restored.bytes += bytes;
                    restored.restored_archives.push(RestoredWalArchive {
                        collection: collection_name.clone(),
                        path: target,
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(restored)
}

pub(crate) fn restore_wal_archives_from_object_store(
    root: &Path,
    object_store: &ColdObjectStoreConfig,
    collection_names: &[String],
) -> Result<WalArchiveRestore> {
    let mut restored = WalArchiveRestore {
        archives: 0,
        segments: 0,
        bytes: 0,
        restored_archives: Vec::new(),
    };
    for collection_name in collection_names {
        let logical_wal_prefix = format!("collections/{collection_name}/wal");
        for archive_name in object_store_child_prefix_names(object_store, &logical_wal_prefix)? {
            let archive_path = Path::new(&archive_name);
            if archive_path.is_absolute()
                || archive_path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(GaussError::InvalidRequest(format!(
                    "invalid object-store WAL archive name '{archive_name}'"
                )));
            }
            let target = root
                .join("collections")
                .join(collection_name)
                .join("wal/archive")
                .join(&archive_name);
            // `restore_object_store_directory_to_local` already uses
            // `<target>.tmp` internally, so use a distinct hidden staging
            // destination here for verification before final publication.
            let staging = target.with_file_name(format!(".{archive_name}.restore"));
            if staging.exists() {
                durable_remove_dir_all(&staging)?;
            }
            let logical_archive_prefix = format!("{logical_wal_prefix}/{archive_name}");
            let read = restore_object_store_directory_to_local(
                object_store,
                &logical_archive_prefix,
                &staging,
            )?;
            if let Err(error) = Wal::load(&staging) {
                let _ = durable_remove_dir_all(&staging);
                return Err(error);
            }
            if target.exists() {
                let validation = require_same_archive(&staging, &target);
                durable_remove_dir_all(&staging)?;
                validation?;
                restored.restored_archives.push(RestoredWalArchive {
                    collection: collection_name.clone(),
                    path: target,
                });
                continue;
            }
            let segments = count_wal_segment_files(&staging)?;
            sync_tree(&staging)?;
            durable_rename(&staging, &target)?;
            restored.archives += 1;
            restored.segments += segments;
            restored.bytes += read.bytes;
            restored.restored_archives.push(RestoredWalArchive {
                collection: collection_name.clone(),
                path: target,
            });
        }
    }
    Ok(restored)
}

pub(crate) fn replay_restored_wal_archives(
    root: &Path,
    restores: [&Option<WalArchiveRestore>; 2],
) -> Result<WalArchiveReplay> {
    use std::collections::HashMap;

    let mut by_collection: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for restore in restores.into_iter().flatten() {
        for restored in &restore.restored_archives {
            by_collection
                .entry(restored.collection.clone())
                .or_default()
                .push(restored.path.clone());
        }
    }

    let mut replay = WalArchiveReplay {
        archives: 0,
        records: 0,
        schema_records: 0,
    };
    for (collection_name, mut archives) in by_collection {
        archives.sort();
        archives.dedup();
        let mut ranges = archives
            .into_iter()
            .map(|archive| {
                let base = Wal::retained_base_lsn(&archive)?;
                let end = Wal::scan_from(&archive, base, |_| Ok(()))?.end_lsn;
                Ok((base, end, archive))
            })
            .collect::<Result<Vec<_>>>()?;
        ranges.sort();
        let collection_wal_dir = root.join("collections").join(&collection_name).join("wal");
        let mut wal = Wal::open(&collection_wal_dir)?;
        for (_, _, archive) in ranges {
            wal.replay_archive(&archive, |record| {
                replay.records += 1;
                if matches!(record.entry, WalEntry::Schema { .. }) {
                    replay.schema_records += 1;
                }
                Ok(())
            })?;
            replay.archives += 1;
        }
    }
    Ok(replay)
}

/// Rebuild a complete source-preserving WAL only inside an uninstalled restore
/// collection. This is used when a requested historical target precedes the
/// live retained base but checked local/imported archives form a contiguous
/// chain from LSN 0 through the live suffix.
pub(crate) fn rehydrate_wal_origin_from_archives(wal_dir: &Path) -> Result<bool> {
    let retained_base = Wal::retained_base_lsn(wal_dir)?;
    if retained_base == 0 {
        return Ok(false);
    }
    let archive_root = wal_dir.join("archive");
    let entries = match fs::read_dir(&archive_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut ranges = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || wal_archive_restore_name(&entry.file_name()).is_none() {
            continue;
        }
        let path = entry.path();
        let base = Wal::retained_base_lsn(&path)?;
        let end = Wal::scan_from(&path, base, |_| Ok(()))?.end_lsn;
        ranges.push((base, end, path));
    }
    ranges.sort();
    if ranges.first().is_none_or(|(base, _, _)| *base != 0) {
        return Ok(false);
    }

    let parent = wal_dir.parent().ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "WAL directory has no collection parent: {}",
            wal_dir.display()
        ))
    })?;
    let operation = uuid::Uuid::new_v4();
    let rebuilt_dir = parent.join(format!(".wal-origin-{operation}"));
    let backup_dir = parent.join(format!(".wal-origin-backup-{operation}"));
    let rebuild = (|| -> Result<()> {
        let mut rebuilt = Wal::open(&rebuilt_dir)?;
        for (_, _, archive) in &ranges {
            rebuilt.replay_archive(archive, |_| Ok(()))?;
        }
        // The live suffix is checked exactly like another archive. A missing
        // link, divergent overlap, or partial frame therefore refuses here.
        rebuilt.replay_archive(wal_dir, |_| Ok(()))?;
        rebuilt.sync()?;
        if Wal::retained_base_lsn(&rebuilt_dir)? != 0 {
            return Err(GaussError::WalCorruption {
                path: rebuilt_dir.display().to_string(),
                message: "rehydrated WAL does not begin at LSN 0".to_string(),
            });
        }
        sync_tree(&rebuilt_dir)?;
        Ok(())
    })();
    if let Err(error) = rebuild {
        let _ = durable_remove_dir_all(&rebuilt_dir);
        return Err(error);
    }

    durable_rename(wal_dir, &backup_dir)?;
    let backup_archives = backup_dir.join("archive");
    let rebuilt_archives = rebuilt_dir.join("archive");
    if backup_archives.exists()
        && let Err(error) = durable_rename(&backup_archives, &rebuilt_archives)
    {
        let _ = durable_rename(&backup_dir, wal_dir);
        let _ = durable_remove_dir_all(&rebuilt_dir);
        return Err(error);
    }
    if let Err(error) = durable_rename(&rebuilt_dir, wal_dir) {
        if rebuilt_archives.exists() {
            let _ = durable_rename(&rebuilt_archives, &backup_archives);
        }
        let _ = durable_rename(&backup_dir, wal_dir);
        return Err(error);
    }
    durable_remove_dir_all(&backup_dir)?;
    sync_directory(parent)?;
    metrics::counter!("chirondb_wal_archive_origin_rehydrations_total").increment(1);
    tracing::info!(path = %wal_dir.display(), "rehydrated staged WAL origin from checked archives");
    Ok(true)
}

fn require_same_archive(source: &Path, existing: &Path) -> Result<()> {
    if Wal::archive_fingerprint(source)? != Wal::archive_fingerprint(existing)? {
        return Err(GaussError::WalCorruption {
            path: source.display().to_string(),
            message: "conflicting WAL archives use the same name".into(),
        });
    }
    Ok(())
}

// ── Command execution ─────────────────────────────────────────────────────────

pub(crate) fn run_wal_archive_command(
    command: &str,
    collection_name: &str,
    archive: &WalArchive,
) -> Result<WalArchiveCommand> {
    if command.trim().is_empty() {
        return Err(GaussError::InvalidRequest(
            "WAL archive command must not be empty".to_string(),
        ));
    }
    let archive_name = archive.path.file_name().ok_or_else(|| {
        GaussError::InvalidRequest(format!(
            "WAL archive path has no final component: {}",
            archive.path.display()
        ))
    })?;
    let output = shell_command(command)
        .env("CHIRONDB_WAL_ARCHIVE_PATH", &archive.path)
        .env("CHIRONDB_WAL_ARCHIVE_NAME", archive_name)
        .env("CHIRONDB_WAL_ARCHIVE_COLLECTION", collection_name)
        .env(
            "CHIRONDB_WAL_ARCHIVE_SEGMENTS",
            archive.segments.to_string(),
        )
        .env("CHIRONDB_WAL_ARCHIVE_BYTES", archive.bytes.to_string())
        .env("GAUSSDB_WAL_ARCHIVE_PATH", &archive.path)
        .env("GAUSSDB_WAL_ARCHIVE_NAME", archive_name)
        .env("GAUSSDB_WAL_ARCHIVE_COLLECTION", collection_name)
        .env("GAUSSDB_WAL_ARCHIVE_SEGMENTS", archive.segments.to_string())
        .env("GAUSSDB_WAL_ARCHIVE_BYTES", archive.bytes.to_string())
        .output()?;
    if !output.status.success() {
        let status = output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |code| code.to_string());
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(GaussError::InvalidRequest(format!(
            "WAL archive command failed with status {status}: {}",
            truncate_message(detail, 512)
        )));
    }
    Ok(WalArchiveCommand { executed: true })
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("sh");
    shell.arg("-c").arg(command);
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd");
    shell.arg("/C").arg(command);
    shell
}

// ── Name parsing ──────────────────────────────────────────────────────────────

pub(crate) fn wal_archive_restore_name(name: &std::ffi::OsStr) -> Option<String> {
    let name = name.to_str()?;
    if is_local_wal_archive_name(name) {
        return Some(name.to_string());
    }
    let (_, local_name) = name.split_once('-')?;
    if is_local_wal_archive_name(local_name) {
        return Some(local_name.to_string());
    }
    None
}

pub(crate) fn is_local_wal_archive_name(name: &str) -> bool {
    let Some((index, end_lsn)) = name.split_once('-') else {
        return false;
    };
    index.len() == 6
        && end_lsn.len() == 20
        && index.chars().all(|ch| ch.is_ascii_digit())
        && end_lsn.chars().all(|ch| ch.is_ascii_digit())
}

fn truncate_message(message: &str, max_chars: usize) -> String {
    let mut truncated = String::new();
    for (index, ch) in message.chars().enumerate() {
        if index >= max_chars {
            truncated.push_str("...");
            break;
        }
        truncated.push(ch);
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn archive_replay_orders_by_source_ranges_not_directory_names() {
        let temp = TempDir::new().unwrap();
        let mut source = Wal::open(&temp.path().join("source")).unwrap();
        source
            .append(&WalEntry::Delete { id: "first".into() })
            .unwrap();
        let first = source
            .archive_and_reset(&temp.path().join("first"))
            .unwrap()
            .unwrap();
        source
            .append(&WalEntry::Delete {
                id: "second".into(),
            })
            .unwrap();
        let second = source
            .archive_current(&temp.path().join("second"))
            .unwrap()
            .unwrap();
        let earlier = temp.path().join("z-first");
        let later = temp.path().join("a-later");
        copy_dir_all(&first.path, &earlier).unwrap();
        copy_dir_all(&second.path, &later).unwrap();
        let restore = Some(WalArchiveRestore {
            archives: 2,
            segments: 2,
            bytes: 0,
            restored_archives: vec![
                RestoredWalArchive {
                    collection: "docs".into(),
                    path: later,
                },
                RestoredWalArchive {
                    collection: "docs".into(),
                    path: earlier,
                },
            ],
        });
        let target = temp.path().join("target");
        let replay = replay_restored_wal_archives(&target, [&restore, &None]).unwrap();
        assert_eq!(replay.records, 2);
        let records = Wal::load(&target.join("collections/docs/wal")).unwrap();
        assert!(matches!(&records[0].entry, WalEntry::Delete { id } if id == "first"));
        assert!(matches!(&records[1].entry, WalEntry::Delete { id } if id == "second"));
        assert_eq!(
            replay_restored_wal_archives(&target, [&restore, &restore])
                .unwrap()
                .records,
            0
        );
    }

    #[test]
    fn archive_import_rejects_conflicting_names_without_overwriting() {
        let temp = TempDir::new().unwrap();
        let name = "000000-00000000000000000001";
        let external = temp.path().join("external");
        let existing = temp
            .path()
            .join("target/collections/docs/wal/archive")
            .join(name);
        let mut original = Wal::open(&existing).unwrap();
        original
            .append(&WalEntry::Delete {
                id: "original".into(),
            })
            .unwrap();
        let path = external.join("collections/docs").join(name);
        let mut different = Wal::open(&path).unwrap();
        different
            .append(&WalEntry::Delete {
                id: "different".into(),
            })
            .unwrap();
        let before = Wal::archive_fingerprint(&existing).unwrap();
        let error = restore_wal_archives_from_external(
            &temp.path().join("target"),
            &external,
            &["docs".into()],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("conflicting WAL archives"),
            "{error}"
        );
        assert_eq!(Wal::archive_fingerprint(&existing).unwrap(), before);
    }

    #[test]
    fn staged_origin_rehydration_joins_checked_archive_and_live_suffix() {
        let temp = TempDir::new().unwrap();
        let wal_dir = temp.path().join("collection/wal");
        let mut wal = Wal::open(&wal_dir).unwrap();
        let cut = wal
            .append(&WalEntry::Delete {
                id: "archived-prefix".into(),
            })
            .unwrap();
        let frozen = wal.freeze_archive_cut(cut).unwrap().unwrap();
        frozen.publish(&wal_dir.join("archive")).unwrap();
        wal.append(&WalEntry::Delete {
            id: "live-suffix".into(),
        })
        .unwrap();
        wal.drop_prefix(cut).unwrap();
        drop(wal);

        assert!(rehydrate_wal_origin_from_archives(&wal_dir).unwrap());
        assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), 0);
        let records = Wal::load(&wal_dir).unwrap();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0].entry,
            WalEntry::Delete { id } if id == "archived-prefix"
        ));
        assert!(matches!(
            &records[1].entry,
            WalEntry::Delete { id } if id == "live-suffix"
        ));
        assert_eq!(fs::read_dir(wal_dir.join("archive")).unwrap().count(), 1);
    }

    #[test]
    fn staged_origin_rehydration_rejects_gap_without_replacing_live_wal() {
        let temp = TempDir::new().unwrap();
        let wal_dir = temp.path().join("collection/wal");
        let mut wal = Wal::open(&wal_dir).unwrap();
        let first_cut = wal
            .append(&WalEntry::Delete {
                id: "archived-prefix".into(),
            })
            .unwrap();
        let first = wal.freeze_archive_cut(first_cut).unwrap().unwrap();
        first.publish(&wal_dir.join("archive")).unwrap();
        let live_base = wal
            .append(&WalEntry::Delete {
                id: "missing-middle".into(),
            })
            .unwrap();
        drop(wal.freeze_archive_cut(live_base).unwrap());
        wal.drop_prefix(live_base).unwrap();
        drop(wal);

        let error = rehydrate_wal_origin_from_archives(&wal_dir).unwrap_err();
        assert!(error.to_string().contains("gap"), "{error}");
        assert_eq!(Wal::retained_base_lsn(&wal_dir).unwrap(), live_base);
        assert!(Wal::load(&wal_dir).unwrap().is_empty());
        assert_eq!(fs::read_dir(wal_dir.join("archive")).unwrap().count(), 1);
    }
}
