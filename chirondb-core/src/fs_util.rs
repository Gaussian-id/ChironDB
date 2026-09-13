//! Pure filesystem utility helpers shared across modules.
//! No GaussDB-specific types; only std I/O and Path operations.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::error::Result;

/// Deterministic, one-shot faults for durability tests. This module is absent
/// from normal and release builds unless the non-production feature is
/// explicitly enabled.
#[cfg(any(test, feature = "fault-injection"))]
pub mod fault_injection {
    #[cfg(test)]
    use std::cell::RefCell;
    use std::{
        cell::Cell,
        fs::OpenOptions,
        io::Write,
        path::{Path, PathBuf},
        thread,
        time::Duration,
    };

    pub const CRASH_HOOK_ENV: &str = "CHIRONDB_CRASH_HOOK";
    pub const CRASH_HOOK_MARKER_ENV: &str = "CHIRONDB_CRASH_HOOK_MARKER";
    pub const CRASH_HOOK_RELEASE_ENV: &str = "CHIRONDB_CRASH_HOOK_RELEASE";
    pub const TEST_WAL_SEGMENT_BYTES_ENV: &str = "CHIRONDB_TEST_WAL_SEGMENT_BYTES";

    pub const HOOK_WAL_AFTER_FRAME_HEADER: &str = "wal_after_frame_header";
    pub const HOOK_WAL_AFTER_FRAME_WRITE: &str = "wal_after_frame_write";
    pub const HOOK_WAL_AFTER_FSYNC: &str = "wal_after_fsync";
    pub const HOOK_WAL_AFTER_ROTATION_PUBLISH: &str = "wal_after_rotation_publish";
    pub const HOOK_WAL_AFTER_ARCHIVE_PUBLISH: &str = "wal_after_archive_publish";
    pub const HOOK_CATALOG_AFTER_DURABLE_COMMIT: &str = "catalog_after_durable_commit";
    pub const HOOK_COMPACT_AFTER_SEGMENT_TREE_SYNC: &str = "compact_after_segment_tree_sync";
    pub const HOOK_COMPACT_AFTER_SEGMENT_PUBLISH: &str = "compact_after_segment_publish";
    pub const HOOK_COMPACT_AFTER_WAL_FSYNC: &str = "compact_after_wal_fsync";
    pub const HOOK_COMPACT_AFTER_MANIFEST_PUBLISH: &str = "compact_after_manifest_publish";
    pub const HOOK_COMPACT_AFTER_CHECKPOINT_PUBLISH: &str = "compact_after_checkpoint_publish";
    pub const HOOK_SNAPSHOT_AFTER_STAGING_SYNC: &str = "snapshot_after_staging_sync";
    pub const HOOK_SNAPSHOT_AFTER_DESTINATION_PUBLISH: &str = "snapshot_after_destination_publish";
    pub const HOOK_RESTORE_AFTER_PREPARED: &str = "restore_after_prepared";
    pub const HOOK_RESTORE_AFTER_OLD_MOVED: &str = "restore_after_old_moved";
    pub const HOOK_RESTORE_AFTER_NEW_INSTALLED: &str = "restore_after_new_installed";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Fault {
        Enospc,
        PermissionDenied,
        ShortWrite,
        Fsync,
        Rename,
        Copy,
    }

    thread_local! {
        static NEXT_FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
        #[cfg(test)]
        static TEST_CRASH_HOOK: RefCell<Option<CrashHookConfig>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Debug)]
    struct CrashHookConfig {
        name: String,
        marker: PathBuf,
        release: Option<PathBuf>,
    }

    /// Fail the next matching durability boundary on the current thread.
    /// Faults are one-shot so a failed operation cannot contaminate cleanup.
    pub fn inject_once(fault: Fault) {
        NEXT_FAULT.with(|slot| slot.set(Some(fault)));
    }

    pub(crate) fn take_if(predicate: impl FnOnce(Fault) -> bool) -> Option<Fault> {
        NEXT_FAULT.with(|slot| {
            let fault = slot.get()?;
            if predicate(fault) {
                slot.set(None);
                Some(fault)
            } else {
                None
            }
        })
    }

    pub(crate) fn injected_error(fault: Fault) -> std::io::Error {
        let kind = match fault {
            Fault::Enospc => std::io::ErrorKind::StorageFull,
            Fault::PermissionDenied => std::io::ErrorKind::PermissionDenied,
            Fault::ShortWrite => std::io::ErrorKind::WriteZero,
            Fault::Fsync | Fault::Rename | Fault::Copy => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, format!("injected {fault:?} failure"))
    }

    /// Mark a named crash boundary and pause until the controlling process
    /// creates the optional release file. If no release path is configured,
    /// the process waits until it is killed. Environment lookup and all hook
    /// code are absent from normal builds because the containing module is
    /// feature-gated.
    pub fn crash_hook(name: &str) -> std::io::Result<()> {
        let Some(config) = crash_hook_config()? else {
            return Ok(());
        };
        if config.name != name {
            return Ok(());
        }

        let mut marker = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&config.marker)?;
        marker.write_all(name.as_bytes())?;
        marker.write_all(b"\n")?;
        marker.sync_all()?;

        loop {
            if config.release.as_deref().is_some_and(Path::exists) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn crash_hook_config() -> std::io::Result<Option<CrashHookConfig>> {
        #[cfg(test)]
        if let Some(config) = TEST_CRASH_HOOK.with(|slot| slot.borrow_mut().take()) {
            return Ok(Some(config));
        }

        let Some(name) = std::env::var_os(CRASH_HOOK_ENV) else {
            return Ok(None);
        };
        let marker = std::env::var_os(CRASH_HOOK_MARKER_ENV).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{CRASH_HOOK_MARKER_ENV} is required when {CRASH_HOOK_ENV} is set"),
            )
        })?;
        Ok(Some(CrashHookConfig {
            name: name.to_string_lossy().into_owned(),
            marker: marker.into(),
            release: std::env::var_os(CRASH_HOOK_RELEASE_ENV).map(PathBuf::from),
        }))
    }

    #[cfg(test)]
    pub(crate) fn arm_crash_hook_for_current_thread(
        name: &str,
        marker: PathBuf,
        release: Option<PathBuf>,
    ) {
        TEST_CRASH_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(CrashHookConfig {
                name: name.to_string(),
                marker,
                release,
            });
        });
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_with(path, |file| {
        file.write_all(bytes)?;
        Ok(())
    })
}

pub(crate) fn atomic_write_with(
    path: &Path,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    fs::create_dir_all(parent)?;
    let tmp = temporary_sibling(path);
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        write(&mut file)?;
        crate::failpoint::check("atomic.before_temp_sync")?;
        file.sync_all()?;
        crate::failpoint::check("atomic.after_temp_sync")?;
        atomic_replace(&tmp, path)?;
        crate::failpoint::check("atomic.after_rename_before_dir_sync")?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub(crate) fn checked_copy(source: &Path, destination: &Path) -> Result<u64> {
    let expected = fs::metadata(source)?.len();
    let parent = destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", destination.display()),
        )
    })?;
    fs::create_dir_all(parent)?;
    let tmp = temporary_sibling(destination);
    let result = (|| -> Result<u64> {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        let copied = std::io::copy(&mut input, &mut output)?;
        if copied != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "copy length mismatch for {}: expected {expected}, copied {copied}",
                    source.display()
                ),
            )
            .into());
        }
        output.sync_all()?;
        crate::failpoint::check("copy.after_temp_sync")?;
        atomic_replace(&tmp, destination)?;
        crate::failpoint::check("copy.after_rename_before_dir_sync")?;
        sync_directory(parent)?;
        Ok(copied)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub(crate) fn durable_create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    sync_directory(path)
}

fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    if destination.exists() {
        // std does not expose ReplaceFileW. The destination is removed only
        // on the best-effort Windows target; required Unix targets retain the
        // atomic rename contract.
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)?;
    Ok(())
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("data");
    path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()))
}

pub(crate) fn read_exact_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let len = fs::metadata(path)?.len();
    if len > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds {max_bytes} bytes", path.display()),
        )
        .into());
    }
    let capacity = usize::try_from(len).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "file length exceeds usize")
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > capacity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file grew while being read",
        )
        .into());
    }
    Ok(bytes)
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        durable_remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    copy_dir_contents(source, destination)?;
    sync_directory(destination)
}

/// Flush directory-entry changes for `path` to stable storage.
///
/// File fsync alone does not make a newly created, renamed, or deleted path
/// durable across a power loss. Callers must sync the containing directory
/// after those operations.
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    crate::failpoint::check("fs.before_directory_sync")?;
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(fault) = fault_injection::take_if(|fault| fault == fault_injection::Fault::Fsync) {
        return Err(fault_injection::injected_error(fault).into());
    }
    sync_directory_impl(path)?;
    crate::failpoint::check("fs.after_directory_sync")?;
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory_impl(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory_impl(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    // Required to open a directory handle with CreateFileW.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

/// Copy a file and make both its contents and directory entry durable.
pub(crate) fn durable_copy(source: &Path, destination: &Path) -> Result<u64> {
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(fault) = fault_injection::take_if(|fault| fault == fault_injection::Fault::Copy) {
        return Err(fault_injection::injected_error(fault).into());
    }
    let copied = fs::copy(source, destination)?;
    sync_copied_file(destination)?;
    if let Some(parent) = destination.parent() {
        sync_directory(parent)?;
    }
    Ok(copied)
}

#[cfg(not(windows))]
fn sync_copied_file(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_copied_file(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

/// Rename a path and durably publish the directory-entry update.
pub(crate) fn durable_rename(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(test, feature = "fault-injection"))]
    if let Some(fault) = fault_injection::take_if(|fault| fault == fault_injection::Fault::Rename) {
        return Err(fault_injection::injected_error(fault).into());
    }
    let source_parent = source.parent();
    let destination_parent = destination.parent();
    fs::rename(source, destination)?;
    if let Some(parent) = destination_parent {
        sync_directory(parent)?;
    }
    if source_parent != destination_parent
        && let Some(parent) = source_parent
    {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Remove a file and make the unlink durable.
pub(crate) fn durable_remove_file(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Remove a directory tree and make removal of its root entry durable.
pub(crate) fn durable_remove_dir_all(path: &Path) -> Result<()> {
    fs::remove_dir_all(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Flush every regular file in a directory tree, then each directory from
/// leaves to root so a staged generation is safe to publish atomically.
pub(crate) fn sync_tree(path: &Path) -> Result<()> {
    if path.is_file() {
        File::open(path)?.sync_all()?;
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            sync_tree(&entry.path())?;
        } else if file_type.is_file() {
            File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(path)
}

pub(crate) fn copy_dir_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if matches!(entry.file_name().to_str(), Some(".chirondb.lock" | "audit")) {
            continue;
        }
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("refusing to copy symbolic link {}", entry.path().display()),
            )
            .into());
        }
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            checked_copy(&entry.path(), &target)?;
        }
    }
    sync_directory(destination)?;
    Ok(())
}

pub(crate) fn directory_size(path: &Path) -> Result<u64> {
    let mut size = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            size += directory_size(&entry.path())?;
        } else if file_type.is_file() {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}

pub(crate) fn count_wal_segment_files(path: &Path) -> Result<usize> {
    let mut segments = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "gdwal")
        {
            segments += 1;
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use tempfile::TempDir;

    use super::{
        durable_copy, durable_rename,
        fault_injection::{
            Fault, HOOK_WAL_AFTER_FRAME_HEADER, arm_crash_hook_for_current_thread, crash_hook,
            inject_once,
        },
    };

    #[test]
    fn injected_copy_failure_does_not_publish_destination() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::write(&source, b"durable source").unwrap();

        inject_once(Fault::Copy);
        let error = durable_copy(&source, &destination).unwrap_err();

        assert!(error.to_string().contains("injected Copy failure"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn injected_rename_failure_does_not_publish_destination() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::write(&source, b"staged generation").unwrap();

        inject_once(Fault::Rename);
        let error = durable_rename(&source, &destination).unwrap_err();

        assert!(error.to_string().contains("injected Rename failure"));
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn crash_hook_writes_marker_and_waits_for_release() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("marker");
        let release = temp.path().join("release");
        let worker_marker = marker.clone();
        let worker_release = release.clone();
        let worker = thread::spawn(move || {
            arm_crash_hook_for_current_thread(
                HOOK_WAL_AFTER_FRAME_HEADER,
                worker_marker,
                Some(worker_release),
            );
            crash_hook(HOOK_WAL_AFTER_FRAME_HEADER).unwrap();
        });

        for _ in 0..200 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            std::fs::write(&release, b"release timed-out hook").unwrap();
            worker.join().unwrap();
            panic!("crash hook marker was not published");
        }
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            format!("{HOOK_WAL_AFTER_FRAME_HEADER}\n")
        );
        assert!(!worker.is_finished());

        std::fs::write(release, b"continue").unwrap();
        worker.join().unwrap();
    }
}
