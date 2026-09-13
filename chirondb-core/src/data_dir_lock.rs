use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

use crate::{
    error::{GaussError, Result},
    fs_util::sync_directory,
};

const MAX_OWNER_METADATA_BYTES: usize = 4 * 1024;

/// An OS-enforced, process-exclusive lease for one resolved data directory.
///
/// The lock file deliberately lives next to the data directory. Restore may
/// rename the live directory, but cannot move the lease protecting that name.
/// The file itself is never unlinked: replacing it would create a second inode
/// that another process could lock while the original inode is still leased.
#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: File,
    root: PathBuf,
    #[allow(dead_code)]
    identity: PathBuf,
    #[allow(dead_code)]
    path: PathBuf,
}

#[derive(Serialize)]
struct OwnerMetadata<'a> {
    pid: u32,
    started_unix_ms: u128,
    version: &'static str,
    data_dir: &'a str,
}

impl DataDirLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let root = absolute_normalized_path(root)?;
        let identity = resolve_data_dir(&root)?;
        let parent = identity.parent().ok_or_else(|| {
            GaussError::InvalidRequest("data directory must have a parent directory".to_string())
        })?;
        let root_name = identity.file_name().ok_or_else(|| {
            GaussError::InvalidRequest("data directory must name a directory".to_string())
        })?;
        let mut lock_name = OsString::from(".");
        lock_name.push(root_name);
        lock_name.push(".chirondb.lock");
        let path = parent.join(lock_name);

        let file = open_lock_file(&path)?;
        if let Err(error) = file.try_lock() {
            return match error {
                fs::TryLockError::WouldBlock => Err(GaussError::DataDirLocked {
                    path: identity.display().to_string(),
                    owner: read_owner_metadata(&file),
                }),
                fs::TryLockError::Error(error) => Err(error.into()),
            };
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        write_owner_metadata(&file, &identity)?;
        sync_directory(parent)?;

        Ok(Self {
            _file: file,
            root,
            identity,
            path,
        })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // Do not rely solely on the platform's close-on-drop behaviour. An
        // explicit unlock makes the hand-off to a replacement process
        // deterministic once the final Db/background-maintenance lease ends.
        if let Err(error) = self._file.unlock() {
            tracing::warn!(
                %error,
                path = %self.path.display(),
                "failed to release data-directory lock explicitly"
            );
        }
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_owner_metadata(file: &File, root: &Path) -> Result<()> {
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let displayed_root = root.display().to_string();
    let mut payload = serde_json::to_vec(&OwnerMetadata {
        pid: std::process::id(),
        started_unix_ms,
        version: env!("CARGO_PKG_VERSION"),
        data_dir: &displayed_root,
    })?;
    if payload.len() >= MAX_OWNER_METADATA_BYTES {
        payload = serde_json::to_vec(&OwnerMetadata {
            pid: std::process::id(),
            started_unix_ms,
            version: env!("CARGO_PKG_VERSION"),
            data_dir: "<omitted: resolved path exceeds lock metadata limit>",
        })?;
    }
    payload.push(b'\n');

    file.set_len(0)?;
    let mut writer = file;
    writer.write_all(&payload)?;
    file.sync_all()?;
    Ok(())
}

fn read_owner_metadata(file: &File) -> Option<String> {
    let mut bytes = [0_u8; MAX_OWNER_METADATA_BYTES];
    let mut reader = file;
    let read = reader.read(&mut bytes).ok()?;
    let owner = String::from_utf8_lossy(&bytes[..read]).trim().to_string();
    (!owner.is_empty()).then_some(owner)
}

/// Canonicalize the nearest existing ancestor while retaining a missing final
/// data-directory name. Creating/canonicalizing the parent before opening the
/// sibling lock makes relative, `..`, and symlink aliases converge on the same
/// lock inode without creating or inspecting the database root itself.
fn resolve_data_dir(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }

    let name = path.file_name().ok_or_else(|| {
        GaussError::InvalidRequest("data directory must name a directory".to_string())
    })?;
    let parent = path.parent().ok_or_else(|| {
        GaussError::InvalidRequest("data directory must have a parent directory".to_string())
    })?;
    fs::create_dir_all(parent)?;
    Ok(fs::canonicalize(parent)?.join(name))
}

fn absolute_normalized_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    normalize_absolute_path(&absolute)
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(GaussError::InvalidRequest(format!(
                        "data directory escapes its filesystem root: {}",
                        path.display()
                    )));
                }
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::DataDirLock;
    use crate::GaussError;

    #[test]
    fn lock_is_exclusive_and_stale_metadata_does_not_block_reopen() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("db");
        let first = DataDirLock::acquire(&root).unwrap();
        let error = DataDirLock::acquire(&root).unwrap_err();
        assert!(matches!(error, GaussError::DataDirLocked { .. }));
        drop(first);
        DataDirLock::acquire(&root).unwrap();
    }

    #[test]
    fn normalized_alias_uses_the_same_lock() {
        let sandbox = TempDir::new().unwrap();
        let root = sandbox.path().join("parent/db");
        let first = DataDirLock::acquire(&root).unwrap();
        let alias = sandbox.path().join("parent/child/../db");
        std::fs::create_dir_all(sandbox.path().join("parent/child")).unwrap();
        assert!(matches!(
            DataDirLock::acquire(&alias),
            Err(GaussError::DataDirLocked { .. })
        ));
        drop(first);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_alias_uses_the_same_lock() {
        use std::os::unix::fs::symlink;

        let sandbox = TempDir::new().unwrap();
        let real_parent = sandbox.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let alias_parent = sandbox.path().join("alias");
        symlink(&real_parent, &alias_parent).unwrap();
        let first = DataDirLock::acquire(&real_parent.join("db")).unwrap();
        assert!(matches!(
            DataDirLock::acquire(&alias_parent.join("db")),
            Err(GaussError::DataDirLocked { .. })
        ));
        drop(first);
    }
}
