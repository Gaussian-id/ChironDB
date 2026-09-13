use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use reqwest::Url;

#[derive(Clone, Debug, Default)]
pub struct StoragePolicy {
    snapshot_root: Option<PathBuf>,
    object_store_prefix: Option<Url>,
    require_https: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StoragePolicyError {
    #[error("snapshot and restore endpoints are disabled; configure snapshot_root")]
    Disabled,
    #[error("storage path is outside the configured snapshot_root")]
    OutsideRoot,
    #[error("storage path traverses a symbolic link")]
    Symlink,
    #[error("invalid object-store URL: {0}")]
    InvalidUrl(String),
    #[error("object-store URL is outside the configured origin/prefix")]
    UrlOutsidePrefix,
    #[error("secure mode requires HTTPS object-store URLs")]
    InsecureUrl,
    #[error("failed to prepare snapshot_root: {0}")]
    Io(#[from] std::io::Error),
}

impl StoragePolicy {
    pub fn new(
        snapshot_root: Option<PathBuf>,
        object_store_prefix: Option<&str>,
        require_https: bool,
    ) -> Result<Self, StoragePolicyError> {
        let snapshot_root = snapshot_root
            .map(|root| {
                std::fs::create_dir_all(&root)?;
                root.canonicalize()
            })
            .transpose()?;
        let object_store_prefix = object_store_prefix.map(parse_url).transpose()?;
        if require_https
            && object_store_prefix
                .as_ref()
                .is_some_and(|url| url.scheme() != "https")
        {
            return Err(StoragePolicyError::InsecureUrl);
        }
        Ok(Self {
            snapshot_root,
            object_store_prefix,
            require_https,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.snapshot_root.is_some()
    }

    pub fn resolve_path(&self, requested: impl AsRef<Path>) -> Result<PathBuf, StoragePolicyError> {
        let root = self
            .snapshot_root
            .as_ref()
            .ok_or(StoragePolicyError::Disabled)?;
        let requested = requested.as_ref();
        let relative = if requested.is_absolute() {
            requested
                .strip_prefix(root)
                .map_err(|_| StoragePolicyError::OutsideRoot)?
        } else {
            requested
        };
        if relative.as_os_str().is_empty()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(StoragePolicyError::OutsideRoot);
        }
        let resolved = root.join(relative);
        reject_symlink_prefix(root, &resolved)?;
        Ok(resolved)
    }

    pub fn resolve_url(&self, requested: &str) -> Result<String, StoragePolicyError> {
        let configured = self
            .object_store_prefix
            .as_ref()
            .ok_or(StoragePolicyError::UrlOutsidePrefix)?;
        let requested = parse_url(requested)?;
        if self.require_https && requested.scheme() != "https" {
            return Err(StoragePolicyError::InsecureUrl);
        }
        if requested.scheme() != configured.scheme()
            || requested.host_str() != configured.host_str()
            || requested.port_or_known_default() != configured.port_or_known_default()
            || !url_path_has_prefix(requested.path(), configured.path())
        {
            return Err(StoragePolicyError::UrlOutsidePrefix);
        }
        Ok(requested.to_string())
    }
}

fn parse_url(value: &str) -> Result<Url, StoragePolicyError> {
    Url::parse(value).map_err(|error| StoragePolicyError::InvalidUrl(error.to_string()))
}

fn url_path_has_prefix(requested: &str, configured: &str) -> bool {
    let configured = configured.trim_end_matches('/');
    configured.is_empty()
        || requested == configured
        || requested
            .strip_prefix(configured)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn reject_symlink_prefix(root: &Path, target: &Path) -> Result<(), StoragePolicyError> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| StoragePolicyError::OutsideRoot)?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(StoragePolicyError::OutsideRoot);
        };
        if name == OsStr::new(".") {
            continue;
        }
        cursor.push(name);
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoragePolicyError::Symlink);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_path_is_sandboxed() {
        let root = tempfile::tempdir().unwrap();
        let policy = StoragePolicy::new(Some(root.path().to_path_buf()), None, false).unwrap();
        assert_eq!(
            policy.resolve_path("snapshots/one").unwrap(),
            root.path().canonicalize().unwrap().join("snapshots/one")
        );
        assert!(matches!(
            policy.resolve_path("../escape"),
            Err(StoragePolicyError::OutsideRoot)
        ));
    }

    #[test]
    fn object_url_must_match_origin_and_path_prefix() {
        let root = tempfile::tempdir().unwrap();
        let policy = StoragePolicy::new(
            Some(root.path().to_path_buf()),
            Some("https://objects.example/chirondb/"),
            true,
        )
        .unwrap();
        assert!(
            policy
                .resolve_url("https://objects.example/chirondb/archive/1")
                .is_ok()
        );
        assert!(
            policy
                .resolve_url("https://objects.example/other/archive/1")
                .is_err()
        );
        assert!(
            policy
                .resolve_url("http://objects.example/chirondb/archive/1")
                .is_err()
        );
    }
}
