//! Deterministic durability fault injection, compiled only for test features.

#[cfg(feature = "fault-injection")]
use crate::GaussError;
use crate::Result;

#[cfg(all(test, feature = "fault-injection"))]
const TEST_ENV_NAMES: [&str; 3] = [
    "CHIRONDB_FAILPOINT",
    "CHIRONDB_FAILPOINT_MARKER",
    "CHIRONDB_FAILPOINT_RELEASE",
];

#[cfg(all(test, feature = "fault-injection"))]
pub(crate) static TEST_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(all(test, feature = "fault-injection"))]
pub(crate) struct TestEnvGuard {
    previous: [Option<std::ffi::OsString>; 3],
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(all(test, feature = "fault-injection"))]
pub(crate) fn test_env(
    failpoint: &str,
    marker: &std::path::Path,
    release: &std::path::Path,
) -> TestEnvGuard {
    let lock = TEST_ENV
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = TEST_ENV_NAMES.map(std::env::var_os);
    // SAFETY: TEST_ENV serializes every in-process test mutation of these
    // process-wide variables and the guard restores them before unlocking.
    unsafe {
        std::env::set_var(TEST_ENV_NAMES[0], failpoint);
        std::env::set_var(TEST_ENV_NAMES[1], marker);
        std::env::set_var(TEST_ENV_NAMES[2], release);
    }
    TestEnvGuard {
        previous,
        _lock: lock,
    }
}

#[cfg(all(test, feature = "fault-injection"))]
impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        // SAFETY: this guard still owns TEST_ENV while restoring the variables.
        unsafe {
            for (name, value) in TEST_ENV_NAMES.into_iter().zip(&self.previous) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

#[cfg(feature = "fault-injection")]
fn pause_for_parent(name: &str) -> Result<()> {
    use std::{fs::OpenOptions, io::Write, path::PathBuf, time::Duration};

    let marker = std::env::var_os("CHIRONDB_FAILPOINT_MARKER")
        .map(PathBuf::from)
        .ok_or_else(|| {
            GaussError::InvalidRequest(
                "pause failpoint requires CHIRONDB_FAILPOINT_MARKER".to_string(),
            )
        })?;
    let parent = marker.parent().ok_or_else(|| {
        GaussError::InvalidRequest("failpoint marker has no parent directory".to_string())
    })?;
    std::fs::create_dir_all(parent)?;
    let contents = format!("pid={} failpoint={name}\n", std::process::id());
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)
    {
        Ok(mut file) => {
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
        }
        // A loop may hit this boundary again after the parent releases it.
        // Reuse only this process's marker for this exact failpoint, without
        // rewriting the parent's evidence or accepting a stale foreign marker.
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists
                && std::fs::read_to_string(&marker).is_ok_and(|value| value == contents) => {}
        Err(error) => return Err(error.into()),
    }

    let release = std::env::var_os("CHIRONDB_FAILPOINT_RELEASE").map(PathBuf::from);

    loop {
        if release.as_ref().is_some_and(|path| path.exists()) {
            return Ok(());
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
}

pub fn check(name: &str) -> Result<()> {
    #[cfg(feature = "fault-injection")]
    if let Ok(config) = std::env::var("CHIRONDB_FAILPOINT") {
        if config == format!("exit:{name}") {
            std::process::exit(86);
        }
        if config == format!("error:{name}") {
            return Err(GaussError::Io(std::io::Error::other(format!(
                "injected failpoint {name}"
            ))));
        }
        if config == format!("pause:{name}") {
            return pause_for_parent(name);
        }
    }
    let _ = name;
    Ok(())
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;

    #[test]
    fn released_pause_can_be_hit_again_without_rewriting_marker() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("marker");
        let release = temp.path().join("release");
        let _env = test_env("pause:seal.after_vamana_cell", &marker, &release);
        std::fs::write(&release, b"continue").unwrap();
        check("seal.after_vamana_cell").unwrap();
        let bytes = std::fs::read(&marker).unwrap();
        let modified = std::fs::metadata(&marker).unwrap().modified().unwrap();
        check("seal.after_vamana_cell").unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&marker).unwrap().modified().unwrap(),
            modified
        );
    }

    #[test]
    fn pause_rejects_foreign_marker_even_when_released() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("marker");
        let release = temp.path().join("release");
        let _env = test_env("pause:seal.after_vamana_cell", &marker, &release);
        std::fs::write(&marker, b"foreign marker").unwrap();
        std::fs::write(&release, b"continue").unwrap();
        assert!(matches!(
            check("seal.after_vamana_cell"),
            Err(GaussError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(std::fs::read(&marker).unwrap(), b"foreign marker");
    }
}
