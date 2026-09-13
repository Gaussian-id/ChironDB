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
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)?;
    writeln!(file, "pid={} failpoint={name}", std::process::id())?;
    file.sync_all()?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;

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
