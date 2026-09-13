//! Crash-recovery journal for atomic data-directory restores.
//!
//! The journal lives in the parent of the live data directory. Staging and
//! backup locations are stored as single relative path components so recovery
//! can never be redirected outside that parent directory.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{GaussError, Result, fs_util::sync_directory};

pub(crate) const RESTORE_JOURNAL_FILE: &str = ".chirondb-restore.journal";
const RESTORE_JOURNAL_TMP_FILE: &str = ".chirondb-restore.journal.tmp";
#[cfg(windows)]
const RESTORE_JOURNAL_PREVIOUS_FILE: &str = ".chirondb-restore.journal.previous";
const MAGIC: &[u8; 8] = b"CHIRRJN1";
const FORMAT_VERSION: u16 = 2;
const LEGACY_FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + 2 + 4 + 4;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RestorePhase {
    Prepared,
    OldMoved,
    NewInstalled,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RestoreInstallMode {
    #[default]
    LegacySwap,
    GenerationSwitch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreJournal {
    pub(crate) operation_id: Uuid,
    pub(crate) phase: RestorePhase,
    #[serde(default)]
    pub(crate) install_mode: RestoreInstallMode,
    pub(crate) staging_name: String,
    pub(crate) backup_name: String,
    #[serde(default)]
    pub(crate) installed_name: Option<String>,
}

impl RestoreJournal {
    pub(crate) fn new(
        operation_id: Uuid,
        phase: RestorePhase,
        staging_name: impl Into<String>,
        backup_name: impl Into<String>,
    ) -> Result<Self> {
        let journal = Self {
            operation_id,
            phase,
            install_mode: RestoreInstallMode::LegacySwap,
            staging_name: staging_name.into(),
            backup_name: backup_name.into(),
            installed_name: None,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub(crate) fn new_generation(
        operation_id: Uuid,
        phase: RestorePhase,
        staging_name: impl Into<String>,
        previous_generation: impl Into<String>,
        installed_generation: impl Into<String>,
    ) -> Result<Self> {
        let journal = Self {
            operation_id,
            phase,
            install_mode: RestoreInstallMode::GenerationSwitch,
            staging_name: staging_name.into(),
            backup_name: previous_generation.into(),
            installed_name: Some(installed_generation.into()),
        };
        journal.validate()?;
        Ok(journal)
    }

    pub(crate) fn with_phase(&self, phase: RestorePhase) -> Self {
        let mut next = self.clone();
        next.phase = phase;
        next
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validate_fields().map_err(|message| {
            GaussError::InvalidRequest(format!("invalid restore journal: {message}"))
        })
    }

    fn validate_fields(&self) -> std::result::Result<(), String> {
        if self.operation_id.is_nil() {
            return Err("operation id must not be nil".into());
        }
        validate_sibling_name("staging", &self.staging_name)?;
        validate_sibling_name("backup", &self.backup_name)?;
        if self.staging_name == self.backup_name {
            return Err("staging and backup names must differ".into());
        }
        match self.install_mode {
            RestoreInstallMode::LegacySwap if self.installed_name.is_some() => {
                return Err("legacy restore must not name an installed generation".into());
            }
            RestoreInstallMode::GenerationSwitch => {
                let installed = self.installed_name.as_deref().ok_or_else(|| {
                    "generation restore must name its installed generation".to_string()
                })?;
                validate_sibling_name("installed generation", installed)?;
                if installed == self.backup_name || installed == self.staging_name {
                    return Err("generation restore paths must be distinct".into());
                }
            }
            RestoreInstallMode::LegacySwap => {}
        }
        Ok(())
    }
}

/// Atomically writes and durably publishes the restore journal.
pub(crate) fn write(parent: &Path, journal: &RestoreJournal) -> Result<()> {
    journal.validate()?;

    let payload = serde_json::to_vec(journal)?;
    let frame = encode_frame(&payload)?;
    let temporary = parent.join(RESTORE_JOURNAL_TMP_FILE);
    let destination = parent.join(RESTORE_JOURNAL_FILE);

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&frame)?;
    file.sync_all()?;
    drop(file);

    atomic_replace(&temporary, &destination)?;
    sync_directory(parent)?;
    Ok(())
}

/// Reads and validates a restore journal. Missing journals return `None`.
pub(crate) fn read(parent: &Path) -> Result<Option<RestoreJournal>> {
    let Some((mut file, path)) = open_published_journal(parent)? else {
        return Ok(None);
    };

    if file.metadata()?.len() > MAX_JOURNAL_BYTES as u64 {
        return Err(corruption(&path, "journal exceeds the 64 KiB limit"));
    }

    // The `take` bound prevents a concurrent or corrupt file from causing an
    // unbounded allocation after the metadata check.
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    Read::by_ref(&mut file)
        .take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(corruption(&path, "journal exceeds the 64 KiB limit"));
    }

    let payload = decode_frame(&path, &bytes)?;
    let journal: RestoreJournal = serde_json::from_slice(payload)
        .map_err(|error| corruption(&path, format!("invalid journal payload: {error}")))?;
    journal
        .validate_fields()
        .map_err(|message| corruption(&path, message))?;
    Ok(Some(journal))
}

/// Removes the published journal and any interrupted temporary write.
pub(crate) fn remove(parent: &Path) -> Result<bool> {
    let mut removed = false;
    for file_name in [RESTORE_JOURNAL_FILE, RESTORE_JOURNAL_TMP_FILE] {
        match fs::remove_file(parent.join(file_name)) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(windows)]
    match fs::remove_file(parent.join(RESTORE_JOURNAL_PREVIOUS_FILE)) {
        Ok(()) => removed = true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if removed {
        sync_directory(parent)?;
    }
    Ok(removed)
}

fn open_published_journal(parent: &Path) -> Result<Option<(File, PathBuf)>> {
    let path = parent.join(RESTORE_JOURNAL_FILE);
    match File::open(&path) {
        Ok(file) => return Ok(Some((file, path))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    #[cfg(windows)]
    {
        // Windows cannot replace an existing file with `std::fs::rename`.
        // If a crash happened between moving the old journal aside and
        // publishing the new one, recover from the still-durable old frame.
        let previous = parent.join(RESTORE_JOURNAL_PREVIOUS_FILE);
        return match File::open(&previous) {
            Ok(file) => Ok(Some((file, previous))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        };
    }

    #[cfg(not(windows))]
    Ok(None)
}

fn validate_sibling_name(label: &str, name: &str) -> std::result::Result<(), String> {
    if name.is_empty() || name.contains(['/', '\\', '\0', ':']) || name == "." || name == ".." {
        return Err(format!("{label} name is not a relative sibling name"));
    }

    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(format!("{label} name is not a relative sibling name"));
    }
    Ok(())
}

fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let total_len = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| GaussError::InvalidRequest("restore journal size overflow".into()))?;
    if total_len > MAX_JOURNAL_BYTES {
        return Err(GaussError::InvalidRequest(
            "restore journal exceeds the 64 KiB limit".into(),
        ));
    }

    let payload_len = u32::try_from(payload.len())
        .map_err(|_| GaussError::InvalidRequest("restore journal payload is too large".into()))?;
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&payload_len.to_le_bytes());

    let mut hasher = Hasher::new();
    hasher.update(&frame);
    hasher.update(payload);
    frame.extend_from_slice(&hasher.finalize().to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_frame<'a>(path: &Path, bytes: &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() < HEADER_BYTES {
        return Err(corruption(path, "truncated journal header"));
    }
    if &bytes[..8] != MAGIC {
        return Err(corruption(path, "invalid journal magic"));
    }

    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed header slice"));
    if !matches!(version, LEGACY_FORMAT_VERSION | FORMAT_VERSION) {
        return Err(corruption(
            path,
            format!("unsupported journal version {version}"),
        ));
    }
    let flags = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed header slice"));
    if flags != 0 {
        return Err(corruption(path, "unsupported journal flags"));
    }

    let payload_len =
        u32::from_le_bytes(bytes[12..16].try_into().expect("fixed header slice")) as usize;
    let expected_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| corruption(path, "journal payload length overflow"))?;
    if expected_len != bytes.len() {
        return Err(corruption(
            path,
            format!(
                "journal length mismatch: header declares {expected_len} bytes, file has {}",
                bytes.len()
            ),
        ));
    }

    let expected_crc = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed header slice"));
    let payload = &bytes[HEADER_BYTES..];
    let mut hasher = Hasher::new();
    hasher.update(&bytes[..16]);
    hasher.update(payload);
    let actual_crc = hasher.finalize();
    if expected_crc != actual_crc {
        return Err(corruption(
            path,
            format!("journal crc mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"),
        ));
    }
    Ok(payload)
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    // `std::fs::rename` cannot replace an existing file on Windows. Preserve
    // the previous valid frame until the new frame is published; `read` falls
    // back to it if a crash interrupts the two renames.
    let parent = destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restore journal destination has no parent",
        )
    })?;
    let previous = parent.join(RESTORE_JOURNAL_PREVIOUS_FILE);
    match fs::remove_file(&previous) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_directory(parent)?;
    if destination.exists() {
        fs::rename(destination, &previous)?;
        // Make the previous committed phase durable before publishing the
        // replacement. A power loss at either rename must leave at least one
        // recoverable journal frame.
        sync_directory(parent)?;
        if let Err(error) = fs::rename(source, destination) {
            let _ = fs::rename(&previous, destination);
            let _ = sync_directory(parent);
            return Err(error.into());
        }
        sync_directory(parent)?;
        return Ok(());
    }
    fs::rename(source, destination)?;
    sync_directory(parent)?;
    Ok(())
}

fn corruption(path: &Path, message: impl Into<String>) -> GaussError {
    GaussError::WalCorruption {
        path: path.display().to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use tempfile::tempdir;

    use super::*;

    fn journal(phase: RestorePhase) -> RestoreJournal {
        RestoreJournal::new(
            Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap(),
            phase,
            ".chirondb-restore-staging-aaaa",
            ".chirondb-restore-backup-aaaa",
        )
        .unwrap()
    }

    #[test]
    fn round_trips_all_phases_and_removes_durably() {
        let directory = tempdir().unwrap();
        let mut expected = journal(RestorePhase::Prepared);

        for phase in [
            RestorePhase::Prepared,
            RestorePhase::OldMoved,
            RestorePhase::NewInstalled,
        ] {
            expected = expected.with_phase(phase);
            write(directory.path(), &expected).unwrap();
            assert_eq!(read(directory.path()).unwrap(), Some(expected.clone()));
        }

        assert!(remove(directory.path()).unwrap());
        assert_eq!(read(directory.path()).unwrap(), None);
        assert!(!remove(directory.path()).unwrap());
    }

    #[test]
    fn round_trips_generation_install_mode() {
        let directory = tempdir().unwrap();
        let journal = RestoreJournal::new_generation(
            Uuid::new_v4(),
            RestorePhase::OldMoved,
            ".gen-next.restore-staging",
            "gen-previous",
            "gen-next",
        )
        .unwrap();
        write(directory.path(), &journal).unwrap();
        assert_eq!(read(directory.path()).unwrap(), Some(journal));
    }

    #[test]
    fn reads_version_one_legacy_frame() {
        let directory = tempdir().unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "operation_id": Uuid::new_v4(),
            "phase": "prepared",
            "staging_name": "staging",
            "backup_name": "backup"
        }))
        .unwrap();
        let mut frame = encode_frame(&payload).unwrap();
        frame[8..10].copy_from_slice(&LEGACY_FORMAT_VERSION.to_le_bytes());
        let mut hasher = Hasher::new();
        hasher.update(&frame[..16]);
        hasher.update(&payload);
        frame[16..20].copy_from_slice(&hasher.finalize().to_le_bytes());
        fs::write(directory.path().join(RESTORE_JOURNAL_FILE), frame).unwrap();
        let restored = read(directory.path()).unwrap().unwrap();
        assert_eq!(restored.install_mode, RestoreInstallMode::LegacySwap);
        assert_eq!(restored.installed_name, None);
    }

    #[test]
    fn rejects_crc_corruption() {
        let directory = tempdir().unwrap();
        write(directory.path(), &journal(RestorePhase::Prepared)).unwrap();
        let path = directory.path().join(RESTORE_JOURNAL_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(b"!").unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            read(directory.path()),
            Err(GaussError::WalCorruption { .. })
        ));
    }

    #[test]
    fn rejects_truncated_frames() {
        let directory = tempdir().unwrap();
        let path = directory.path().join(RESTORE_JOURNAL_FILE);
        for length in [0, HEADER_BYTES - 1, HEADER_BYTES + 3] {
            let frame =
                encode_frame(&serde_json::to_vec(&journal(RestorePhase::Prepared)).unwrap())
                    .unwrap();
            fs::write(&path, &frame[..length]).unwrap();
            assert!(matches!(
                read(directory.path()),
                Err(GaussError::WalCorruption { .. })
            ));
        }
    }

    #[test]
    fn rejects_oversize_journals_before_allocation() {
        let directory = tempdir().unwrap();
        fs::write(
            directory.path().join(RESTORE_JOURNAL_FILE),
            vec![0_u8; MAX_JOURNAL_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            read(directory.path()),
            Err(GaussError::WalCorruption { .. })
        ));

        let oversized = RestoreJournal {
            staging_name: "s".repeat(MAX_JOURNAL_BYTES),
            ..journal(RestorePhase::Prepared)
        };
        assert!(matches!(
            write(directory.path(), &oversized),
            Err(GaussError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_path_traversal_and_nil_operation_ids() {
        for name in [
            "",
            ".",
            "..",
            "../staging",
            "nested/staging",
            "..\\staging",
            "C:staging",
            "/absolute",
        ] {
            assert!(
                RestoreJournal::new(Uuid::new_v4(), RestorePhase::Prepared, name, "backup")
                    .is_err()
            );
        }
        assert!(
            RestoreJournal::new(Uuid::nil(), RestorePhase::Prepared, "staging", "backup").is_err()
        );
        assert!(
            RestoreJournal::new(Uuid::new_v4(), RestorePhase::Prepared, "same", "same").is_err()
        );
    }

    #[test]
    fn rejects_traversal_from_an_authenticated_frame() {
        let directory = tempdir().unwrap();
        let invalid = serde_json::json!({
            "operation_id": Uuid::new_v4(),
            "phase": "prepared",
            "staging_name": "../outside",
            "backup_name": "backup"
        });
        let frame = encode_frame(&serde_json::to_vec(&invalid).unwrap()).unwrap();
        fs::write(directory.path().join(RESTORE_JOURNAL_FILE), frame).unwrap();

        assert!(matches!(
            read(directory.path()),
            Err(GaussError::WalCorruption { .. })
        ));
    }
}
