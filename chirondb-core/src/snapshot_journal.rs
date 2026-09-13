//! CRC-framed control journal for crash-atomic snapshot publication.

use std::{
    fs,
    path::{Component, Path},
};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    GaussError, Result,
    fs_util::{atomic_write, durable_remove_file},
};

const MAGIC: &[u8; 8] = b"CHIRSJN1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 2 + 4 + 4;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotPhase {
    Prepared,
    Published,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotJournal {
    pub(crate) operation_id: Uuid,
    pub(crate) phase: SnapshotPhase,
    pub(crate) staging_name: String,
    pub(crate) destination_name: String,
}

impl SnapshotJournal {
    pub(crate) fn new(
        operation_id: Uuid,
        phase: SnapshotPhase,
        staging_name: String,
        destination_name: String,
    ) -> Result<Self> {
        let journal = Self {
            operation_id,
            phase,
            staging_name,
            destination_name,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub(crate) fn with_phase(&self, phase: SnapshotPhase) -> Self {
        let mut journal = self.clone();
        journal.phase = phase;
        journal
    }

    fn validate(&self) -> Result<()> {
        if self.operation_id.is_nil() {
            return Err(invalid("snapshot journal operation id is nil"));
        }
        validate_name(&self.staging_name)?;
        validate_name(&self.destination_name)?;
        if self.staging_name == self.destination_name {
            return Err(invalid("snapshot staging and destination names match"));
        }
        Ok(())
    }
}

pub(crate) fn write(parent: &Path, identity: &str, journal: &SnapshotJournal) -> Result<()> {
    journal.validate()?;
    let payload = serde_json::to_vec(journal)?;
    let total_len = HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| invalid("snapshot journal size overflow"))?;
    if total_len > MAX_BYTES {
        return Err(invalid("snapshot journal exceeds 64 KiB"));
    }
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let mut hasher = Hasher::new();
    hasher.update(&frame);
    hasher.update(&payload);
    frame.extend_from_slice(&hasher.finalize().to_le_bytes());
    frame.extend_from_slice(&payload);
    atomic_write(&journal_path(parent, identity), &frame)
}

pub(crate) fn read(parent: &Path, identity: &str) -> Result<Option<SnapshotJournal>> {
    let path = journal_path(parent, identity);
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_BYTES as u64 {
        return Err(corruption(&path, "snapshot journal exceeds 64 KiB"));
    }
    let bytes = fs::read(&path)?;
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(corruption(&path, "invalid snapshot journal header"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("version"));
    let flags = u16::from_le_bytes(bytes[10..12].try_into().expect("flags"));
    if version != VERSION || flags != 0 {
        return Err(corruption(
            &path,
            "unsupported snapshot journal version or flags",
        ));
    }
    let payload_len = u32::from_le_bytes(bytes[12..16].try_into().expect("length")) as usize;
    if HEADER_LEN.checked_add(payload_len) != Some(bytes.len()) {
        return Err(corruption(&path, "snapshot journal length mismatch"));
    }
    let payload = &bytes[HEADER_LEN..];
    let expected_crc = u32::from_le_bytes(bytes[16..20].try_into().expect("crc"));
    let mut hasher = Hasher::new();
    hasher.update(&bytes[..16]);
    hasher.update(payload);
    if hasher.finalize() != expected_crc {
        return Err(corruption(&path, "snapshot journal CRC mismatch"));
    }
    let journal: SnapshotJournal = serde_json::from_slice(payload)
        .map_err(|error| corruption(&path, &format!("invalid snapshot journal: {error}")))?;
    journal.validate()?;
    Ok(Some(journal))
}

pub(crate) fn remove(parent: &Path, identity: &str) -> Result<()> {
    let path = journal_path(parent, identity);
    if path.exists() {
        durable_remove_file(&path)?;
    }
    Ok(())
}

fn journal_path(parent: &Path, identity: &str) -> std::path::PathBuf {
    parent.join(format!(".chirondb-snapshot-{identity}.journal"))
}

fn validate_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(invalid("snapshot journal contains a non-sibling path"));
    }
    Ok(())
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.to_string())
}

fn corruption(path: &Path, message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_crc_failure() {
        let directory = tempfile::tempdir().unwrap();
        let journal = SnapshotJournal::new(
            Uuid::new_v4(),
            SnapshotPhase::Prepared,
            ".stage".into(),
            "snapshot".into(),
        )
        .unwrap();
        write(directory.path(), "identity", &journal).unwrap();
        assert_eq!(read(directory.path(), "identity").unwrap(), Some(journal));
        let path = journal_path(directory.path(), "identity");
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(matches!(
            read(directory.path(), "identity"),
            Err(GaussError::WalCorruption { .. })
        ));
    }
}
