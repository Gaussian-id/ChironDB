//! Rebuildable audit frontier. Raw prefix bytes and the decryption context must
//! still match, and cached terminals are checked against current decisions.
//! This never authorizes removal of either audit history or the original WAL.
use super::*;
use crate::relational::wal_decode::{MetadataCharge, Owned};
use serde::Deserialize;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    version: u16,
    installation: uuid::Uuid,
    authoritative: bool,
    key_context: [u8; 32],
    pub(super) sequence: u64,
    pub(super) previous_hash: String,
    pub(super) closed_segments: usize,
    history_digest: [u8; 32],
    pub(super) active_bytes: u64,
    active_digest: [u8; 32],
}

fn memory(root: &Path) -> Result<MetadataCharge> {
    let mut memory = MetadataCharge::default();
    memory.prepare(
        (root.as_os_str().len() as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add(72 * 1024))
            .ok_or_else(|| invalid("audit checkpoint paths too large"))?,
    )?;
    Ok(memory)
}

fn hash_bytes(path: &Path, count: u64, hash: &mut Sha256) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid("audit checkpoint log is not a regular file"));
    }
    let mut file = File::open(path)?;
    if file.metadata()?.len() < count {
        return Err(invalid("audit checkpoint exceeds retained log"));
    }
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = count;
    while remaining != 0 {
        crate::relational::check_sql_cancelled()?;
        let take = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..take])?;
        hash.update(&buffer[..take]);
        remaining -= take as u64;
    }
    Ok(())
}

fn history_file(path: &Path, hash: &mut Sha256) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("audit checkpoint log name is not UTF-8"))?;
    let bytes = fs::metadata(path)?.len();
    hash.update((name.len() as u64).to_le_bytes());
    hash.update(name.as_bytes());
    hash.update(bytes.to_le_bytes());
    hash_bytes(path, bytes, hash)
}

pub(super) fn publish(
    registry: &mut registry::Registry,
    root: &Path,
    binding: (uuid::Uuid, bool),
    sequence: u64,
    previous_hash: &str,
) -> Result<()> {
    let _memory = memory(root)?;
    registry.flush()?;
    let active = audit_log_path(root);
    let mut history = Sha256::new();
    history.update(b"CHIRON-AUDIT-PREFIX-1");
    let mut closed_segments = 0;
    for path in audit_log_paths(root)? {
        if path == active {
            continue;
        }
        history_file(&path, &mut history)?;
        closed_segments += 1;
    }
    let active_bytes = fs::metadata(&active)?.len();
    let mut suffix = Sha256::new();
    suffix.update(active_bytes.to_le_bytes());
    hash_bytes(&active, active_bytes, &mut suffix)?;
    let checkpoint = Checkpoint {
        version: 1,
        installation: binding.0,
        authoritative: binding.1,
        key_context: encryption::recovery_context_fingerprint()?,
        sequence,
        previous_hash: previous_hash.into(),
        closed_segments,
        history_digest: history.finalize().into(),
        active_bytes,
        active_digest: suffix.finalize().into(),
    };
    crate::failpoint::check("audit_checkpoint.before_publish")?;
    registry.disk.publish_checkpoint(&checkpoint)?;
    crate::failpoint::check("audit_checkpoint.after_publish")?;
    metrics::counter!("chirondb_audit_checkpoints_total").increment(1);
    Ok(())
}

fn matches(root: &Path, checkpoint: &Checkpoint) -> Result<bool> {
    let _memory = memory(root)?;
    let mut paths = audit_log_paths(root)?.into_iter();
    let mut history = Sha256::new();
    history.update(b"CHIRON-AUDIT-PREFIX-1");
    let mut last_closed = None;
    for _ in 0..checkpoint.closed_segments {
        let Some(path) = paths.next() else {
            return Ok(false);
        };
        if path == audit_log_path(root) {
            return Ok(false);
        }
        history_file(&path, &mut history)?;
        last_closed = Some(path);
    }
    if <[u8; 32]>::from(history.finalize()) != checkpoint.history_digest {
        return Ok(false);
    }
    let Some(path) = paths.next() else {
        return Ok(false);
    };
    let mut active = Sha256::new();
    active.update(checkpoint.active_bytes.to_le_bytes());
    // The former active file may have rotated since publication. Its prefix
    // remains the boundary; newly closed files are part of normal suffix work.
    hash_bytes(&path, checkpoint.active_bytes, &mut active)?;
    if <[u8; 32]>::from(active.finalize()) != checkpoint.active_digest {
        return Ok(false);
    }
    // Bind the resume hash and sequence to a real record, including when a
    // checkpoint followed rotation. A manifest alone cannot invent a frontier.
    if checkpoint.active_bytes != 0 {
        boundary_matches(&path, checkpoint.active_bytes, checkpoint)
    } else if let Some(path) = last_closed {
        boundary_matches(&path, fs::metadata(&path)?.len(), checkpoint)
    } else {
        Ok(checkpoint.sequence == 0 && checkpoint.previous_hash == genesis_hash())
    }
}

fn boundary_matches(path: &Path, end: u64, checkpoint: &Checkpoint) -> Result<bool> {
    if end == 0 {
        return Ok(false);
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(end - 1))?;
    let mut last = [0; 1];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        return Ok(false);
    }
    let mut cursor = end - 1;
    let mut buffer = [0; 4096];
    let start = loop {
        crate::relational::check_sql_cancelled()?;
        let start = cursor.saturating_sub(buffer.len() as u64);
        if end - start > (crate::wal::MAX_WAL_RECORD_BYTES * 2 + 4096) as u64 {
            return Err(invalid("audit checkpoint boundary exceeds maximum frame"));
        }
        file.seek(SeekFrom::Start(start))?;
        let count = (cursor - start) as usize;
        file.read_exact(&mut buffer[..count])?;
        if let Some(index) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            break start + index as u64 + 1;
        }
        if start == 0 {
            break 0;
        }
        cursor = start;
    };
    file.seek(SeekFrom::Start(start))?;
    let mut lines = reader::Lines::new(file.take(end - start))?;
    let Some(line) = lines.next()? else {
        return Ok(false);
    };
    reader::decode(line)?.consume(|mut value| {
        if value.get("sequence").and_then(Value::as_u64) != Some(checkpoint.sequence) {
            // Legacy records without sequences keep full verification.
            return Ok(false);
        }
        let Some(hash) = value
            .as_object_mut()
            .and_then(|object| object.remove("record_hash"))
        else {
            return Ok(false);
        };
        Ok(hash.as_str() == Some(checkpoint.previous_hash.as_str())
            && hash_json_value(&value)? == checkpoint.previous_hash)
    })
}

pub(super) fn recover(
    registry: &mut registry::Registry,
    root: &Path,
    journal: Option<&crate::transaction_journal::TransactionJournal>,
) -> Result<Option<Owned<Checkpoint>>> {
    let Some(journal) = journal else {
        return Ok(None);
    };
    let Some(binding) = journal.audit_checkpoint_binding()? else {
        return Ok(None);
    };
    let load = (|| {
        let Some(c): Option<Owned<Checkpoint>> = registry.disk.load_checkpoint()? else {
            return Ok(None);
        };
        if c.version != 1
            || (c.installation, c.authoritative) != binding
            || c.key_context != encryption::recovery_context_fingerprint()?
            || c.previous_hash.len() != 64
            || !c.previous_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || c.sequence == u64::MAX
        {
            return Err(invalid("audit recovery checkpoint context changed"));
        }
        if !matches(root, &c)? {
            return Err(invalid("audit recovery checkpoint prefix changed"));
        }
        let authority = journal.storage_projection_authority()?;
        for record in registry.disk.cursor()? {
            let record = record?;
            let entry = record.decode::<registry::Entry>()?;
            if record.key() != entry.key() {
                return Err(invalid("audit checkpoint entry binding changed"));
            }
            match &*entry {
                registry::Entry::Terminal(value) => {
                    if value.sequence > c.sequence {
                        return Err(invalid("audit checkpoint sequence changed"));
                    }
                    registry::validate(authority, value)?;
                }
                registry::Entry::Intent(value) if value.sequence > c.sequence => {
                    return Err(invalid("audit checkpoint intent sequence changed"));
                }
                _ => {}
            }
        }
        metrics::counter!("chirondb_audit_recovery_checkpoint_hits_total").increment(1);
        Ok(Some(c))
    })();
    match load {
        Ok(cache) => Ok(cache),
        Err(error @ GaussError::ResourceExhausted(_)) => Err(error),
        Err(error) => {
            tracing::warn!(%error, "discarding audit checkpoint; validating full log");
            metrics::counter!("chirondb_audit_checkpoint_fallbacks_total").increment(1);
            registry.disk = crate::relational::disk_map::DiskMap::new(
                audit_log_path(root).parent().expect("audit directory"),
            )?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
