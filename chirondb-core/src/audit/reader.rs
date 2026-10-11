//! Frame and path admission follows the reader, never the whole audit history.
use super::*;
use crate::relational::wal_decode::{self, MetadataCharge, Owned};

const MAX_LINE: usize = crate::wal::MAX_WAL_RECORD_BYTES * 2 + 4096;
pub(super) struct Paths {
    paths: Vec<PathBuf>,
    _memory: MetadataCharge,
}
impl IntoIterator for Paths {
    type Item = PathBuf;
    type IntoIter = PathIter;
    fn into_iter(self) -> Self::IntoIter {
        PathIter {
            paths: self.paths.into_iter(),
            _memory: self._memory,
        }
    }
}
pub(super) struct PathIter {
    paths: std::vec::IntoIter<PathBuf>,
    _memory: MetadataCharge,
}
impl Iterator for PathIter {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> {
        self.paths.next()
    }
}
impl Paths {
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.paths.len()
    }
    pub(super) fn new(root: &Path) -> Result<Self> {
        let mut memory = MetadataCharge::default();
        memory.prepare(root.as_os_str().len() as u64 * 8 + 4096)?;
        let current = audit_log_path(root);
        let directory = current.parent().expect("audit directory");
        let mut paths = Vec::new();
        let mut reserved = root.as_os_str().len() as u64 * 8 + 4096;
        if directory.try_exists()? {
            if fs::symlink_metadata(directory)?.file_type().is_symlink() {
                return Err(invalid("audit directory is a symbolic link"));
            }
            for entry in fs::read_dir(directory)? {
                crate::relational::check_sql_cancelled()?;
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == "audit.jsonl" || name.starts_with("audit-") && name.ends_with(".jsonl") {
                    if !entry.file_type()?.is_file() {
                        return Err(invalid("audit log is not a regular file"));
                    }
                    let bytes = (directory.as_os_str().len() + name.len() + 1) as u64;
                    reserved = reserved
                        .checked_add(bytes * 2 + 256)
                        .ok_or_else(|| invalid("audit path inventory overflow"))?;
                    memory.prepare(reserved)?;
                    paths
                        .try_reserve_exact(1)
                        .map_err(|_| invalid("audit path allocation failed"))?;
                    paths.push(entry.path());
                }
            }
        }
        // Active file follows every immutable rotated segment.
        paths.sort_unstable_by(|a, b| (a == &current).cmp(&(b == &current)).then_with(|| a.cmp(b)));
        Ok(Self {
            paths,
            _memory: memory,
        })
    }
}

pub(super) struct Lines<R> {
    reader: R,
    bytes: Vec<u8>,
    _memory: MetadataCharge,
}
impl<R: BufRead> Lines<R> {
    pub(super) fn next(&mut self) -> Result<Option<&str>> {
        self.bytes.clear();
        loop {
            crate::relational::check_sql_cancelled()?;
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let take = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |n| n + 1);
            let needed = self
                .bytes
                .len()
                .checked_add(take)
                .filter(|n| *n <= MAX_LINE)
                .ok_or_else(|| invalid("audit frame exceeds maximum size"))?;
            if needed > self.bytes.capacity() {
                let capacity = needed.next_power_of_two().min(MAX_LINE);
                self._memory
                    .prepare((self.bytes.capacity() + capacity) as u64 + 16384)?;
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(|_| invalid("audit frame allocation failed"))?;
            }
            let newline = available[take - 1] == b'\n';
            self.bytes.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            if newline {
                break;
            }
        }
        if self.bytes.is_empty() {
            return Ok(None);
        }
        let line =
            std::str::from_utf8(&self.bytes).map_err(|_| invalid("audit frame is not UTF-8"))?;
        Ok(Some(line.trim_end_matches(['\r', '\n'])))
    }
}

impl<R: Read> Lines<BufReader<R>> {
    pub(super) fn new(reader: R) -> Result<Self> {
        let mut memory = MetadataCharge::default();
        memory.prepare(16384)?;
        Ok(Self {
            reader: BufReader::new(reader),
            bytes: Vec::new(),
            _memory: memory,
        })
    }
}

pub(super) fn decode(line: &str) -> Result<Owned<Value>> {
    let mut memory = MetadataCharge::default();
    // Base64 output, plaintext and the decryptor's chunk overlap remain charged
    // until the separately admitted JSON owner has been formed.
    memory.prepare(line.len() as u64 * 3 + 4096)?;
    let decoded;
    let bytes = if let Some(envelope) = line.strip_prefix(ENCRYPTED_AUDIT_PREFIX) {
        decoded = STANDARD
            .decode(envelope)
            .map_err(|error| invalid(format!("invalid encrypted audit frame encoding: {error}")))?;
        decoded.as_slice()
    } else {
        line.as_bytes()
    };
    let plaintext = encryption::decode_persistent_bounded(
        bytes,
        bytes.len().min(crate::wal::MAX_WAL_RECORD_BYTES),
    )?;
    wal_decode::decode(&plaintext)
}

pub(super) fn encrypted_tail_is_truncated(line: &str) -> Result<bool> {
    if !line.is_empty()
        && line.len() < ENCRYPTED_AUDIT_PREFIX.len()
        && ENCRYPTED_AUDIT_PREFIX.starts_with(line)
    {
        return encryption::audit_frame_is_truncated(&[], crate::wal::MAX_WAL_RECORD_BYTES);
    }
    let Some(envelope) = line.strip_prefix(ENCRYPTED_AUDIT_PREFIX) else {
        return Ok(false);
    };
    let mut memory = MetadataCharge::default();
    memory.prepare(line.len() as u64 * 3 + 4096)?;
    let bytes = match STANDARD.decode(envelope) {
        Ok(bytes) => bytes,
        Err(
            base64::DecodeError::InvalidLength(_)
            | base64::DecodeError::InvalidPadding
            | base64::DecodeError::InvalidLastSymbol(_, _),
        ) => {
            // Only complete base64 groups contribute bytes. The remaining
            // partial group must itself contain valid alphabet characters.
            let boundary = envelope.len() / 4 * 4;
            if !envelope.as_bytes()[boundary..]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return Err(invalid("invalid encrypted audit tail encoding"));
            }
            STANDARD
                .decode(&envelope[..boundary])
                .map_err(|_| invalid("invalid encrypted audit tail encoding"))?
        }
        Err(error) => {
            return Err(invalid(format!(
                "invalid encrypted audit tail encoding: {error}"
            )));
        }
    };
    encryption::audit_frame_is_truncated(&bytes, crate::wal::MAX_WAL_RECORD_BYTES)
}
