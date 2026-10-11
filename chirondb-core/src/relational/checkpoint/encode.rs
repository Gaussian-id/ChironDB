//! A single admitted JSON buffer, followed by fixed-size encrypted persistence.
use super::*;
use crate::encryption::{DEFAULT_CHUNK_SIZE, atomic_write_persistent_stream};
use std::io;

#[cfg(test)]
mod tests;

// The current persistent stream writer holds one plaintext chunk and a
// ciphertext Vec that may grow from one to two chunks when appending its tag.
// Admit both old/new ciphertext blocks plus plaintext; the remaining envelope
// covers the bounded key ID, headers/AAD and fixed writer bookkeeping.
const STREAM_SCRATCH_BYTES: u64 = (4 * DEFAULT_CHUNK_SIZE + 4096) as u64;

pub(in crate::relational) fn write(path: &Path, checkpoint: &RelationalCheckpoint) -> Result<()> {
    check_sql_cancelled()?;
    let mut scratch = memory::Charge::storage();
    scratch.prepare(STREAM_SCRATCH_BYTES)?;
    // Aggregate storage admission bounds this buffer. It is independent of a
    // single query's working-set ceiling; no whole-file ciphertext copy follows.
    let payload = segment::EncodedBuffer::encode(checkpoint, usize::MAX)?;
    let payload_len = u64::try_from(payload.bytes.len()).map_err(|_| sql_overloaded())?;
    let plaintext_len = payload_len
        .checked_add(RELATIONAL_CHECKPOINT_HEADER_LEN as u64)
        .ok_or_else(sql_overloaded)?;
    let mut header = [0_u8; RELATIONAL_CHECKPOINT_HEADER_LEN];
    header[..8].copy_from_slice(RELATIONAL_CHECKPOINT_MAGIC);
    header[8..16].copy_from_slice(&payload_len.to_le_bytes());
    header[16..20].copy_from_slice(&crc32fast::hash(&payload.bytes).to_le_bytes());
    let result = atomic_write_persistent_stream(
        path,
        FileType::Segment,
        plaintext_len,
        CancelReader(header.as_slice().chain(payload.bytes.as_slice())),
    );
    // Read's I/O error adapter must not turn cancellation into a storage fault.
    if result.is_err() {
        check_sql_cancelled()?;
    }
    result
}

struct CancelReader<R>(R);

impl<R: Read> Read for CancelReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        check_sql_cancelled().map_err(io::Error::other)?;
        let len = out.len().min(DEFAULT_CHUNK_SIZE);
        self.0.read(&mut out[..len])
    }
}
