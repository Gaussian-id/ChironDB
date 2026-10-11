//! Immutable byte owners keep reservations across moves and shared record clones.

use super::*;
use crate::relational::memory::Charge;
use std::{
    cmp::Ordering,
    ops::{Deref, Range},
};

// Covers Allocation and its Arc header on supported 64-bit targets, with
// conservative allocator headroom. Charge separately admits its lease header.
pub(in crate::relational) const OWNER_BYTES: u64 = 128;

#[derive(Debug)]
struct Allocation {
    bytes: Vec<u8>,
    // The byte allocation must be dropped before its reservation.
    _charge: Charge,
}

#[derive(Clone, Debug)]
pub(in crate::relational) struct RecordBytes(Arc<Allocation>);

impl Deref for RecordBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0.bytes
    }
}

impl PartialEq for RecordBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for RecordBytes {}
impl Ord for RecordBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
impl PartialOrd for RecordBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq<Vec<u8>> for RecordBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl PartialEq<RecordBytes> for Vec<u8> {
    fn eq(&self, other: &RecordBytes) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl RecordBytes {
    pub(in crate::relational) fn from_admitted(bytes: Vec<u8>, charge: Charge) -> Self {
        debug_assert!(charge.bytes() >= bytes.capacity() as u64 + OWNER_BYTES);
        Self(Arc::new(Allocation {
            bytes,
            _charge: charge,
        }))
    }

    #[cfg(test)]
    pub(in crate::relational) fn test_edit(&self, edit: impl FnOnce(&mut Vec<u8>)) -> Self {
        let mut bytes = self.to_vec();
        edit(&mut bytes);
        bytes.into()
    }

    pub(in crate::relational) fn copy(bytes: &[u8]) -> Result<Self> {
        let mut charge = Charge::storage();
        charge.prepare(
            (bytes.len() as u64)
                .checked_add(OWNER_BYTES)
                .ok_or_else(super::super::sql_overloaded)?,
        )?;
        Ok(Self::from_admitted(bytes.to_vec(), charge))
    }

    /// Test fixtures can adopt already-produced bytes; production encoders
    /// reserve during growth and transfer their reservation directly.
    #[cfg(test)]
    pub(super) fn adopt(bytes: Vec<u8>) -> Result<Self> {
        let mut charge = Charge::storage();
        charge.prepare(
            (bytes.capacity() as u64)
                .checked_add(OWNER_BYTES)
                .ok_or_else(super::super::sql_overloaded)?,
        )?;
        Ok(Self::from_admitted(bytes, charge))
    }

    pub(super) fn read(file: &PersistentFile, range: Range<usize>) -> Result<Self> {
        // Keep bytes before their lease until all fallible admission completes.
        let mut owned = file.read_range_admitted(range)?.into_owned()?;
        owned.1.prepare(
            (owned.0.capacity() as u64)
                .checked_add(OWNER_BYTES)
                .ok_or_else(super::super::sql_overloaded)?,
        )?;
        Ok(Self::from_admitted(owned.0, owned.1.into_charge()))
    }

    fn json(value: &impl Serialize, limit: usize) -> Result<Self> {
        let mut buffer = admission::EncodedBuffer::encode(value, limit)?;
        buffer.charge.prepare(
            (buffer.bytes.capacity() as u64)
                .checked_add(OWNER_BYTES)
                .ok_or_else(super::super::sql_overloaded)?,
        )?;
        Ok(Self::from_admitted(buffer.bytes, buffer.charge))
    }
}

impl SegmentRecord {
    #[cfg(test)]
    pub(in crate::relational) fn json(key: Vec<u8>, value: &impl Serialize) -> Result<Self> {
        Self::json_admitted(RecordBytes::adopt(key)?, value)
    }

    pub(in crate::relational) fn json_admitted(
        key: RecordBytes,
        value: &impl Serialize,
    ) -> Result<Self> {
        let limit = crate::resource_profile::current().sql_request_working_set_bytes as usize;
        let remaining = limit
            .checked_sub(RECORD_HEADER_LEN)
            .and_then(|n| n.checked_sub(key.len()))
            .ok_or_else(super::super::sql_overloaded)?;
        let value = RecordBytes::json(value, remaining)?;
        Ok(Self { key, value })
    }
}

#[cfg(test)]
impl From<Vec<u8>> for RecordBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::adopt(bytes).expect("test record admission")
    }
}

#[cfg(test)]
mod tests;
