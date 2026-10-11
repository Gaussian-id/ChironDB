//! Internal range results retain output admission through parsing and iteration.
use super::*;
use crate::relational::wal_decode::MetadataCharge;

#[derive(Debug)]
pub(crate) struct AdmittedRange<'a> {
    bytes: Cow<'a, [u8]>,
    // The output allocation dies before its reservation.
    _memory: MetadataCharge,
}

impl std::ops::Deref for AdmittedRange<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for AdmittedRange<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<'a> AdmittedRange<'a> {
    pub(crate) fn borrowed(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
            _memory: Default::default(),
        }
    }

    pub(crate) fn borrowed_bytes(&self) -> Option<&'a [u8]> {
        match &self.bytes {
            Cow::Borrowed(bytes) => Some(*bytes),
            Cow::Owned(_) => None,
        }
    }

    // Public compatibility cannot carry the internal lease.
    pub(super) fn into_compat(self) -> Cow<'a, [u8]> {
        self.bytes
    }

    pub(crate) fn into_owned(self) -> Result<(Vec<u8>, MetadataCharge)> {
        match self.bytes {
            Cow::Owned(bytes) => Ok((bytes, self._memory)),
            Cow::Borrowed(bytes) => {
                let (mut output, memory) = Self::buffer(bytes.len())?;
                output.extend_from_slice(bytes);
                Ok((output, memory))
            }
        }
    }

    pub(super) fn owned(bytes: Vec<u8>, memory: MetadataCharge) -> Self {
        Self {
            bytes: Cow::Owned(bytes),
            _memory: memory,
        }
    }

    pub(crate) fn read_from(reader: &mut impl Read, length: usize) -> Result<Self> {
        // Keep bytes before their lease in one owner across fallible IO.
        let mut output = Self::buffer(length)?;
        output.0.resize(length, 0);
        reader.read_exact(&mut output.0)?;
        Ok(Self::owned(output.0, output.1))
    }

    pub(super) fn buffer(length: usize) -> Result<(Vec<u8>, MetadataCharge)> {
        if length == 0 {
            return Ok((Vec::new(), Default::default()));
        }
        let exhausted = || GaussError::ResourceExhausted("persisted range memory is full".into());
        let peak = (length as u64)
            // The exact allocation starts from an empty Vec; no old/new overlap.
            .checked_add(256)
            .ok_or_else(exhausted)?;
        let total = peak
            .checked_add(crate::relational::wal_decode::lease_root_bytes())
            .ok_or_else(exhausted)?;
        if crate::relational::wal_decode::storage_available_bytes() < total
            && let Some(cache) = PERSISTENT_CHUNK_CACHE.get()
        {
            cache
                .write()
                .map_err(|_| corruption("persistent chunk cache poisoned"))?
                .shrink_to(0);
        }
        let mut memory = MetadataCharge::default();
        memory.prepare(peak)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| exhausted())?;
        let retained = (bytes.capacity() as u64)
            .checked_add(std::mem::size_of::<Self>() as u64 + 64)
            .ok_or_else(exhausted)?;
        if retained > peak {
            return Err(exhausted());
        }
        memory.reduce(retained);
        Ok((bytes, memory))
    }
}
