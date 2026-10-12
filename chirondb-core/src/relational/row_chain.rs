//! Version metadata owns its reservation while borrowed by a snapshot, copied
//! for a mutation, or collected from disk. Payloads have their own shared lease.
use super::*;
use std::ops::{Deref, DerefMut};

#[cfg(test)]
mod tests;

const OWNER_BYTES: u64 = 128;

#[derive(Debug, Default)]
pub(super) struct VersionChain {
    versions: Vec<RowVersion>,
    // Return quota only after the vector and its payload owners are dropped.
    charge: memory::Charge,
}

impl VersionChain {
    pub(super) fn single(version: RowVersion) -> Result<Self> {
        let mut chain = Self::default();
        chain.push(version)?;
        Ok(chain)
    }

    pub(super) fn copy(versions: &[RowVersion]) -> Result<Self> {
        let mut chain = Self::default();
        chain.reserve(versions.len())?;
        chain.versions.extend_from_slice(versions);
        Ok(chain)
    }

    pub(super) fn capacity(&self) -> usize {
        self.versions.capacity()
    }

    fn reserve(&mut self, capacity: usize) -> Result<()> {
        if capacity <= self.capacity() {
            return Ok(());
        }
        check_sql_cancelled()?;
        let size = std::mem::size_of::<RowVersion>() as u64;
        let next = (capacity as u64)
            .checked_mul(size)
            .and_then(|bytes| bytes.checked_add(OWNER_BYTES))
            .ok_or_else(sql_overloaded)?;
        let peak = (self.capacity() as u64)
            .checked_mul(size)
            .and_then(|old| next.checked_add(old))
            .ok_or_else(sql_overloaded)?;
        if peak > crate::resource_profile::current().sql_request_working_set_bytes {
            return Err(sql_overloaded());
        }
        if self.capacity() == 0 {
            self.charge = memory::Charge::storage();
        }
        let before = self.charge.bytes();
        self.charge.prepare(peak)?;
        if self
            .versions
            .try_reserve_exact(capacity - self.versions.len())
            .is_err()
        {
            self.charge.prepare(before)?;
            return Err(sql_overloaded());
        }
        // Old and new allocation overlap was charged until reserve completed.
        self.charge.prepare(next)?;
        Ok(())
    }

    pub(super) fn push(&mut self, version: RowVersion) -> Result<()> {
        check_sql_cancelled()?;
        if self.len() == self.capacity() {
            let capacity = self
                .capacity()
                .max(1)
                .checked_mul(2)
                .ok_or_else(sql_overloaded)?;
            self.reserve(capacity)?;
        }
        self.versions.push(version);
        Ok(())
    }

    pub(super) fn remove(&mut self, index: usize) {
        self.versions.remove(index);
    }
}

impl Deref for VersionChain {
    type Target = [RowVersion];
    fn deref(&self) -> &Self::Target {
        &self.versions
    }
}
impl DerefMut for VersionChain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.versions
    }
}

#[derive(Debug)]
pub(super) enum ChainRead<'a> {
    Borrowed(&'a [RowVersion]),
    Owned(VersionChain),
}

impl ChainRead<'_> {
    pub(super) fn into_owned(self) -> Result<VersionChain> {
        match self {
            Self::Borrowed(versions) => VersionChain::copy(versions),
            Self::Owned(versions) => Ok(versions),
        }
    }
}
impl Deref for ChainRead<'_> {
    type Target = [RowVersion];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(versions) => versions,
            Self::Owned(versions) => versions,
        }
    }
}
