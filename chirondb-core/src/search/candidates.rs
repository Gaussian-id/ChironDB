//! Candidate containers retain admission through scoring and consuming iteration.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use std::{
    hash::Hash,
    mem::size_of,
    ops::{Deref, DerefMut},
};

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("search candidate memory is full".into())
}
fn bytes(capacity: usize, width: usize) -> Result<u64> {
    (capacity as u64)
        .checked_mul(width as u64)
        .ok_or_else(exhausted)
}

#[derive(Debug)]
pub(crate) struct AdmittedVec<T> {
    pub(super) values: Vec<T>,
    pub(super) extra_bytes: u64,
    pub(super) memory: MetadataCharge,
}
impl<T> Default for AdmittedVec<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            extra_bytes: 0,
            memory: Default::default(),
        }
    }
}
impl<T> Deref for AdmittedVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> DerefMut for AdmittedVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}
impl<T> AdmittedVec<T> {
    pub(crate) fn into_parts(self) -> (Vec<T>, MetadataCharge) {
        (self.values, self.memory)
    }
    pub(crate) fn push(&mut self, value: T) -> Result<()> {
        if self.values.len() == self.values.capacity() {
            let capacity = self
                .values
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(exhausted)?;
            let peak = bytes(capacity, size_of::<T>())?
                .checked_add(bytes(self.values.capacity(), size_of::<T>())?)
                .and_then(|n| n.checked_add(self.extra_bytes))
                .and_then(|n| n.checked_add(256))
                .ok_or_else(exhausted)?;
            self.memory.prepare(peak)?;
            self.values
                .try_reserve_exact(capacity - self.values.len())
                .map_err(|_| exhausted())?;
            let retained = bytes(self.values.capacity(), size_of::<T>())?
                .checked_add(self.extra_bytes)
                .and_then(|n| n.checked_add((size_of::<Self>() + 64) as u64))
                .ok_or_else(exhausted)?;
            if retained > peak {
                return Err(exhausted());
            }
            self.memory.reduce(retained);
        }
        self.values.push(value);
        Ok(())
    }
}

impl AdmittedVec<String> {
    pub(crate) fn copy_push(&mut self, id: &str) -> Result<()> {
        let grows = self.len() == self.values.capacity();
        let capacity = if grows {
            self.len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(exhausted)?
        } else {
            self.values.capacity()
        };
        let peak = bytes(capacity, size_of::<String>())?
            .checked_add(if grows {
                bytes(self.values.capacity(), size_of::<String>())?
            } else {
                0
            })
            .and_then(|n| n.checked_add(self.extra_bytes))
            .and_then(|n| n.checked_add(id.len() as u64))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(exhausted)?;
        self.memory.prepare(peak)?;
        self.values
            .try_reserve_exact(capacity - self.len())
            .map_err(|_| exhausted())?;
        let mut copied = String::new();
        copied
            .try_reserve_exact(id.len())
            .map_err(|_| exhausted())?;
        copied.push_str(id);
        let extra = self
            .extra_bytes
            .checked_add(copied.capacity() as u64)
            .ok_or_else(exhausted)?;
        let retained = bytes(self.values.capacity(), size_of::<String>())?
            .checked_add(extra)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(exhausted)?;
        if retained > peak {
            return Err(exhausted());
        }
        self.values.push(copied);
        self.extra_bytes = extra;
        self.memory.reduce(retained);
        Ok(())
    }
}

pub(crate) struct AdmittedIter<T> {
    values: std::vec::IntoIter<T>,
    _memory: MetadataCharge,
}
impl<T> Iterator for AdmittedIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<T> IntoIterator for AdmittedVec<T> {
    type Item = T;
    type IntoIter = AdmittedIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        AdmittedIter {
            values: self.values.into_iter(),
            _memory: self.memory,
        }
    }
}

// Backend producers still require their own scratch/output preallocation.
// This adoption retains the returned IDs while the native consumer uses them.
pub(super) fn ids(values: Vec<String>) -> Result<AdmittedVec<String>> {
    let mut owner = AdmittedVec {
        values,
        extra_bytes: 0,
        memory: Default::default(),
    };
    owner.extra_bytes = owner.values.iter().try_fold(0u64, |n, id| {
        n.checked_add(id.capacity() as u64).ok_or_else(exhausted)
    })?;
    if owner.values.capacity() != 0 {
        owner.memory.prepare(
            bytes(owner.values.capacity(), size_of::<String>())?
                .checked_add(owner.extra_bytes)
                .and_then(|n| n.checked_add(128))
                .ok_or_else(exhausted)?,
        )?;
    }
    Ok(owner)
}

// Keep the point inline: vector capacity admits it without another boxed allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum CandidatePoint<'a> {
    Borrowed(&'a Point),
    Owned(crate::seal::AdmittedPoint),
}
impl Deref for CandidatePoint<'_> {
    type Target = Point;
    fn deref(&self) -> &Point {
        match self {
            Self::Borrowed(point) => point,
            Self::Owned(point) => point,
        }
    }
}
impl<'a> CandidatePoint<'a> {
    pub(super) fn from_compat(point: Cow<'a, Point>) -> Result<Self> {
        match point {
            Cow::Borrowed(point) => Ok(Self::Borrowed(point)),
            Cow::Owned(point) => crate::seal::AdmittedPoint::copy(&point).map(Self::Owned),
        }
    }
}

pub(super) struct Seen<K> {
    keys: HashSet<K>,
    key_bytes: u64,
    memory: MetadataCharge,
}
impl<K> Default for Seen<K> {
    fn default() -> Self {
        Self {
            keys: HashSet::new(),
            key_bytes: 0,
            memory: Default::default(),
        }
    }
}
impl<K> Deref for Seen<K> {
    type Target = HashSet<K>;
    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}
impl<K: Eq + Hash> Seen<K> {
    fn prepare(&mut self, key_bytes: u64) -> Result<()> {
        let required = self.keys.len().checked_add(1).ok_or_else(exhausted)?;
        let containers = if required > self.keys.capacity() {
            let capacity = required.checked_next_power_of_two().ok_or_else(exhausted)?;
            // Hash bucket/control/load-factor and old/new growth overlap.
            bytes(capacity, 128)?
                .checked_add(bytes(self.keys.capacity(), 64)?)
                .ok_or_else(exhausted)?
        } else {
            bytes(self.keys.capacity(), 64)?
        };
        self.memory.prepare(
            containers
                .checked_add(self.key_bytes)
                .and_then(|n| n.checked_add(key_bytes))
                .and_then(|n| n.checked_add(256))
                .ok_or_else(exhausted)?,
        )?;
        self.keys.try_reserve(1).map_err(|_| exhausted())?;
        Ok(())
    }
    fn reduce(&mut self) -> Result<()> {
        self.memory.reduce(
            bytes(self.keys.capacity(), 64)?
                .checked_add(self.key_bytes)
                .and_then(|n| n.checked_add(128))
                .ok_or_else(exhausted)?,
        );
        Ok(())
    }
}
impl<'a> Seen<&'a str> {
    pub(super) fn insert(&mut self, id: &'a str) -> Result<bool> {
        if self.keys.contains(id) {
            return Ok(false);
        }
        self.prepare(0)?;
        self.keys.insert(id);
        self.reduce()?;
        Ok(true)
    }
}
impl Seen<String> {
    pub(super) fn insert(&mut self, id: &str) -> Result<bool> {
        if self.keys.contains(id) {
            return Ok(false);
        }
        self.prepare(id.len() as u64)?;
        let mut key = String::new();
        key.try_reserve_exact(id.len()).map_err(|_| exhausted())?;
        key.push_str(id);
        self.key_bytes = self
            .key_bytes
            .checked_add(key.capacity() as u64)
            .ok_or_else(exhausted)?;
        self.keys.insert(key);
        self.reduce()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relational::wal_decode::with_test_storage_pool;

    #[test]
    fn candidate_growth_refusal_preserves_prior_values_and_consuming_owner() {
        with_test_storage_pool(1024, |used| {
            let mut rows = AdmittedVec::default();
            let mut count = 0;
            loop {
                let before = (rows.values.capacity(), rows.len(), used());
                match rows.push(count) {
                    Ok(()) => count += 1,
                    Err(GaussError::ResourceExhausted(_)) => {
                        assert_eq!((rows.values.capacity(), rows.len(), used()), before);
                        break;
                    }
                    Err(error) => panic!("unexpected refusal: {error}"),
                }
                assert!(count < 1024);
            }
            assert!(count > 0);
            let retained = used();
            let mut iter = rows.into_iter();
            assert_eq!(iter.next(), Some(0));
            assert_eq!(
                used(),
                retained,
                "consuming iterator retains its backing allocation"
            );
            assert_eq!(iter.next(), Some(1));
            drop(iter);
            assert_eq!(
                used(),
                0,
                "early iterator drop frees data before the reservation"
            );
            let mut retry = AdmittedVec::default();
            retry.push(41u64).unwrap();
            assert_eq!(&*retry, [41]);
            drop(retry);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn candidate_dedup_admits_keys_and_preserves_borrowed_identity() {
        let key = "unicode-日本語".repeat(512);
        with_test_storage_pool(1, |used| {
            let mut owned = Seen::<String>::default();
            assert!(matches!(
                owned.insert(&key),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert!(owned.is_empty());
            assert_eq!(used(), 0);
        });
        with_test_storage_pool(64 * 1024, |used| {
            let mut borrowed = Seen::<&str>::default();
            assert!(borrowed.insert(&key).unwrap());
            assert_eq!(borrowed.get(key.as_str()).unwrap().as_ptr(), key.as_ptr());
            let retained = used();
            assert!(!borrowed.insert(&key).unwrap());
            assert_eq!(used(), retained);
            drop(borrowed);
            assert_eq!(used(), 0);
            let mut owned = Seen::<String>::default();
            assert!(owned.insert(&key).unwrap());
            let retained = used();
            assert!(retained > key.len() as u64);
            assert!(!owned.insert(&key).unwrap());
            assert_eq!(used(), retained);
            drop(owned);
            assert_eq!(used(), 0);
        });
    }

    #[test]
    fn candidate_id_handoff_and_cancellation_release_all_backing() {
        with_test_storage_pool(64 * 1024, |used| {
            let rows = ids(vec!["x".repeat(4096), "y".repeat(4096)]).unwrap();
            let retained = used();
            assert!(retained > 8192);
            let mut iter = rows.into_iter();
            assert_eq!(iter.next().unwrap(), "x".repeat(4096));
            assert_eq!(used(), retained);
            drop(iter);
            assert_eq!(used(), 0);
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let result = crate::relational::with_sql_cancellation(cancel, || {
                let mut rows = AdmittedVec::default();
                rows.push(4u32)
            });
            assert!(
                matches!(result,Err(GaussError::InvalidRequest(message)) if message=="query canceled")
            );
            assert_eq!(used(), 0);
        });
    }
    #[test]
    fn selection_ids_admit_copy_growth_and_retain_consuming_backing() {
        let id = "日本語".repeat(1024);
        crate::relational::wal_decode::with_test_storage_pool(1, |used| {
            let mut ids = AdmittedVec::<String>::default();
            assert!(matches!(
                ids.copy_push(&id),
                Err(GaussError::ResourceExhausted(_))
            ));
            assert_eq!(ids.values.capacity(), 0);
            assert_eq!(used(), 0);
        });
        crate::relational::wal_decode::with_test_storage_pool(32768, |used| {
            let mut ids = AdmittedVec::<String>::default();
            ids.copy_push(&id).unwrap();
            assert_eq!(ids[0], id);
            assert_ne!(ids[0].as_ptr(), id.as_ptr());
            let retained = used();
            let mut iter = ids.into_iter();
            let value = iter.next().unwrap();
            assert_eq!(used(), retained);
            drop(value);
            drop(iter);
            assert_eq!(used(), 0);
        });
        crate::relational::wal_decode::with_test_storage_pool(1024, |used| {
            let mut ids = AdmittedVec::<String>::default();
            loop {
                let before = (ids.len(), ids.values.capacity(), used());
                match ids.copy_push("selection") {
                    Ok(()) => assert!(ids.len() < 100),
                    Err(GaussError::ResourceExhausted(_)) => {
                        assert_eq!((ids.len(), ids.values.capacity(), used()), before);
                        break;
                    }
                    Err(error) => panic!("unexpected error: {error}"),
                }
            }
            drop(ids);
            assert_eq!(used(), 0);
        });
    }
}
