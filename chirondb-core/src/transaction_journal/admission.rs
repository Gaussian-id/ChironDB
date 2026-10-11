//! Live journal metadata reserves before PREPARE, including every future flag.
//! Disk terminal decisions keep history out of the live maps. The capacities
//! retained by std containers remain charged after eviction, until journal drop.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use std::mem::size_of;

const ROOT_BYTES: u64 = 4096;

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("transaction journal metadata memory is full".into())
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(exhausted)
}
fn slots<K, V>(capacity: usize, high_water: usize, needed: usize) -> Result<u64> {
    // Deletions can reduce reported capacity while tombstone buckets remain
    // allocated. Keep the largest observed allocation; never shrink these maps.
    // For supported std HashMap/HashSet implementations, <=2 slots per reported
    // capacity cover buckets/control/alignment. Growth can overlap old/new
    // tables; eight slots per old capacity + requested count cover that peak,
    // including the initial four-bucket allocation. Vec uses the same upper
    // bound, so its old/new geometric growth is also preadmitted.
    let allocated = capacity.max(high_water);
    let count = if needed > capacity {
        (allocated as u64)
            .checked_add(needed as u64)
            .and_then(|n| n.checked_mul(8))
    } else {
        (allocated as u64).checked_mul(2)
    }
    .ok_or_else(exhausted)?;
    count
        .checked_mul((size_of::<K>() + size_of::<V>() + 32) as u64)
        .ok_or_else(exhausted)
}
fn key_heap(key: &idempotency::ScopedKey) -> u64 {
    key.principal_id.capacity() as u64 + key.tenant_id.as_ref().map_or(0, |id| id.capacity() as u64)
}
fn key_copy_heap(key: &idempotency::ScopedKey) -> u64 {
    key.principal_id.len() as u64 + key.tenant_id.as_ref().map_or(0, |id| id.len() as u64)
}
fn reference_heap(reference: &PreparedRef) -> u64 {
    reference.principal_id.capacity() as u64
        + reference
            .tenant_id
            .as_ref()
            .map_or(0, |id| id.capacity() as u64)
        + reference.idempotency_key.as_ref().map_or(0, key_heap)
        + reference
            .recovery
            .as_ref()
            .map_or(0, recovery::RecoveryDescriptor::heap_bytes)
}
fn current_heap(state: &JournalState) -> Result<u64> {
    state
        .prepares
        .values()
        .map(reference_heap)
        .chain(state.idempotency.keys().map(key_heap))
        .try_fold(0, add)
}
fn state_bytes(state: &JournalState, count: usize, keyed: usize, heap: u64) -> Result<u64> {
    [
        slots::<TransactionId, PreparedRef>(
            state.prepares.capacity(),
            state.metadata_capacities[0],
            count,
        )?,
        slots::<TransactionId, ()>(
            state.commits.capacity(),
            state.metadata_capacities[1],
            count,
        )?,
        slots::<(TransactionId, ProjectionKind), ()>(
            state.projections.capacity(),
            state.metadata_capacities[2],
            count.checked_mul(2).ok_or_else(exhausted)?,
        )?,
        slots::<TransactionId, ()>(
            state.unknown.capacity(),
            state.metadata_capacities[3],
            count,
        )?,
        slots::<TransactionId, ()>(
            state.completed.capacity(),
            state.metadata_capacities[4],
            count,
        )?,
        slots::<idempotency::ScopedKey, TransactionId>(
            state.idempotency.capacity(),
            state.metadata_capacities[5],
            keyed,
        )?,
        heap,
    ]
    .into_iter()
    .try_fold(ROOT_BYTES, add)
}

impl JournalState {
    pub(super) fn reserve_prepare_metadata(&mut self, prepare: &TransactionPrepare) -> Result<()> {
        let count = self.prepares.len().checked_add(1).ok_or_else(exhausted)?;
        let keyed = self
            .idempotency
            .len()
            .checked_add(usize::from(prepare.idempotency.is_some()))
            .ok_or_else(exhausted)?;
        // String::clone copies its length into a new owned buffer. Key strings
        // appear separately in PreparedRef and the consumed-key live map.
        let incoming = prepare.audit.principal_id.len() as u64
            + prepare
                .audit
                .tenant_id
                .as_ref()
                .map_or(0, |id| id.len() as u64)
            + prepare.idempotency.as_ref().map_or(0, |record| {
                key_copy_heap(record.scoped_key()).saturating_mul(2)
            })
            + if self.authoritative {
                recovery::prepare_heap(prepare)
            } else {
                0
            };
        let heap = add(current_heap(self)?, incoming)?;
        self.metadata_memory
            .prepare(state_bytes(self, count, keyed, heap)?)?;
        // Reserve for ALL still-live decisions, not just the next immediate
        // insert. COMMIT, unknown-outcome and both publication markers must not
        // allocate a container after a durable decision.
        self.prepares
            .try_reserve(count.saturating_sub(self.prepares.len()))
            .map_err(|_| exhausted())?;
        self.note_capacities();
        self.commits
            .try_reserve(count.saturating_sub(self.commits.len()))
            .map_err(|_| exhausted())?;
        self.note_capacities();
        self.projections
            .try_reserve(count * 2 - self.projections.len())
            .map_err(|_| exhausted())?;
        self.note_capacities();
        self.unknown
            .try_reserve(count.saturating_sub(self.unknown.len()))
            .map_err(|_| exhausted())?;
        self.note_capacities();
        self.completed
            .try_reserve(count.saturating_sub(self.completed.len()))
            .map_err(|_| exhausted())?;
        self.note_capacities();
        self.idempotency
            .try_reserve(keyed.saturating_sub(self.idempotency.len()))
            .map_err(|_| exhausted())?;
        self.note_capacities();
        Ok(())
    }

    fn note_capacities(&mut self) {
        let current = [
            self.prepares.capacity(),
            self.commits.capacity(),
            self.projections.capacity(),
            self.unknown.capacity(),
            self.completed.capacity(),
            self.idempotency.capacity(),
        ];
        for (high_water, capacity) in self.metadata_capacities.iter_mut().zip(current) {
            *high_water = (*high_water).max(capacity);
        }
    }

    pub(super) fn release_evicted_metadata(&mut self) {
        // Containers/keys have already dropped. This unique lease only shrinks;
        // it must not consult cancellation or acquire quota after publication.
        let heap = current_heap(self).expect("previously admitted metadata");
        let bytes = state_bytes(self, 0, 0, heap).expect("allocated metadata capacity");
        self.metadata_memory.reduce(bytes);
    }
}

pub(super) fn claim_value(context: &AuditContext) -> Result<MetadataCharge> {
    let mut memory = MetadataCharge::default();
    memory.prepare(
        ROOT_BYTES
            + context.principal_id.len() as u64
            + context.tenant_id.as_ref().map_or(0, |id| id.len() as u64),
    )?;
    Ok(memory)
}
pub(super) fn key_value(key: &idempotency::ScopedKey) -> Result<MetadataCharge> {
    let mut memory = MetadataCharge::default();
    memory.prepare(ROOT_BYTES + key_copy_heap(key))?;
    Ok(memory)
}
pub(super) fn reserve_claim(inner: &mut JournalInner, key: &idempotency::ScopedKey) -> Result<()> {
    let map = &inner.inflight_idempotency;
    let heap = map.keys().map(key_heap).try_fold(key_copy_heap(key), add)?;
    let bytes = add(
        ROOT_BYTES,
        add(
            slots::<idempotency::ScopedKey, [u8; 32]>(
                map.capacity(),
                inner.claim_capacity,
                map.len() + 1,
            )?,
            heap,
        )?,
    )?;
    inner.claim_memory.prepare(bytes)?;
    let result = inner
        .inflight_idempotency
        .try_reserve(1)
        .map_err(|_| exhausted());
    inner.claim_capacity = inner
        .claim_capacity
        .max(inner.inflight_idempotency.capacity());
    result
}
pub(super) fn release_claim(inner: &mut JournalInner) {
    let map = &inner.inflight_idempotency;
    let heap = map
        .keys()
        .map(key_heap)
        .try_fold(0, add)
        .expect("admitted claim heap");
    let bytes = ROOT_BYTES
        + slots::<idempotency::ScopedKey, [u8; 32]>(map.capacity(), inner.claim_capacity, 0)
            .expect("allocated claim capacity")
        + heap;
    inner.claim_memory.reduce(bytes);
}

#[cfg(test)]
mod tests;
