//! Unique reservations for persistence roots, headers and stream buffer overlap.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use std::mem::size_of;

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("encrypted persistence metadata memory is full".into())
}

pub(super) fn owner(bytes: usize) -> Result<MetadataCharge> {
    let mut memory = MetadataCharge::default();
    memory.prepare(
        (bytes as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(exhausted)?,
    )?;
    Ok(memory)
}

pub(super) fn path(path: &Path, bytes: usize) -> Result<(MetadataCharge, u64)> {
    let budget = (path.as_os_str().len() as u64)
        .checked_mul(8)
        .and_then(|n| n.checked_add((bytes as u64).checked_mul(2)?))
        .ok_or_else(exhausted)?;
    let mut memory = MetadataCharge::default();
    // File opening/inspection can temporarily allocate path conversion and
    // diagnostics. Keep that scratch only during construction; the returned
    // budget covers the retained path/root (including a boxed/shared owner).
    memory.prepare(budget.checked_add(8192).ok_or_else(exhausted)?)?;
    Ok((memory, budget))
}

// Validate the allocation-relevant fixed fields without creating a key-id String.
fn header_len(fixed: &[u8]) -> Result<usize> {
    if fixed.len() < FIXED_HEADER_LEN || !fixed.starts_with(MAGIC) {
        return Err(corruption("missing CHIRENC1 header"));
    }
    let key_len = u16::from_le_bytes(fixed[10..12].try_into().unwrap()) as usize;
    if key_len == 0 || key_len > MAX_KEY_ID_BYTES {
        return Err(corruption("invalid encrypted key ID length"));
    }
    let wrapped_len = u16::from_le_bytes(fixed[52..54].try_into().unwrap()) as usize;
    if wrapped_len != 32 + TAG_LEN {
        return Err(corruption("invalid wrapped DEK length"));
    }
    Ok(FIXED_HEADER_LEN + key_len + wrapped_len)
}

pub(super) struct Header {
    bytes: Vec<u8>,
    _memory: MetadataCharge,
}
impl std::ops::Deref for Header {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) fn header(file: &mut File) -> Result<Header> {
    let mut memory = owner(size_of::<Header>())?;
    file.seek(SeekFrom::Start(0))?;
    let mut fixed = [0; FIXED_HEADER_LEN];
    file.read_exact(&mut fixed)?;
    let length = header_len(&fixed)?;
    if length as u64 > file.metadata()?.len() {
        return Err(corruption("truncated encrypted header"));
    }
    memory.prepare(8192 + 2 * size_of::<Header>() as u64 + 2 * length as u64)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| exhausted())?;
    bytes.resize(length, 0);
    bytes[..FIXED_HEADER_LEN].copy_from_slice(&fixed);
    file.read_exact(&mut bytes[FIXED_HEADER_LEN..])?;
    Ok(Header {
        bytes,
        _memory: memory,
    })
}

pub(super) fn layout(input: &[u8]) -> Result<MetadataCharge> {
    let mut memory = owner(size_of::<EncryptedLayout>())?;
    let length = header_len(input)?;
    // Key-id, wrapped/unwrapped key and crypto scratch; ignore borrowed body size.
    memory.prepare(8192 + 2 * size_of::<EncryptedLayout>() as u64 + 4 * length as u64)?;
    Ok(memory)
}

pub(super) fn cached_chunk(encoded_bytes: usize) -> Result<MetadataCharge> {
    // decrypt_chunk_frame copies the encoded body once and truncates in place.
    // The retained Arc owns that capacity; crypto/AAD scratch dies on return.
    let peak = (encoded_bytes as u64)
        .checked_add(cached_chunk_root_bytes())
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(exhausted)?;
    let total = peak
        .checked_add(crate::relational::wal_decode::lease_root_bytes())
        .ok_or_else(exhausted)?;
    if crate::relational::wal_decode::storage_available_bytes() < total {
        // Eviction releases only cache ownership. In-flight Arc pins retain
        // their lease, so the subsequent atomic reservation can still refuse.
        persistent_chunk_cache()
            .write()
            .map_err(|_| corruption("persistent chunk cache poisoned"))?
            .shrink_to(0);
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(peak)?;
    Ok(memory)
}

pub(super) fn cached_chunk_root_bytes() -> u64 {
    // CachedChunk, Arc header and conservative allocator alignment.
    (size_of::<CachedChunk>() + 2 * size_of::<usize>() + 64) as u64
}

fn container_peak(capacity: usize, required: usize) -> Result<u64> {
    if required <= capacity {
        return Ok(capacity as u64);
    }
    // Reserve old/new allocation overlap. HashMap includes control buckets;
    // the conservative per-bucket bound below also covers its unused slots.
    (required as u64)
        .checked_next_power_of_two()
        .and_then(|n| n.checked_mul(2))
        .map(|n| n.max(4))
        .and_then(|n| n.checked_add(capacity as u64))
        .ok_or_else(exhausted)
}

pub(super) fn cache_containers(cache: &PersistentChunkCache, inserting: bool) -> Result<u64> {
    let (hash, probation, main) = if inserting {
        (
            container_peak(
                cache.hash_capacity,
                if cache.chunks.len().checked_add(1).ok_or_else(exhausted)?
                    > cache.chunks.capacity()
                {
                    // Reserve can rehash/grow after tombstones exhaust the
                    // available slots even when the allocated table is larger.
                    cache.hash_capacity.checked_add(1).ok_or_else(exhausted)?
                } else {
                    0
                },
            )?,
            container_peak(
                cache.probation.capacity(),
                cache.probation.len().checked_add(1).ok_or_else(exhausted)?,
            )?,
            container_peak(
                cache.main.capacity(),
                cache
                    .main
                    .len()
                    .checked_add(cache.probation.len())
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(exhausted)?,
            )?,
        )
    } else {
        (
            cache.hash_capacity as u64,
            cache.probation.capacity() as u64,
            cache.main.capacity() as u64,
        )
    };
    hash.checked_mul(128)
        .and_then(|n| {
            n.checked_add(
                probation
                    .checked_add(main)?
                    .checked_mul(size_of::<(u64, usize)>() as u64)?,
            )
        })
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(exhausted)
}

pub(super) fn cache_allocation_error() -> GaussError {
    exhausted()
}
