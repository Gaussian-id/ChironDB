//! Cold page, range-workspace and cache-container admission follows ownership.
use super::*;
use crate::relational::wal_decode::{MetadataCharge, lease_root_bytes, storage_available_bytes};
use std::mem::size_of;

pub(super) fn exhausted() -> GaussError {
    GaussError::ResourceExhausted("DiskANN storage memory is full".into())
}

pub(super) fn reserve(bytes: u64) -> Result<MetadataCharge> {
    let total = bytes
        .checked_add(lease_root_bytes())
        .ok_or_else(exhausted)?;
    if storage_available_bytes() < total
        && let Some(cache) = GLOBAL_PAGE_CACHE.get()
    {
        cache.lock().map_err(|_| exhausted())?.clear();
    }
    let mut memory = MetadataCharge::default();
    memory.prepare(bytes)?;
    Ok(memory)
}

pub(super) fn artifact(path_bytes: usize) -> Result<MetadataCharge> {
    reserve(
        (path_bytes as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add((2 * size_of::<DiskAnnArtifact>() + 8192) as u64))
            .ok_or_else(exhausted)?,
    )
}

pub(super) fn page_bytes() -> u64 {
    (size_of::<CachedPage>() + 2 * size_of::<usize>() + 64) as u64
}

pub(super) fn batch(count: usize) -> Result<MetadataCharge> {
    reserve(
        (count as u64)
            .checked_mul((4 * size_of::<MetadataCharge>() + 128) as u64)
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(exhausted)?,
    )
}

pub(super) fn ranges(source: &PageSource, ranges: &[Range<u64>]) -> Result<MetadataCharge> {
    let layout = match source {
        PageSource::EncryptedLocal { layout, .. }
        | PageSource::EncryptedObjectStore { layout, .. } => Some(layout),
        _ => None,
    };
    let mut output = 0u64;
    let mut encoded_peak = 0u64;
    let mut chunks_peak = 0u64;
    for range in ranges {
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or_else(|| GaussError::InvalidRequest("DiskANN range is reversed".into()))?;
        output = output.checked_add(length).ok_or_else(exhausted)?;
        if let Some(layout) = layout {
            if range.end > layout.info().plaintext_len {
                return Err(GaussError::InvalidRequest(
                    "DiskANN range is out of bounds".into(),
                ));
            }
            if length != 0 {
                let chunk = layout.info().chunk_size as u64;
                let first = usize::try_from(range.start / chunk).map_err(|_| exhausted())?;
                let last = usize::try_from((range.end - 1) / chunk).map_err(|_| exhausted())?;
                let encoded = layout
                    .encrypted_chunk_range(last)?
                    .end
                    .checked_sub(layout.encrypted_chunk_range(first)?.start)
                    .ok_or_else(exhausted)?;
                encoded_peak = encoded_peak.max(encoded);
                chunks_peak = chunks_peak.max((last - first + 1) as u64);
            }
        }
    }
    // Plain/object output can overlap a provider Bytes response. Encrypted
    // ranges retain prior outputs, all fetched frames for one range, one
    // decrypt body/AAD, and its frame/range controller arrays.
    let peak = output
        .checked_mul(2)
        .and_then(|n| n.checked_add(encoded_peak.checked_mul(3)?))
        .and_then(|n| n.checked_add(chunks_peak.checked_mul(128)?))
        .and_then(|n| n.checked_add((ranges.len() as u64).checked_mul(256)?))
        .and_then(|n| n.checked_add(8192))
        .ok_or_else(exhausted)?;
    reserve(peak)
}

pub(super) fn vectors(count: usize, dim: usize) -> Result<MetadataCharge> {
    reserve(
        (dim as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add((size_of::<Vec<f32>>() + 64) as u64))
            .and_then(|n| n.checked_mul(count as u64))
            .and_then(|n| n.checked_add(8192))
            .ok_or_else(exhausted)?,
    )
}

fn capacity_peak(capacity: usize, required: usize) -> Result<u64> {
    if required <= capacity {
        return Ok(capacity as u64);
    }
    (required as u64)
        .checked_next_power_of_two()
        .and_then(|n| n.checked_mul(2))
        .map(|n| n.max(4))
        .and_then(|n| n.checked_add(capacity as u64))
        .ok_or_else(exhausted)
}

pub(super) fn containers(cache: &PageCache, inserting: bool) -> Result<u64> {
    let (hash, order) = if inserting {
        (
            capacity_peak(
                cache.hash_capacity,
                if cache.pages.len().checked_add(1).ok_or_else(exhausted)? > cache.pages.capacity()
                {
                    cache.hash_capacity.checked_add(1).ok_or_else(exhausted)?
                } else {
                    0
                },
            )?,
            capacity_peak(
                cache.order.capacity(),
                cache.order.len().checked_add(1).ok_or_else(exhausted)?,
            )?,
        )
    } else {
        (cache.hash_capacity as u64, cache.order.capacity() as u64)
    };
    hash.checked_mul(128)
        .and_then(|n| n.checked_add(order.checked_mul(32)?))
        .ok_or_else(exhausted)
}
