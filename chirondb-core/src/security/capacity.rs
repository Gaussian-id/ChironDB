//! Bound aggregate authority before WAL admission, including retired identities.
//! Individual record limits alone cannot guarantee a checkpoint can be written.
use super::{CollectionPolicy, PointKey, ResourceRecord, SECURITY_VERSION, SecurityError};
use serde::Serialize;
use std::collections::BTreeMap;
use uuid::Uuid;

type Result<T> = std::result::Result<T, SecurityError>;

// The disk reader caps the encrypted file at 1 GiB. Leave room for the
// authenticated chunk envelope (20 bytes per 64 KiB plus the key header).
pub(super) const LIMIT: usize = super::storage::MAX_CHECKPOINT_BYTES as usize - 1024 * 1024;

pub(super) fn record_bytes(record: &ResourceRecord) -> Result<usize> {
    super::storage::serialized_len(record, LIMIT)
        .map_err(|_| SecurityError::BudgetExceeded)?
        .checked_add(1) // Conservatively allow a comma for every record.
        .ok_or(SecurityError::BudgetExceeded)
}

pub(super) fn check(
    collection: &str,
    incarnation: Uuid,
    policy: &CollectionPolicy,
    records_bytes: usize,
    limit: usize,
) -> Result<()> {
    #[derive(Serialize)]
    struct Header<'a> {
        version: u32,
        collection: &'a str,
        incarnation: Uuid,
        revision: u64,
        data_generation: u64,
        policy: &'a CollectionPolicy,
        resources: [(); 0],
    }
    #[derive(Serialize)]
    struct Stored<'a> {
        wal_watermark: u64,
        authority: Header<'a>,
    }
    let stored = Stored {
        wal_watermark: u64::MAX,
        authority: Header {
            version: SECURITY_VERSION,
            collection,
            incarnation,
            revision: u64::MAX,
            data_generation: u64::MAX,
            policy,
            resources: [],
        },
    };
    let remaining = limit
        .checked_sub(records_bytes)
        .and_then(|bytes| bytes.checked_sub(52))
        .ok_or(SecurityError::BudgetExceeded)?;
    super::storage::serialized_len(&stored, remaining)
        .map_err(|_| SecurityError::BudgetExceeded)?;
    Ok(())
}

/// The caller validates unique changed keys. Only those records are serialized;
/// ordinary writes never serialize the full authority catalog.
pub(super) fn overlay_bytes(
    current: usize,
    records: &BTreeMap<PointKey, ResourceRecord>,
    changed: &[ResourceRecord],
) -> Result<usize> {
    let mut next = current;
    for record in changed {
        if let Some(old) = records.get(&record.key) {
            next = next
                .checked_sub(record_bytes(old)?)
                .ok_or(SecurityError::Unavailable)?;
        }
        next = next
            .checked_add(record_bytes(record)?)
            .ok_or(SecurityError::BudgetExceeded)?;
    }
    Ok(next)
}
