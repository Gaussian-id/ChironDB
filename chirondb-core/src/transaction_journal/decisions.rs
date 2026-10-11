//! Completed decisions and consumed keys leave the live maps in bounded batches.
//! Encrypted lookup runs are a cache bound to an unchanged validated WAL prefix.
//! Pending publications and uncertain live writes remain in memory for repair.

use super::*;
use crate::relational::wal_decode::Owned;
use sha2::{Digest, Sha256};

const DECISION_BATCH: usize = 512;
pub(super) const ORDERED_PREFIX: &[u8] = &[3];
pub(super) const INDEX_VERSION: u16 = 2;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommittedRef {
    pub(super) transaction_id: TransactionId,
    pub(super) lsn: u64,
    pub(super) commit_sequence: u64,
}
pub(super) fn ordered_key(sequence: u64) -> [u8; 9] {
    let mut key = [0; 9];
    key[0] = ORDERED_PREFIX[0];
    key[1..].copy_from_slice(&sequence.to_be_bytes());
    key
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    prepare: PreparedRef,
    committed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConsumedKey {
    key: idempotency::ScopedKey,
    transaction_id: TransactionId,
}

// Serialize directly from live references; do not clone their string payloads.
#[derive(Serialize)]
struct DecisionView<'a> {
    prepare: &'a PreparedRef,
    committed: bool,
}
#[derive(Serialize)]
struct ConsumedKeyView<'a> {
    key: &'a idempotency::ScopedKey,
    transaction_id: TransactionId,
}
// Keep the decoded owner on the stack; boxing adds a new unadmitted allocation.
#[allow(clippy::large_enum_variant)]
pub(super) enum Reference<'a> {
    Hot(&'a PreparedRef),
    Disk(Owned<PreparedRef>),
}
impl std::ops::Deref for Reference<'_> {
    type Target = PreparedRef;
    fn deref(&self) -> &PreparedRef {
        match self {
            Self::Hot(value) => value,
            Self::Disk(value) => value,
        }
    }
}

fn decision_key(id: TransactionId) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = 1;
    key[1..].copy_from_slice(id.0.as_bytes());
    key
}

fn consumed_key(key: &idempotency::ScopedKey) -> Result<[u8; 33]> {
    let mut bytes = [0; 33];
    bytes[0] = 2;
    struct HashWriter(Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, key)?;
    bytes[1..].copy_from_slice(&writer.0.finalize());
    Ok(bytes)
}

impl JournalState {
    fn disk_decision(&self, id: TransactionId) -> Result<Option<Owned<Decision>>> {
        self.decisions
            .as_ref()
            .map_or(Ok(None), |disk| disk.get_owned(&decision_key(id)))
    }

    pub(super) fn prepare(&self, id: TransactionId) -> Result<Option<Reference<'_>>> {
        if let Some(prepare) = self.prepares.get(&id) {
            return Ok(Some(Reference::Hot(prepare)));
        }
        self.disk_decision(id)?
            .map(|decision| {
                decision
                    .try_map(|decision| Ok(decision.prepare))
                    .map(Reference::Disk)
            })
            .transpose()
    }

    pub(super) fn consumed_key(
        &self,
        key: &idempotency::ScopedKey,
    ) -> Result<Option<TransactionId>> {
        if let Some(id) = self.idempotency.get(key) {
            return Ok(Some(*id));
        }
        let Some(disk) = &self.decisions else {
            return Ok(None);
        };
        let Some(record): Option<Owned<ConsumedKey>> = disk.get_owned(&consumed_key(key)?)? else {
            return Ok(None);
        };
        if &record.key != key {
            return Err(corrupt("consumed key digest collision or changed binding"));
        }
        Ok(Some(record.transaction_id))
    }

    pub(super) fn checked_status(&self, id: TransactionId) -> Result<TransactionStatus> {
        if self.prepares.contains_key(&id) || self.unknown.contains(&id) {
            return Ok(hot_status(self, id));
        }
        let Some(decision) = self.disk_decision(id)? else {
            return Ok(hot_status(self, id));
        };
        Ok(TransactionStatus {
            transaction_id: id,
            state: if decision.committed {
                TransactionState::Committed
            } else {
                TransactionState::Rejected
            },
            commit_sequence: Some(decision.prepare.commit_sequence),
            storage_projected: decision.committed,
            audit_projected: decision.committed,
        })
    }

    pub(super) fn flush_completed(&mut self, dir: &Path) -> Result<()> {
        if self.completed.len() < DECISION_BATCH {
            return Ok(());
        }
        self.flush_decisions(dir)
    }

    pub(super) fn flush_decisions(&mut self, dir: &Path) -> Result<()> {
        if self.completed.is_empty() {
            return Ok(());
        }
        let Some(disk) = &mut self.decisions else {
            return Ok(());
        };
        let ids = &self.completed;
        let prepares = &self.prepares;
        let commits = &self.commits;
        disk.insert_batch(|batch| {
            for id in ids {
                let reference = prepares
                    .get(id)
                    .ok_or_else(|| corrupt("completed decision lost its PREPARE"))?;
                if reference.hot.is_some() || self.unknown.contains(id) {
                    return Err(corrupt("cannot evict an uncertain or unpublished decision"));
                }
                let committed = commits.contains(id);
                if committed
                    && (!self.projections.contains(&(*id, ProjectionKind::Storage))
                        || !self.projections.contains(&(*id, ProjectionKind::Audit)))
                {
                    return Err(corrupt("cannot evict an incomplete projection"));
                }
                batch.insert(
                    &decision_key(*id),
                    &DecisionView {
                        prepare: reference,
                        committed,
                    },
                )?;
                let retain_proofs =
                    committed && self.authoritative && reference.storage_proof_version.is_some();
                let retain_receipt = committed
                    && self.authoritative
                    && reference.idempotency_key.is_some()
                    && reference.idempotency.as_ref().is_some_and(|receipt| {
                        receipt.retained_until_unix_ms > self.receipt_floor_ms
                    });
                if retain_proofs || retain_receipt {
                    let prepare = reference.load(dir, *id)?;
                    if retain_proofs {
                        projection::insert(batch, &prepare)?;
                    }
                    if retain_receipt {
                        authority::insert_receipt(batch, &prepare, self.receipt_floor_ms)?;
                    }
                }
                if committed {
                    batch.insert(
                        &ordered_key(reference.commit_sequence),
                        &CommittedRef {
                            transaction_id: *id,
                            lsn: reference.lsn,
                            commit_sequence: reference.commit_sequence,
                        },
                    )?;
                }
                if let Some(key) = &reference.idempotency_key {
                    batch.insert(
                        &consumed_key(key)?,
                        &ConsumedKeyView {
                            key,
                            transaction_id: *id,
                        },
                    )?;
                }
            }
            Ok(())
        })?;
        // Failed writes/merges never reach this point or remove a consumed key.
        for id in self.completed.drain(..) {
            if let Some(reference) = self.prepares.remove(&id)
                && let Some(key) = reference.idempotency_key
            {
                self.idempotency.remove(&key);
            }
            self.commits.remove(&id);
            self.projections.remove(&(id, ProjectionKind::Storage));
            self.projections.remove(&(id, ProjectionKind::Audit));
        }
        self.release_evicted_metadata();
        metrics::counter!("chirondb_transaction_decision_batches_total").increment(1);
        Ok(())
    }

    pub(super) fn finish_recovery(&mut self, dir: &Path) -> Result<()> {
        // Only EOF proves a recovered PREPARE without COMMIT is rejected.
        // Keep partial committed projections available to the repair visitor.
        loop {
            self.flush_decisions(dir)?;
            self.completed.extend(
                self.prepares
                    .iter()
                    .filter_map(|(id, _)| (!self.commits.contains(id)).then_some(*id))
                    .take(DECISION_BATCH),
            );
            if self.completed.is_empty() {
                break;
            }
        }
        Ok(())
    }
}

fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_JOURNAL_DIR.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
