//! Durable terminal decisions, permanent consumed keys, retained retry bodies
//! and SQL projection proofs. This store is independent of the disposable WAL
//! cache. Format 3 never reconstructs a missing authority from historical WAL.
use super::*;
use crate::relational::{
    disk_map::{Batch, DiskMap},
    wal_decode::Owned,
};

const VERSION: u16 = 1;
const RECEIPT_PREFIX: u8 = 4;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RelationalProof {
    version: u16,
    digest: [u8; 32],
}
impl RelationalProof {
    pub(super) fn from_prepare(prepare: &TransactionPrepare) -> Result<Option<Self>> {
        let batch = match (&prepare.target, prepare.mutation.as_ref()) {
            (TransactionTarget::Relational, WalEntry::RelationalBatch { batch }) => batch,
            (TransactionTarget::MultiModel { .. }, WalEntry::MultiModelBatch { batch }) => {
                &batch.relational
            }
            _ => return Ok(None),
        };
        Ok(Some(Self {
            version: VERSION,
            digest: crate::relational::relational_projection_fingerprint(batch)?,
        }))
    }
    pub(super) fn validate(&self, batch: &crate::relational::RelationalBatch) -> Result<()> {
        if self.version != VERSION
            || self.digest != crate::relational::relational_projection_fingerprint(batch)?
        {
            return Err(corrupt(
                "relational projection differs from its durable proof",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u16,
    decision_index_version: u16,
    installation_id: uuid::Uuid,
    end_lsn: u64,
    next_sequence: u64,
    max_committed_sequence: u64,
    committed_count: usize,
    receipt_floor_ms: u64,
    next_receipt_expiry_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedReceipt {
    transaction_id: TransactionId,
    commit_sequence: u64,
    record: IdempotencyRecord,
    mutation: Box<WalEntry>,
}
#[derive(Serialize)]
struct ReceiptView<'a> {
    transaction_id: TransactionId,
    commit_sequence: u64,
    record: &'a IdempotencyRecord,
    mutation: &'a WalEntry,
}
fn receipt_key(id: TransactionId) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = RECEIPT_PREFIX;
    key[1..].copy_from_slice(id.0.as_bytes());
    key
}
pub(super) fn insert_receipt(
    batch: &mut Batch,
    prepare: &TransactionPrepare,
    floor: u64,
) -> Result<()> {
    let record = prepare
        .idempotency
        .as_ref()
        .ok_or_else(|| corrupt("receipt lost its request identity"))?;
    if record.retained_until_unix_ms > floor {
        batch.insert(
            &receipt_key(prepare.transaction_id),
            &ReceiptView {
                transaction_id: prepare.transaction_id,
                commit_sequence: prepare.commit_sequence,
                record,
                mutation: &prepare.mutation,
            },
        )?;
    }
    Ok(())
}
pub(super) fn receipt(
    state: &JournalState,
    id: TransactionId,
    reference: &PreparedRef,
) -> Result<Owned<RetainedReceipt>> {
    let body = state
        .decisions
        .as_ref()
        .expect("decision map")
        .get_owned::<RetainedReceipt>(&receipt_key(id))?
        .ok_or_else(|| corrupt("retained idempotency receipt is missing"))?;
    if body.transaction_id != id || body.commit_sequence != reference.commit_sequence {
        return Err(corrupt("retained idempotency receipt identity changed"));
    }
    Ok(body)
}
impl RetainedReceipt {
    pub(super) fn into_replay(
        self,
        key: &idempotency::ScopedKey,
        summary: &idempotency::IdempotencySummary,
    ) -> Result<(Option<Value>, Option<Box<WalEntry>>)> {
        if self.record.key != *key
            || self.record.fingerprint != summary.fingerprint
            || self.record.retained_until_unix_ms != summary.retained_until_unix_ms
            || self.record.version != 1
        {
            return Err(corrupt("retained idempotency receipt binding changed"));
        }
        Ok((Some(self.record.response), Some(self.mutation)))
    }
}

fn parent(dir: &Path) -> PathBuf {
    dir.parent().expect("transaction parent").join("authority")
}
fn load(dir: &Path, installation_id: uuid::Uuid) -> Result<(DiskMap, Owned<Checkpoint>)> {
    let metadata = std::fs::symlink_metadata(parent(dir))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(corrupt(
            "transaction authority root is not a regular directory",
        ));
    }
    let mut disk = DiskMap::new(&parent(dir))?;
    let checkpoint = disk
        .load_checkpoint::<Checkpoint>()?
        .ok_or_else(|| corrupt("transaction authority checkpoint is missing"))?;
    if checkpoint.version != VERSION
        || checkpoint.decision_index_version != decisions::INDEX_VERSION
        || checkpoint.installation_id != installation_id
        || checkpoint.max_committed_sequence > checkpoint.next_sequence
        || checkpoint.committed_count as u64 > checkpoint.next_sequence
        || checkpoint.next_receipt_expiry_ms <= checkpoint.receipt_floor_ms
    {
        return Err(corrupt("invalid transaction authority checkpoint"));
    }
    Wal::validate_authority_frontier(dir, checkpoint.end_lsn)?;
    Ok((disk, checkpoint))
}
pub(super) fn validate_materialized_frontier(
    data: &Path,
    installation: uuid::Uuid,
    frontier: u64,
) -> Result<()> {
    let dir = data.join(TRANSACTION_JOURNAL_DIR);
    let checkpoint: Owned<Checkpoint> = DiskMap::inspect_checkpoint(&parent(&dir))?;
    if checkpoint.version != VERSION
        || checkpoint.decision_index_version != decisions::INDEX_VERSION
        || checkpoint.installation_id != installation
        || checkpoint.max_committed_sequence > checkpoint.next_sequence
        || checkpoint.committed_count as u64 > checkpoint.next_sequence
        || checkpoint.next_receipt_expiry_ms <= checkpoint.receipt_floor_ms
        || frontier > checkpoint.max_committed_sequence
    {
        return Err(corrupt(
            "materialized frontier has no current authority binding",
        ));
    }
    Wal::validate_authority_frontier(&dir, checkpoint.end_lsn)
}

pub(super) fn validate_existing(data_dir: &Path, installation_id: uuid::Uuid) -> Result<()> {
    crate::security::onboarding::validate_transaction_authority_reader(data_dir)?;
    validate_materialized_frontier(data_dir, installation_id, 0)
}
pub(super) fn recover(dir: &Path, installation_id: uuid::Uuid) -> Result<(JournalState, u64)> {
    let (disk, checkpoint) = load(dir, installation_id)?;
    let mut state = JournalState {
        installation_id: Some(installation_id),
        authoritative: true,
        decisions: Some(disk),
        next_sequence: checkpoint.next_sequence,
        max_committed_sequence: checkpoint.max_committed_sequence,
        committed_count: checkpoint.committed_count,
        checkpointed_sequence: checkpoint.next_sequence,
        authority_checkpointed: true,
        receipt_floor_ms: checkpoint.receipt_floor_ms,
        next_receipt_expiry_ms: checkpoint.next_receipt_expiry_ms,
        ..JournalState::default()
    };
    let stats = Wal::recover_journal_authority_suffix(dir, checkpoint.end_lsn, |record| {
        let lsn = record.lsn;
        record.consume(|record| apply_record(&mut state, lsn, record.entry))?;
        state.flush_completed(dir)
    })?;
    metrics::counter!("chirondb_transaction_recovery_decoded_records_total")
        .increment(stats.records);
    #[cfg(test)]
    {
        state.recovery_decoded_records = stats.records;
    }
    state.finish_recovery(dir)?;
    Ok((state, stats.end_lsn))
}
pub(super) fn publish(dir: &Path, state: &mut JournalState, end_lsn: u64) -> Result<()> {
    publish_at(dir, state, end_lsn, idempotency::now_ms()?)
}
fn publish_at(dir: &Path, state: &mut JournalState, end_lsn: u64, now: u64) -> Result<()> {
    let now = now.max(state.receipt_floor_ms);
    if state.active_publications != 0
        || !state.unknown.is_empty()
        || state.pending_storage != 0
        || state.pending_audit != 0
    {
        return Ok(());
    }
    if state.authority_checkpointed
        && state.next_sequence == state.checkpointed_sequence
        && now < state.next_receipt_expiry_ms
    {
        return Ok(());
    }
    state.flush_decisions(dir)?;
    if !state.prepares.is_empty() {
        return Err(corrupt("authority publication has nonterminal decisions"));
    }
    if now >= state.next_receipt_expiry_ms {
        let mut next = u64::MAX;
        state
            .decisions
            .as_mut()
            .expect("decision map")
            .retain(|record| {
                if record.key().first() != Some(&RECEIPT_PREFIX) {
                    return Ok(true);
                }
                let receipt = record.decode::<RetainedReceipt>()?;
                if record.key() != receipt_key(receipt.transaction_id) {
                    return Err(corrupt("receipt index identity changed"));
                }
                let expiry = receipt.record.retained_until_unix_ms;
                if expiry <= now {
                    return Ok(false);
                }
                next = next.min(expiry);
                Ok(true)
            })?;
        // Even if publication/fsync fails, this live map has discarded these
        // expired bodies. Persist this floor with the next complete generation;
        // a clock rollback must not turn a consumed key into a new execution.
        state.receipt_floor_ms = now;
        state.next_receipt_expiry_ms = next;
    }
    let checkpoint = Checkpoint {
        version: VERSION,
        decision_index_version: decisions::INDEX_VERSION,
        installation_id: state
            .installation_id
            .ok_or_else(|| corrupt("authority has no installation identity"))?,
        end_lsn,
        next_sequence: state.next_sequence,
        max_committed_sequence: state.max_committed_sequence,
        committed_count: state.committed_count,
        receipt_floor_ms: state.receipt_floor_ms,
        next_receipt_expiry_ms: state.next_receipt_expiry_ms,
    };
    state
        .decisions
        .as_mut()
        .expect("decision map")
        .publish_checkpoint(&checkpoint)?;
    // The cache publisher syncs CURRENT, its root and run generation. Authority
    // also persists the newly created directory's entry in both ancestor roots.
    crate::failpoint::check("transaction_authority.before_parent_sync")?;
    crate::fs_util::sync_directory(&parent(dir))?;
    crate::fs_util::sync_directory(dir.parent().expect("transaction parent"))?;
    crate::failpoint::check("transaction_authority.after_parent_sync")?;
    state.checkpointed_sequence = state.next_sequence;
    state.authority_checkpointed = true;
    Ok(())
}

/// The caller holds the journal mutex and exclusive offline Db lease. Raising
/// the protected installation fence precedes every authority-store mutation.
pub(super) fn migrate(
    journal: &TransactionJournal,
    inner: &mut JournalInner,
    id: uuid::Uuid,
) -> Result<bool> {
    if inner.state.authoritative {
        return Ok(false);
    }
    if !inner.inflight_idempotency.is_empty()
        || inner.state.active_publications != 0
        || !inner.state.unknown.is_empty()
        || inner.state.pending_storage != 0
        || inner.state.pending_audit != 0
    {
        return Err(GaussError::WalUnavailable(
            "authority migration requires completed storage and audit projections".into(),
        ));
    }
    inner.wal.sync()?;
    crate::failpoint::check("transaction_authority.before_fence")?;
    crate::security::onboarding::fence_transaction_authority_reader(&journal.data_dir, id)?;
    crate::failpoint::check("transaction_authority.after_fence")?;
    let authority_dir = parent(&journal.dir);
    match std::fs::symlink_metadata(&authority_dir) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(corrupt(
                "transaction authority root is not a regular directory",
            ));
        }
        Ok(_) => DiskMap::cleanup_interrupted(&authority_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut state = JournalState {
        installation_id: Some(id),
        authoritative: true,
        receipt_floor_ms: idempotency::now_ms()?,
        decisions: Some(DiskMap::new(&parent(&journal.dir))?),
        next_receipt_expiry_ms: u64::MAX,
        ..JournalState::default()
    };
    // Rebuild from the complete old generation; no body mirror is persisted.
    let stats = Wal::recover_journal_from(&journal.dir, 0, |record| {
        let lsn = record.lsn;
        record.consume(|record| apply_record(&mut state, lsn, record.entry))?;
        state.flush_completed(&journal.dir)
    })?;
    if Wal::retained_base_lsn(&journal.dir)? != 0 {
        return Err(corrupt(
            "offline migration requires the complete legacy journal",
        ));
    }
    state.finish_recovery(&journal.dir)?;
    if state.pending_storage != 0 || state.pending_audit != 0 {
        return Err(corrupt("migration recovered incomplete projections"));
    }
    publish(&journal.dir, &mut state, stats.end_lsn)?;
    crate::failpoint::check("transaction_authority.before_activation")?;
    crate::encryption::atomic_write_persistent(
        &journal.data_dir.join(TRANSACTION_FORMAT_MARKER),
        crate::encryption::FileType::Metadata,
        format!("CHIRONTXN3\n{id}\n").as_bytes(),
    )?;
    // A failed directory sync may leave FORMAT3 visible. Reopen is required by
    // the maintenance API on any error; never continue using the old live map.
    inner.state = state;
    inner.claim_installation_id = id;
    crate::failpoint::check("transaction_authority.after_activation")?;
    Ok(true)
}
fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_AUTHORITY_DIR.into(),
        message: message.into(),
    }
}

#[cfg(test)]
pub(super) mod tests;
