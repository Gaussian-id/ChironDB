//! Complete checkpoint scheduling. Legacy lookup caches bind to an unchanged
//! WAL prefix; explicit format 3 publishes its separate durable authority.
use super::*;
use crate::relational::disk_map::DiskMap;

const CHECKPOINT_INTERVAL: u64 = 8192;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    decision_index_version: u16,
    installation_id: Option<uuid::Uuid>,
    prefix: crate::wal::WalPrefix,
    next_sequence: u64,
    max_committed_sequence: u64,
    committed_count: usize,
}

pub(super) fn recover(
    dir: &Path,
    installation_id: Option<uuid::Uuid>,
) -> Result<(JournalState, u64)> {
    let mut disk = DiskMap::new(dir)?;
    let cached = (|| -> Result<Option<crate::relational::wal_decode::Owned<Checkpoint>>> {
        let Some(cache): Option<crate::relational::wal_decode::Owned<Checkpoint>> =
            disk.load_checkpoint()?
        else {
            return Ok(None);
        };
        if cache.decision_index_version != decisions::INDEX_VERSION
            || cache.installation_id != installation_id
            || cache.max_committed_sequence > cache.next_sequence
            || cache.committed_count as u64 > cache.next_sequence
            || !Wal::matches_checkpoint_prefix(dir, &cache.prefix)?
        {
            return Err(GaussError::WalCorruption {
                path: dir.display().to_string(),
                message: "stale decision checkpoint".into(),
            });
        }
        Ok(Some(cache))
    })();
    let cache = match cached {
        Ok(cache) => cache,
        Err(error @ GaussError::ResourceExhausted(_)) => return Err(error),
        Err(error) => {
            tracing::warn!(%error, "discarding derived decision checkpoint; validating full journal");
            metrics::counter!("chirondb_transaction_checkpoint_fallbacks_total").increment(1);
            disk = DiskMap::new(dir)?;
            None
        }
    };
    let mut state = JournalState {
        installation_id,
        decisions: Some(disk),
        ..JournalState::default()
    };
    if let Some(cache) = &cache {
        state.next_sequence = cache.next_sequence;
        state.max_committed_sequence = cache.max_committed_sequence;
        state.committed_count = cache.committed_count;
        state.checkpointed_sequence = cache.next_sequence;
    }
    let mut visit = |record: crate::relational::wal_decode::Owned<crate::wal::WalRecord>| {
        let lsn = record.lsn;
        record.consume(|record| apply_record(&mut state, lsn, record.entry))?;
        state.flush_completed(dir)
    };
    let stats = match cache {
        Some(cache) => Wal::recover_journal_checkpoint_suffix(dir, &cache.prefix, &mut visit)?,
        None => Wal::recover_journal_from(dir, 0, &mut visit)?,
    };
    metrics::counter!("chirondb_transaction_recovery_decoded_records_total")
        .increment(stats.records);
    #[cfg(test)]
    {
        state.recovery_decoded_records = stats.records;
    }
    state.finish_recovery(dir)?;
    Ok((state, stats.end_lsn))
}

pub(super) fn maintain(dir: &Path, inner: &mut JournalInner) -> Result<()> {
    if inner
        .state
        .next_sequence
        .saturating_sub(inner.state.checkpointed_sequence)
        < CHECKPOINT_INTERVAL
    {
        return Ok(());
    }
    publish(dir, &mut inner.state, inner.wal.len()?)
}

pub(super) fn publish(dir: &Path, state: &mut JournalState, end_lsn: u64) -> Result<()> {
    if state.authoritative {
        return authority::publish(dir, state, end_lsn);
    }
    if state.next_sequence == state.checkpointed_sequence
        || state.next_sequence < 512
        || state.active_publications != 0
        || !state.unknown.is_empty()
        || state.pending_storage != 0
        || state.pending_audit != 0
    {
        return Ok(());
    }
    state.flush_decisions(dir)?;
    if !state.prepares.is_empty() {
        return Ok(());
    }
    let cache = Checkpoint {
        decision_index_version: decisions::INDEX_VERSION,
        installation_id: state.installation_id,
        prefix: Wal::checkpoint_prefix(dir, end_lsn)?,
        next_sequence: state.next_sequence,
        max_committed_sequence: state.max_committed_sequence,
        committed_count: state.committed_count,
    };
    state
        .decisions
        .as_mut()
        .expect("decision map")
        .publish_checkpoint(&cache)?;
    state.checkpointed_sequence = state.next_sequence;
    Ok(())
}

#[cfg(test)]
mod tests;
