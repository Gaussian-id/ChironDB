//! Retained scan containers admit growth and keep their reservation through iteration.
use super::*;
use crate::relational::wal_decode::MetadataCharge;
use std::mem::size_of;

struct Snapshot {
    cold: crate::relational::disk_map::Cursor,
    cold_head: Option<decisions::CommittedRef>,
    hot: std::vec::IntoIter<decisions::CommittedRef>,
    hot_head: Option<decisions::CommittedRef>,
    expected: usize,
    max_sequence: u64,
    wal: crate::wal::OrderedJournalReader,
    _memory: MetadataCharge,
}

impl Snapshot {
    fn capture(journal: &TransactionJournal) -> Result<Self> {
        let inner = journal
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        let state = &inner.state;
        let count = state.commits.len();
        let mut memory = MetadataCharge::default();
        memory.prepare(
            (count as u64)
                .checked_mul(size_of::<decisions::CommittedRef>() as u64)
                .and_then(|bytes| bytes.checked_add(size_of::<Self>() as u64 + 4096))
                .ok_or_else(exhausted)?,
        )?;
        let mut hot = Vec::new();
        hot.try_reserve_exact(count).map_err(|_| exhausted())?;
        for id in &state.commits {
            let reference = state
                .prepares
                .get(id)
                .ok_or_else(|| corrupt("live committed decision lost its PREPARE"))?;
            hot.push(decisions::CommittedRef {
                transaction_id: *id,
                lsn: reference.lsn,
                commit_sequence: reference.commit_sequence,
            });
        }
        hot.sort_unstable_by_key(|reference| reference.commit_sequence);
        let cold = state
            .decisions
            .as_ref()
            .ok_or_else(|| corrupt("decision index is missing"))?
            .prefix_cursor(decisions::ORDERED_PREFIX)?;
        let mut hot = hot.into_iter();
        let hot_head = hot.next();
        let wal = crate::wal::OrderedJournalReader::open(&journal.dir, inner.wal.len()?)?;
        Ok(Self {
            cold,
            cold_head: None,
            hot,
            hot_head,
            expected: state.committed_count,
            max_sequence: state.max_committed_sequence,
            wal,
            _memory: memory,
        })
    }

    fn next_reference(&mut self) -> Result<Option<decisions::CommittedRef>> {
        if self.cold_head.is_none()
            && let Some(record) = self.cold.next().transpose()?
        {
            let reference = record.decode::<decisions::CommittedRef>()?;
            if record.key() != decisions::ordered_key(reference.commit_sequence) {
                return Err(corrupt("ordered decision binding changed"));
            }
            self.cold_head = Some(*reference);
        }
        match (self.cold_head, self.hot_head) {
            (Some(cold), Some(hot)) => match cold.commit_sequence.cmp(&hot.commit_sequence) {
                std::cmp::Ordering::Equal => {
                    Err(corrupt("duplicate committed sequence in decision snapshot"))
                }
                std::cmp::Ordering::Less => Ok(self.cold_head.take()),
                std::cmp::Ordering::Greater => {
                    self.hot_head = self.hot.next();
                    Ok(Some(hot))
                }
            },
            (Some(_), None) => Ok(self.cold_head.take()),
            (None, Some(hot)) => {
                self.hot_head = self.hot.next();
                Ok(Some(hot))
            }
            (None, None) => Ok(None),
        }
    }
}

impl Snapshot {
    fn read_prepare(
        &mut self,
        candidate: decisions::CommittedRef,
    ) -> Result<crate::relational::wal_decode::Owned<TransactionPrepare>> {
        crate::failpoint::check("transaction.scan.before_prepare_read")?;
        let prepare = self.wal.read(candidate.lsn)?.try_map(|record| {
            let WalEntry::TransactionPrepare { prepare } = record.entry else {
                return Err(corrupt("committed snapshot location is not a PREPARE"));
            };
            if record.lsn != candidate.lsn
                || prepare.transaction_id != candidate.transaction_id
                || prepare.commit_sequence != candidate.commit_sequence
            {
                return Err(corrupt("committed snapshot PREPARE identity changed"));
            }
            Ok(prepare)
        })?;
        metrics::counter!("chirondb_transaction_repair_prepare_reads_total").increment(1);
        Ok(prepare)
    }
}

fn for_each_decision(
    journal: &TransactionJournal,
    mut visitor: impl FnMut(&mut Snapshot, decisions::CommittedRef, TransactionStatus) -> Result<()>,
) -> Result<()> {
    let mut snapshot = Snapshot::capture(journal)?;
    let mut seen = 0_usize;
    let mut previous_sequence = 0;
    while let Some(candidate) = snapshot.next_reference()? {
        crate::relational::check_sql_cancelled()?;
        if candidate.commit_sequence <= previous_sequence
            || candidate.commit_sequence > snapshot.max_sequence
        {
            return Err(corrupt("committed snapshot sequence is invalid"));
        }
        previous_sequence = candidate.commit_sequence;
        let status = {
            let inner = journal.inner.lock().map_err(|_| {
                GaussError::WalUnavailable("transaction journal lock poisoned".into())
            })?;
            let status = inner.state.checked_status(candidate.transaction_id)?;
            let reference = inner
                .state
                .prepare(candidate.transaction_id)?
                .ok_or_else(|| corrupt("committed transaction lost its PREPARE"))?;
            if status.state != TransactionState::Committed
                || reference.lsn != candidate.lsn
                || reference.commit_sequence != candidate.commit_sequence
            {
                return Err(corrupt("committed decision binding changed during scan"));
            }
            status
        };
        seen = seen.checked_add(1).ok_or_else(exhausted)?;
        if seen > snapshot.expected {
            return Err(corrupt("duplicate committed PREPARE in snapshot"));
        }
        visitor(&mut snapshot, candidate, status)?;
    }
    if seen != snapshot.expected {
        return Err(corrupt(
            "committed PREPARE is missing from decision snapshot",
        ));
    }
    Ok(())
}

pub(super) fn for_each_committed(
    journal: &TransactionJournal,
    mut visitor: impl FnMut(CommittedTransaction) -> Result<()>,
) -> Result<()> {
    for_each_decision(journal, |snapshot, candidate, status| {
        visitor(CommittedTransaction {
            prepare: PreparedTransaction::new(snapshot.read_prepare(candidate)?),
            storage_projected: status.storage_projected,
            audit_projected: status.audit_projected,
        })
    })
}

pub(super) fn for_each_recovery(
    journal: &TransactionJournal,
    select: impl FnMut(&RecoveryDecision<'_>) -> Result<bool>,
    visitor: impl FnMut(CommittedTransaction) -> Result<()>,
) -> Result<()> {
    for_each_recovery_after(journal, 0, select, visitor)
}

pub(super) fn for_each_recovery_after(
    journal: &TransactionJournal,
    frontier: u64,
    mut select: impl FnMut(&RecoveryDecision<'_>) -> Result<bool>,
    mut visitor: impl FnMut(CommittedTransaction) -> Result<()>,
) -> Result<()> {
    for_each_decision(journal, |snapshot, candidate, status| {
        // A materialized common frontier already binds this prefix. Do not
        // decode its descriptors or historical PREPAREs again.
        if candidate.commit_sequence <= frontier {
            if !status.storage_projected || !status.audit_projected {
                return Err(corrupt("materialized prefix has an unfinished projection"));
            }
            return Ok(());
        }
        let descriptor = {
            let inner = journal.inner.lock().map_err(|_| {
                GaussError::WalUnavailable("transaction journal lock poisoned".into())
            })?;
            let reference = inner
                .state
                .prepare(candidate.transaction_id)?
                .ok_or_else(|| corrupt("committed recovery lost its decision"))?;
            match reference {
                decisions::Reference::Hot(reference) => {
                    crate::relational::wal_decode::copy(&reference.recovery)?
                }
                decisions::Reference::Disk(reference) => {
                    reference.try_map(|reference| Ok(reference.recovery))?
                }
            }
        };
        let mut legacy_prepare = None;
        let legacy_descriptor;
        let descriptor = if let Some(descriptor) = descriptor.as_ref() {
            descriptor
        } else {
            let prepare = snapshot.read_prepare(candidate)?;
            legacy_descriptor = recovery::RecoveryDescriptor::owned(&prepare)?;
            legacy_prepare = Some(prepare);
            &legacy_descriptor
        };
        descriptor.validate()?;
        // A pending decision may be completed by the selector (for example a
        // retired collection incarnation). Validate its original identity and
        // routing before any callback can acknowledge that repair.
        if legacy_prepare.is_none() && (!status.storage_projected || !status.audit_projected) {
            legacy_prepare = Some(snapshot.read_prepare(candidate)?);
        }
        if let Some(prepare) = &legacy_prepare {
            descriptor.validate_prepare(prepare)?;
        }
        if !select(&RecoveryDecision::new(candidate, &status, descriptor))? {
            return Ok(());
        }
        let prepare = match legacy_prepare {
            Some(prepare) => prepare,
            None => snapshot.read_prepare(candidate)?,
        };
        descriptor.validate_prepare(&prepare)?;
        visitor(CommittedTransaction {
            prepare: PreparedTransaction::new(prepare),
            storage_projected: status.storage_projected,
            audit_projected: status.audit_projected,
        })
    })
}

fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_JOURNAL_DIR.into(),
        message: message.into(),
    }
}

#[derive(Debug, Default)]
pub struct CommittedTransactions {
    transactions: Vec<CommittedTransaction>,
    // Last: the Vec allocation and its elements drop before its reservation.
    _memory: MetadataCharge,
}

impl CommittedTransactions {
    pub(super) fn push(&mut self, transaction: CommittedTransaction) -> Result<()> {
        if self.transactions.len() == self.transactions.capacity() {
            let capacity = self
                .transactions
                .len()
                .checked_add(1)
                .and_then(usize::checked_next_power_of_two)
                .ok_or_else(exhausted)?;
            let bytes = (capacity as u64)
                .checked_add(self.transactions.capacity() as u64)
                .and_then(|n| n.checked_mul(size_of::<CommittedTransaction>() as u64))
                .and_then(|n| n.checked_add(4096))
                .ok_or_else(exhausted)?;
            self._memory.prepare(bytes)?;
            self.transactions
                .try_reserve_exact(capacity - self.transactions.len())
                .map_err(|_| exhausted())?;
            self._memory.reduce(
                4096 + self.transactions.capacity() as u64
                    * size_of::<CommittedTransaction>() as u64,
            );
        }
        self.transactions.push(transaction);
        Ok(())
    }
}

fn exhausted() -> GaussError {
    GaussError::ResourceExhausted(
        "committed transaction scan memory is full; use for_each_committed".into(),
    )
}

impl std::ops::Deref for CommittedTransactions {
    type Target = [CommittedTransaction];
    fn deref(&self) -> &Self::Target {
        &self.transactions
    }
}

pub struct CommittedTransactionsIter {
    transactions: std::vec::IntoIter<CommittedTransaction>,
    _memory: MetadataCharge,
}
impl Iterator for CommittedTransactionsIter {
    type Item = CommittedTransaction;
    fn next(&mut self) -> Option<Self::Item> {
        self.transactions.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.transactions.size_hint()
    }
}
impl DoubleEndedIterator for CommittedTransactionsIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.transactions.next_back()
    }
}
impl ExactSizeIterator for CommittedTransactionsIter {}
impl std::iter::FusedIterator for CommittedTransactionsIter {}
impl IntoIterator for CommittedTransactions {
    type Item = CommittedTransaction;
    type IntoIter = CommittedTransactionsIter;
    fn into_iter(self) -> Self::IntoIter {
        CommittedTransactionsIter {
            transactions: self.transactions.into_iter(),
            _memory: self._memory,
        }
    }
}
impl<'a> IntoIterator for &'a CommittedTransactions {
    type Item = &'a CommittedTransaction;
    type IntoIter = std::slice::Iter<'a, CommittedTransaction>;
    fn into_iter(self) -> Self::IntoIter {
        self.transactions.iter()
    }
}

#[cfg(test)]
mod tests;
