//! Durable request identity and receipts share the commit journal. A receipt
//! can expire, but its consumed key must remain in every journal checkpoint.

use std::{
    io::Write,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;

const RECEIPT_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_FINGERPRINT_BYTES: usize = 8 * 1024 * 1024;
const CLAIM_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopedKey {
    installation_id: uuid::Uuid,
    pub(super) principal_id: String,
    pub(super) tenant_id: Option<String>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyRecord {
    pub(super) version: u16,
    pub(super) key: ScopedKey,
    pub(super) fingerprint: [u8; 32],
    pub(super) retained_until_unix_ms: u64,
    pub(super) response: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct IdempotencySummary {
    pub(super) fingerprint: [u8; 32],
    pub(super) retained_until_unix_ms: u64,
}

impl IdempotencyRecord {
    pub(super) fn scoped_key(&self) -> &ScopedKey {
        &self.key
    }
}

impl From<&IdempotencyRecord> for IdempotencySummary {
    fn from(record: &IdempotencyRecord) -> Self {
        Self {
            fingerprint: record.fingerprint,
            retained_until_unix_ms: record.retained_until_unix_ms,
        }
    }
}

#[derive(Debug)]
pub struct IdempotencyReceipt {
    pub status: TransactionStatus,
    /// Present only for a committed decision within its retention window.
    pub response: Option<Value>,
    /// The authenticated PREPARE mutation accompanies a live replay so callers
    /// can recheck current authority without extending the durable receipt.
    pub mutation: Option<Box<WalEntry>>,
    pub expired: bool,
    // Last: payload fields die before their decoded ownership reservation.
    _memory: crate::relational::wal_decode::Reservation,
}

#[derive(Debug)]
pub enum IdempotencyAdmission {
    Execute(IdempotencyGuard),
    Replay(IdempotencyReceipt),
}

/// Serializes only duplicate keys, never unrelated requests. Holding this
/// through preparation/publication prevents a racing retry from seeing an
/// unfinished PREPARE as a terminal rejection or preparing different IDs.
#[derive(Debug)]
pub struct IdempotencyGuard {
    journal: Arc<TransactionJournal>,
    key: ScopedKey,
    fingerprint: [u8; 32],
    // Last: the unique key payload drops before its own reservation.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl Drop for IdempotencyGuard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.journal.inner.lock() {
            inner.inflight_idempotency.remove(&self.key);
            admission::release_claim(&mut inner);
            self.journal.idempotency_changed.notify_all();
        }
    }
}

impl IdempotencyGuard {
    pub fn commit(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        response: Value,
    ) -> Result<CommittedTransaction> {
        self.commit_record(target, mutation, audit, response, None, None)
    }

    pub(crate) fn commit_with_decision(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        response: Value,
        decision_started: &std::sync::atomic::AtomicBool,
    ) -> Result<CommittedTransaction> {
        self.commit_record(
            target,
            mutation,
            audit,
            response,
            None,
            Some(decision_started),
        )
    }

    /// Use an identity already returned to the caller before COMMIT. Only
    /// the session owner can reach this after freezing its private write set.
    #[cfg(test)]
    pub(crate) fn commit_with_id(
        &self,
        transaction_id: TransactionId,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        response: Value,
    ) -> Result<CommittedTransaction> {
        self.commit_record(
            target,
            mutation,
            audit,
            response,
            Some(transaction_id),
            None,
        )
    }

    /// Retire the frozen SQL session only after the journal starts consuming
    /// its stable identity; admission failures before that may retry in place.
    pub(crate) fn commit_with_id_and_decision(
        &self,
        transaction_id: TransactionId,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        response: Value,
        decision_started: &std::sync::atomic::AtomicBool,
    ) -> Result<CommittedTransaction> {
        self.commit_record(
            target,
            mutation,
            audit,
            response,
            Some(transaction_id),
            Some(decision_started),
        )
    }

    fn commit_record(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        response: Value,
        transaction_id: Option<TransactionId>,
        decision_started: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<CommittedTransaction> {
        if audit.principal_id != self.key.principal_id || audit.tenant_id != self.key.tenant_id {
            return Err(invalid(
                "idempotency claim owner does not match transaction owner",
            ));
        }
        let _key_copy_memory = admission::key_value(&self.key)?;
        let receipt_time = now_ms()?.max(
            self.journal
                .inner
                .lock()
                .map_err(|_| unavailable())?
                .state
                .receipt_floor_ms,
        );
        let record = IdempotencyRecord {
            version: 1,
            key: self.key.clone(),
            fingerprint: self.fingerprint,
            retained_until_unix_ms: receipt_time
                .checked_add(RECEIPT_RETENTION_MS)
                .ok_or_else(|| invalid("idempotency retention timestamp overflow"))?,
            response,
        };
        self.journal.commit_inner(
            target,
            mutation,
            audit,
            Some(record),
            transaction_id,
            decision_started,
        )
    }
}

impl TransactionJournal {
    /// `request` is the typed logical request, before allocating IDs or
    /// preparing mutations. Correlation IDs and transport names must not be
    /// included: the same logical request can be retried over another protocol.
    pub fn begin_idempotent<T: Serialize>(
        self: &Arc<Self>,
        key: &str,
        context: &AuditContext,
        operation: &str,
        request: &T,
        mut check_cancelled: impl FnMut() -> Result<()>,
    ) -> Result<IdempotencyAdmission> {
        if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
            return Err(invalid(
                "idempotency_key must contain 1 to 256 bytes without control characters",
            ));
        }
        if context.principal_id.is_empty()
            || context.principal_id.len() > 256
            || context
                .tenant_id
                .as_ref()
                .is_some_and(|id| id.is_empty() || id.len() > 256)
        {
            return Err(invalid("invalid idempotency owner"));
        }
        let fingerprint = fingerprint(operation, request)?;
        let deadline = Instant::now() + CLAIM_TIMEOUT;
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        check_cancelled()?;
        let installation_id = inner.claim_installation_id;
        // Declare the reservation first: key payload drops before it, including
        // a duplicate wait, rejection, replay or panic.
        let key_memory = admission::claim_value(context)?;
        let key = ScopedKey {
            installation_id,
            principal_id: context.principal_id.clone(),
            tenant_id: context.tenant_id.clone(),
            digest: Sha256::digest(key.as_bytes()).into(),
        };
        loop {
            check_cancelled()?;
            if let Some(active) = inner.inflight_idempotency.get(&key) {
                if active != &fingerprint {
                    return Err(invalid("idempotency_key was used with a different request"));
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(GaussError::ResourceExhausted(
                        "idempotency request is still executing; retry later".into(),
                    ));
                }
                (inner, _) = self
                    .idempotency_changed
                    .wait_timeout(inner, remaining.min(Duration::from_millis(25)))
                    .map_err(|_| unavailable())?;
                continue;
            }
            if let Some(receipt) = replay(&inner.state, &self.dir, &key, &fingerprint, now_ms()?)? {
                return Ok(IdempotencyAdmission::Replay(receipt));
            }
            let limit = crate::resource_profile::current()
                .query_workers
                .saturating_mul(2)
                .clamp(2, 128);
            if inner.inflight_idempotency.len() >= limit {
                return Err(GaussError::ResourceExhausted(
                    "too many active idempotency keys".into(),
                ));
            }
            admission::reserve_claim(&mut inner, &key)?;
            inner.inflight_idempotency.insert(key.clone(), fingerprint);
            return Ok(IdempotencyAdmission::Execute(IdempotencyGuard {
                journal: Arc::clone(self),
                key,
                fingerprint,
                _memory: key_memory,
            }));
        }
    }
}

pub(super) fn register(state: &mut JournalState, prepare: &TransactionPrepare) -> Result<()> {
    let Some(record) = &prepare.idempotency else {
        return Ok(());
    };
    if record.version != 1
        || record.key.installation_id.is_nil()
        || Some(record.key.installation_id) != state.installation_id
        || record.key.principal_id != prepare.audit.principal_id
        || record.key.tenant_id != prepare.audit.tenant_id
        || prepare.version != IDEMPOTENT_JOURNAL_VERSION
        || record.retained_until_unix_ms < RECEIPT_RETENTION_MS
    {
        return Err(corrupt("invalid idempotency receipt binding"));
    }
    if state.consumed_key(&record.key)?.is_some() {
        return Err(corrupt("duplicate consumed idempotency key"));
    }
    state
        .idempotency
        .insert(record.key.clone(), prepare.transaction_id);
    if state.authoritative && record.retained_until_unix_ms > state.receipt_floor_ms {
        state.next_receipt_expiry_ms = state
            .next_receipt_expiry_ms
            .min(record.retained_until_unix_ms);
    }
    Ok(())
}

pub(super) fn replay(
    state: &JournalState,
    dir: &Path,
    key: &ScopedKey,
    fingerprint: &[u8; 32],
    now: u64,
) -> Result<Option<IdempotencyReceipt>> {
    let Some(id) = state.consumed_key(key)? else {
        return Ok(None);
    };
    let reference = state
        .prepare(id)?
        .ok_or_else(|| corrupt("consumed idempotency key has no PREPARE"))?;
    let summary = reference
        .idempotency
        .as_ref()
        .ok_or_else(|| corrupt("consumed idempotency key has no receipt"))?;
    if &summary.fingerprint != fingerprint {
        return Err(invalid("idempotency_key was used with a different request"));
    }
    let status = state.checked_status(id)?;
    let expired = now.max(state.receipt_floor_ms) >= summary.retained_until_unix_ms;
    let (response, mutation, memory) = if !expired && status.state == TransactionState::Committed {
        let prepare = if state.authoritative && !state.prepares.contains_key(&id) {
            authority::receipt(state, id, &reference)?
                .try_map(|receipt| receipt.into_replay(key, summary))?
        } else {
            reference.load(dir, id)?.try_map(|prepare| {
                let record = prepare
                    .idempotency
                    .ok_or_else(|| corrupt("consumed idempotency key has no durable receipt"))?;
                if record.key != *key
                    || record.fingerprint != summary.fingerprint
                    || record.retained_until_unix_ms != summary.retained_until_unix_ms
                {
                    return Err(corrupt("consumed idempotency receipt changed"));
                }
                Ok((Some(record.response), Some(prepare.mutation)))
            })?
        };
        let ((response, mutation), memory) = prepare.into_parts();
        (response, mutation, memory)
    } else {
        (None, None, Default::default())
    };
    Ok(Some(IdempotencyReceipt {
        status,
        response,
        mutation,
        expired,
        _memory: memory,
    }))
}

fn fingerprint(operation: &str, request: &impl Serialize) -> Result<[u8; 32]> {
    struct Hasher {
        digest: Sha256,
        bytes: usize,
    }
    impl Write for Hasher {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_FINGERPRINT_BYTES)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::FileTooLarge))?;
            self.digest.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hasher = Hasher {
        digest: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut hasher, &(1_u16, operation, request))?;
    Ok(hasher.digest.finalize().into())
}

pub(super) fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| invalid("system clock is outside supported receipt timestamp range"))
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.into())
}
fn unavailable() -> GaussError {
    GaussError::WalUnavailable("transaction journal lock poisoned".into())
}
fn corrupt(message: &str) -> GaussError {
    GaussError::WalCorruption {
        path: TRANSACTION_JOURNAL_DIR.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    fn begin(
        journal: &Arc<TransactionJournal>,
        context: &AuditContext,
        value: u64,
    ) -> IdempotencyAdmission {
        journal
            .begin_idempotent("request-1", context, "test_delete", &value, || Ok(()))
            .unwrap()
    }

    fn commit(guard: &IdempotencyGuard, context: &AuditContext) -> CommittedTransaction {
        guard
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                TransactionAudit::mutation("delete", Some("docs"), context, Value::Null),
                serde_json::json!({"affected_rows": 1, "allocated_ids": ["one"]}),
            )
            .unwrap()
    }

    #[test]
    fn reserved_transaction_identity_cannot_replace_an_existing_decision() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let context = AuditContext::embedded();
        let IdempotencyAdmission::Execute(first) = begin(&journal, &context, 1) else {
            panic!()
        };
        let reserved = TransactionId::new();
        let commit_with_id = |claim: &IdempotencyGuard, id| {
            claim.commit_with_id(
                id,
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                TransactionAudit::mutation("delete", Some("docs"), &context, Value::Null),
                serde_json::json!({"affected_rows": 1}),
            )
        };
        assert!(
            commit_with_id(
                &first,
                "00000000-0000-0000-0000-000000000000".parse().unwrap()
            )
            .is_err()
        );
        let committed = commit_with_id(&first, reserved).unwrap();
        assert_eq!(committed.prepare.transaction_id, reserved);
        journal
            .mark_projected(reserved, ProjectionKind::Storage)
            .unwrap();
        journal
            .mark_projected(reserved, ProjectionKind::Audit)
            .unwrap();
        drop(first);
        drop(journal);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        assert!(journal.inner.lock().unwrap().state.prepares.is_empty());
        let IdempotencyAdmission::Execute(second) = journal
            .begin_idempotent("second-key", &context, "test_delete", &2, || Ok(()))
            .unwrap()
        else {
            panic!()
        };
        assert!(commit_with_id(&second, reserved).is_err());
        assert_eq!(journal.status(reserved).state, TransactionState::Committed);
        assert_eq!(journal.committed().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_retry_has_one_durable_decision_across_transports_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let barrier = Barrier::new(16);
        let executions = AtomicUsize::new(0);
        let ids = std::thread::scope(|scope| {
            (0..16)
                .map(|i| {
                    let (journal, barrier, executions) = (&journal, &barrier, &executions);
                    scope.spawn(move || {
                        let mut context = AuditContext::embedded();
                        context.transport = format!("transport-{i}");
                        context.request_id = Some(format!("correlation-{i}"));
                        barrier.wait();
                        match begin(journal, &context, 42) {
                            IdempotencyAdmission::Execute(guard) => {
                                executions.fetch_add(1, Ordering::SeqCst);
                                commit(&guard, &context).prepare.transaction_id
                            }
                            IdempotencyAdmission::Replay(receipt) => {
                                assert_eq!(receipt.response.unwrap()["affected_rows"], 1);
                                receipt.status.transaction_id
                            }
                        }
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(journal.committed().unwrap().len(), 1);
        drop(journal);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let IdempotencyAdmission::Replay(receipt) = begin(&journal, &AuditContext::embedded(), 42)
        else {
            panic!("retry executed again")
        };
        assert_eq!(receipt.status.state, TransactionState::Committed);
        assert_eq!(receipt.status.transaction_id, ids[0]);
        assert_eq!(
            receipt.response.unwrap()["allocated_ids"],
            serde_json::json!(["one"])
        );
    }

    #[test]
    fn scope_and_fingerprint_prevent_cross_request_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let context = AuditContext::embedded();
        let IdempotencyAdmission::Execute(guard) = begin(&journal, &context, 42) else {
            panic!()
        };
        assert!(
            journal
                .begin_idempotent("request-1", &context, "test_delete", &43_u64, || Ok(()))
                .is_err()
        );
        commit(&guard, &context);
        drop(guard);
        assert!(
            journal
                .begin_idempotent("request-1", &context, "test_delete", &43_u64, || Ok(()))
                .is_err()
        );
        for foreign in [
            AuditContext {
                principal_id: "other".into(),
                ..context.clone()
            },
            AuditContext {
                tenant_id: Some("other".into()),
                ..context.clone()
            },
        ] {
            let IdempotencyAdmission::Execute(guard) = begin(&journal, &foreign, 42) else {
                panic!("foreign receipt disclosed")
            };
            commit(&guard, &foreign);
        }
        let other = tempfile::tempdir().unwrap();
        let other = TransactionJournal::open(other.path()).unwrap();
        assert!(matches!(
            begin(&other, &context, 42),
            IdempotencyAdmission::Execute(_)
        ));
        assert_eq!(journal.committed().unwrap().len(), 3);
    }

    #[test]
    fn expiry_hides_receipt_without_releasing_consumed_key() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let context = AuditContext::embedded();
        let IdempotencyAdmission::Execute(guard) = begin(&journal, &context, 42) else {
            panic!()
        };
        let transaction = commit(&guard, &context);
        journal
            .mark_projected(transaction.prepare.transaction_id, ProjectionKind::Storage)
            .unwrap();
        journal
            .mark_projected(transaction.prepare.transaction_id, ProjectionKind::Audit)
            .unwrap();
        let record = transaction.prepare.idempotency.as_ref().unwrap().clone();
        drop(guard);
        drop(journal);
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let inner = journal.inner.lock().unwrap();
        let current = replay(
            &inner.state,
            &journal.dir,
            &record.key,
            &record.fingerprint,
            record.retained_until_unix_ms - 1,
        )
        .unwrap()
        .unwrap();
        assert!(current.response.is_some());
        let expired = replay(
            &inner.state,
            &journal.dir,
            &record.key,
            &record.fingerprint,
            record.retained_until_unix_ms,
        )
        .unwrap()
        .unwrap();
        assert!(expired.expired);
        assert!(expired.response.is_none());
        assert_eq!(expired.status.state, TransactionState::Committed);
        assert!(replay(&inner.state, &journal.dir, &record.key, &[0; 32], u64::MAX).is_err());
    }

    #[test]
    fn cancellation_and_preparation_failure_release_only_unconsumed_claims() {
        let temp = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(temp.path()).unwrap();
        let context = AuditContext::embedded();
        let IdempotencyAdmission::Execute(guard) = begin(&journal, &context, 42) else {
            panic!()
        };
        assert!(
            journal
                .begin_idempotent("request-1", &context, "test_delete", &42_u64, || Err(
                    invalid("cancelled")
                ))
                .is_err()
        );
        drop(guard); // Caller rejected validation before any journal decision.
        let IdempotencyAdmission::Execute(guard) = begin(&journal, &context, 42) else {
            panic!()
        };
        commit(&guard, &context);
        drop(guard);
        assert!(
            journal
                .inner
                .lock()
                .unwrap()
                .inflight_idempotency
                .is_empty()
        );
    }

    #[test]
    fn unsupported_or_missing_journal_format_rejects_before_mutable_db_open() {
        fn files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            let mut files_by_path = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    files_by_path.extend(files(&path));
                } else {
                    files_by_path.insert(path.clone(), std::fs::read(path).unwrap());
                }
            }
            files_by_path
        }
        for marker in [Some(b"CHIRONTXN99\n".as_slice()), None] {
            let temp = tempfile::tempdir().unwrap();
            drop(crate::Db::open(temp.path()).unwrap());
            let path = temp.path().join(TRANSACTION_FORMAT_MARKER);
            if let Some(bytes) = marker {
                std::fs::write(path, bytes).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
            let before = files(temp.path());
            assert!(crate::Db::open(temp.path()).is_err());
            assert_eq!(files(temp.path()), before);
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn ambiguous_commit_and_rejected_prepare_cannot_execute_again() {
        for cut in [
            "transaction.after_prepare",
            "transaction.before_commit_fsync",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let journal = TransactionJournal::open(temp.path()).unwrap();
            let context = AuditContext::embedded();
            let IdempotencyAdmission::Execute(guard) = begin(&journal, &context, 42) else {
                panic!()
            };
            let fault = crate::failpoint::test_env(
                &format!("error:{cut}"),
                &temp.path().join("cut"),
                &temp.path().join("release"),
            );
            let result = guard.commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                TransactionAudit::mutation("delete", Some("docs"), &context, Value::Null),
                Value::Null,
            );
            assert!(result.is_err());
            drop(fault);
            drop(guard);
            let IdempotencyAdmission::Replay(receipt) = begin(&journal, &context, 42) else {
                panic!("executed uncertain/rejected request")
            };
            assert!(receipt.response.is_none());
            assert_eq!(
                receipt.status.state,
                if cut == "transaction.after_prepare" {
                    TransactionState::Rejected
                } else {
                    TransactionState::OutcomeUnknown
                }
            );
            let id = receipt.status.transaction_id;
            drop(journal);
            let journal = TransactionJournal::open(temp.path()).unwrap();
            let IdempotencyAdmission::Replay(receipt) = begin(&journal, &context, 42) else {
                panic!("re-executed after restart")
            };
            assert_eq!(receipt.status.transaction_id, id);
            assert_eq!(
                receipt.status.state,
                if cut == "transaction.after_prepare" {
                    TransactionState::Rejected
                } else {
                    TransactionState::Committed
                }
            );
            assert_eq!(
                journal.committed().unwrap().len(),
                usize::from(cut != "transaction.after_prepare")
            );
        }
    }
}
