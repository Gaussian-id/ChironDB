//! Installation-scoped decision journal for mutations that span content and
//! audit durability. Collection/catalog WALs and `audit.jsonl` are rebuildable
//! projections; a durable [`TransactionCommit`] is the commit authority.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    GaussError, Result,
    audit::AuditContext,
    wal::{Wal, WalEntry},
};

mod admission;
mod audit;
mod authority;
mod checkpoint;
mod decisions;
mod idempotency;
mod projection;
mod recovery;
mod scan;

#[cfg(test)]
pub(crate) use authority::tests::activate as activate_test_authority;
pub use idempotency::{
    IdempotencyAdmission, IdempotencyGuard, IdempotencyReceipt, IdempotencyRecord,
};
pub(crate) use projection::StorageTarget;
pub(crate) use recovery::{CatalogChange, RecoveryDecision};
pub use scan::{CommittedTransactions, CommittedTransactionsIter};
const IDEMPOTENT_JOURNAL_VERSION: u16 = 2;
pub const TRANSACTION_JOURNAL_VERSION: u16 = 1;
pub const TRANSACTION_JOURNAL_DIR: &str = "transactions/journal";
pub const TRANSACTION_FORMAT_MARKER: &str = "transactions/FORMAT";
const TRANSACTION_FORMAT_BYTES: &[u8] = b"CHIRONTXN1\n";
pub(crate) const TRANSACTION_AUTHORITY_DIR: &str = "transactions/authority";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TransactionId(uuid::Uuid);

impl TransactionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub(crate) fn encode_hyphenated(self, buffer: &mut [u8; 36]) -> &str {
        self.0.hyphenated().encode_lower(buffer)
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TransactionId {
    type Err = GaussError;

    fn from_str(value: &str) -> Result<Self> {
        uuid::Uuid::parse_str(value)
            .map(Self)
            .map_err(|error| GaussError::InvalidRequest(format!("invalid transaction ID: {error}")))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransactionTarget {
    Collection { name: String },
    Catalog,
    Relational,
    MultiModel { collections: Vec<String> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionAudit {
    pub category: String,
    pub operation: String,
    pub collection: Option<String>,
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub transport: String,
    pub request_id: Option<String>,
    #[serde(default)]
    pub details: Value,
}

impl TransactionAudit {
    pub fn new(
        category: impl Into<String>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: &AuditContext,
        details: Value,
    ) -> Self {
        Self {
            category: category.into(),
            operation: operation.into(),
            collection: collection.map(str::to_string),
            principal_id: context.principal_id.clone(),
            tenant_id: context.tenant_id.clone(),
            transport: context.transport.clone(),
            request_id: context.request_id.clone(),
            details,
        }
    }

    pub fn mutation(
        operation: impl Into<String>,
        collection: Option<&str>,
        context: &AuditContext,
        details: Value,
    ) -> Self {
        Self::new("mutation", operation, collection, context, details)
    }

    pub fn context(&self) -> AuditContext {
        AuditContext {
            principal_id: self.principal_id.clone(),
            tenant_id: self.tenant_id.clone(),
            transport: self.transport.clone(),
            request_id: self.request_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionPrepare {
    pub version: u16,
    pub transaction_id: TransactionId,
    pub commit_sequence: u64,
    pub target: TransactionTarget,
    pub mutation: Box<WalEntry>,
    pub audit: TransactionAudit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<IdempotencyRecord>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionCommit {
    pub version: u16,
    pub transaction_id: TransactionId,
    pub commit_sequence: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionKind {
    Storage,
    Audit,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionProjection {
    pub version: u16,
    pub transaction_id: TransactionId,
    pub kind: ProjectionKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Committed,
    Rejected,
    OutcomeUnknown,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionStatus {
    pub transaction_id: TransactionId,
    pub state: TransactionState,
    pub commit_sequence: Option<u64>,
    pub storage_projected: bool,
    pub audit_projected: bool,
}

#[derive(Clone, Debug)]
pub struct CommittedTransaction {
    pub prepare: PreparedTransaction,
    pub storage_projected: bool,
    pub audit_projected: bool,
}

/// An immutable admitted PREPARE shared by the live decision and its receipt.
/// Clone shares the same allocation/reservation; it never copies a mutation.
#[derive(Clone, Debug)]
pub struct PreparedTransaction(Arc<crate::relational::wal_decode::Owned<TransactionPrepare>>);
impl std::ops::Deref for PreparedTransaction {
    type Target = TransactionPrepare;
    fn deref(&self) -> &TransactionPrepare {
        &self.0
    }
}
impl AsRef<TransactionPrepare> for PreparedTransaction {
    fn as_ref(&self) -> &TransactionPrepare {
        self
    }
}
impl Serialize for PreparedTransaction {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        std::ops::Deref::deref(self).serialize(serializer)
    }
}
impl PreparedTransaction {
    fn new(owned: crate::relational::wal_decode::Owned<TransactionPrepare>) -> Self {
        Self(Arc::new(owned))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PreparedRef {
    lsn: u64,
    commit_sequence: u64,
    principal_id: String,
    tenant_id: Option<String>,
    idempotency: Option<idempotency::IdempotencySummary>,
    idempotency_key: Option<idempotency::ScopedKey>,
    relational_proof: Option<authority::RelationalProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_proof_version: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<recovery::RecoveryDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_proof: Option<audit::Proof>,
    /// A live PREPARE may have an uncertain WAL write. Keep its mutation until
    /// both projections finish; recovered decisions reload it by LSN.
    #[serde(skip)]
    hot: Option<PreparedTransaction>,
}

impl PreparedRef {
    fn new(
        prepare: &TransactionPrepare,
        lsn: u64,
        hot: Option<PreparedTransaction>,
        authoritative: bool,
    ) -> Result<Self> {
        Ok(Self {
            lsn,
            commit_sequence: prepare.commit_sequence,
            principal_id: prepare.audit.principal_id.clone(),
            tenant_id: prepare.audit.tenant_id.clone(),
            idempotency: prepare
                .idempotency
                .as_ref()
                .map(idempotency::IdempotencySummary::from),
            idempotency_key: prepare
                .idempotency
                .as_ref()
                .map(|record| record.scoped_key().clone()),
            relational_proof: if authoritative {
                authority::RelationalProof::from_prepare(prepare)?
            } else {
                None
            },
            storage_proof_version: (authoritative
                && !matches!(prepare.target, TransactionTarget::Relational))
            .then_some(projection::VERSION),
            recovery: authoritative
                .then(|| recovery::RecoveryDescriptor::from_prepare(prepare))
                .transpose()?,
            audit_proof: authoritative
                .then(|| audit::Proof::new(prepare))
                .transpose()?,
            hot,
        })
    }

    fn load(
        &self,
        dir: &Path,
        id: TransactionId,
    ) -> Result<crate::relational::wal_decode::Owned<TransactionPrepare>> {
        if let Some(prepare) = &self.hot {
            return crate::relational::wal_decode::copy(&**prepare);
        }
        Wal::read_at_owned(dir, self.lsn)?.try_map(|record| {
            let WalEntry::TransactionPrepare { prepare } = record.entry else {
                return Err(GaussError::WalCorruption {
                    path: dir.display().to_string(),
                    message: format!("transaction {id} location is not a PREPARE"),
                });
            };
            if prepare.transaction_id != id || prepare.commit_sequence != self.commit_sequence {
                return Err(GaussError::WalCorruption {
                    path: dir.display().to_string(),
                    message: format!("transaction {id} PREPARE identity changed"),
                });
            }
            Ok(prepare)
        })
    }
}

#[derive(Debug, Default)]
struct JournalState {
    installation_id: Option<uuid::Uuid>,
    authoritative: bool,
    receipt_floor_ms: u64,
    next_receipt_expiry_ms: u64,
    authority_checkpointed: bool,
    idempotency: HashMap<idempotency::ScopedKey, TransactionId>,
    prepares: HashMap<TransactionId, PreparedRef>,
    commits: HashSet<TransactionId>,
    projections: HashSet<(TransactionId, ProjectionKind)>,
    unknown: HashSet<TransactionId>,
    decisions: Option<crate::relational::disk_map::DiskMap>,
    completed: Vec<TransactionId>,
    committed_count: usize,
    next_sequence: u64,
    max_committed_sequence: u64,
    pending_storage: usize,
    pending_audit: usize,
    active_publications: usize,
    visibility_revision: u64,
    checkpointed_sequence: u64,
    #[cfg(test)]
    recovery_decoded_records: u64,
    // Last: maps and copied metadata drop before their unique reservation.
    metadata_capacities: [usize; 6],
    metadata_memory: crate::relational::wal_decode::MetadataCharge,
}

#[derive(Debug)]
struct JournalInner {
    wal: Wal,
    claim_installation_id: uuid::Uuid,
    inflight_idempotency: HashMap<idempotency::ScopedKey, [u8; 32]>,
    state: JournalState,
    // Last: the inflight key copies drop before their reservation.
    claim_capacity: usize,
    claim_memory: crate::relational::wal_decode::MetadataCharge,
}

#[derive(Debug)]
pub struct TransactionJournal {
    data_dir: PathBuf,
    dir: PathBuf,
    inner: Mutex<JournalInner>,
    idempotency_changed: Condvar,
    // Embedded relational handles can outlive Db. Keep exclusive startup from
    // treating their journal readers as orphaned after the last Db drops.
    _root_lease: Option<Arc<crate::data_dir_lock::DataDirLock>>,
    // Last: journal paths, inner state and Arc root stay covered until drop.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl TransactionJournal {
    pub(crate) fn validate_existing_format(data_dir: &Path) -> Result<()> {
        match std::fs::symlink_metadata(data_dir.join(TRANSACTION_FORMAT_MARKER)) {
            Ok(_) => {
                let format = validate_format(data_dir)?;
                if format.authoritative {
                    authority::validate_existing(
                        data_dir,
                        format.installation_id.expect("authority identity"),
                    )?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let dir = data_dir.join(TRANSACTION_JOURNAL_DIR);
                if dir.exists() && std::fs::read_dir(&dir)?.next().is_some() {
                    return Err(GaussError::WalCorruption {
                        path: dir.display().to_string(),
                        message: "transaction journal is missing its format marker".into(),
                    });
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn open(data_dir: &Path) -> Result<Arc<Self>> {
        Self::open_inner(data_dir, None)
    }

    pub(crate) fn open_with_root_lease(
        data_dir: &Path,
        lease: Arc<crate::data_dir_lock::DataDirLock>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(data_dir, Some(lease))
    }

    fn open_inner(
        data_dir: &Path,
        root_lease: Option<Arc<crate::data_dir_lock::DataDirLock>>,
    ) -> Result<Arc<Self>> {
        let memory = crate::wal::layout_root(data_dir, std::mem::size_of::<Self>())?;
        Self::validate_existing_format(data_dir)?;
        let marker = data_dir.join(TRANSACTION_FORMAT_MARKER);
        if !marker.exists() {
            crate::encryption::atomic_write_persistent(
                &marker,
                crate::encryption::FileType::Metadata,
                TRANSACTION_FORMAT_BYTES,
            )?;
        }
        let dir = data_dir.join(TRANSACTION_JOURNAL_DIR);
        crate::relational::disk_map::DiskMap::cleanup_interrupted(&dir)?;
        let format = validate_format(data_dir)?;
        if format.authoritative {
            crate::relational::disk_map::DiskMap::cleanup_interrupted(
                &data_dir.join(TRANSACTION_AUTHORITY_DIR),
            )?;
        }
        let (mut state, end_lsn) = if format.authoritative {
            authority::recover(&dir, format.installation_id.expect("authority identity"))?
        } else {
            checkpoint::recover(&dir, format.installation_id)?
        };
        checkpoint::publish(&dir, &mut state, end_lsn)?;
        state
            .decisions
            .as_mut()
            .expect("decision map")
            .cleanup_checkpoint_generations()?;
        let claim_installation_id = claim_installation_id(&state, data_dir)?;
        let wal = Wal::open_control_journal(&dir)?;
        Ok(Arc::new(Self {
            data_dir: data_dir.to_path_buf(),
            dir,
            inner: Mutex::new(JournalInner {
                wal,
                claim_installation_id,
                state,
                inflight_idempotency: HashMap::new(),
                claim_capacity: 0,
                claim_memory: Default::default(),
            }),
            idempotency_changed: Condvar::new(),
            _root_lease: root_lease,
            _memory: memory,
        }))
    }

    pub fn commit(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
    ) -> Result<CommittedTransaction> {
        self.commit_inner(target, mutation, audit, None, None, None)
    }

    pub(crate) fn commit_with_decision(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        decision_started: &std::sync::atomic::AtomicBool,
    ) -> Result<CommittedTransaction> {
        self.commit_inner(target, mutation, audit, None, None, Some(decision_started))
    }

    fn commit_inner(
        &self,
        target: TransactionTarget,
        mutation: WalEntry,
        audit: TransactionAudit,
        idempotency: Option<IdempotencyRecord>,
        reserved_id: Option<TransactionId>,
        decision_started: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<CommittedTransaction> {
        validate_mutation(&mutation)?;
        validate_target_mutation(&target, &mutation)?;
        let mut inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        if inner.wal.is_poisoned() {
            return Err(GaussError::WalUnavailable(
                "transaction journal requires recovery after a WAL failure".into(),
            ));
        }
        let transaction_id = reserved_id.unwrap_or_default();
        inner.state.flush_completed(&self.dir)?;
        checkpoint::maintain(&self.dir, &mut inner)?;
        if transaction_id.0.is_nil() || inner.state.prepare(transaction_id)?.is_some() {
            return Err(GaussError::InvalidRequest(
                "transaction identity is invalid or already consumed".into(),
            ));
        }
        let commit_sequence =
            inner.state.next_sequence.checked_add(1).ok_or_else(|| {
                GaussError::ResourceExhausted("commit sequence overflow".to_string())
            })?;
        let prepare = TransactionPrepare {
            version: if idempotency.is_some() {
                IDEMPOTENT_JOURNAL_VERSION
            } else {
                journal_version(&inner.state)
            },
            transaction_id,
            commit_sequence,
            target,
            mutation: Box::new(mutation),
            audit,
            idempotency,
        };
        let prepare_lsn = inner.wal.len()?;
        let prepared_record = Wal::prepare_transaction_record(prepare_lsn, &prepare)?;
        drop(prepare);
        let (owned, payload) = prepared_record.into_parts();
        let prepare = PreparedTransaction::new(owned.try_map(|record| {
            let WalEntry::TransactionPrepare { prepare } = record.entry else {
                unreachable!("preflight PREPARE")
            };
            Ok(prepare)
        })?);
        inner.state.reserve_prepare_metadata(&prepare)?;
        let reference = PreparedRef::new(
            &prepare,
            prepare_lsn,
            Some(prepare.clone()),
            inner.state.authoritative,
        )?;
        inner.state.active_publications += 1;
        inner.state.visibility_revision = inner.state.visibility_revision.wrapping_add(1);
        let result = (|| {
            crate::failpoint::check("transaction.before_prepare")?;
            if prepare.idempotency.is_some() {
                self.ensure_idempotency_format(&mut inner)?;
            }
            if let Some(started) = decision_started {
                // PREPARE body/recovery DTO and journal metadata have all been
                // admitted. From key consumption / first PREPARE write onward
                // a failure requires reconciliation rather than a blind retry.
                started.store(true, std::sync::atomic::Ordering::Release);
            }
            // Consume the claim before an ambiguous PREPARE write. Recovery
            // reconstructs consumption from PREPARE even without COMMIT.
            idempotency::register(&mut inner.state, &prepare)?;
            inner.state.prepares.insert(transaction_id, reference);
            inner.state.next_sequence = commit_sequence;
            inner
                .wal
                .append_prepared_transaction(prepare_lsn, &payload)?;
            crate::failpoint::check("transaction.after_prepare")?;
            let commit = TransactionCommit {
                version: prepare.version,
                transaction_id,
                commit_sequence,
            };
            crate::failpoint::check("transaction.before_commit")?;
            let decision = inner
                .wal
                .append_no_sync(&WalEntry::TransactionCommit { commit })
                .and_then(|_| crate::failpoint::check("transaction.before_commit_fsync"))
                .and_then(|_| inner.wal.sync());
            if decision.is_err() {
                inner.state.unknown.insert(transaction_id);
                return Err(GaussError::CommitOutcomeUnknown {
                    transaction_id: transaction_id.to_string(),
                });
            }
            inner.state.commits.insert(transaction_id);
            inner.state.committed_count += 1;
            inner.state.max_committed_sequence = commit_sequence;
            inner.state.pending_storage += 1;
            inner.state.pending_audit += 1;
            inner.state.unknown.remove(&transaction_id);
            // COMMIT is already durable and reflected in the in-memory decision
            // table. An injected ordinary error at this boundary must not turn an
            // acknowledged commit into a rejected result. The `exit` failpoint
            // action still terminates the process and exercises restart recovery.
            let _ = crate::failpoint::check("transaction.after_commit");
            Ok(CommittedTransaction {
                prepare,
                storage_projected: false,
                audit_projected: false,
            })
        })();
        if result.is_err() {
            inner.state.active_publications = inner.state.active_publications.saturating_sub(1);
            inner.state.visibility_revision = inner.state.visibility_revision.wrapping_add(1);
        }
        result
    }

    pub fn mark_projected(
        &self,
        transaction_id: TransactionId,
        kind: ProjectionKind,
    ) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        let status = inner.state.checked_status(transaction_id)?;
        if match kind {
            ProjectionKind::Storage => status.storage_projected,
            ProjectionKind::Audit => status.audit_projected,
        } {
            return Ok(());
        }
        if !inner.state.commits.contains(&transaction_id) {
            return Err(GaussError::InvalidRequest(format!(
                "cannot project uncommitted transaction {transaction_id}"
            )));
        }
        let pending = match kind {
            ProjectionKind::Storage => inner.state.pending_storage,
            ProjectionKind::Audit => inner.state.pending_audit,
        };
        if pending == 0 {
            return Err(GaussError::WalCorruption {
                path: self.dir.display().to_string(),
                message: "journal projection counter underflow".into(),
            });
        }
        let version = journal_version(&inner.state);
        inner.wal.append(&WalEntry::TransactionProjection {
            projection: TransactionProjection {
                version,
                transaction_id,
                kind,
            },
        })?;
        inner.state.projections.insert((transaction_id, kind));
        match kind {
            ProjectionKind::Storage => inner.state.pending_storage -= 1,
            ProjectionKind::Audit => inner.state.pending_audit -= 1,
        }
        if inner
            .state
            .projections
            .contains(&(transaction_id, ProjectionKind::Storage))
            && inner
                .state
                .projections
                .contains(&(transaction_id, ProjectionKind::Audit))
            && let Some(prepare) = inner.state.prepares.get_mut(&transaction_id)
        {
            prepare.hot = None;
            inner.state.completed.push(transaction_id);
        }
        if kind == ProjectionKind::Storage {
            inner.state.active_publications = inner.state.active_publications.saturating_sub(1);
            inner.state.visibility_revision = inner.state.visibility_revision.wrapping_add(1);
        }
        Ok(())
    }

    pub fn status(&self, transaction_id: TransactionId) -> TransactionStatus {
        let Ok(inner) = self.inner.lock() else {
            return TransactionStatus {
                transaction_id,
                state: TransactionState::OutcomeUnknown,
                commit_sequence: None,
                storage_projected: false,
                audit_projected: false,
            };
        };
        status_from_state(&inner.state, transaction_id)
    }

    /// Return a status only when the durable PREPARE belongs to the exact
    /// protected principal and tenant. A missing or foreign transaction is
    /// deliberately indistinguishable to callers.
    pub fn status_for_owner(
        &self,
        transaction_id: TransactionId,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<TransactionStatus>> {
        let inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        let Some(prepare) = inner.state.prepare(transaction_id)? else {
            return Ok(None);
        };
        if prepare.principal_id != principal_id || prepare.tenant_id.as_deref() != Some(tenant_id) {
            return Ok(None);
        }
        Ok(Some(inner.state.checked_status(transaction_id)?))
    }

    /// A projection is derived data: its ID, target and exact SQL batch must
    /// still belong to a committed installation-journal PREPARE. Historical
    /// decisions use the disk cache; only one PREPARE is loaded at a time.
    pub(crate) fn validate_relational_projection(
        &self,
        id: TransactionId,
        batch: &crate::relational::RelationalBatch,
    ) -> Result<()> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        if inner.state.checked_status(id)?.state != TransactionState::Committed {
            return Err(GaussError::WalCorruption {
                path: self.dir.display().to_string(),
                message: format!("relational projection {id} has no committed decision"),
            });
        }
        let reference = inner
            .state
            .prepare(id)?
            .ok_or_else(|| GaussError::WalCorruption {
                path: self.dir.display().to_string(),
                message: format!("relational projection {id} lost its PREPARE"),
            })?;
        if inner.state.authoritative
            && reference.hot.is_none()
            && inner.state.checked_status(id)?.storage_projected
            && inner.state.checked_status(id)?.audit_projected
        {
            return reference
                .relational_proof
                .as_ref()
                .ok_or_else(|| GaussError::WalCorruption {
                    path: self.dir.display().to_string(),
                    message: "relational projection has no durable proof".into(),
                })?
                .validate(batch);
        }
        if let Some(prepare) = reference.hot.as_deref() {
            crate::relational::validate_relational_prepare(prepare, batch)
        } else {
            Wal::inspect_at(&self.dir, reference.lsn, |record| {
                let WalEntry::TransactionPrepare { prepare } = &record.entry else {
                    return Err(GaussError::WalCorruption {
                        path: self.dir.display().to_string(),
                        message: format!("transaction {id} location is not a PREPARE"),
                    });
                };
                if prepare.transaction_id != id
                    || prepare.commit_sequence != reference.commit_sequence
                {
                    return Err(GaussError::WalCorruption {
                        path: self.dir.display().to_string(),
                        message: format!("transaction {id} PREPARE identity changed"),
                    });
                }
                crate::relational::validate_relational_prepare(prepare, batch)
            })
        }
    }

    pub fn committed(&self) -> Result<CommittedTransactions> {
        let mut transactions = CommittedTransactions::default();
        self.for_each_committed(|transaction| transactions.push(transaction))?;
        Ok(transactions)
    }

    /// Stream committed PREPAREs in sequence order using a pinned decision-index
    /// snapshot and direct WAL reads, without retaining historical mutations.
    /// The callback runs outside the journal lock and may repair projections.
    pub fn for_each_committed(
        &self,
        visitor: impl FnMut(CommittedTransaction) -> Result<()>,
    ) -> Result<()> {
        scan::for_each_committed(self, visitor)
    }

    /// Inspect compact committed decisions, reading original bodies only for
    /// selected repairs. Legacy decisions without a descriptor retain their
    /// original PREPARE validation. Callbacks run outside the journal lock.
    pub(crate) fn for_each_recovery(
        &self,
        select: impl FnMut(&RecoveryDecision<'_>) -> Result<bool>,
        visitor: impl FnMut(CommittedTransaction) -> Result<()>,
    ) -> Result<()> {
        scan::for_each_recovery(self, select, visitor)
    }

    pub(crate) fn for_each_recovery_after(
        &self,
        frontier: u64,
        select: impl FnMut(&RecoveryDecision<'_>) -> Result<bool>,
        visitor: impl FnMut(CommittedTransaction) -> Result<()>,
    ) -> Result<()> {
        if frontier == 0 {
            return self.for_each_recovery(select, visitor);
        }
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        if frontier > inner.state.max_committed_sequence {
            return Err(GaussError::WalUnavailable(
                "common frontier is ahead of authority".into(),
            ));
        }
        drop(inner);
        scan::for_each_recovery_after(self, frontier, select, visitor)
    }

    /// Returns a visibility frontier only when every durable commit has
    /// completed its storage projection. Readers spanning several engines use
    /// the value as a seqlock: the same frontier before and after execution
    /// proves no coordinated mutation became visible between their stages.
    pub fn stable_visibility_frontier(&self) -> Result<Option<u64>> {
        let inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        if inner.state.active_publications != 0
            || !inner.state.unknown.is_empty()
            || inner.state.pending_storage != 0
        {
            return Ok(None);
        }
        Ok(Some(
            inner.state.next_sequence ^ inner.state.visibility_revision.rotate_left(17),
        ))
    }

    /// Highest durable COMMIT sequence after every committed transaction has
    /// both storage and audit projections. Unlike the reader seqlock above,
    /// this is a monotonic journal position suitable for a backup manifest.
    /// An uncommitted PREPARE can reserve a later sequence without advancing
    /// this frontier. The caller must still freeze mutations while copying
    /// the journal and every projected store.
    pub fn completed_commit_frontier(&self) -> Result<Option<u64>> {
        let inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        if inner.state.active_publications != 0
            || !inner.state.unknown.is_empty()
            || inner.state.pending_storage != 0
            || inner.state.pending_audit != 0
        {
            return Ok(None);
        }
        Ok(Some(inner.state.max_committed_sequence))
    }

    pub(crate) fn checkpoint_completed_frontier(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        let end = inner.wal.len()?;
        checkpoint::publish(&self.dir, &mut inner.state, end)
    }

    pub(crate) fn validate_materialized_frontier(
        data: &Path,
        installation: uuid::Uuid,
        frontier: u64,
    ) -> Result<()> {
        authority::validate_materialized_frontier(data, installation, frontier)
    }

    pub(crate) fn content_root_changed(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        inner.state.visibility_revision = inner.state.visibility_revision.wrapping_add(1);
        Ok(())
    }

    /// Rebind the journal after a legacy root-directory restore swaps the
    /// filesystem object at the same installation path. Open file handles
    /// otherwise keep appending to the retired generation.
    pub(crate) fn reload_after_root_swap(&self, data_dir: &Path) -> Result<()> {
        let expected_dir = data_dir.join(TRANSACTION_JOURNAL_DIR);
        if expected_dir != self.dir {
            return Err(GaussError::WalUnavailable(format!(
                "transaction journal root changed from {} to {}",
                self.dir.display(),
                expected_dir.display()
            )));
        }
        let marker = data_dir.join(TRANSACTION_FORMAT_MARKER);
        if !marker.exists() {
            crate::encryption::atomic_write_persistent(
                &marker,
                crate::encryption::FileType::Metadata,
                TRANSACTION_FORMAT_BYTES,
            )?;
        }
        let format = validate_format(data_dir)?;
        let (mut state, _) = if format.authoritative {
            authority::recover(
                &expected_dir,
                format.installation_id.expect("authority identity"),
            )?
        } else {
            checkpoint::recover(&expected_dir, format.installation_id)?
        };
        let claim_installation_id = claim_installation_id(&state, data_dir)?;
        let wal = Wal::open_control_journal(&expected_dir)?;
        let mut inner = self.inner.lock().map_err(|_| {
            GaussError::WalUnavailable("transaction journal lock poisoned".to_string())
        })?;
        if !inner.inflight_idempotency.is_empty() {
            return Err(GaussError::ResourceExhausted(
                "cannot reload a journal with active idempotency claims".into(),
            ));
        }
        // Runtime readers must not accept an old optimistic frontier after a
        // control/content restore, including rollback of a failed activation.
        state.visibility_revision = inner.state.visibility_revision.wrapping_add(1);
        *inner = JournalInner {
            wal,
            claim_installation_id,
            state,
            inflight_idempotency: HashMap::new(),
            claim_capacity: 0,
            claim_memory: Default::default(),
        };
        Ok(())
    }

    fn ensure_idempotency_format(&self, inner: &mut JournalInner) -> Result<uuid::Uuid> {
        if let Some(id) = inner.state.installation_id {
            return Ok(id);
        }
        let marker = self.data_dir.join(TRANSACTION_FORMAT_MARKER);
        // An uncertain rename must retry with its original installation ID.
        let id = if let Some(id) = read_format(&marker)?.installation_id {
            if id != inner.claim_installation_id {
                return Err(GaussError::WalUnavailable(
                    "transaction journal installation changed".into(),
                ));
            }
            crate::fs_util::sync_directory(marker.parent().expect("journal marker parent"))?;
            id
        } else {
            let protected_id =
                crate::security::onboarding::fence_transaction_reader(&self.data_dir)?;
            let id = inner.claim_installation_id;
            if protected_id.is_some_and(|expected| expected != id) {
                return Err(GaussError::WalUnavailable(
                    "transaction journal installation changed".into(),
                ));
            }
            crate::encryption::atomic_write_persistent(
                &marker,
                crate::encryption::FileType::Metadata,
                format!("CHIRONTXN2\n{id}\n").as_bytes(),
            )?;
            id
        };
        inner.state.installation_id = Some(id);
        Ok(id)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn audit_checkpoint_binding(&self) -> Result<Option<(uuid::Uuid, bool)>> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        let stable = inner.state.installation_id.is_some()
            || crate::security::onboarding::installation_id_for_journal(&self.data_dir)?.is_some();
        Ok(stable.then_some((inner.claim_installation_id, inner.state.authoritative)))
    }

    pub(crate) fn migrate_authority_offline(&self) -> Result<bool> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| GaussError::WalUnavailable("transaction journal lock poisoned".into()))?;
        let id = inner.claim_installation_id;
        authority::migrate(self, &mut inner, id)
    }

    pub(crate) fn has_authority_format(data_dir: &Path) -> Result<bool> {
        // Trusted private restore staging may still carry the deliberately
        // non-runnable backup installation marker. Startup uses validate_format.
        Ok(read_format(&data_dir.join(TRANSACTION_FORMAT_MARKER))?.authoritative)
    }

    #[cfg(test)]
    pub(crate) fn inject_write_failure(&self) {
        self.inner
            .lock()
            .expect("transaction journal lock")
            .wal
            .inject_write_failure();
    }

    #[cfg(test)]
    pub(crate) fn inject_sync_failure(&self) {
        self.inner
            .lock()
            .expect("transaction journal lock")
            .wal
            .inject_sync_failure();
    }
}

fn claim_installation_id(state: &JournalState, data_dir: &Path) -> Result<uuid::Uuid> {
    Ok(state
        .installation_id
        .or(crate::security::onboarding::installation_id_for_journal(
            data_dir,
        )?)
        .unwrap_or_else(uuid::Uuid::new_v4))
}

fn journal_version(state: &JournalState) -> u16 {
    if state.installation_id.is_some() {
        IDEMPOTENT_JOURNAL_VERSION
    } else {
        TRANSACTION_JOURNAL_VERSION
    }
}

fn validate_record_version(state: &JournalState, version: u16) -> Result<()> {
    validate_version(version)?;
    if version == IDEMPOTENT_JOURNAL_VERSION && state.installation_id.is_none() {
        return Err(GaussError::WalCorruption {
            path: TRANSACTION_FORMAT_MARKER.into(),
            message: "idempotent journal has no installation identity".into(),
        });
    }
    Ok(())
}

struct JournalFormat {
    installation_id: Option<uuid::Uuid>,
    authoritative: bool,
}
fn validate_format(data_dir: &Path) -> Result<JournalFormat> {
    let marker = data_dir.join(TRANSACTION_FORMAT_MARKER);
    let format = read_format(&marker)?;
    if let (Some(actual), Some(expected)) = (
        format.installation_id,
        crate::security::onboarding::installation_id_for_journal(data_dir)?,
    ) && actual != expected
    {
        return Err(GaussError::WalCorruption {
            path: marker.display().to_string(),
            message: "transaction journal belongs to another installation".into(),
        });
    }
    Ok(format)
}

fn read_format(marker: &Path) -> Result<JournalFormat> {
    let metadata = std::fs::symlink_metadata(marker)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err(GaussError::WalCorruption {
            path: marker.display().to_string(),
            message: "invalid transaction format marker".into(),
        });
    }
    let bytes = crate::encryption::read_persistent(marker)?;
    if bytes == TRANSACTION_FORMAT_BYTES {
        return Ok(JournalFormat {
            installation_id: None,
            authoritative: false,
        });
    }
    let text = std::str::from_utf8(&bytes).ok();
    let authoritative = text.is_some_and(|text| text.starts_with("CHIRONTXN3\n"));
    let id = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|value| {
            value.strip_prefix(if authoritative {
                "CHIRONTXN3\n"
            } else {
                "CHIRONTXN2\n"
            })
        })
        .and_then(|value| value.strip_suffix('\n'))
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .filter(|id| !id.is_nil())
        .ok_or_else(|| GaussError::WalCorruption {
            path: marker.display().to_string(),
            message: "unsupported transaction format marker".into(),
        })?;
    Ok(JournalFormat {
        installation_id: Some(id),
        authoritative,
    })
}

fn validate_mutation(entry: &WalEntry) -> Result<()> {
    match entry {
        WalEntry::TransactionPrepare { .. }
        | WalEntry::TransactionCommit { .. }
        | WalEntry::TransactionProjection { .. }
        | WalEntry::TransactionApply { .. } => Err(GaussError::InvalidRequest(
            "nested transaction journal record".to_string(),
        )),
        _ => Ok(()),
    }
}

fn validate_target_mutation(target: &TransactionTarget, entry: &WalEntry) -> Result<()> {
    match (target, entry) {
        (TransactionTarget::MultiModel { collections }, WalEntry::MultiModelBatch { batch }) => {
            batch.validate()?;
            let projected = batch
                .collections
                .iter()
                .map(|projection| projection.collection.as_str())
                .collect::<Vec<_>>();
            let declared = collections.iter().map(String::as_str).collect::<Vec<_>>();
            if declared != projected {
                return Err(GaussError::InvalidRequest(
                    "multi-model transaction target does not match its collection projections"
                        .to_string(),
                ));
            }
            Ok(())
        }
        (TransactionTarget::MultiModel { .. }, _) => Err(GaussError::InvalidRequest(
            "multi-model transaction target requires a multi-model batch".to_string(),
        )),
        (_, WalEntry::MultiModelBatch { .. }) => Err(GaussError::InvalidRequest(
            "multi-model batch requires a multi-model transaction target".to_string(),
        )),
        _ => Ok(()),
    }
}

fn validate_version(version: u16) -> Result<()> {
    if !matches!(
        version,
        TRANSACTION_JOURNAL_VERSION | IDEMPOTENT_JOURNAL_VERSION
    ) {
        return Err(GaussError::WalCorruption {
            path: TRANSACTION_JOURNAL_DIR.to_string(),
            message: format!(
                "unsupported transaction journal version {version}; expected {TRANSACTION_JOURNAL_VERSION}"
            ),
        });
    }
    Ok(())
}

fn apply_record(state: &mut JournalState, lsn: u64, entry: WalEntry) -> Result<()> {
    match entry {
        WalEntry::TransactionPrepare { prepare } => {
            validate_record_version(state, prepare.version)?;
            if state.prepare(prepare.transaction_id)?.is_some() {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.into(),
                    message: "duplicate transaction PREPARE".into(),
                });
            }
            if prepare.commit_sequence <= state.next_sequence {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.to_string(),
                    message: "non-monotonic transaction PREPARE sequence".to_string(),
                });
            }
            validate_mutation(&prepare.mutation)?;
            validate_target_mutation(&prepare.target, &prepare.mutation)?;
            state.reserve_prepare_metadata(&prepare)?;
            idempotency::register(state, &prepare)?;
            state.next_sequence = prepare.commit_sequence;
            if state
                .prepares
                .insert(
                    prepare.transaction_id,
                    PreparedRef::new(&prepare, lsn, None, state.authoritative)?,
                )
                .is_some()
            {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.to_string(),
                    message: "duplicate transaction PREPARE".to_string(),
                });
            }
        }
        WalEntry::TransactionCommit { commit } => {
            validate_record_version(state, commit.version)?;
            let Some(prepare) = state.prepares.get(&commit.transaction_id) else {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.to_string(),
                    message: "COMMIT without PREPARE".to_string(),
                });
            };
            if prepare.commit_sequence != commit.commit_sequence
                || !state.commits.insert(commit.transaction_id)
            {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.to_string(),
                    message: "duplicate or mismatched transaction COMMIT".to_string(),
                });
            }
            state.max_committed_sequence = state.max_committed_sequence.max(commit.commit_sequence);
            state.committed_count += 1;
            state.pending_storage += 1;
            state.pending_audit += 1;
        }
        WalEntry::TransactionProjection { projection } => {
            validate_record_version(state, projection.version)?;
            let pending = match projection.kind {
                ProjectionKind::Storage => state.pending_storage,
                ProjectionKind::Audit => state.pending_audit,
            };
            if pending == 0
                || !state.commits.contains(&projection.transaction_id)
                || !state
                    .projections
                    .insert((projection.transaction_id, projection.kind))
            {
                return Err(GaussError::WalCorruption {
                    path: TRANSACTION_JOURNAL_DIR.to_string(),
                    message: "duplicate projection or projection before COMMIT".to_string(),
                });
            }
            match projection.kind {
                ProjectionKind::Storage => state.pending_storage -= 1,
                ProjectionKind::Audit => state.pending_audit -= 1,
            }
            if state
                .projections
                .contains(&(projection.transaction_id, ProjectionKind::Storage))
                && state
                    .projections
                    .contains(&(projection.transaction_id, ProjectionKind::Audit))
            {
                state.completed.push(projection.transaction_id);
            }
        }
        _ => {
            return Err(GaussError::WalCorruption {
                path: TRANSACTION_JOURNAL_DIR.to_string(),
                message: "non-transaction record in transaction journal".to_string(),
            });
        }
    }
    Ok(())
}

fn status_from_state(state: &JournalState, transaction_id: TransactionId) -> TransactionStatus {
    state
        .checked_status(transaction_id)
        .unwrap_or(TransactionStatus {
            transaction_id,
            state: TransactionState::OutcomeUnknown,
            commit_sequence: None,
            storage_projected: false,
            audit_projected: false,
        })
}

fn hot_status(state: &JournalState, transaction_id: TransactionId) -> TransactionStatus {
    let prepare = state.prepares.get(&transaction_id);
    let status = if state.commits.contains(&transaction_id) {
        TransactionState::Committed
    } else if state.unknown.contains(&transaction_id) {
        TransactionState::OutcomeUnknown
    } else if prepare.is_some() {
        TransactionState::Rejected
    } else {
        TransactionState::Expired
    };
    TransactionStatus {
        transaction_id,
        state: status,
        commit_sequence: prepare.map(|prepare| prepare.commit_sequence),
        storage_projected: state
            .projections
            .contains(&(transaction_id, ProjectionKind::Storage)),
        audit_projected: state
            .projections
            .contains(&(transaction_id, ProjectionKind::Audit)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::Point,
        relational::{RelationalBatch, RelationalMutation},
        wal::{GraphBatch, MULTI_MODEL_BATCH_VERSION, MultiModelBatch, MultiModelCollectionBatch},
    };

    fn audit() -> TransactionAudit {
        TransactionAudit::mutation(
            "upsert",
            Some("docs"),
            &AuditContext::embedded(),
            serde_json::json!({"requested_points": 1}),
        )
    }

    #[test]
    fn historical_relational_projection_proofs_leave_live_id_maps_and_reload_exact_prepares() {
        let directory = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(directory.path()).unwrap();
        let mut first = None;
        // Completed entries flush before the next commit, so entry 513
        // moves the first 512 decisions out of the live ID maps.
        for sequence in 1..=513 {
            let batch = crate::relational::RelationalBatch {
                sequence,
                mutations: Vec::new(),
            };
            let transaction = journal
                .commit(
                    TransactionTarget::Relational,
                    WalEntry::RelationalBatch { batch },
                    audit(),
                )
                .unwrap();
            let id = transaction.prepare.transaction_id;
            first.get_or_insert(id);
            journal.mark_projected(id, ProjectionKind::Storage).unwrap();
            journal.mark_projected(id, ProjectionKind::Audit).unwrap();
        }
        let id = first.unwrap();
        assert!(
            !journal
                .inner
                .lock()
                .unwrap()
                .state
                .prepares
                .contains_key(&id)
        );
        journal
            .validate_relational_projection(
                id,
                &crate::relational::RelationalBatch {
                    sequence: 1,
                    mutations: Vec::new(),
                },
            )
            .unwrap();
        assert!(matches!(
            journal.validate_relational_projection(
                id,
                &crate::relational::RelationalBatch {
                    sequence: 2,
                    mutations: Vec::new()
                }
            ),
            Err(GaussError::WalCorruption { .. })
        ));
        drop(journal);
        let journal = TransactionJournal::open(directory.path()).unwrap();
        assert!(
            !journal
                .inner
                .lock()
                .unwrap()
                .state
                .prepares
                .contains_key(&id)
        );
        journal
            .validate_relational_projection(
                id,
                &crate::relational::RelationalBatch {
                    sequence: 1,
                    mutations: Vec::new(),
                },
            )
            .unwrap();
    }

    #[test]
    fn committed_status_survives_reopen() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let committed = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::UpsertBatch {
                    points: vec![Point {
                        id: "one".into(),
                        vector: vec![1.0, 0.0],
                        vectors: Default::default(),
                        sparse_vector: None,
                        payload: Value::Null,
                    }],
                },
                audit(),
            )
            .unwrap();
        journal
            .mark_projected(committed.prepare.transaction_id, ProjectionKind::Storage)
            .unwrap();
        let transaction_id = committed.prepare.transaction_id;
        drop(journal);

        let reopened = TransactionJournal::open(root.path()).unwrap();
        let status = reopened.status(transaction_id);
        assert_eq!(status.state, TransactionState::Committed);
        assert!(status.storage_projected);
        assert!(!status.audit_projected);
    }

    #[test]
    fn visiting_commits_keeps_order_and_allows_projection_repair() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let mut expected = Vec::new();
        for index in 0..3 {
            let committed = journal
                .commit(
                    TransactionTarget::Collection {
                        name: "docs".into(),
                    },
                    WalEntry::DeleteBatch {
                        ids: vec![format!("row-{index}")],
                    },
                    audit(),
                )
                .unwrap();
            expected.push(committed.prepare.transaction_id);
        }
        drop(journal);

        let reopened = TransactionJournal::open(root.path()).unwrap();
        let mut visited = Vec::new();
        reopened
            .for_each_committed(|transaction| {
                assert!(!transaction.storage_projected);
                visited.push(transaction.prepare.transaction_id);
                reopened.mark_projected(transaction.prepare.transaction_id, ProjectionKind::Storage)
            })
            .unwrap();
        assert_eq!(visited, expected);

        let mut repaired = Vec::new();
        reopened
            .for_each_committed(|transaction| {
                assert!(transaction.storage_projected);
                repaired.push(transaction.prepare.transaction_id);
                Ok(())
            })
            .unwrap();
        assert_eq!(repaired, expected);
    }

    #[test]
    fn committed_visit_excludes_a_later_append_without_copying_the_commit_set() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let first = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["first".into()],
                },
                audit(),
            )
            .unwrap()
            .prepare
            .transaction_id;
        let mut visited = Vec::new();
        let mut later = None;
        journal
            .for_each_committed(|transaction| {
                visited.push(transaction.prepare.transaction_id);
                later = Some(
                    journal
                        .commit(
                            TransactionTarget::Collection {
                                name: "docs".into(),
                            },
                            WalEntry::DeleteBatch {
                                ids: vec!["later".into()],
                            },
                            audit(),
                        )?
                        .prepare
                        .transaction_id,
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, vec![first]);
        let later = later.unwrap();
        visited.clear();
        journal
            .for_each_committed(|transaction| {
                visited.push(transaction.prepare.transaction_id);
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, vec![first, later]);
    }

    #[test]
    fn completed_decision_releases_hot_mutation_and_reloads_receipt() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let context = AuditContext::embedded();
        let request = serde_json::json!({"delete": "one"});
        let IdempotencyAdmission::Execute(guard) = journal
            .begin_idempotent("delete-one", &context, "delete", &request, || Ok(()))
            .unwrap()
        else {
            panic!("first request must execute")
        };
        let receipt = serde_json::json!({"deleted": 1});
        let committed = guard
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                audit(),
                receipt.clone(),
            )
            .unwrap();
        let id = committed.prepare.transaction_id;
        journal.mark_projected(id, ProjectionKind::Storage).unwrap();
        journal.mark_projected(id, ProjectionKind::Audit).unwrap();
        assert!(
            journal
                .inner
                .lock()
                .unwrap()
                .state
                .prepares
                .get(&id)
                .unwrap()
                .hot
                .is_none()
        );
        drop(guard);
        let IdempotencyAdmission::Replay(replayed) = journal
            .begin_idempotent("delete-one", &context, "delete", &request, || Ok(()))
            .unwrap()
        else {
            panic!("consumed request must replay")
        };
        assert_eq!(replayed.status.transaction_id, id);
        assert_eq!(replayed.response, Some(receipt.clone()));
        drop(journal);
        let reopened = TransactionJournal::open(root.path()).unwrap();
        let IdempotencyAdmission::Replay(replayed) = reopened
            .begin_idempotent("delete-one", &context, "delete", &request, || Ok(()))
            .unwrap()
        else {
            panic!("reopened request must replay")
        };
        assert_eq!(replayed.status.transaction_id, id);
        assert_eq!(replayed.response, Some(receipt));
    }

    #[test]
    fn protected_status_is_visible_only_to_its_exact_owner() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let owned_audit = TransactionAudit::mutation(
            "delete",
            Some("docs"),
            &AuditContext {
                principal_id: "alice".into(),
                tenant_id: Some("acme".into()),
                transport: "protected-test".into(),
                request_id: None,
            },
            serde_json::json!({"requested_points": 1}),
        );
        let committed = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                owned_audit,
            )
            .unwrap();
        let transaction_id = committed.prepare.transaction_id;
        assert_eq!(
            journal
                .status_for_owner(transaction_id, "alice", "acme")
                .unwrap()
                .unwrap()
                .state,
            TransactionState::Committed
        );
        assert!(
            journal
                .status_for_owner(transaction_id, "bob", "acme")
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .status_for_owner(transaction_id, "alice", "other")
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .status_for_owner(TransactionId::new(), "alice", "acme")
                .unwrap()
                .is_none()
        );

        drop(journal);
        let reopened = TransactionJournal::open(root.path()).unwrap();
        assert!(
            reopened
                .status_for_owner(transaction_id, "alice", "acme")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn visibility_frontier_is_stable_only_after_storage_publication() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let before = journal
            .stable_visibility_frontier()
            .unwrap()
            .expect("fresh journal is readable");
        let committed = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                audit(),
            )
            .unwrap();

        assert_eq!(journal.stable_visibility_frontier().unwrap(), None);
        journal
            .mark_projected(committed.prepare.transaction_id, ProjectionKind::Storage)
            .unwrap();
        let after = journal
            .stable_visibility_frontier()
            .unwrap()
            .expect("publication reopens reads");
        assert_ne!(before, after);
    }

    #[test]
    fn backup_frontier_requires_both_projections_and_ignores_uncommitted_prepare() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        assert_eq!(journal.completed_commit_frontier().unwrap(), Some(0));
        let first = journal
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                audit(),
            )
            .unwrap();
        assert_eq!(first.prepare.commit_sequence, 1);
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
        journal
            .mark_projected(first.prepare.transaction_id, ProjectionKind::Storage)
            .unwrap();
        // Storage publication alone is enough for readers, but not backup.
        assert!(journal.stable_visibility_frontier().unwrap().is_some());
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
        drop(journal);

        let journal = TransactionJournal::open(root.path()).unwrap();
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
        journal
            .mark_projected(first.prepare.transaction_id, ProjectionKind::Audit)
            .unwrap();
        assert_eq!(journal.completed_commit_frontier().unwrap(), Some(1));
        drop(journal);

        // A crash after PREPARE consumes sequence 2, but it never committed.
        let dir = root.path().join(TRANSACTION_JOURNAL_DIR);
        let mut wal = Wal::open(&dir).unwrap();
        let pending = TransactionId::new();
        wal.append(&WalEntry::TransactionPrepare {
            prepare: TransactionPrepare {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id: pending,
                commit_sequence: 2,
                target: TransactionTarget::Collection {
                    name: "docs".into(),
                },
                mutation: Box::new(WalEntry::DeleteBatch {
                    ids: vec!["pending".into()],
                }),
                audit: audit(),
                idempotency: None,
            },
        })
        .unwrap();
        drop(wal);
        let reopened = TransactionJournal::open(root.path()).unwrap();
        assert_eq!(reopened.status(pending).state, TransactionState::Rejected);
        assert_eq!(reopened.completed_commit_frontier().unwrap(), Some(1));
        let second = reopened
            .commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["two".into()],
                },
                audit(),
            )
            .unwrap();
        assert_eq!(second.prepare.commit_sequence, 3);
        assert_eq!(reopened.completed_commit_frontier().unwrap(), None);
        reopened
            .mark_projected(second.prepare.transaction_id, ProjectionKind::Storage)
            .unwrap();
        reopened
            .mark_projected(second.prepare.transaction_id, ProjectionKind::Audit)
            .unwrap();
        assert_eq!(reopened.completed_commit_frontier().unwrap(), Some(3));
    }

    #[test]
    fn projection_counters_survive_interleaved_recovery_and_duplicate_marks() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let mut ids = Vec::new();
        for index in 0..3 {
            let committed = journal
                .commit(
                    TransactionTarget::Collection {
                        name: "docs".into(),
                    },
                    WalEntry::DeleteBatch {
                        ids: vec![format!("row-{index}")],
                    },
                    audit(),
                )
                .unwrap();
            ids.push(committed.prepare.transaction_id);
        }
        journal
            .mark_projected(ids[0], ProjectionKind::Storage)
            .unwrap();
        journal
            .mark_projected(ids[2], ProjectionKind::Audit)
            .unwrap();
        assert_eq!(journal.stable_visibility_frontier().unwrap(), None);
        journal
            .mark_projected(ids[1], ProjectionKind::Storage)
            .unwrap();
        journal
            .mark_projected(ids[2], ProjectionKind::Storage)
            .unwrap();
        assert!(journal.stable_visibility_frontier().unwrap().is_some());
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
        drop(journal);

        let reopened = TransactionJournal::open(root.path()).unwrap();
        {
            let inner = reopened.inner.lock().unwrap();
            assert_eq!(inner.state.pending_storage, 0);
            assert_eq!(inner.state.pending_audit, 2);
            assert_eq!(inner.state.max_committed_sequence, 3);
        }
        reopened
            .mark_projected(ids[0], ProjectionKind::Storage)
            .unwrap();
        reopened
            .mark_projected(ids[2], ProjectionKind::Audit)
            .unwrap();
        assert_eq!(reopened.completed_commit_frontier().unwrap(), None);
        reopened
            .mark_projected(ids[1], ProjectionKind::Audit)
            .unwrap();
        reopened
            .mark_projected(ids[0], ProjectionKind::Audit)
            .unwrap();
        assert_eq!(reopened.completed_commit_frontier().unwrap(), Some(3));
    }

    #[test]
    fn replay_rejects_duplicate_prepare_sequence_before_backup_frontier_can_be_used() {
        let root = tempfile::tempdir().unwrap();
        drop(TransactionJournal::open(root.path()).unwrap());
        let dir = root.path().join(TRANSACTION_JOURNAL_DIR);
        let mut wal = Wal::open(&dir).unwrap();
        for id in [TransactionId::new(), TransactionId::new()] {
            wal.append(&WalEntry::TransactionPrepare {
                prepare: TransactionPrepare {
                    version: TRANSACTION_JOURNAL_VERSION,
                    transaction_id: id,
                    commit_sequence: 1,
                    target: TransactionTarget::Collection {
                        name: "docs".into(),
                    },
                    mutation: Box::new(WalEntry::DeleteBatch {
                        ids: vec!["one".into()],
                    }),
                    audit: audit(),
                    idempotency: None,
                },
            })
            .unwrap();
        }
        drop(wal);
        assert!(matches!(
            TransactionJournal::open(root.path()),
            Err(GaussError::WalCorruption { message, .. })
                if message == "non-monotonic transaction PREPARE sequence"
        ));
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn backup_frontier_refuses_an_uncertain_commit_decision() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let _failpoint = crate::failpoint::test_env(
            "error:transaction.before_commit_fsync",
            &root.path().join("unused-marker"),
            &root.path().join("unused-release"),
        );
        assert!(matches!(
            journal.commit(
                TransactionTarget::Collection {
                    name: "docs".into(),
                },
                WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                },
                audit(),
            ),
            Err(GaussError::CommitOutcomeUnknown { .. })
        ));
        assert_eq!(journal.completed_commit_frontier().unwrap(), None);
    }

    #[test]
    fn prepare_without_commit_is_rejected_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        drop(TransactionJournal::open(root.path()).unwrap());
        let dir = root.path().join(TRANSACTION_JOURNAL_DIR);
        let mut wal = Wal::open(&dir).unwrap();
        let transaction_id = TransactionId::new();
        wal.append(&WalEntry::TransactionPrepare {
            prepare: TransactionPrepare {
                version: TRANSACTION_JOURNAL_VERSION,
                transaction_id,
                commit_sequence: 1,
                target: TransactionTarget::Collection {
                    name: "docs".into(),
                },
                mutation: Box::new(WalEntry::DeleteBatch {
                    ids: vec!["one".into()],
                }),
                audit: audit(),
                idempotency: None,
            },
        })
        .unwrap();
        drop(wal);

        let reopened = TransactionJournal::open(root.path()).unwrap();
        assert_eq!(
            reopened.status(transaction_id).state,
            TransactionState::Rejected
        );
        assert!(reopened.committed().unwrap().is_empty());
    }

    #[test]
    fn multi_model_target_and_write_set_are_bound_and_recoverable() {
        let root = tempfile::tempdir().unwrap();
        let journal = TransactionJournal::open(root.path()).unwrap();
        let collection_batch = GraphBatch {
            point_mutations: vec![crate::wal::GraphPointMutation::Upsert {
                point: Point {
                    id: "chunk-1".into(),
                    vector: vec![1.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: Value::Null,
                },
            }],
            ..GraphBatch::default()
        };
        let mutation = WalEntry::MultiModelBatch {
            batch: MultiModelBatch {
                version: MULTI_MODEL_BATCH_VERSION,
                relational: RelationalBatch {
                    sequence: 1,
                    mutations: vec![RelationalMutation::DropTable {
                        name: "documents".into(),
                    }],
                },
                collections: vec![MultiModelCollectionBatch {
                    collection: "chunks".into(),
                    batch: collection_batch,
                    security: None,
                }],
            },
        };
        let mismatch = journal
            .commit(
                TransactionTarget::MultiModel {
                    collections: vec!["other".into()],
                },
                mutation.clone(),
                audit(),
            )
            .unwrap_err();
        assert!(
            mismatch.to_string().contains("does not match"),
            "unexpected mismatch error: {mismatch}"
        );

        let committed = journal
            .commit(
                TransactionTarget::MultiModel {
                    collections: vec!["chunks".into()],
                },
                mutation,
                audit(),
            )
            .unwrap();
        let transaction_id = committed.prepare.transaction_id;
        drop(journal);

        let reopened = TransactionJournal::open(root.path()).unwrap();
        let recovered = reopened.committed().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].prepare.transaction_id, transaction_id);
        assert!(matches!(
            recovered[0].prepare.mutation.as_ref(),
            WalEntry::MultiModelBatch { .. }
        ));
        assert_eq!(
            reopened.status(transaction_id).state,
            TransactionState::Committed
        );
        assert_eq!(reopened.stable_visibility_frontier().unwrap(), None);
    }
}
