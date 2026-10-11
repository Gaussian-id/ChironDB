use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    GaussError, Result,
    encryption::{self, FileType},
    fs_util::sync_directory,
};

pub(crate) mod binding;
mod checkpoint;
mod reader;
mod registry;

pub const AUDIT_LOG_FILE: &str = "audit/audit.jsonl";
const ENCRYPTED_AUDIT_PREFIX: &str = "CHIRENC1:";
const AUDIT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const AUDIT_QUEUE_CAPACITY: usize = 8192;
const AUDIT_GROUP_COMMIT_MAX: usize = 128;
const AUDIT_GROUP_COMMIT_DELAY: Duration = Duration::from_millis(1);

static AUDIT_APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    schema_version: u8,
    sequence: u64,
    event_id: String,
    timestamp_unix_ms: u128,
    category: &'a str,
    operation: &'a str,
    operation_id: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<&'a str>,
    principal_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<&'a str>,
    transport: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'a str>,
    prev_record_hash: &'a str,
    details: binding::Sanitized<'a>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditContext {
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub transport: String,
    pub request_id: Option<String>,
}

pub struct AuditEvent<'a> {
    pub category: &'a str,
    pub operation: &'a str,
    pub outcome: &'a str,
    pub collection: Option<&'a str>,
    pub context: &'a AuditContext,
    pub error_code: Option<&'a str>,
    pub details: Value,
    pub durable: bool,
}

impl AuditContext {
    pub fn embedded() -> Self {
        Self {
            principal_id: "embedded-system".to_string(),
            tenant_id: None,
            transport: "embedded".to_string(),
            request_id: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuditIntent {
    category: String,
    operation_id: String,
    operation: String,
    collection: Option<String>,
    context: AuditContext,
}

#[derive(Debug)]
pub struct AuditOperation {
    writer: Arc<AuditWriter>,
    intent: Option<AuditIntent>,
    _slot: AuditSlot,
}

#[derive(Debug)]
struct AuditSlot {
    pending: Arc<AtomicUsize>,
}

impl Drop for AuditSlot {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::Release);
    }
}

impl AuditOperation {
    pub fn success(mut self, details: Value) -> Result<()> {
        let intent = self
            .intent
            .as_ref()
            .ok_or_else(|| invalid("audit operation is already complete"))?;
        self.writer
            .finish(intent, "success", None, details)
            .map_err(audit_unavailable)?;
        self.intent = None;
        Ok(())
    }

    pub fn failure(self, error_code: &str) -> Result<()> {
        self.failure_with_details(error_code, Value::Null)
    }

    pub fn failure_with_details(mut self, error_code: &str, details: Value) -> Result<()> {
        let intent = self
            .intent
            .as_ref()
            .ok_or_else(|| invalid("audit operation is already complete"))?;
        self.writer
            .finish(intent, "failure", Some(error_code), details)
            .map_err(audit_unavailable)?;
        self.intent = None;
        Ok(())
    }
}

impl Drop for AuditOperation {
    fn drop(&mut self) {
        let Some(intent) = self.intent.take() else {
            return;
        };
        if let Err(error) =
            self.writer
                .finish(&intent, "failure", Some("operation_aborted"), Value::Null)
        {
            tracing::error!(%error, operation = %intent.operation, "audit outcome write failed");
        }
    }
}

#[derive(Debug)]
pub struct AuditWriter {
    state: Arc<Mutex<WriterState>>,
    commit: Arc<Condvar>,
    pending: Arc<AtomicUsize>,
    group_committer: GroupCommitter,
    closed: AtomicBool,
    // Last: registry files and their temporary owners drop before the root lease.
    journal: Option<Arc<crate::transaction_journal::TransactionJournal>>,
}

#[derive(Debug, Default)]
struct GroupCommitSignal {
    pending: bool,
    closed: bool,
}

#[derive(Debug)]
struct GroupCommitter {
    signal: Arc<(Mutex<GroupCommitSignal>, Condvar)>,
    handle: Mutex<Option<JoinHandle<()>>>,
    #[cfg_attr(not(test), allow(dead_code, reason = "test-only idle wake assertion"))]
    wakeups: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct WriterState {
    file: File,
    path: PathBuf,
    sequence: u64,
    previous_hash: String,
    durable_sequence: u64,
    group_pending: usize,
    group_started: Option<Instant>,
    writer_error: Option<String>,
    registry: registry::Registry,
}

impl AuditWriter {
    pub fn open(root: impl AsRef<Path>) -> Result<Arc<Self>> {
        Self::open_inner(root.as_ref(), None)
    }

    pub(crate) fn open_with_journal(
        root: &Path,
        journal: Arc<crate::transaction_journal::TransactionJournal>,
    ) -> Result<Arc<Self>> {
        Self::open_inner(root, Some(journal))
    }

    fn open_inner(
        root: &Path,
        journal: Option<Arc<crate::transaction_journal::TransactionJournal>>,
    ) -> Result<Arc<Self>> {
        if journal.is_some() {
            // The journal retains the exclusive installation lease. Standalone
            // public audit writers never delete another live writer's cache.
            let mut memory = crate::relational::wal_decode::MetadataCharge::default();
            memory.prepare(root.as_os_str().len() as u64 * 2 + 1024)?;
            let path = audit_log_path(root);
            let directory = path.parent().expect("audit directory");
            match fs::symlink_metadata(directory) {
                Ok(metadata) if !metadata.file_type().is_dir() => {
                    return Err(invalid("audit directory is not a regular directory"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            crate::relational::disk_map::DiskMap::cleanup_interrupted(directory)?;
        }
        repair_active_tail(root)?;
        let path = audit_log_path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (registry, previous_hash, sequence) =
            registry::Registry::recover(root, journal.as_deref())?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        sync_recovered_audit(&file, &path)?;
        let state = Arc::new(Mutex::new(WriterState {
            file,
            path,
            sequence,
            previous_hash,
            durable_sequence: sequence,
            group_pending: 0,
            group_started: None,
            writer_error: None,
            registry,
        }));
        let commit = Arc::new(Condvar::new());
        let signal = Arc::new((Mutex::new(GroupCommitSignal::default()), Condvar::new()));
        let wakeups = Arc::new(AtomicUsize::new(0));
        let handle = spawn_group_committer(
            Arc::downgrade(&state),
            Arc::downgrade(&commit),
            Arc::clone(&signal),
            Arc::clone(&wakeups),
        );
        let writer = Arc::new(Self {
            state,
            commit,
            pending: Arc::new(AtomicUsize::new(0)),
            group_committer: GroupCommitter {
                signal,
                handle: Mutex::new(Some(handle)),
                wakeups,
            },
            closed: AtomicBool::new(false),
            journal,
        });
        writer.recover_interrupted(root)?;
        Ok(writer)
    }

    fn wake_group_committer(&self) {
        let (lock, ready) = &*self.group_committer.signal;
        let mut signal = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        signal.pending = true;
        ready.notify_one();
    }

    #[cfg(test)]
    fn group_committer_wakeups(&self) -> usize {
        self.group_committer.wakeups.load(Ordering::Acquire)
    }

    pub(crate) fn flush_and_shutdown(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?;
        let flush = if state.group_pending > 0 {
            state.file.sync_all()
        } else {
            Ok(())
        };
        if flush.is_ok() {
            state.durable_sequence = state.sequence;
            state.group_pending = 0;
            state.group_started = None;
        } else {
            state.writer_error = Some("audit synchronization failed during shutdown".to_string());
        }
        let writer_error = state.writer_error.clone();
        self.commit.notify_all();
        drop(state);
        self.stop_group_committer();
        if let Some(error) = writer_error {
            Err(GaussError::AuditUnavailable(error))
        } else {
            flush?;
            // This cache is optional. A failed publication leaves the durable
            // audit log authoritative and normal full recovery available.
            if let Err(error) = self.checkpoint_recovery() {
                metrics::counter!("chirondb_audit_checkpoint_failures_total").increment(1);
                tracing::warn!(%error, "audit recovery checkpoint was not published");
            }
            Ok(())
        }
    }

    pub(crate) fn checkpoint_recovery(&self) -> Result<()> {
        let Some(journal) = self.journal.as_deref() else {
            return Ok(());
        };
        let Some(binding) = journal.audit_checkpoint_binding()? else {
            return Ok(());
        };
        let mut state = loop {
            crate::relational::check_sql_cancelled()?;
            match self.state.try_lock() {
                Ok(state) => break state,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(invalid("audit writer lock poisoned"));
                }
            }
        };
        if let Some(error) = &state.writer_error {
            return Err(GaussError::AuditUnavailable(error.clone()));
        }
        state.file.sync_all()?;
        state.durable_sequence = state.sequence;
        state.group_pending = 0;
        state.group_started = None;
        self.commit.notify_all();
        let WriterState {
            path,
            sequence,
            previous_hash,
            registry,
            ..
        } = &mut *state;
        let root = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid("audit root missing"))?;
        checkpoint::publish(registry, root, binding, *sequence, previous_hash)
    }

    pub(crate) fn with_frozen_frontier<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut state = loop {
            match self.state.try_lock() {
                Ok(state) => break state,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(invalid("audit writer lock poisoned"));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(invalid("audit frontier deadline exceeded"));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        if let Some(error) = &state.writer_error {
            return Err(GaussError::AuditUnavailable(error.clone()));
        }
        state.file.sync_all()?;
        state.durable_sequence = state.sequence;
        state.group_pending = 0;
        state.group_started = None;
        self.commit.notify_all();
        operation()
    }

    fn stop_group_committer(&self) {
        let (lock, ready) = &*self.group_committer.signal;
        {
            let mut signal = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            signal.closed = true;
            ready.notify_all();
        }
        if let Some(handle) = self
            .group_committer
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }

    /// Rebind the active audit file after a legacy root-directory restore.
    /// The restore already copied the durable live audit chain, including the
    /// in-flight restore intent, into the installed root. Do not run orphan
    /// intent recovery here because this operation will append its success
    /// outcome immediately after the swap.
    pub(crate) fn reload_after_root_swap(&self, root: &Path) -> Result<()> {
        repair_active_tail(root)?;
        let path = audit_log_path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (registry, previous_hash, sequence) =
            registry::Registry::recover(root, self.journal.as_deref())?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        sync_recovered_audit(&file, &path)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(GaussError::AuditUnavailable(
                "audit writer is shutting down".to_string(),
            ));
        }
        *state = WriterState {
            file,
            path,
            sequence,
            previous_hash,
            durable_sequence: sequence,
            group_pending: 0,
            group_started: None,
            writer_error: None,
            registry,
        };
        self.commit.notify_all();
        Ok(())
    }

    pub fn begin(
        &self,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
    ) -> Result<AuditIntent> {
        self.begin_in_category("mutation", operation, collection, context)
    }

    pub fn begin_in_category(
        &self,
        category: impl Into<String>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
    ) -> Result<AuditIntent> {
        self.begin_with_details(category, operation, collection, context, Value::Null)
    }

    fn begin_with_details(
        &self,
        category: impl Into<String>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
        details: Value,
    ) -> Result<AuditIntent> {
        let intent = AuditIntent {
            category: category.into(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            operation: operation.into(),
            collection: collection.map(str::to_string),
            context,
        };
        self.append(
            &intent.category,
            &intent.operation,
            &intent.operation_id,
            "intent",
            intent.collection.as_deref(),
            &intent.context,
            None,
            details,
            true,
        )?;
        Ok(intent)
    }

    pub fn operation(
        self: &Arc<Self>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
    ) -> Result<AuditOperation> {
        self.operation_in_category("mutation", operation, collection, context)
    }

    pub fn operation_in_category(
        self: &Arc<Self>,
        category: impl Into<String>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
    ) -> Result<AuditOperation> {
        self.operation_with_details(category, operation, collection, context, Value::Null)
    }

    pub fn operation_with_details(
        self: &Arc<Self>,
        category: impl Into<String>,
        operation: impl Into<String>,
        collection: Option<&str>,
        context: AuditContext,
        details: Value,
    ) -> Result<AuditOperation> {
        let slot = self.reserve_slot()?;
        let intent = self.begin_with_details(category, operation, collection, context, details)?;
        Ok(AuditOperation {
            writer: self.clone(),
            intent: Some(intent),
            _slot: slot,
        })
    }

    pub fn finish(
        &self,
        intent: &AuditIntent,
        outcome: &str,
        error_code: Option<&str>,
        details: Value,
    ) -> Result<()> {
        self.append(
            &intent.category,
            &intent.operation,
            &intent.operation_id,
            outcome,
            intent.collection.as_deref(),
            &intent.context,
            error_code,
            details,
            true,
        )
    }

    /// Materialize the audit projection of a canonical transaction exactly
    /// once. Recovery can safely call this again after a crash between the
    /// audit fsync and the journal's projection marker.
    pub fn project_committed_transaction(
        &self,
        transaction_id: crate::transaction_journal::TransactionId,
        audit: &crate::transaction_journal::TransactionAudit,
    ) -> Result<()> {
        let mut id = [0; 36];
        let operation_id = transaction_id.encode_hyphenated(&mut id);
        let digest = binding::expected(audit)?;
        if let Some(journal) = self
            .journal
            .as_deref()
            .map(|journal| journal.storage_projection_authority())
            .transpose()?
            .flatten()
        {
            journal.validate_audit_projection(transaction_id, digest)?;
        }
        let mut memory = crate::relational::wal_decode::MetadataCharge::default();
        memory.prepare(
            audit.principal_id.len() as u64
                + audit.tenant_id.as_ref().map_or(0, |id| id.len() as u64)
                + audit.transport.len() as u64
                + audit.request_id.as_ref().map_or(0, |id| id.len() as u64)
                + 512,
        )?;
        self.append_inner(
            &audit.category,
            &audit.operation,
            operation_id,
            "success",
            audit.collection.as_deref(),
            &audit.context(),
            None,
            &audit.details,
            true,
            true,
        )
    }

    /// The recovered hash chain was synchronized before these IDs were
    /// installed. If a live group is not yet durable, use the normal append
    /// path so duplicate detection waits for synchronization.
    pub(crate) fn has_durable_transaction_projection(
        &self,
        transaction_id: crate::transaction_journal::TransactionId,
    ) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(GaussError::AuditUnavailable(
                "audit writer is shutting down".into(),
            ));
        }
        if let Some(error) = &state.writer_error {
            return Err(GaussError::AuditUnavailable(error.clone()));
        }
        let mut id = [0; 36];
        Ok(state.durable_sequence == state.sequence
            && state
                .registry
                .terminal(transaction_id.encode_hyphenated(&mut id))?
                .is_some())
    }

    pub fn record(&self, event: AuditEvent<'_>) -> Result<()> {
        let _slot = self.reserve_slot()?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        self.append(
            event.category,
            event.operation,
            &operation_id,
            event.outcome,
            event.collection,
            event.context,
            event.error_code,
            event.details,
            event.durable,
        )
    }

    fn reserve_slot(&self) -> Result<AuditSlot> {
        self.pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                (pending < AUDIT_QUEUE_CAPACITY).then_some(pending + 1)
            })
            .map_err(|_| GaussError::AuditUnavailable("audit queue is full".to_string()))?;
        Ok(AuditSlot {
            pending: Arc::clone(&self.pending),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &self,
        category: &str,
        operation: &str,
        operation_id: &str,
        outcome: &str,
        collection: Option<&str>,
        context: &AuditContext,
        error_code: Option<&str>,
        details: Value,
        durable: bool,
    ) -> Result<()> {
        self.append_inner(
            category,
            operation,
            operation_id,
            outcome,
            collection,
            context,
            error_code,
            &details,
            durable,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_inner(
        &self,
        category: &str,
        operation: &str,
        operation_id: &str,
        outcome: &str,
        collection: Option<&str>,
        context: &AuditContext,
        error_code: Option<&str>,
        details: &Value,
        durable: bool,
        once: bool,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(GaussError::AuditUnavailable(
                "audit writer is shutting down".to_string(),
            ));
        }
        if let Some(error) = state.writer_error.as_deref() {
            return Err(audit_unavailable(invalid(error.to_string())));
        }
        // Deduplication and append share this lock. A terminal ID may have
        // become visible before its group fsync, or before a failed sync.
        // Never acknowledge it merely because its bytes can be read back.
        if once && let Some(existing) = state.registry.terminal(operation_id)? {
            let record = AuditRecord {
                schema_version: 2,
                sequence: 0,
                event_id: String::new(),
                timestamp_unix_ms: 0,
                category,
                operation,
                operation_id,
                outcome,
                collection,
                principal_id: &context.principal_id,
                tenant_id: context.tenant_id.as_deref(),
                transport: &context.transport,
                request_id: context.request_id.as_deref(),
                error_code,
                prev_record_hash: "",
                details: binding::Sanitized(details),
            };
            if existing.digest != binding::record_expected(&record)? {
                return Err(invalid(
                    "audit projection retry changed its committed semantics",
                ));
            }
            let frontier = state.sequence;
            while state.durable_sequence < frontier && state.writer_error.is_none() {
                state = self
                    .commit
                    .wait(state)
                    .map_err(|_| invalid("audit group commit lock poisoned"))?;
            }
            if let Some(error) = state.writer_error.as_deref() {
                return Err(audit_unavailable(invalid(error.to_string())));
            }
            return Ok(());
        }
        if state.file.metadata()?.len() >= AUDIT_SEGMENT_BYTES && state.group_pending > 0 {
            state.file.sync_all()?;
            state.durable_sequence = state.sequence;
            state.group_pending = 0;
            state.group_started = None;
            self.commit.notify_all();
        }
        rotate_if_needed(&mut state)?;
        let next = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("audit sequence overflow"))?;
        let record = AuditRecord {
            schema_version: 2,
            sequence: next,
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp_unix_ms: now_ms(),
            category,
            operation,
            operation_id,
            outcome,
            collection,
            principal_id: &context.principal_id,
            tenant_id: context.tenant_id.as_deref(),
            transport: &context.transport,
            request_id: context.request_id.as_deref(),
            error_code,
            prev_record_hash: &state.previous_hash,
            details: binding::Sanitized(details),
        };
        let mut value = crate::relational::wal_decode::json(&record)?;
        let record_hash = hash_json_value(&value)?;
        value.reserve_extra(512)?;
        let value = value.try_map(|mut value| {
            value
                .as_object_mut()
                .ok_or_else(|| invalid("audit record is not an object"))?
                .insert(
                    "record_hash".to_string(),
                    Value::String(record_hash.clone()),
                );
            Ok(value)
        })?;
        let entry = state.registry.prepare(&value, next)?;
        let frame = encode_audit_value(&value)?;
        if let Err(error) = crate::failpoint::check("audit.before_append")
            .and_then(|_| state.file.write_all(&frame.bytes).map_err(Into::into))
        {
            state.writer_error = Some("audit append failed".into());
            self.commit.notify_all();
            return Err(audit_unavailable(error));
        }
        state.sequence = next;
        state.previous_hash = record_hash;
        if let Some(entry) = entry
            && let Err(error) = state.registry.install(entry)
        {
            state.writer_error = Some("audit registry installation failed".into());
            self.commit.notify_all();
            return Err(audit_unavailable(error));
        }
        if durable {
            if let Err(error) = crate::failpoint::check("audit.before_sync")
                .and_then(|_| state.file.sync_all().map_err(Into::into))
            {
                state.writer_error = Some("audit synchronization failed".into());
                self.commit.notify_all();
                return Err(audit_unavailable(error));
            }
            state.durable_sequence = next;
            state.group_pending = 0;
            state.group_started = None;
            self.commit.notify_all();
        } else {
            if state.group_pending == 0 {
                state.group_started = Some(Instant::now());
            }
            state.group_pending = state.group_pending.saturating_add(1);
            self.commit.notify_all();
            self.wake_group_committer();
            while state.durable_sequence < next && state.writer_error.is_none() {
                state = self
                    .commit
                    .wait(state)
                    .map_err(|_| invalid("audit group commit lock poisoned"))?;
            }
            if let Some(error) = state.writer_error.as_deref() {
                return Err(audit_unavailable(invalid(error.to_string())));
            }
        }
        Ok(())
    }

    fn recover_interrupted(&self, _root: &Path) -> Result<()> {
        registry::recover_orphans(self)
    }
}

impl Drop for AuditWriter {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.stop_group_committer();
    }
}

/// Recovery may see a complete frame whose writer died before fsync. Establish
/// durability before installing recovered IDs as acknowledged projections.
/// Synchronize directory entries too, including a newly created audit file.
fn sync_recovered_audit(file: &File, path: &Path) -> Result<()> {
    (|| {
        crate::failpoint::check("audit.before_recovery_sync")?;
        file.sync_all()?;
        if let Some(directory) = path.parent() {
            sync_directory(directory)?;
            if let Some(root) = directory.parent() {
                sync_directory(if root.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    root
                })?;
            }
        }
        Ok(())
    })()
    .map_err(audit_unavailable)
}

fn spawn_group_committer(
    state: std::sync::Weak<Mutex<WriterState>>,
    commit: std::sync::Weak<Condvar>,
    signal: Arc<(Mutex<GroupCommitSignal>, Condvar)>,
    wakeups: Arc<AtomicUsize>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("chirondb-audit-commit".to_string())
        .spawn(move || {
            loop {
                let (signal_lock, ready) = &*signal;
                let mut notification = signal_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !notification.pending && !notification.closed {
                    notification = ready
                        .wait(notification)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                if notification.closed {
                    return;
                }
                notification.pending = false;
                drop(notification);
                wakeups.fetch_add(1, Ordering::AcqRel);
                metrics::counter!("chirondb_audit_worker_wake_total").increment(1);

                let Some(state) = state.upgrade() else {
                    return;
                };
                let Some(commit) = commit.upgrade() else {
                    return;
                };
                let mut state = match state.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                if state.group_pending == 0 {
                    continue;
                }
                while state.group_pending < AUDIT_GROUP_COMMIT_MAX {
                    let started = state.group_started.unwrap_or_else(Instant::now);
                    let Some(remaining) = AUDIT_GROUP_COMMIT_DELAY.checked_sub(started.elapsed())
                    else {
                        break;
                    };
                    let waited = commit.wait_timeout(state, remaining);
                    let Ok((next, timeout)) = waited else {
                        return;
                    };
                    state = next;
                    if timeout.timed_out() {
                        break;
                    }
                }
                match state.file.sync_all() {
                    Ok(()) => {
                        state.durable_sequence = state.sequence;
                        state.group_pending = 0;
                        state.group_started = None;
                        metrics::counter!("chirondb_audit_worker_flush_total").increment(1);
                    }
                    Err(error) => {
                        state.writer_error = Some(format!("audit group commit failed: {error}"));
                    }
                }
                commit.notify_all();
                if state.writer_error.is_some() {
                    return;
                }
            }
        })
        .expect("spawn audit group committer")
}

pub fn audit_log_path(root: &Path) -> PathBuf {
    if root
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "generations")
        && let Some(data_dir) = root.parent().and_then(Path::parent)
    {
        return data_dir.join(AUDIT_LOG_FILE);
    }
    root.join(AUDIT_LOG_FILE)
}

fn audit_log_paths(root: &Path) -> Result<reader::Paths> {
    reader::Paths::new(root)
}

pub(crate) fn preserve_durable_log(live_root: &Path, staged_root: &Path) -> Result<()> {
    verify_hash_chain(live_root)?;
    let staged = audit_log_path(staged_root);
    let parent = staged.parent().expect("staged audit directory");
    fs::create_dir_all(parent)?;
    for path in audit_log_paths(staged_root)? {
        crate::fs_util::durable_remove_file(&path)?;
    }
    for path in audit_log_paths(live_root)? {
        let target = parent.join(
            path.file_name()
                .ok_or_else(|| invalid("audit log has no name"))?,
        );
        crate::fs_util::durable_copy(&path, &target)?;
    }
    sync_directory(parent)?;
    Ok(())
}

fn rotate_if_needed(state: &mut WriterState) -> Result<()> {
    rotate_if_needed_at(state, AUDIT_SEGMENT_BYTES)
}

fn rotate_if_needed_at(state: &mut WriterState, threshold: u64) -> Result<()> {
    if state.file.metadata()?.len() < threshold {
        return Ok(());
    }
    state.file.sync_all()?;
    let directory = state
        .path
        .parent()
        .ok_or_else(|| invalid("audit path has no parent"))?;
    let rotated = directory.join(format!("audit-{:020}.jsonl", state.sequence));
    if rotated.exists() {
        return Err(invalid(format!(
            "audit rotation destination already exists: {}",
            rotated.display()
        )));
    }
    fs::rename(&state.path, &rotated)?;
    sync_directory(directory)?;
    state.file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .append(true)
        .open(&state.path)?;
    state.file.sync_all()?;
    sync_directory(directory)
}

pub fn append_success(
    root: &Path,
    operation: &str,
    collection: Option<&str>,
    details: Value,
) -> Result<()> {
    append_record(root, operation, collection, "success", details)
}

fn append_record(
    root: &Path,
    operation: &str,
    collection: Option<&str>,
    outcome: &str,
    details: Value,
) -> Result<()> {
    let _guard = AUDIT_APPEND_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| GaussError::InvalidRequest("audit append lock poisoned".to_string()))?;
    let path = audit_log_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let (prev_record_hash, previous_sequence) = previous_record_state(root)?;
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or_else(|| GaussError::InvalidRequest("audit sequence overflow".to_string()))?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let record = AuditRecord {
        schema_version: 2,
        sequence,
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp_unix_ms: now_ms(),
        category: "mutation",
        operation,
        operation_id: &operation_id,
        outcome,
        collection,
        principal_id: "embedded-system",
        tenant_id: None,
        transport: "embedded",
        request_id: None,
        error_code: None,
        prev_record_hash: &prev_record_hash,
        details: binding::Sanitized(&details),
    };
    let mut value = crate::relational::wal_decode::json(&record)?;
    let record_hash = hash_json_value(&value)?;
    value.reserve_extra(512)?;
    let value = value.try_map(|mut value| {
        value
            .as_object_mut()
            .ok_or_else(|| invalid("audit record is not an object"))?
            .insert("record_hash".to_string(), Value::String(record_hash));
        Ok(value)
    })?;
    write_audit_value(&mut file, &value)?;
    file.sync_all()?;
    Ok(())
}

pub fn verify_hash_chain(root: &Path) -> Result<()> {
    verify_hash_chain_prefix(root, None)
}

fn verify_hash_chain_prefix(root: &Path, active_prefix_len: Option<u64>) -> Result<()> {
    scan_verified(root, active_prefix_len, |_, _| Ok(())).map(|_| ())
}

fn scan_verified(
    root: &Path,
    active_prefix_len: Option<u64>,
    mut visitor: impl FnMut(&Value, u64) -> Result<()>,
) -> Result<(String, u64)> {
    scan_verified_from(root, active_prefix_len, None, &mut visitor)
}

fn scan_verified_from(
    root: &Path,
    active_prefix_len: Option<u64>,
    checkpoint: Option<&checkpoint::Checkpoint>,
    mut visitor: impl FnMut(&Value, u64) -> Result<()>,
) -> Result<(String, u64)> {
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    memory.prepare(root.as_os_str().len() as u64 + 1024)?;
    let mut expected_prev = checkpoint.map_or_else(genesis_hash, |c| c.previous_hash.clone());
    let mut expected_sequence = checkpoint.map_or(Ok(1), |c| {
        c.sequence
            .checked_add(1)
            .ok_or_else(|| invalid("audit sequence overflow"))
    })?;
    let mut index = usize::try_from(expected_sequence - 1)
        .map_err(|_| invalid("audit sequence exceeds usize"))?;
    let active = audit_log_path(root);
    for (position, path) in audit_log_paths(root)?.into_iter().enumerate() {
        if checkpoint.is_some_and(|c| position < c.closed_segments) {
            continue;
        }
        let mut file = OpenOptions::new().read(true).open(&path)?;
        let offset = if let Some(c) = checkpoint.filter(|c| position == c.closed_segments) {
            file.seek(SeekFrom::Start(c.active_bytes))?;
            c.active_bytes
        } else {
            0
        };
        let limit = if path == active {
            active_prefix_len.map_or(u64::MAX, |end| end.saturating_sub(offset))
        } else {
            u64::MAX
        };
        let mut lines = reader::Lines::new(file.take(limit))?;
        while let Some(line) = lines.next()? {
            if line.trim().is_empty() {
                continue;
            }
            reader::decode(line)?.consume(|mut value| {
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| invalid_chain(index, "record is not an object"))?;
                if index == 0 && object.get("schema_version").is_none() {
                    expected_prev = legacy_genesis_hash();
                }
                let record_hash = object
                    .remove("record_hash")
                    .ok_or_else(|| invalid_chain(index, "missing record_hash"))?;
                let record_hash = record_hash
                    .as_str()
                    .ok_or_else(|| invalid_chain(index, "invalid record_hash"))?;
                let prev = object
                    .get("prev_record_hash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_chain(index, "missing prev_record_hash"))?;
                if prev != expected_prev {
                    return Err(invalid_chain(index, "prev_record_hash mismatch"));
                }
                if let Some(sequence) = object.get("sequence").and_then(Value::as_u64)
                    && sequence != expected_sequence
                {
                    return Err(invalid_chain(index, "non-linear sequence"));
                }
                if hash_json_value(&value)? != record_hash {
                    return Err(invalid_chain(index, "record_hash mismatch"));
                }
                visitor(&value, expected_sequence)?;
                expected_prev.clear();
                expected_prev.push_str(record_hash);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("audit sequence overflow"))?;
                index += 1;
                Ok(())
            })?;
        }
    }
    Ok((expected_prev, expected_sequence - 1))
}

fn repair_active_tail(root: &Path) -> Result<()> {
    let path = audit_log_path(root);
    if !path.try_exists()? {
        return Ok(());
    }
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(invalid("active audit log is not a regular file"));
    }
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    memory.prepare(path.as_os_str().len() as u64 + 8192)?;
    let mut input = File::open(&path)?;
    let length = input.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    input.seek(SeekFrom::End(-1))?;
    let mut last = [0; 1];
    input.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let mut end = length;
    let mut buffer = [0; 4096];
    let prefix_len = loop {
        crate::relational::check_sql_cancelled()?;
        let start = end.saturating_sub(buffer.len() as u64);
        if length - start > (crate::wal::MAX_WAL_RECORD_BYTES * 2 + 4096) as u64 {
            return Err(invalid("audit tail exceeds maximum frame size"));
        }
        input.seek(SeekFrom::Start(start))?;
        let count = (end - start) as usize;
        input.read_exact(&mut buffer[..count])?;
        if let Some(index) = buffer[..count].iter().rposition(|b| *b == b'\n') {
            break start + index as u64 + 1;
        }
        if start == 0 {
            break 0;
        }
        end = start;
    };
    input.seek(SeekFrom::Start(prefix_len))?;
    let mut lines = reader::Lines::new(input.take(length - prefix_len))?;
    let tail = lines.next()?.ok_or_else(|| invalid("missing audit tail"))?;
    let complete = match reader::decode(tail) {
        Ok(_) => true,
        Err(GaussError::Json(error))
            if error.is_eof() && !tail.starts_with(ENCRYPTED_AUDIT_PREFIX) =>
        {
            false
        }
        // Authentication, missing key, cancellation, admission and complete
        // malformed records cannot be mistaken for an unacknowledged tail.
        Err(error) => {
            if reader::encrypted_tail_is_truncated(tail)? {
                false
            } else {
                return Err(error);
            }
        }
    };
    verify_hash_chain_prefix(root, (!complete).then_some(prefix_len))?;
    let mut file = OpenOptions::new()
        .write(true)
        .append(complete)
        .open(&path)?;
    if complete {
        file.write_all(b"\n")?;
    } else {
        file.set_len(prefix_len)?;
    }
    file.sync_all()?;
    if let Some(directory) = path.parent() {
        sync_directory(directory)?;
    }
    Ok(())
}

/// Test evidence only; this is not a tenant-facing audit export API.
#[cfg(test)]
pub(crate) fn records_for_test(root: &Path) -> Result<Vec<Value>> {
    let mut records = Vec::new();
    for path in audit_log_paths(root)? {
        for line in BufReader::new(OpenOptions::new().read(true).open(path)?).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                records.push(decode_audit_line(&line)?);
            }
        }
    }
    Ok(records)
}

fn previous_record_state(root: &Path) -> Result<(String, u64)> {
    scan_verified(root, None, |_, _| Ok(()))
}

struct OutputFrame {
    bytes: Vec<u8>,
    _memory: crate::relational::wal_decode::MetadataCharge,
}

fn encode_audit_value(value: &Value) -> Result<OutputFrame> {
    let plaintext =
        crate::relational::wal_decode::encode_limited(value, crate::wal::MAX_WAL_RECORD_BYTES)?;
    let mut admission = crate::relational::wal_decode::FrameAdmission::new()?;
    admission.prepare(plaintext.len(), false)?;
    let encoded = encryption::encode_persistent(FileType::Audit, &plaintext)?;
    let mut memory = crate::relational::wal_decode::MetadataCharge::default();
    let capacity = encoded
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| invalid("audit output frame overflow"))?;
    memory.prepare(capacity as u64)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(capacity)
        .map_err(|_| invalid("audit output allocation failed"))?;
    if encryption::is_encrypted(encoded.as_ref()) {
        frame.extend_from_slice(ENCRYPTED_AUDIT_PREFIX.as_bytes());
        // Encode directly into the admitted destination; no second base64 String.
        let start = frame.len();
        frame.resize(start + encoded.len().div_ceil(3) * 4, 0);
        STANDARD
            .encode_slice(encoded.as_ref(), &mut frame[start..])
            .map_err(|error| invalid(format!("audit encoding failed: {error}")))?;
    } else {
        frame.extend_from_slice(encoded.as_ref());
    }
    frame.push(b'\n');
    Ok(OutputFrame {
        bytes: frame,
        _memory: memory,
    })
}

fn write_audit_value(file: &mut File, value: &Value) -> Result<()> {
    file.write_all(&encode_audit_value(value)?.bytes)?;
    Ok(())
}

#[cfg(test)]
fn decode_audit_line(line: &str) -> Result<Value> {
    reader::decode(line)?.consume(Ok)
}

pub(crate) fn audit_unavailable(error: GaussError) -> GaussError {
    match error {
        GaussError::AuditUnavailable(_) | GaussError::ResourceExhausted(_) => error,
        GaussError::InvalidRequest(ref message) if message == "query canceled" => error,
        other => GaussError::AuditUnavailable(other.to_string()),
    }
}

fn hash_json_value(value: &Value) -> Result<String> {
    let digest = binding::digest(value)?;
    Ok(hex_digest(&digest))
}

fn hex_digest(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn genesis_hash() -> String {
    hash_bytes(b"chirondb-audit-genesis-v2")
}

fn legacy_genesis_hash() -> String {
    hash_bytes(b"gaussdb-audit-genesis-v1")
}

fn invalid_chain(index: usize, message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("audit hash chain record {index}: {message}"))
}

#[cfg(test)]
mod projection_tests;

#[cfg(test)]
mod tests {
    use std::{io::Write as _, sync::Arc};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn committed_transaction_duplicate_rejects_changed_audit_context() {
        let temp = tempfile::tempdir().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let id = crate::transaction_journal::TransactionId::new();
        let audit = crate::transaction_journal::TransactionAudit::mutation(
            "insert",
            None,
            &AuditContext::embedded(),
            serde_json::json!({"rows": 1}),
        );
        writer.project_committed_transaction(id, &audit).unwrap();
        let mut changed = audit.clone();
        changed.principal_id = "another-principal".into();
        assert!(writer.project_committed_transaction(id, &changed).is_err());
        writer.project_committed_transaction(id, &audit).unwrap();
        assert_eq!(records_for_test(temp.path()).unwrap().len(), 1);
    }

    #[test]
    fn recovered_transaction_presence_requires_durable_open_writer() {
        let temp = tempfile::tempdir().unwrap();
        let id = crate::transaction_journal::TransactionId::new();
        let audit = crate::transaction_journal::TransactionAudit::mutation(
            "insert",
            None,
            &AuditContext::embedded(),
            Value::Null,
        );
        let writer = AuditWriter::open(temp.path()).unwrap();
        assert!(!writer.has_durable_transaction_projection(id).unwrap());
        writer.project_committed_transaction(id, &audit).unwrap();
        assert!(writer.has_durable_transaction_projection(id).unwrap());
        writer.flush_and_shutdown().unwrap();
        assert!(matches!(
            writer.has_durable_transaction_projection(id),
            Err(GaussError::AuditUnavailable(_))
        ));
        drop(writer);
        let writer = AuditWriter::open(temp.path()).unwrap();
        assert!(writer.has_durable_transaction_projection(id).unwrap());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn transaction_presence_never_acknowledges_failed_audit_sync() {
        let temp = tempfile::tempdir().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let id = crate::transaction_journal::TransactionId::new();
        let audit = crate::transaction_journal::TransactionAudit::mutation(
            "insert",
            None,
            &AuditContext::embedded(),
            Value::Null,
        );
        let marker = temp.path().join("marker");
        let release = temp.path().join("release");
        {
            let _env = crate::failpoint::test_env("error:audit.before_sync", &marker, &release);
            assert!(writer.project_committed_transaction(id, &audit).is_err());
        }
        assert!(matches!(
            writer.has_durable_transaction_projection(id),
            Err(GaussError::AuditUnavailable(_))
        ));
    }

    #[test]
    fn startup_preserves_complete_record_missing_final_delimiter() {
        let temp = TempDir::new().unwrap();
        append_success(temp.path(), "first", None, Value::Null).unwrap();
        let path = audit_log_path(temp.path());
        let mut contents = fs::read(&path).unwrap();
        assert_eq!(contents.pop(), Some(b'\n'));
        fs::write(&path, contents).unwrap();

        let writer = AuditWriter::open(temp.path()).unwrap();
        writer
            .record(AuditEvent {
                category: "mutation",
                operation: "second",
                outcome: "success",
                collection: None,
                context: &AuditContext::embedded(),
                error_code: None,
                details: Value::Null,
                durable: true,
            })
            .unwrap();
        drop(writer);

        verify_hash_chain(temp.path()).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.lines().count(), 2);
    }

    #[test]
    fn startup_trims_incomplete_active_tail_before_next_record() {
        let temp = TempDir::new().unwrap();
        append_success(temp.path(), "first", None, Value::Null).unwrap();
        let path = audit_log_path(temp.path());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial\"")
            .unwrap();

        let writer = AuditWriter::open(temp.path()).unwrap();
        writer
            .record(AuditEvent {
                category: "mutation",
                operation: "second",
                outcome: "success",
                collection: None,
                context: &AuditContext::embedded(),
                error_code: None,
                details: Value::Null,
                durable: true,
            })
            .unwrap();
        drop(writer);

        verify_hash_chain(temp.path()).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(!contents.contains("partial"));
    }

    #[test]
    fn concurrent_appends_keep_a_single_linear_chain() {
        let temp = Arc::new(TempDir::new().unwrap());
        let threads = (0..8)
            .map(|_| {
                let temp = temp.clone();
                std::thread::spawn(move || {
                    for _ in 0..32 {
                        append_success(temp.path(), "read", None, Value::Null).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }

        verify_hash_chain(temp.path()).unwrap();
        let contents = fs::read_to_string(audit_log_path(temp.path())).unwrap();
        assert_eq!(contents.lines().count(), 256);
    }

    #[test]
    fn one_writer_serializes_concurrent_intent_outcome_pairs() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let threads = (0..8)
            .map(|_| {
                let writer = writer.clone();
                std::thread::spawn(move || {
                    for _ in 0..16 {
                        writer
                            .operation("upsert", Some("docs"), AuditContext::embedded())
                            .unwrap()
                            .success(serde_json::json!({"points": 1}))
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        verify_hash_chain(temp.path()).unwrap();
        let contents = fs::read_to_string(audit_log_path(temp.path())).unwrap();
        assert_eq!(contents.lines().count(), 8 * 16 * 2);
    }

    #[test]
    fn operation_category_is_preserved_for_query_audits() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        writer
            .operation_in_category(
                "query",
                "graph.allow_degraded_search",
                Some("docs"),
                AuditContext {
                    principal_id: "alice".to_string(),
                    tenant_id: Some("acme".to_string()),
                    transport: "test".to_string(),
                    request_id: Some("request-1".to_string()),
                },
            )
            .unwrap()
            .success(serde_json::json!({"allow_degraded": true}))
            .unwrap();

        let records = fs::read_to_string(audit_log_path(temp.path())).unwrap();
        let records = records
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record["category"] == "query"));
        assert!(
            records
                .iter()
                .all(|record| record["operation"] == "graph.allow_degraded_search")
        );
        assert_eq!(records[1]["principal_id"], "alice");
        assert_eq!(records[1]["tenant_id"], "acme");
        assert_eq!(records[1]["outcome"], "success");
    }

    #[test]
    fn read_events_group_commit_and_wait_for_durability() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let threads = (0..AUDIT_GROUP_COMMIT_MAX)
            .map(|_| {
                let writer = writer.clone();
                std::thread::spawn(move || {
                    writer
                        .record(AuditEvent {
                            category: "access",
                            operation: "search",
                            outcome: "success",
                            collection: Some("docs"),
                            context: &AuditContext::embedded(),
                            error_code: None,
                            details: Value::Null,
                            durable: false,
                        })
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        let state = writer.state.lock().unwrap();
        assert_eq!(state.durable_sequence, AUDIT_GROUP_COMMIT_MAX as u64);
        assert_eq!(state.group_pending, 0);
        drop(state);
        verify_hash_chain(temp.path()).unwrap();
    }

    #[test]
    fn group_committer_has_no_idle_timer_wakeups() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let baseline = writer.group_committer_wakeups();
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(writer.group_committer_wakeups(), baseline);

        writer
            .record(AuditEvent {
                category: "access",
                operation: "search",
                outcome: "success",
                collection: Some("docs"),
                context: &AuditContext::embedded(),
                error_code: None,
                details: Value::Null,
                durable: false,
            })
            .unwrap();
        assert_eq!(writer.group_committer_wakeups(), baseline + 1);
    }

    #[test]
    fn explicit_shutdown_is_idempotent_and_joins_after_writer_error() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        writer.state.lock().unwrap().writer_error = Some("injected failure".to_string());

        assert!(writer.flush_and_shutdown().is_err());
        assert!(writer.group_committer.handle.lock().unwrap().is_none());
        assert!(writer.flush_and_shutdown().is_err());
    }

    #[test]
    fn startup_marks_orphaned_intent_interrupted() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        let operation = writer
            .operation("restore", None, AuditContext::embedded())
            .unwrap();
        std::mem::forget(operation);
        drop(writer);

        let reopened = AuditWriter::open(temp.path()).unwrap();
        drop(reopened);
        verify_hash_chain(temp.path()).unwrap();
        let contents = fs::read_to_string(audit_log_path(temp.path())).unwrap();
        assert!(contents.lines().any(|line| line.contains("interrupted")));
    }

    #[test]
    fn rotated_segments_preserve_one_hash_chain() {
        let temp = TempDir::new().unwrap();
        let writer = AuditWriter::open(temp.path()).unwrap();
        writer
            .record(AuditEvent {
                category: "access",
                operation: "read",
                outcome: "success",
                collection: Some("docs"),
                context: &AuditContext::embedded(),
                error_code: None,
                details: Value::Null,
                durable: true,
            })
            .unwrap();
        {
            let mut state = writer.state.lock().unwrap();
            rotate_if_needed_at(&mut state, 0).unwrap();
        }
        writer
            .record(AuditEvent {
                category: "access",
                operation: "read",
                outcome: "success",
                collection: Some("docs"),
                context: &AuditContext::embedded(),
                error_code: None,
                details: Value::Null,
                durable: true,
            })
            .unwrap();
        verify_hash_chain(temp.path()).unwrap();
        assert_eq!(audit_log_paths(temp.path()).unwrap().len(), 2);
    }
}
