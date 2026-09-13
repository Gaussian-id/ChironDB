use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    GaussError, Result,
    encryption::{self, FileType},
    fs_util::sync_directory,
};

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
    details: Value,
}

#[derive(Clone, Debug)]
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
    state: Mutex<WriterState>,
    commit: Condvar,
    pending: Arc<AtomicUsize>,
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
}

impl AuditWriter {
    pub fn open(root: impl AsRef<Path>) -> Result<Arc<Self>> {
        let root = root.as_ref();
        verify_hash_chain(root)?;
        let path = audit_log_path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (previous_hash, sequence) = previous_record_state(root)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let writer = Arc::new(Self {
            state: Mutex::new(WriterState {
                file,
                path,
                sequence,
                previous_hash,
                durable_sequence: sequence,
                group_pending: 0,
                group_started: None,
                writer_error: None,
            }),
            commit: Condvar::new(),
            pending: Arc::new(AtomicUsize::new(0)),
        });
        spawn_group_committer(Arc::downgrade(&writer));
        writer.recover_interrupted(root)?;
        Ok(writer)
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
            Value::Null,
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
        let slot = self.reserve_slot()?;
        let intent = self.begin_in_category(category, operation, collection, context)?;
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("audit writer lock poisoned"))?;
        if let Some(error) = state.writer_error.as_deref() {
            return Err(audit_unavailable(invalid(error.to_string())));
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
            details: sanitize_details(details),
        };
        let mut value = serde_json::to_value(record)?;
        let record_hash = hash_json_value(&value)?;
        value
            .as_object_mut()
            .ok_or_else(|| invalid("audit record is not an object"))?
            .insert(
                "record_hash".to_string(),
                Value::String(record_hash.clone()),
            );
        write_audit_value(&mut state.file, &value)?;
        state.sequence = next;
        state.previous_hash = record_hash;
        if durable {
            state.file.sync_all()?;
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

    fn recover_interrupted(&self, root: &Path) -> Result<()> {
        let mut intents = HashMap::<String, (String, Option<String>, AuditContext)>::new();
        let mut completed = HashSet::new();
        for path in audit_log_paths(root)? {
            let file = OpenOptions::new().read(true).open(path)?;
            for line in BufReader::new(file).lines() {
                let value = decode_audit_line(&line?)?;
                let Some(operation_id) = value.get("operation_id").and_then(Value::as_str) else {
                    continue;
                };
                match value.get("outcome").and_then(Value::as_str) {
                    Some("intent") => {
                        intents.insert(
                            operation_id.to_string(),
                            (
                                value["operation"].as_str().unwrap_or("unknown").to_string(),
                                value["collection"].as_str().map(str::to_string),
                                AuditContext {
                                    principal_id: value["principal_id"]
                                        .as_str()
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    tenant_id: value["tenant_id"].as_str().map(str::to_string),
                                    transport: value["transport"]
                                        .as_str()
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    request_id: value["request_id"].as_str().map(str::to_string),
                                },
                            ),
                        );
                    }
                    Some(_) => {
                        completed.insert(operation_id.to_string());
                    }
                    None => {}
                }
            }
        }
        for (operation_id, (operation, collection, context)) in intents {
            if completed.contains(&operation_id) {
                continue;
            }
            self.append(
                "mutation",
                &operation,
                &operation_id,
                "interrupted",
                collection.as_deref(),
                &context,
                Some("process_interrupted"),
                Value::Null,
                true,
            )?;
        }
        Ok(())
    }
}

fn spawn_group_committer(writer: std::sync::Weak<AuditWriter>) {
    let _ = std::thread::Builder::new()
        .name("chirondb-audit-commit".to_string())
        .spawn(move || {
            loop {
                let Some(writer) = writer.upgrade() else {
                    break;
                };
                let mut state = match writer.state.lock() {
                    Ok(state) => state,
                    Err(_) => break,
                };
                while state.group_pending == 0 {
                    if Arc::strong_count(&writer) == 1 {
                        return;
                    }
                    let waited = writer.commit.wait_timeout(state, AUDIT_GROUP_COMMIT_DELAY);
                    let Ok((next, _)) = waited else {
                        return;
                    };
                    state = next;
                }
                while state.group_pending < AUDIT_GROUP_COMMIT_MAX {
                    let started = state.group_started.unwrap_or_else(Instant::now);
                    let Some(remaining) = AUDIT_GROUP_COMMIT_DELAY.checked_sub(started.elapsed())
                    else {
                        break;
                    };
                    let waited = writer.commit.wait_timeout(state, remaining);
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
                    }
                    Err(error) => {
                        state.writer_error = Some(format!("audit group commit failed: {error}"));
                    }
                }
                writer.commit.notify_all();
            }
        });
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

fn audit_log_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let current = audit_log_path(root);
    let Some(directory) = current.parent() else {
        return Ok(Vec::new());
    };
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            (entry.file_type().ok()?.is_file()
                && name.starts_with("audit-")
                && name.ends_with(".jsonl"))
            .then(|| entry.path())
        })
        .collect::<Vec<_>>();
    paths.sort();
    if current.exists() {
        paths.push(current);
    }
    Ok(paths)
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
        details: sanitize_details(details),
    };
    let mut value = serde_json::to_value(record)?;
    let record_hash = hash_json_value(&value)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| GaussError::InvalidRequest("audit record is not an object".to_string()))?;
    object.insert("record_hash".to_string(), Value::String(record_hash));
    write_audit_value(&mut file, &value)?;
    file.sync_all()?;
    Ok(())
}

pub fn verify_hash_chain(root: &Path) -> Result<()> {
    let paths = audit_log_paths(root)?;
    if paths.is_empty() {
        return Ok(());
    }
    let mut expected_prev = genesis_hash();
    let mut expected_sequence = 1_u64;
    let mut index = 0_usize;
    for path in paths {
        let file = OpenOptions::new().read(true).open(path)?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let mut value = decode_audit_line(&line)?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| invalid_chain(index, "record is not an object"))?;
            if index == 0 && object.get("schema_version").is_none() {
                expected_prev = legacy_genesis_hash();
            }
            let record_hash = object
                .remove("record_hash")
                .and_then(|value| value.as_str().map(str::to_string))
                .ok_or_else(|| invalid_chain(index, "missing record_hash"))?;
            let prev_record_hash = object
                .get("prev_record_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_chain(index, "missing prev_record_hash"))?;
            if prev_record_hash != expected_prev {
                return Err(invalid_chain(index, "prev_record_hash mismatch"));
            }
            if let Some(sequence) = object.get("sequence").and_then(Value::as_u64)
                && sequence != expected_sequence
            {
                return Err(invalid_chain(index, "non-linear sequence"));
            }
            let actual_hash = hash_json_value(&Value::Object(object.clone()))?;
            if record_hash != actual_hash {
                return Err(invalid_chain(index, "record_hash mismatch"));
            }
            expected_prev = record_hash;
            expected_sequence = expected_sequence.saturating_add(1);
            index = index.saturating_add(1);
        }
    }
    Ok(())
}

fn previous_record_state(root: &Path) -> Result<(String, u64)> {
    let mut last_line = None;
    let mut records = 0_u64;
    for path in audit_log_paths(root)? {
        let file = OpenOptions::new().read(true).open(path)?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                records = records.saturating_add(1);
                last_line = Some(line);
            }
        }
    }
    let Some(line) = last_line else {
        return Ok((genesis_hash(), 0));
    };
    let value = decode_audit_line(&line)?;
    let hash = value
        .get("record_hash")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| hash_bytes(line.as_bytes()));
    let sequence = value
        .get("sequence")
        .and_then(Value::as_u64)
        .unwrap_or(records);
    Ok((hash, sequence))
}

fn sanitize_details(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.to_ascii_lowercase().as_str(),
                        "api_key" | "vector" | "vectors" | "payload" | "sql" | "query" | "point_id"
                    )
                })
                .map(|(key, value)| (key, sanitize_details(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_details).collect()),
        other => other,
    }
}

fn write_audit_value(file: &mut File, value: &Value) -> Result<()> {
    let plaintext = serde_json::to_vec(value)?;
    let encoded = encryption::encode_persistent(FileType::Audit, &plaintext)?;
    if encryption::is_encrypted(encoded.as_ref()) {
        file.write_all(ENCRYPTED_AUDIT_PREFIX.as_bytes())?;
        file.write_all(STANDARD.encode(encoded.as_ref()).as_bytes())?;
    } else {
        file.write_all(encoded.as_ref())?;
    }
    file.write_all(b"\n")?;
    Ok(())
}

fn decode_audit_line(line: &str) -> Result<Value> {
    let decoded;
    let bytes = if let Some(envelope) = line.strip_prefix(ENCRYPTED_AUDIT_PREFIX) {
        decoded = STANDARD
            .decode(envelope)
            .map_err(|error| invalid(format!("invalid encrypted audit frame encoding: {error}")))?;
        decoded.as_slice()
    } else {
        line.as_bytes()
    };
    let plaintext = encryption::decode_persistent(bytes)?;
    serde_json::from_slice(&plaintext).map_err(Into::into)
}

fn audit_unavailable(error: GaussError) -> GaussError {
    match error {
        GaussError::AuditUnavailable(_) => error,
        other => GaussError::AuditUnavailable(other.to_string()),
    }
}

fn hash_json_value(value: &Value) -> Result<String> {
    Ok(hash_bytes(&serde_json::to_vec(value)?))
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
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
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
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;

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
