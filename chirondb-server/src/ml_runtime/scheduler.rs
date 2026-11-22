//! Durable, opt-in refresh scheduling. SQL owns truth; memory owns only leases
//! and monotonic waiting. One dispatcher shares admission with manual refresh.
use super::*;
use chirondb_core::{MlSourceMetadata, MlSourceRevision};
use chirondb_types::{
    MlRefreshActivity as Activity, MlRefreshAvailability as Availability,
    MlRefreshFreshness as Freshness, MlRefreshRevision,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SCHEDULE_TABLE: &str = "__chiron_ml_schedule";
pub(super) const PROVENANCE_TABLE: &str = "__chiron_ml_job_provenance";
const DEBOUNCE_MS: u64 = 5_000;
const MAX_COALESCE_MS: u64 = 30_000;
const COOLDOWN_MS: u64 = 300_000;
static PROCESS_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);

struct WorkerPermit;
impl WorkerPermit {
    fn acquire() -> Option<Self> {
        PROCESS_WORKER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}
impl Drop for WorkerPermit {
    fn drop(&mut self) {
        PROCESS_WORKER_ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Schedule {
    #[serde(skip)]
    catalog_lineage: String,
    format: u32,
    name: String,
    epoch: String,
    definition: String,
    mode: MlRefreshMode,
    source_id: Option<u64>,
    lineage: Option<String>,
    desired: Option<MlSourceRevision>,
    published: Option<MlSourceRevision>,
    first_dirty: Option<u64>,
    last_dirty: Option<u64>,
    #[serde(default)]
    stale_since: Option<u64>,
    pending: bool,
    manual: bool,
    job: Option<String>,
    claim: Option<String>,
    requested_revision: Option<MlSourceRevision>,
    retry_at: Option<u64>,
    failures: u32,
    blocked: bool,
    error_code: Option<String>,
    error: Option<String>,
    last_success: Option<u64>,
    #[serde(default)]
    requested_at: Option<u64>,
    #[serde(default)]
    started_at: Option<u64>,
    #[serde(default)]
    finished_at: Option<u64>,
    #[serde(default)]
    failed_at: Option<u64>,
    #[serde(default)]
    worker_identity: Option<Value>,
    version: u64,
    actor: String,
    tenant: Option<String>,
}

impl Schedule {
    pub(super) fn finished_at(&self) -> u64 {
        self.finished_at.unwrap_or(0)
    }
    fn new(name: &str, definition: String, version: u64) -> Self {
        Self {
            catalog_lineage: String::new(),
            format: 1,
            name: name.into(),
            epoch: uuid::Uuid::new_v4().to_string(),
            definition,
            mode: MlRefreshMode::Manual,
            source_id: None,
            lineage: None,
            desired: None,
            published: None,
            first_dirty: None,
            last_dirty: None,
            stale_since: None,
            pending: false,
            manual: false,
            job: None,
            claim: None,
            requested_revision: None,
            retry_at: None,
            failures: 0,
            blocked: false,
            error_code: None,
            error: None,
            last_success: None,
            requested_at: None,
            started_at: None,
            finished_at: None,
            failed_at: None,
            worker_identity: None,
            version,
            actor: "ml-scheduler".into(),
            tenant: None,
        }
    }

    fn definition(&self) -> MlResult<MlMaterialize> {
        let value: Value = serde_json::from_str(&self.definition).map_err(storage_error)?;
        let text = |key: &str| {
            value[key].as_str().map(str::to_string).ok_or_else(|| {
                MlError::new("chironql.ml_storage_failed", "invalid stored ML definition")
            })
        };
        let task = match text("task")?.as_str() {
            "regression" => MlTask::Regression,
            "classification" => MlTask::Classification,
            _ => {
                return Err(MlError::new(
                    "chironql.ml_storage_failed",
                    "unknown stored task",
                ));
            }
        };
        let model = match text("model")?.as_str() {
            "decision_tree" => MlModel::DecisionTree,
            "random_forest" => MlModel::RandomForest,
            _ => {
                return Err(MlError::new(
                    "chironql.ml_storage_failed",
                    "unknown stored model",
                ));
            }
        };
        Ok(MlMaterialize {
            view: self.name.clone(),
            source: text("source")?,
            target: text("target")?,
            features: serde_json::from_value(value["features"].clone()).map_err(storage_error)?,
            task,
            model,
        })
    }

    fn bind(&mut self, metadata: &MlSourceMetadata, now: u64) {
        self.source_id = Some(metadata.revision.table_id);
        self.lineage = Some(metadata.lineage.clone());
        self.desired = Some(metadata.revision);
        self.track_freshness(now);
    }

    fn identity_matches(&self, metadata: &MlSourceMetadata) -> bool {
        self.source_id == Some(metadata.revision.table_id)
            && self.lineage.as_deref() == Some(&metadata.lineage)
    }

    fn dirty(&mut self, revision: MlSourceRevision, now: u64) {
        if self.desired == Some(revision) {
            return;
        }
        self.desired = Some(revision);
        self.track_freshness(now);
        if !self.pending {
            // A blocked/completed intent has ended. New data gets its own
            // debounce window; changes within one pending intent retain it.
            self.first_dirty = Some(now);
        } else {
            self.first_dirty.get_or_insert(now);
        }
        self.pending = true;
        self.last_dirty = Some(now);
        // A changed revision permits a new preflight, but cannot reset backoff.
        self.blocked = false;
    }

    fn track_freshness(&mut self, now: u64) {
        if self.desired.is_some() && self.desired != self.published {
            self.stale_since.get_or_insert(now);
        } else {
            self.stale_since = None;
        }
    }

    fn observed_freshness_lag_ms(&self, now: u64) -> Option<u64> {
        self.desired.and_then(|desired| {
            if self.published == Some(desired) {
                Some(0)
            } else {
                self.stale_since.map(|since| now.saturating_sub(since))
            }
        })
    }

    fn eligible_at(&self) -> u64 {
        let debounce = if self.manual {
            self.first_dirty.unwrap_or(0)
        } else {
            self.last_dirty
                .unwrap_or(0)
                .saturating_add(DEBOUNCE_MS)
                .min(
                    self.first_dirty
                        .unwrap_or(0)
                        .saturating_add(MAX_COALESCE_MS),
                )
        };
        debounce.max(self.retry_at.unwrap_or(0))
    }

    fn queue_priority(&self) -> u64 {
        // A completed view with a pending follow-up goes behind work already
        // waiting. This changes ordering, never its coalescing eligibility.
        self.eligible_at().max(self.finished_at.unwrap_or(0))
    }

    fn fail(&mut self, error: &MlError, now: u64) {
        self.claim = None;
        self.job = None;
        self.manual = false;
        self.error_code = Some(error.code.into());
        self.error = Some(error.message.clone());
        self.failures = self.failures.saturating_add(1);
        self.failed_at = Some(now);
        self.finished_at = Some(now);
        self.blocked = !error.transient;
        self.pending = self.mode == MlRefreshMode::Auto && error.transient;
        self.first_dirty.get_or_insert(now);
        self.last_dirty
            .get_or_insert(now.saturating_sub(DEBOUNCE_MS));
        self.retry_at = error.transient.then(|| {
            now.saturating_add(match self.failures {
                1 => 5_000,
                2 => 30_000,
                _ => COOLDOWN_MS,
            })
        });
    }

    fn clamp_recovered_clock(&mut self, now: u64) {
        self.stale_since = self.stale_since.map(|value| value.min(now));
        // Legacy records without this observation time start at recovery;
        // neither a revision number nor job provenance gives a commit time.
        self.track_freshness(now);
        self.first_dirty = self.first_dirty.map(|value| value.min(now));
        self.last_dirty = self.last_dirty.map(|value| value.min(now));
        // This copy is also the queue's finish-order clock. Job provenance is
        // stored separately and retains the original observed finish time.
        self.finished_at = self.finished_at.map(|value| value.min(now));
        self.retry_at = self
            .retry_at
            .map(|value| value.min(now.saturating_add(COOLDOWN_MS)));
    }

    fn audit(&self, job: Option<&str>) -> AuditContext {
        audit(
            if self.manual {
                &self.actor
            } else {
                "ml-scheduler"
            },
            self.tenant.as_deref(),
            job,
        )
    }
}

fn record_committed_observation(previous: Option<&Schedule>, next: &Schedule) {
    let Some(previous) = previous else {
        return;
    };
    if previous.desired.is_some() && previous.desired != next.desired {
        metrics::counter!("chirondb_ml_observed_source_revision_changes_total").increment(1);
        if previous.pending {
            metrics::counter!("chirondb_ml_coalesced_revision_observations_total").increment(1);
        }
    }
}

fn record_freshness_lag(inner: &Inner, now: u64) {
    for record in inner
        .records
        .values()
        .filter(|record| record.mode == MlRefreshMode::Auto)
    {
        // Failed source validation/metadata reads do not establish current
        // freshness. Keep the timestamp, but emit no invented zero sample.
        if matches!(
            record.error_code.as_deref(),
            Some(
                "chironql.ml_invalid_source"
                    | "chironql.ml_invalid_schema"
                    | "chironql.ml_storage_failed"
            )
        ) {
            continue;
        }
        if let Some(lag) = record.observed_freshness_lag_ms(now) {
            metrics::histogram!("chirondb_ml_observed_freshness_lag_seconds")
                .record(lag as f64 / 1000.0);
        }
    }
}

fn storage_error(error: impl std::fmt::Display) -> MlError {
    MlError::new("chironql.ml_storage_failed", error.to_string())
}

fn catalog_sql(
    db: &Db,
    statements: Vec<SqlStatementRequest>,
    audit: &AuditContext,
    lineage: &str,
) -> MlResult<chirondb_core::SqlExecutionResponse> {
    db.execute_ml_catalog(
        SqlExecutionRequest {
            statements,
            idempotency_key: None,
            retry_id: audit.request_id.clone(),
        },
        audit,
        lineage,
    )
    .and_then(|response| response.consume(Ok))
    .map_err(engine_error)
}

fn audit(actor: &str, tenant: Option<&str>, request: Option<&str>) -> AuditContext {
    AuditContext {
        principal_id: actor.into(),
        tenant_id: tenant.map(str::to_string),
        transport: "chironql-ml".into(),
        request_id: request.map(str::to_string),
    }
}

fn text(value: impl Into<String>) -> RelationalValue {
    RelationalValue::Text(value.into())
}

pub(super) fn save_statement(record: &Schedule) -> MlResult<SqlStatementRequest> {
    Ok(statement(
        format!("UPDATE {SCHEDULE_TABLE} SET state = $1 WHERE name = $2"),
        vec![
            text(serde_json::to_string(record).map_err(storage_error)?),
            text(&record.name),
        ],
    ))
}

fn insert_statement(record: &Schedule) -> MlResult<SqlStatementRequest> {
    Ok(statement(
        format!("INSERT INTO {SCHEDULE_TABLE} (name, state) VALUES ($1, $2)"),
        vec![
            text(&record.name),
            text(serde_json::to_string(record).map_err(storage_error)?),
        ],
    ))
}

pub(super) fn stored_state(db: &Db, name: &str, lineage: &str) -> MlResult<String> {
    let response = catalog_sql(
        db,
        vec![statement(
            format!("SELECT state FROM {SCHEDULE_TABLE} WHERE name = $1"),
            vec![text(name)],
        )],
        &audit("ml-scheduler", None, None),
        lineage,
    )?;
    let row = rows(&response.results[0])?
        .1
        .first()
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML schedule disappeared"))?;
    Ok(one_text(&row[0])?.into())
}

#[derive(Default)]
pub(super) struct Inner {
    initialized: bool,
    lineage: String,
    records: BTreeMap<String, Schedule>,
    // An absent SQL projection cannot disprove an unknown WAL COMMIT. Never
    // issue another catalog mutation for this root until reopen/restore.
    recovery_required: bool,
}

const RECOVERY_REQUIRED_CODE: &str = "chironql.ml_recovery_required";
const RECOVERY_REQUIRED_MESSAGE: &str =
    "an ML transaction outcome is unknown; reopen the database to recover before refreshing";

impl Inner {
    fn require_mutations(&self) -> MlResult<()> {
        if self.recovery_required {
            Err(MlError::new(
                RECOVERY_REQUIRED_CODE,
                RECOVERY_REQUIRED_MESSAGE,
            ))
        } else {
            Ok(())
        }
    }

    fn observe<T>(&mut self, result: MlResult<T>) -> MlResult<T> {
        if result
            .as_ref()
            .is_err_and(|error| error.code == "chironql.ml_commit_unknown")
        {
            self.recovery_required = true;
        }
        result
    }
}

struct Shared {
    inner: Mutex<Inner>,
    wake: Condvar,
    stop: AtomicBool,
    wall_start: u64,
    monotonic_start: Instant,
}

impl Shared {
    fn now(&self) -> u64 {
        self.wall_start
            .saturating_add(self.monotonic_start.elapsed().as_millis() as u64)
    }
}

pub(super) struct Runtime {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        if let Some(thread) = self
            .thread
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = thread.join();
        }
    }
}

impl chirondb_core::MlRuntimeService for Runtime {
    fn shutdown(&self, deadline: Instant) -> bool {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        loop {
            let mut handle = self
                .thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if handle.as_ref().is_none_or(JoinHandle::is_finished) {
                if let Some(thread) = handle.take() {
                    let _ = thread.join();
                }
                return true;
            }
            drop(handle);
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

pub(super) fn state_for(db: &Db) -> Arc<Runtime> {
    db.ml_runtime(|| {
        metrics::describe_counter!(
            "chirondb_ml_observed_source_revision_changes_total",
            "Observed source revision transitions saved durably; not source commit counts"
        );
        metrics::describe_counter!(
            "chirondb_ml_coalesced_revision_observations_total",
            "Durable revision observations merged into an already pending intent"
        );
        metrics::describe_histogram!(
            "chirondb_ml_observed_freshness_lag_seconds",
            "Per-AUTO-view elapsed time since first observed unpublished revision; fresh views sample zero"
        );
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner::default()),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            wall_start: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            monotonic_start: Instant::now(),
        });
        let engine = db.ml_background_clone();
        let state = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("chiron-ml-scheduler".into())
            .spawn(move || dispatcher(engine, state))
            .expect("ML scheduler thread");
        Runtime {
            shared,
            thread: Mutex::new(Some(thread)),
        }
    })
}

/// Called once at transport startup; recovery is not a side effect of status GET.
pub(crate) fn initialize(db: &Db) -> MlResult<()> {
    if local_preview(db).is_err() {
        return Ok(());
    }
    let runtime = state_for(db);
    let mut inner = runtime.shared.inner.lock().expect("ML scheduler state");
    if db
        .relational_tables()
        .iter()
        .any(|table| table.name == VIEWS_TABLE)
    {
        ensure_catalog(
            db,
            &mut inner,
            runtime.shared.now(),
            &audit("ml-recovery", None, None),
        )?;
    }
    Ok(())
}

pub(super) fn ensure_catalog(
    db: &Db,
    inner: &mut Inner,
    now: u64,
    audit: &AuditContext,
) -> MlResult<()> {
    let lineage = db.ml_catalog_lineage().map_err(engine_error)?;
    if inner.lineage != lineage {
        inner.recovery_required = false;
    }
    inner.require_mutations()?;
    if inner.initialized && inner.lineage == lineage {
        return Ok(());
    }
    inner.initialized = false;
    inner.lineage = lineage;
    inner.records.clear();
    local_preview(db)?;
    let result = catalog_sql(
        db,
        vec![
            statement(
                format!(
                    "CREATE TABLE IF NOT EXISTS {VIEWS_TABLE} (name TEXT PRIMARY KEY, definition TEXT NOT NULL, source TEXT NOT NULL, version BIGINT NOT NULL, source_version BIGINT, row_count BIGINT)"
                ),
                vec![],
            ),
            statement(
                format!(
                    "CREATE TABLE IF NOT EXISTS {JOBS_TABLE} (id TEXT PRIMARY KEY, view_name TEXT NOT NULL, status TEXT NOT NULL, source_version BIGINT, row_count BIGINT, context_rows BIGINT, error TEXT, duration_ms BIGINT)"
                ),
                vec![],
            ),
            statement(
                format!(
                    "CREATE TABLE IF NOT EXISTS {SCHEDULE_TABLE} (name TEXT PRIMARY KEY, state TEXT NOT NULL)"
                ),
                vec![],
            ),
            statement(
                format!(
                    "CREATE TABLE IF NOT EXISTS {PROVENANCE_TABLE} (id TEXT PRIMARY KEY, details TEXT NOT NULL)"
                ),
                vec![],
            ),
        ],
        audit,
        &inner.lineage,
    );
    inner.observe(result)?;
    let response = catalog_sql(
        db,
        vec![
            statement(
                format!("SELECT name, definition, version FROM {VIEWS_TABLE}"),
                vec![],
            ),
            statement(format!("SELECT name, state FROM {SCHEDULE_TABLE}"), vec![]),
        ],
        audit,
        &inner.lineage,
    )?;
    let mut records = BTreeMap::new();
    for row in rows(&response.results[1])?.1 {
        let mut record: Schedule =
            serde_json::from_str(one_text(&row[1])?).map_err(storage_error)?;
        record.catalog_lineage = inner.lineage.clone();
        if record.format != 1 || record.name != one_text(&row[0])? {
            return Err(storage_error("unsupported ML scheduler format"));
        }
        records.insert(record.name.clone(), record);
    }
    let mut updates = Vec::new();
    for row in rows(&response.results[0])?.1 {
        let name = one_text(&row[0])?;
        if !records.contains_key(name) {
            let mut record = Schedule::new(
                name,
                one_text(&row[1])?.into(),
                one_integer(&row[2])? as u64,
            );
            record.catalog_lineage = inner.lineage.clone();
            updates.push(insert_statement(&record)?);
            records.insert(name.into(), record);
        }
    }
    // Queued requests with a persisted schedule survive; an interrupted lease
    // never silently resumes an unknown worker or reuses its publication token.
    for record in records.values_mut() {
        let before = serde_json::to_string(record).map_err(storage_error)?;
        record.clamp_recovered_clock(now);
        if record.claim.is_some() {
            let mut error =
                MlError::new("chironql.ml_interrupted", "server restarted during refresh");
            error.transient = true;
            record.fail(&error, now);
        }
        if serde_json::to_string(record).map_err(storage_error)? != before {
            updates.push(save_statement(record)?);
        }
    }
    updates.push(statement(format!("UPDATE {JOBS_TABLE} SET status = 'failed', error = 'server_restarted' WHERE status = 'running'"), vec![]));
    if !updates.is_empty() {
        // Existing deployments may contain many independent manual views.
        // Each inserted schedule is restart-idempotent; respect SQL's request
        // limit rather than requiring all view migrations in one transaction.
        for batch in updates.chunks(24) {
            let result = catalog_sql(db, batch.to_vec(), audit, &inner.lineage);
            inner.observe(result)?;
        }
    }
    inner.records = records;
    inner.initialized = true;
    Ok(())
}

pub(super) fn read_ready(db: &Db) -> MlResult<()> {
    let runtime = state_for(db);
    let inner = runtime.shared.inner.lock().expect("ML scheduler state");
    if !inner.initialized {
        return Err(MlError::new(
            "chironql.ml_not_found",
            "ML runtime is not initialized; initialize it when opening the database",
        ));
    }
    if db.ml_catalog_lineage().map_err(engine_error)? != inner.lineage {
        return Err(MlError::new(
            "chironql.ml_recovering",
            "ML scheduler is reloading the restored database",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn ensure_catalog_for_test(db: &Db, runtime: &Runtime) -> MlResult<()> {
    ensure_catalog(
        db,
        &mut runtime.shared.inner.lock().expect("ML scheduler state"),
        runtime.shared.now(),
        &audit("test", None, None),
    )
}

fn metadata(db: &Db, record: &Schedule) -> MlResult<MlSourceMetadata> {
    let definition = record.definition()?;
    let metadata = db
        .ml_source_revision(&definition.source)
        .map_err(storage_error)?
        .ok_or_else(|| {
            MlError::new(
                "chironql.ml_invalid_source",
                "source table no longer exists",
            )
        })?;
    if record.source_id.is_some() && !record.identity_matches(&metadata) {
        return Err(MlError::new(
            "chironql.ml_invalid_source",
            "source identity changed; drop and recreate the ML view to rebind",
        ));
    }
    if record.mode == MlRefreshMode::Auto && metadata.table.managed_by_ml {
        return Err(MlError::new(
            "chironql.ml_invalid_source",
            "automatic refresh cannot depend on another managed ML table",
        ));
    }
    crate::chironql_ml::validate_source(&definition, std::slice::from_ref(&metadata.table))
        .map_err(|message| MlError::new("chironql.ml_invalid_schema", message))?;
    Ok(metadata)
}

pub(super) fn submit(
    db: &Db,
    definition: &MlMaterialize,
    actor: &str,
    tenant: Option<&str>,
) -> MlResult<MlSubmitted> {
    local_preview(db)?;
    for name in [&definition.view, &definition.source, &definition.target] {
        identifier(name)?;
    }
    for name in &definition.features {
        identifier(name)?;
    }
    if definition.view.eq_ignore_ascii_case(&definition.source) {
        return Err(MlError::new(
            "chironql.ml_invalid_name",
            "view and source must differ",
        ));
    }
    let runtime = state_for(db);
    let mut inner = runtime.shared.inner.lock().expect("ML scheduler state");
    inner.require_mutations()?;
    worker_config()?;
    let now = runtime.shared.now();
    let audit = audit(actor, tenant, None);
    ensure_catalog(db, &mut inner, now, &audit)?;
    let canonical = canonical_definition(definition);
    let exists = inner.records.contains_key(&definition.view);
    let mut record = inner
        .records
        .get(&definition.view)
        .cloned()
        .unwrap_or_else(|| Schedule::new(&definition.view, canonical.clone(), 0));
    if record.definition != canonical {
        return Err(MlError::new(
            "chironql.ml_definition_conflict",
            "view has another definition; drop it before changing parameters",
        ));
    }
    if record.claim.is_some() || record.job.is_some() {
        return Err(MlError::new(
            "chironql.ml_refresh_running",
            "a refresh for this view is already queued or running",
        ));
    }
    if !exists
        && db
            .relational_tables()
            .iter()
            .any(|table| table.name.eq_ignore_ascii_case(&definition.view))
    {
        return Err(MlError::new(
            "chironql.ml_name_conflict",
            "view name belongs to a relational table",
        ));
    }
    let source = metadata(db, &record)?;
    db.ensure_ml_source_format().map_err(engine_error)?;
    record.catalog_lineage = inner.lineage.clone();
    record.bind(&source, now);
    record.requested_at = Some(now);
    record.started_at = None;
    record.finished_at = None;
    record.manual = true;
    record.pending = true;
    record.first_dirty = Some(now);
    record.last_dirty = Some(now);
    record.retry_at = None;
    record.blocked = false;
    record.failures = 0;
    record.actor = actor.into();
    record.tenant = tenant.map(str::to_string);
    let job = uuid::Uuid::new_v4().to_string();
    record.job = Some(job.clone());
    record.requested_revision = record.desired;
    let mut statements = Vec::new();
    if !exists {
        statements.push(statement(format!("INSERT INTO {VIEWS_TABLE} (name, definition, source, version) VALUES ($1, $2, $3, 0)"), vec![text(&definition.view), text(canonical), text(&definition.source)]));
        statements.push(insert_statement(&record)?);
    } else {
        statements.push(save_statement(&record)?);
    }
    statements.push(statement(
        format!("INSERT INTO {JOBS_TABLE} (id, view_name, status) VALUES ($1, $2, 'queued')"),
        vec![text(&job), text(&definition.view)],
    ));
    statements.push(provenance_statement(&record, &job, None, false));
    let result = catalog_sql(db, statements, &audit, &inner.lineage);
    inner.observe(result)?;
    record_committed_observation(inner.records.get(&record.name), &record);
    inner.records.insert(record.name.clone(), record);
    runtime.shared.wake.notify_all();
    Ok(MlSubmitted {
        job_id: job,
        view: definition.view.clone(),
        status: "queued",
    })
}

pub(crate) fn set_refresh_policy(
    db: &Db,
    name: &str,
    mode: MlRefreshMode,
    actor: &str,
    tenant: Option<&str>,
) -> MlResult<MlRefreshStatus> {
    local_preview(db)?;
    identifier(name)?;
    read_ready(db)?;
    let runtime = state_for(db);
    let mut inner = runtime.shared.inner.lock().expect("ML scheduler state");
    inner.require_mutations()?;
    let mut record = inner
        .records
        .get(name)
        .cloned()
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML view was not found"))?;
    let now = runtime.shared.now();
    let previous_mode = record.mode;
    record.mode = mode;
    record.actor = actor.into();
    record.tenant = tenant.map(str::to_string);
    let mut statements = Vec::new();
    if mode == MlRefreshMode::Auto {
        worker_config()?;
        let source = metadata(db, &record)?;
        db.ensure_ml_source_format().map_err(storage_error)?;
        if record.source_id.is_none() {
            record.bind(&source, now);
        }
        record.dirty(source.revision, now);
        if record.published != Some(source.revision) && record.claim.is_none() {
            record.pending = true;
            record.first_dirty.get_or_insert(now);
            record.last_dirty.get_or_insert(now);
        }
        if previous_mode != mode {
            record.blocked = false;
            record.retry_at = None;
            record.failures = 0;
        }
    } else if !record.manual {
        record.pending = false;
        record.first_dirty = None;
        record.last_dirty = None;
        record.retry_at = None;
        if record.claim.is_none() {
            record.job = None;
        }
    }
    statements.push(save_statement(&record)?);
    let result = catalog_sql(db, statements, &audit(actor, tenant, None), &inner.lineage);
    inner.observe(result)?;
    record_committed_observation(inner.records.get(name), &record);
    inner.records.insert(name.into(), record.clone());
    runtime.shared.wake.notify_all();
    status(db, &record, now, inner.recovery_required)
}

fn revision(value: MlSourceRevision) -> MlRefreshRevision {
    MlRefreshRevision {
        data: value.data_revision,
        schema: value.schema_revision,
    }
}

fn status(
    db: &Db,
    record: &Schedule,
    now: u64,
    recovery_required: bool,
) -> MlResult<MlRefreshStatus> {
    let current = metadata(db, record);
    let freshness = match &current {
        Err(_) => Freshness::InvalidSource,
        Ok(source) if record.published == Some(source.revision) => Freshness::Fresh,
        _ => Freshness::Stale,
    };
    let activity = if recovery_required {
        Activity::Blocked
    } else if record.claim.is_some() {
        Activity::Running
    } else if record.blocked {
        Activity::Blocked
    } else if record.pending && record.retry_at.is_some_and(|retry| retry > now) {
        Activity::RetryWait
    } else if record.pending && record.eligible_at() > now {
        Activity::Debouncing
    } else if record.pending {
        Activity::Queued
    } else {
        Activity::Idle
    };
    if db.ml_catalog_lineage().map_err(engine_error)? != record.catalog_lineage {
        return Err(MlError::new(
            "chironql.ml_recovering",
            "ML scheduler is reloading a restored database",
        ));
    }
    Ok(MlRefreshStatus {
        view: record.name.clone(),
        mode: record.mode,
        availability: if record.version == 0 {
            Availability::NotReady
        } else {
            Availability::Available
        },
        activity,
        freshness,
        source_table_id: record.source_id,
        current_revision: current.ok().map(|source| revision(source.revision)),
        published_revision: record.published.map(revision),
        active_job_id: record.job.clone(),
        last_success_at_ms: record.last_success,
        queue_age_ms: record
            .pending
            .then(|| now.saturating_sub(record.first_dirty.unwrap_or(now))),
        retry_at_ms: if recovery_required {
            None
        } else {
            record.retry_at
        },
        error_code: if recovery_required {
            Some(RECOVERY_REQUIRED_CODE.into())
        } else {
            record.error_code.clone()
        },
        blocked_reason: if recovery_required {
            Some(RECOVERY_REQUIRED_MESSAGE.into())
        } else {
            record.blocked.then(|| record.error.clone()).flatten()
        },
        refresh_version: record.version,
    })
}

pub(crate) fn get_refresh_status(db: &Db, name: &str) -> MlResult<MlRefreshStatus> {
    local_preview(db)?;
    identifier(name)?;
    read_ready(db)?;
    let runtime = state_for(db);
    let inner = runtime.shared.inner.lock().expect("ML scheduler state");
    let record = inner
        .records
        .get(name)
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML view was not found"))?;
    status(db, record, runtime.shared.now(), inner.recovery_required)
}

pub(super) fn drop_view(db: &Db, name: &str, actor: &str, tenant: Option<&str>) -> MlResult<Value> {
    local_preview(db)?;
    identifier(name)?;
    read_ready(db)?;
    let runtime = state_for(db);
    let mut inner = runtime.shared.inner.lock().expect("ML scheduler state");
    inner.require_mutations()?;
    let record = inner
        .records
        .get(name)
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML view was not found"))?;
    if record.claim.is_some() {
        return Err(MlError::new(
            "chironql.ml_refresh_running",
            "cannot drop a view while its refresh runs",
        ));
    }
    let mut statements = vec![
        statement(format!("DROP TABLE IF EXISTS {name}"), vec![]),
        statement(
            format!("DELETE FROM {VIEWS_TABLE} WHERE name = $1"),
            vec![text(name)],
        ),
        statement(
            format!("DELETE FROM {SCHEDULE_TABLE} WHERE name = $1"),
            vec![text(name)],
        ),
    ];
    if let Some(job) = &record.job {
        statements.push(statement(
            format!(
                "UPDATE {JOBS_TABLE} SET status = 'failed', error = 'view_dropped' WHERE id = $1"
            ),
            vec![text(job)],
        ));
    }
    let result = catalog_sql(db, statements, &audit(actor, tenant, None), &inner.lineage);
    inner.observe(result)?;
    inner.records.remove(name);
    Ok(json!({"name": name, "dropped": true}))
}

fn reconcile(db: &Db, inner: &mut Inner, now: u64) -> MlResult<()> {
    inner.require_mutations()?;
    let result = reconcile_inner(db, inner, now);
    inner.observe(result)
}

fn reconcile_inner(db: &Db, inner: &mut Inner, now: u64) -> MlResult<()> {
    for record in inner
        .records
        .values_mut()
        .filter(|record| record.mode == MlRefreshMode::Auto)
    {
        let mut next = record.clone();
        match metadata(db, record) {
            Ok(source) => {
                if next.source_id.is_none() {
                    next.bind(&source, now);
                }
                next.dirty(source.revision, now);
                if next.published != Some(source.revision)
                    && !next.blocked
                    && next.claim.is_none()
                    && !next.pending
                {
                    next.pending = true;
                    next.first_dirty = Some(now);
                    next.last_dirty = Some(now);
                }
            }
            Err(error) => {
                next.blocked = true;
                next.pending = false;
                next.error_code = Some(error.code.into());
                next.error = Some(error.message);
            }
        }
        if serde_json::to_string(&next).map_err(storage_error)?
            != serde_json::to_string(record).map_err(storage_error)?
        {
            catalog_sql(
                db,
                vec![save_statement(&next)?],
                &audit("ml-scheduler", None, None),
                &inner.lineage,
            )?;
            record_committed_observation(Some(record), &next);
            *record = next;
        }
    }
    Ok(())
}

struct Active {
    _permit: WorkerPermit,
    name: String,
    epoch: String,
    claim: String,
    job: String,
    definition: MlMaterialize,
    snapshot: SourceSnapshot,
    started: Instant,
    receiver: mpsc::Receiver<MlResult<Value>>,
    thread: Option<JoinHandle<()>>,
    outcome: Option<MlResult<Value>>,
    cancel: Arc<AtomicBool>,
    operation: Option<chirondb_core::audit::AuditOperation>,
}

fn queued_job(record: &Schedule, job: &str) -> SqlStatementRequest {
    statement(
        format!("INSERT INTO {JOBS_TABLE} (id, view_name, status) VALUES ($1, $2, 'queued')"),
        vec![text(job), text(&record.name)],
    )
}

fn provenance_statement(
    record: &Schedule,
    job: &str,
    source: Option<MlSourceRevision>,
    update: bool,
) -> SqlStatementRequest {
    let trigger = if record.manual {
        "manual"
    } else if record.error_code.as_deref() == Some("chironql.ml_interrupted") {
        "recovery"
    } else {
        "automatic"
    };
    let details = json!({"requested_revision": record.requested_revision.map(revision), "source_revision": source.map(revision),
        "trigger": trigger, "actor": record.actor,
        "attempt": record.failures.saturating_add(1), "view_epoch": record.epoch, "claim": record.claim,
        "requested_at_ms": record.requested_at, "started_at_ms": record.started_at, "finished_at_ms": record.finished_at,
        "worker_identity": source.and(record.worker_identity.as_ref())}).to_string();
    if update {
        statement(
            format!("UPDATE {PROVENANCE_TABLE} SET details = $1 WHERE id = $2"),
            vec![text(details), text(job)],
        )
    } else {
        statement(
            format!("INSERT INTO {PROVENANCE_TABLE} (id, details) VALUES ($1, $2)"),
            vec![text(job), text(details)],
        )
    }
}

fn worker_identity(config: &WorkerConfig) -> MlResult<Value> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let digest = |path: &std::path::Path| -> MlResult<String> {
        let mut file = std::fs::File::open(path)
            .map_err(|error| MlError::new("chironql.ml_unavailable", error.to_string()))?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| MlError::new("chironql.ml_unavailable", error.to_string()))?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    };
    Ok(
        json!({"script_sha256_at_dispatch": digest(&config.script)?, "python_sha256_at_dispatch": digest(&config.python)?}),
    )
}

pub(super) fn finish_provenance_statement(
    db: &Db,
    job: &str,
    now: u64,
    lineage: &str,
) -> MlResult<SqlStatementRequest> {
    let response = catalog_sql(
        db,
        vec![statement(
            format!("SELECT details FROM {PROVENANCE_TABLE} WHERE id = $1"),
            vec![text(job)],
        )],
        &audit("ml-scheduler", None, None),
        lineage,
    )?;
    let row = rows(&response.results[0])?
        .1
        .first()
        .ok_or_else(|| storage_error("ML job provenance disappeared"))?;
    let mut details: Value = serde_json::from_str(one_text(&row[0])?).map_err(storage_error)?;
    details["finished_at_ms"] = json!(now);
    Ok(statement(
        format!("UPDATE {PROVENANCE_TABLE} SET details = $1 WHERE id = $2"),
        vec![text(details.to_string()), text(job)],
    ))
}

fn fail_before_spawn(db: &Db, record: &mut Schedule, error: MlError, now: u64) -> MlResult<()> {
    let mut next = record.clone();
    let job = next
        .job
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut statements = Vec::new();
    next.finished_at = Some(now);
    if next.job.is_none() {
        next.requested_revision = next.desired;
        next.requested_at = next.first_dirty.or(Some(now));
        next.started_at = None;
        statements.push(queued_job(&next, &job));
        statements.push(provenance_statement(&next, &job, None, false));
    } else {
        statements.push(finish_provenance_statement(
            db,
            &job,
            now,
            &record.catalog_lineage,
        )?);
    }
    next.fail(&error, now);
    statements.push(statement(
        format!(
            "UPDATE {JOBS_TABLE} SET status = 'failed', error = $1, duration_ms = 0 WHERE id = $2"
        ),
        vec![
            text(format!("{}: {}", error.code, error.message)),
            text(&job),
        ],
    ));
    statements.push(save_statement(&next)?);
    catalog_sql(
        db,
        statements,
        &audit("ml-scheduler", None, Some(&job)),
        &record.catalog_lineage,
    )?;
    *record = next;
    Ok(())
}

fn dispatch(
    db: &Db,
    inner: &mut Inner,
    shared: &Arc<Shared>,
    now: u64,
) -> MlResult<Option<Active>> {
    inner.require_mutations()?;
    let result = dispatch_inner(db, inner, shared, now);
    inner.observe(result)
}

fn dispatch_inner(
    db: &Db,
    inner: &mut Inner,
    shared: &Arc<Shared>,
    now: u64,
) -> MlResult<Option<Active>> {
    let selected = inner
        .records
        .values()
        .filter(|record| {
            record.pending
                && !record.blocked
                && record.claim.is_none()
                && record.eligible_at() <= now
        })
        .min_by_key(|record| (record.queue_priority(), record.first_dirty, &record.name))
        .map(|record| record.name.clone());
    let Some(name) = selected else {
        return Ok(None);
    };
    let Some(permit) = WorkerPermit::acquire() else {
        return Ok(None);
    };
    let record = inner.records.get_mut(&name).expect("selected record");
    let prepared = (|| {
        local_preview(db)?;
        let definition = record.definition()?;
        metadata(db, record)?;
        let worker = worker_config()?;
        let snapshot = read_snapshot(db, &definition)?;
        if !record.identity_matches(&snapshot.source.metadata) {
            return Err(MlError::new(
                "chironql.ml_invalid_source",
                "source changed before dispatch",
            ));
        }
        let request = worker_request(&definition, &snapshot)?;
        let identity = worker_identity(&worker)?;
        Ok((definition, worker, snapshot, request, identity))
    })();
    let (definition, worker, snapshot, request, identity) = match prepared {
        Ok(value) => value,
        Err(error) => {
            fail_before_spawn(db, record, error, now)?;
            return Ok(None);
        }
    };
    let mut next = record.clone();
    let queue_age = now.saturating_sub(record.first_dirty.unwrap_or(now));
    let job = next
        .job
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let claim = uuid::Uuid::new_v4().to_string();
    let mut statements = Vec::new();
    let existing_job = next.job.is_some();
    if !existing_job {
        next.requested_at = next.first_dirty.or(Some(now));
    }
    next.started_at = Some(now);
    next.finished_at = None;
    next.worker_identity = Some(identity);
    if !existing_job {
        statements.push(queued_job(&next, &job));
    }
    next.job = Some(job.clone());
    next.claim = Some(claim.clone());
    if !existing_job {
        next.requested_revision = next.desired;
    }
    next.desired = Some(snapshot.source.metadata.revision);
    next.track_freshness(now);
    next.pending = false;
    next.first_dirty = None;
    next.last_dirty = None;
    statements.push(provenance_statement(
        &next,
        &job,
        Some(snapshot.source.metadata.revision),
        existing_job,
    ));
    statements.push(statement(
        format!("UPDATE {JOBS_TABLE} SET status = 'running', source_version = $1 WHERE id = $2"),
        vec![
            RelationalValue::Integer(snapshot.source_version() as i64),
            text(&job),
        ],
    ));
    statements.push(save_statement(&next)?);
    let operation = db
        .audit_network_operation(
            "ml_refresh",
            Some(&name),
            &next.audit(Some(&job)).principal_id,
            next.tenant.as_deref(),
            "chironql-ml",
            Some(&job),
        )
        .map_err(engine_error)?;
    if let Err(error) = catalog_sql(
        db,
        statements,
        &next.audit(Some(&job)),
        &next.catalog_lineage,
    ) {
        if error.code == "chironql.ml_commit_unknown" {
            *record = next;
        }
        return Err(error);
    }
    // A failed durable claim cannot launch a child. The one dispatcher owns
    // this single Active slot across manual and automatic submissions.
    record_committed_observation(Some(record), &next);
    *record = next.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let stop = Arc::clone(shared);
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let thread = thread::Builder::new()
        .name("chiron-ml-worker".into())
        .spawn(move || {
            let outcome = worker::run(&worker, &request, &worker_cancel).map_err(|error| MlError {
                code: error.code(),
                message: error.message.clone(),
                transient: error.is_transient(),
            });
            let _ = sender.send(outcome);
            stop.wake.notify_all();
        });
    // Once the claim is durable, retain an Active even if the OS refuses the
    // thread. Completion owns and retries recording this failure when storage
    // is unavailable; otherwise the claim could remain orphaned until restart.
    let (thread, outcome) = match thread {
        Ok(thread) => (Some(thread), None),
        Err(error) => (
            None,
            Some(Err(MlError {
                code: "chironql.ml_worker_resource",
                message: error.to_string(),
                transient: true,
            })),
        ),
    };
    metrics::gauge!("chirondb_ml_active_workers").set(1.0);
    metrics::histogram!("chirondb_ml_queue_age_seconds").record(queue_age as f64 / 1000.0);
    Ok(Some(Active {
        _permit: permit,
        name,
        epoch: next.epoch,
        claim,
        job,
        definition,
        snapshot,
        started: Instant::now(),
        receiver,
        thread,
        outcome,
        cancel,
        operation: Some(operation),
    }))
}

fn reconcile_receipt(db: &Db, record: &mut Schedule, active: &mut Active) -> MlResult<bool> {
    // Resolve an ambiguous commit acknowledgement before attempting publication
    // again. Receipt and generation were committed in the same transaction.
    let receipt = catalog_sql(
        db,
        vec![statement(
            format!("SELECT status FROM {JOBS_TABLE} WHERE id = $1"),
            vec![text(&active.job)],
        )],
        &record.audit(Some(&active.job)),
        &record.catalog_lineage,
    )?;
    if rows(&receipt.results[0])?
        .1
        .first()
        .is_some_and(|row| one_text(&row[0]).ok() == Some("succeeded"))
    {
        let lineage = record.catalog_lineage.clone();
        *record = serde_json::from_str(&stored_state(db, &active.name, &record.catalog_lineage)?)
            .map_err(storage_error)?;
        record.catalog_lineage = lineage;
        if let Some(operation) = active.operation.take() {
            db.finish_committed_network_audit(
                operation,
                json!({"view": active.name, "version": record.version, "reconciled": true}),
            );
        }
        return Ok(true);
    }
    Ok(false)
}

fn complete(db: &Db, inner: &mut Inner, active: &mut Active, now: u64) -> MlResult<()> {
    inner.require_mutations()?;
    let result = complete_inner(db, inner, active, now);
    inner.observe(result)
}

fn complete_inner(db: &Db, inner: &mut Inner, active: &mut Active, now: u64) -> MlResult<()> {
    let record = inner
        .records
        .get_mut(&active.name)
        .ok_or_else(|| storage_error("active ML view disappeared"))?;
    if record.epoch != active.epoch || record.claim.as_deref() != Some(&active.claim) {
        return Err(storage_error(
            "ML publication lease no longer owns this view",
        ));
    }
    let audit = record.audit(Some(&active.job));
    if reconcile_receipt(db, record, active)? {
        return Ok(());
    }
    let mut next = record.clone();
    let outcome = active.outcome.as_ref().expect("completed worker outcome");
    let result = match outcome {
        Ok(result) => {
            next.published = Some(active.snapshot.source.metadata.revision);
            next.track_freshness(now);
            next.version = next.version.saturating_add(1);
            next.last_success = Some(now);
            next.finished_at = Some(now);
            next.failures = 0;
            next.retry_at = None;
            next.error = None;
            next.error_code = None;
            next.blocked = false;
            next.claim = None;
            next.job = None;
            next.manual = false;
            if next.mode == MlRefreshMode::Manual {
                next.pending = false;
            } else if next.desired != next.published {
                next.pending = true;
                next.first_dirty.get_or_insert(now);
                next.last_dirty.get_or_insert(now);
            }
            publish(
                db,
                result,
                Publication {
                    definition: &active.definition,
                    snapshot: &active.snapshot,
                    job_id: &active.job,
                    audit: &audit,
                    duration_ms: active.started.elapsed().as_millis() as i64,
                    schedule: &next,
                },
            )
        }
        Err(error) => Err(MlError {
            code: error.code,
            message: error.message.clone(),
            transient: error.transient,
        }),
    };
    match result {
        Ok((version, _)) => {
            next.version = version as u64;
            *record = next;
            if let Some(operation) = active.operation.take() {
                db.finish_committed_network_audit(operation,
                json!({"view": active.name, "version": version, "source_revision": active.snapshot.source.metadata.revision,
                    "rows": active.snapshot.source.rows.len(), "duration_ms": active.started.elapsed().as_millis()}));
            }
            metrics::counter!("chirondb_ml_refresh_total", "outcome" => "succeeded").increment(1);
        }
        Err(mut error) => {
            // A publication error cannot overwrite a durable success receipt,
            // including failures while serializing an already committed reply.
            if active.outcome.as_ref().is_some_and(Result::is_ok) {
                match reconcile_receipt(db, record, active) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(receipt_error) => {
                        // A failed read cannot erase the original unknown WAL
                        // decision and permit a second publication next tick.
                        return Err(if error.code == "chironql.ml_commit_unknown" {
                            error
                        } else {
                            receipt_error
                        });
                    }
                }
            }
            // Retain the claim/outcome. Unknown WAL decisions latch this root
            // until recovery; other storage failures may retry receipt reads.
            if matches!(
                error.code,
                "chironql.ml_commit_unknown" | "chironql.ml_storage_unavailable"
            ) {
                return Err(error);
            }
            if error.code == "chironql.ml_publication_rejected" {
                // A changed source schema/identity is known pre-publication and
                // permanent until revalidation; ordinary I/O remains uncertain.
                let current = metadata(db, record);
                if current.as_ref().is_ok_and(|source| {
                    source.revision.schema_revision
                        != active.snapshot.source.metadata.revision.schema_revision
                }) {
                    error = MlError {
                        code: "chironql.ml_source_changed",
                        message: "source schema changed during training; retry from a new snapshot"
                            .into(),
                        transient: true,
                    };
                }
            }
            next = record.clone();
            // A permanent failure belongs to the captured snapshot. Preserve a
            // newer intent already observed while this claim was running.
            let newer_pending = !error.transient
                && record.mode == MlRefreshMode::Auto
                && record.pending
                && record
                    .desired
                    .is_some_and(|revision| revision != active.snapshot.source.metadata.revision);
            next.fail(&error, now);
            if newer_pending {
                next.pending = true;
                next.blocked = false;
            }
            catalog_sql(
                db,
                vec![
                    statement(
                        format!(
                            "UPDATE {JOBS_TABLE} SET status = 'failed', error = $1, duration_ms = $2 WHERE id = $3"
                        ),
                        vec![
                            text(format!("{}: {}", error.code, error.message)),
                            RelationalValue::Integer(active.started.elapsed().as_millis() as i64),
                            text(&active.job),
                        ],
                    ),
                    save_statement(&next)?,
                    finish_provenance_statement(db, &active.job, now, &record.catalog_lineage)?,
                ],
                &audit,
                &record.catalog_lineage,
            )?;
            *record = next;
            if let Some(operation) = active.operation.take()
                && let Err(audit_error) = operation.failure_with_details(error.code, json!({"view": active.name,
                    "source_revision": active.snapshot.source.metadata.revision, "duration_ms": active.started.elapsed().as_millis()})) {
                    tracing::error!(%audit_error, "ML failure audit could not be persisted");
            }
            metrics::counter!("chirondb_ml_refresh_total", "outcome" => "failed").increment(1);
        }
    }
    metrics::histogram!("chirondb_ml_worker_seconds")
        .record(active.started.elapsed().as_secs_f64());
    Ok(())
}

fn dispatcher(db: Db, shared: Arc<Shared>) {
    let mut active: Option<Active> = None;
    while !shared.stop.load(Ordering::Acquire) && !db.is_shutting_down() {
        let mut inner = shared.inner.lock().expect("ML scheduler state");
        let lineage_changed = db
            .ml_catalog_lineage()
            .is_ok_and(|lineage| lineage != inner.lineage);
        if !inner.lineage.is_empty()
            && (lineage_changed || (!inner.initialized && !inner.recovery_required))
        {
            if lineage_changed {
                inner.recovery_required = false;
            }
            if let Some(mut running) = active.take() {
                running.cancel.store(true, Ordering::Release);
                if let Some(thread) = running.thread.take() {
                    let _ = thread.join();
                }
            }
            inner.initialized = false;
            inner.records.clear();
            if db
                .relational_tables()
                .iter()
                .any(|table| table.name == VIEWS_TABLE)
                && let Err(error) = ensure_catalog(
                    &db,
                    &mut inner,
                    shared.now(),
                    &audit("ml-restore-recovery", None, None),
                )
            {
                tracing::error!(code = error.code, message = %error.message, "ML restore recovery deferred");
            }
        }
        if inner.initialized && !inner.recovery_required && local_preview(&db).is_ok() {
            let now = shared.now();
            if let Err(error) = reconcile(&db, &mut inner, now) {
                tracing::error!(code = error.code, message = %error.message, "ML reconciliation deferred");
            }
            if !inner.recovery_required
                && let Some(running) = active.as_mut()
            {
                if running.outcome.is_none() {
                    match running.receiver.try_recv() {
                        Ok(outcome) => running.outcome = Some(outcome),
                        Err(mpsc::TryRecvError::Disconnected) => {
                            let mut error = MlError::new(
                                "chironql.ml_worker_failed",
                                "worker thread stopped without a result",
                            );
                            error.transient = true;
                            running.outcome = Some(Err(error));
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                }
                if running.outcome.is_some() {
                    match complete(&db, &mut inner, running, now) {
                        Ok(()) => {
                            if let Some(thread) = running.thread.take() {
                                let _ = thread.join();
                            }
                            active = None;
                            metrics::gauge!("chirondb_ml_active_workers").set(0.0);
                        }
                        Err(error) => {
                            tracing::error!(code = error.code, message = %error.message, "ML completion awaits durable reconciliation")
                        }
                    }
                }
            }
            if !inner.recovery_required && active.is_none() {
                match dispatch(&db, &mut inner, &shared, now) {
                    Ok(next) => active = next,
                    Err(error) => {
                        tracing::error!(code = error.code, message = %error.message, "ML dispatch deferred")
                    }
                }
            }
        }
        if inner.initialized {
            record_freshness_lag(&inner, shared.now());
        }
        let _ = shared
            .wake
            .wait_timeout(inner, Duration::from_secs(1))
            .expect("ML scheduler wake");
    }
    shared.stop.store(true, Ordering::Release);
    if let Some(mut running) = active {
        running.cancel.store(true, Ordering::Release);
        if let Some(thread) = running.thread.take() {
            let _ = thread.join();
        }
    }
    metrics::gauge!("chirondb_ml_active_workers").set(0.0);
}

#[cfg(test)]
mod tests;
