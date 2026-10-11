//! Optional tabular ML jobs over the durable relational engine.
//!
//! One SQL transaction publishes a complete replacement of each result table.
//! The relational engine supplies snapshot reads, WAL ordering, and atomic
//! visibility; this module owns only job orchestration and the worker process.

use std::{
    collections::{HashMap, HashSet},
    env,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, LazyLock, Mutex, Weak},
    thread,
    time::{Duration, Instant},
};

use chirondb_core::{
    Db, RelationalType, RelationalValue, SqlExecutionRequest, SqlResult, SqlStatementRequest,
    TableDefinition, audit::AuditContext,
};
use serde_json::{Value, json};

use crate::chironql_parser::{MlMaterialize, MlModel, MlTask};

const MAX_SOURCE_ROWS: usize = 10_000;
const WORKER_TIMEOUT: Duration = Duration::from_secs(300);
const INSERT_BATCH_ROWS: usize = 400;

const VIEWS_TABLE: &str = "__chiron_ml_views";
const JOBS_TABLE: &str = "__chiron_ml_jobs";

static STATES: LazyLock<Mutex<HashMap<PathBuf, Weak<MlState>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Default)]
struct MlState {
    inner: Mutex<MlStateInner>,
}

#[derive(Default)]
struct MlStateInner {
    initialized: bool,
    active_views: HashSet<String>,
}

#[derive(Debug)]
pub(crate) struct MlError {
    pub code: &'static str,
    pub message: String,
}

impl MlError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(crate) type MlResult<T> = Result<T, MlError>;

#[derive(Debug)]
pub(crate) struct MlSubmitted {
    pub job_id: String,
    pub view: String,
    pub status: &'static str,
}

#[derive(Clone)]
struct WorkerConfig {
    python: PathBuf,
    script: PathBuf,
}

struct SourceSnapshot {
    table: TableDefinition,
    selected_columns: Vec<String>,
    rows: Vec<Vec<RelationalValue>>,
    source_version: u64,
    labeled_rows: usize,
}

fn state_for(db: &Db) -> Arc<MlState> {
    let mut states = STATES.lock().expect("ML state registry mutex");
    let key = db.data_dir();
    if let Some(state) = states.get(&key).and_then(Weak::upgrade) {
        return state;
    }
    let state = Arc::new(MlState::default());
    states.insert(key, Arc::downgrade(&state));
    state
}

fn statement(sql: impl Into<String>, parameters: Vec<RelationalValue>) -> SqlStatementRequest {
    SqlStatementRequest {
        sql: sql.into(),
        parameters,
    }
}

fn execute_sql(
    db: &Db,
    statements: Vec<SqlStatementRequest>,
    audit: &AuditContext,
) -> MlResult<chirondb_core::SqlExecutionResponse> {
    db.execute_sql_with_audit(
        SqlExecutionRequest {
            statements,
            idempotency_key: None,
            retry_id: audit.request_id.clone(),
        },
        audit,
    )
    .map_err(|error| MlError::new("chironql.ml_storage_failed", error.to_string()))
}

fn rows(result: &SqlResult) -> MlResult<(&[String], &[Vec<RelationalValue>])> {
    match result {
        SqlResult::Rows { columns, rows, .. } => Ok((columns, rows)),
        _ => Err(MlError::new(
            "chironql.ml_storage_failed",
            "expected SQL rows",
        )),
    }
}

fn one_text(value: &RelationalValue) -> MlResult<&str> {
    match value {
        RelationalValue::Text(value) => Ok(value),
        _ => Err(MlError::new(
            "chironql.ml_storage_failed",
            "invalid ML catalog value",
        )),
    }
}

fn one_integer(value: &RelationalValue) -> MlResult<i64> {
    match value {
        RelationalValue::Integer(value) => Ok(*value),
        _ => Err(MlError::new(
            "chironql.ml_storage_failed",
            "invalid ML catalog integer",
        )),
    }
}

fn identifier(value: &str) -> MlResult<&str> {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        || value.to_ascii_lowercase().starts_with("__chiron_ml_")
    {
        return Err(MlError::new(
            "chironql.ml_invalid_name",
            "ML names must be simple identifiers outside the reserved namespace",
        ));
    }
    Ok(value)
}

fn model_name(model: MlModel) -> &'static str {
    match model {
        MlModel::DecisionTree => "decision_tree",
        MlModel::RandomForest => "random_forest",
    }
}

fn task_name(task: MlTask) -> &'static str {
    match task {
        MlTask::Classification => "classification",
        MlTask::Regression => "regression",
    }
}

fn canonical_definition(definition: &MlMaterialize) -> String {
    json!({
        "source": definition.source,
        "target": definition.target,
        "features": definition.features,
        "task": task_name(definition.task),
        "model": model_name(definition.model),
    })
    .to_string()
}

fn worker_config() -> MlResult<WorkerConfig> {
    let python = env::var_os("CHIRONDB_ML_WORKER_PYTHON")
        .map(PathBuf::from)
        .ok_or_else(|| {
            MlError::new(
                "chironql.ml_unavailable",
                "CHIRONDB_ML_WORKER_PYTHON is not configured",
            )
        })?;
    let script = env::var_os("CHIRONDB_ML_WORKER_SCRIPT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            MlError::new(
                "chironql.ml_unavailable",
                "CHIRONDB_ML_WORKER_SCRIPT is not configured",
            )
        })?;
    if !python.is_file() || !script.is_file() {
        return Err(MlError::new(
            "chironql.ml_unavailable",
            "configured ML worker executable or script does not exist",
        ));
    }
    Ok(WorkerConfig { python, script })
}

fn ensure_catalog(db: &Db, state: &mut MlStateInner, audit: &AuditContext) -> MlResult<()> {
    if state.initialized {
        return Ok(());
    }
    execute_sql(
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
                    "UPDATE {JOBS_TABLE} SET status = 'failed', error = 'server_restarted' WHERE status = 'queued' OR status = 'running'"
                ),
                vec![],
            ),
        ],
        audit,
    )?;
    state.initialized = true;
    Ok(())
}

fn read_snapshot(db: &Db, definition: &MlMaterialize) -> MlResult<SourceSnapshot> {
    let tables = db.relational_tables();
    crate::chironql_ml::validate_source(definition, &tables)
        .map_err(|message| MlError::new("chironql.ml_invalid_schema", message))?;
    let table = tables
        .into_iter()
        .find(|table| table.name.eq_ignore_ascii_case(&definition.source))
        .expect("validated source table");
    let mut selected_columns = table.primary_key.clone();
    selected_columns.extend(definition.features.iter().cloned());
    selected_columns.push(definition.target.clone());
    for name in &selected_columns {
        identifier(name)?;
    }
    let order = table.primary_key.join(", ");
    let response = db
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                format!(
                    "SELECT {} FROM {} ORDER BY {order} LIMIT {}",
                    selected_columns.join(", "),
                    definition.source,
                    MAX_SOURCE_ROWS + 1,
                ),
                vec![],
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .map_err(|error| MlError::new("chironql.ml_source_failed", error.to_string()))?;
    let (_, result_rows) = rows(&response.results[0])?;
    if result_rows.is_empty() || result_rows.len() > MAX_SOURCE_ROWS {
        return Err(MlError::new(
            "chironql.ml_invalid_rows",
            format!("source must contain 1 to {MAX_SOURCE_ROWS} rows"),
        ));
    }
    let labeled_rows = result_rows
        .iter()
        .filter(|row| !matches!(row.last(), Some(RelationalValue::Null)))
        .count();
    if labeled_rows == 0 || labeled_rows == result_rows.len() {
        return Err(MlError::new(
            "chironql.ml_invalid_rows",
            "source must contain both labeled rows and NULL targets",
        ));
    }
    Ok(SourceSnapshot {
        table,
        selected_columns,
        rows: result_rows.to_vec(),
        source_version: response.snapshot,
        labeled_rows,
    })
}

pub(crate) fn submit(
    db: &Db,
    definition: &MlMaterialize,
    actor: &str,
    tenant_id: Option<&str>,
) -> MlResult<MlSubmitted> {
    for name in [&definition.view, &definition.source, &definition.target] {
        identifier(name)?;
    }
    if definition.view.eq_ignore_ascii_case(&definition.source) {
        return Err(MlError::new(
            "chironql.ml_invalid_name",
            "view and source table must have different names",
        ));
    }
    let worker = worker_config()?;
    let state = state_for(db);
    let mut guard = state.inner.lock().expect("ML view state mutex");
    let audit = AuditContext {
        principal_id: actor.into(),
        tenant_id: tenant_id.map(str::to_string),
        transport: "chironql-ml".into(),
        request_id: None,
    };
    ensure_catalog(db, &mut guard, &audit)?;
    if guard.active_views.contains(&definition.view) {
        return Err(MlError::new(
            "chironql.ml_refresh_running",
            "a refresh for this view is already running",
        ));
    }
    let existing = execute_sql(
        db,
        vec![statement(
            format!("SELECT definition FROM {VIEWS_TABLE} WHERE name = $1"),
            vec![RelationalValue::Text(definition.view.clone())],
        )],
        &audit,
    )?;
    let (_, existing_rows) = rows(&existing.results[0])?;
    let canonical = canonical_definition(definition);
    if let Some(row) = existing_rows.first() {
        if one_text(&row[0])? != canonical {
            return Err(MlError::new(
                "chironql.ml_definition_conflict",
                "view already has a different ML definition; drop it before changing parameters",
            ));
        }
    } else if db
        .relational_tables()
        .iter()
        .any(|table| table.name.eq_ignore_ascii_case(&definition.view))
    {
        return Err(MlError::new(
            "chironql.ml_name_conflict",
            "view name already belongs to a relational table",
        ));
    }
    let snapshot = read_snapshot(db, definition)?;
    let job_id = uuid::Uuid::new_v4().to_string();
    let mut statements = Vec::new();
    if existing_rows.is_empty() {
        statements.push(statement(
            format!("INSERT INTO {VIEWS_TABLE} (name, definition, source, version) VALUES ($1, $2, $3, 0)"),
            vec![
                RelationalValue::Text(definition.view.clone()),
                RelationalValue::Text(canonical),
                RelationalValue::Text(definition.source.clone()),
            ],
        ));
    }
    statements.push(statement(
        format!("INSERT INTO {JOBS_TABLE} (id, view_name, status, source_version) VALUES ($1, $2, 'queued', $3)"),
        vec![
            RelationalValue::Text(job_id.clone()),
            RelationalValue::Text(definition.view.clone()),
            RelationalValue::Integer(snapshot.source_version as i64),
        ],
    ));
    execute_sql(db, statements, &audit)?;
    guard.active_views.insert(definition.view.clone());
    drop(guard);

    let view = definition.view.clone();
    let db = db.clone();
    let definition = definition.clone();
    let job = job_id.clone();
    thread::spawn(move || run_job(db, state, worker, definition, snapshot, job, audit));
    Ok(MlSubmitted {
        job_id,
        view,
        status: "queued",
    })
}

fn value_json(value: &RelationalValue) -> MlResult<Value> {
    match value {
        RelationalValue::Null => Ok(Value::Null),
        RelationalValue::Boolean(value) => Ok(json!(value)),
        RelationalValue::Integer(value) => Ok(json!(value)),
        RelationalValue::Float(value) => Ok(json!(value)),
        RelationalValue::Decimal(value) => value
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .map(|value| json!(value))
            .ok_or_else(|| MlError::new("chironql.ml_invalid_rows", "non-finite decimal value")),
        RelationalValue::Text(value)
        | RelationalValue::Date(value)
        | RelationalValue::TimestampUtc(value) => Ok(json!(value)),
        RelationalValue::Uuid(value) => Ok(json!(value.to_string())),
        _ => Err(MlError::new(
            "chironql.ml_invalid_rows",
            "source value has an unsupported ML type",
        )),
    }
}

fn worker_request(definition: &MlMaterialize, snapshot: &SourceSnapshot) -> MlResult<Value> {
    let rows = snapshot
        .rows
        .iter()
        .map(|row| {
            let mut object = serde_json::Map::new();
            for (name, value) in snapshot.selected_columns.iter().zip(row) {
                object.insert(name.clone(), value_json(value)?);
            }
            Ok(Value::Object(object))
        })
        .collect::<MlResult<Vec<_>>>()?;
    let training_rows = rows
        .iter()
        .filter(|row| !row[&definition.target].is_null())
        .cloned()
        .collect::<Vec<_>>();
    Ok(json!({
        "model": model_name(definition.model),
        "task": task_name(definition.task),
        "features": definition.features,
        "target": definition.target,
        "training_rows": training_rows,
        "prediction_rows": rows,
    }))
}

fn run_worker(config: &WorkerConfig, request: &Value) -> MlResult<Value> {
    let input = serde_json::to_vec(request)
        .map_err(|error| MlError::new("chironql.ml_worker_failed", error.to_string()))?;
    if input.len() > 8 * 1024 * 1024 {
        return Err(MlError::new(
            "chironql.ml_invalid_rows",
            "worker request exceeds 8 MiB",
        ));
    }
    let mut command = Command::new(&config.python);
    command
        .arg(&config.script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PYTHONNOUSERSITE", "1");
    if let Some(system_root) = env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .spawn()
        .map_err(|error| MlError::new("chironql.ml_worker_failed", error.to_string()))?;
    let mut stdin = child.stdin.take().expect("piped worker stdin");
    let stdout = child.stdout.take().expect("piped worker stdout");
    let stderr = child.stderr.take().expect("piped worker stderr");
    let output_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let error_reader = thread::spawn(move || {
        let mut output = Vec::new();
        stderr
            .take(64 * 1024 + 1)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let input_writer = thread::spawn(move || stdin.write_all(&input));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < WORKER_TIMEOUT => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MlError::new(
                    "chironql.ml_worker_timeout",
                    "ML worker exceeded five minutes",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MlError::new("chironql.ml_worker_failed", error.to_string()));
            }
        }
    };
    let output = output_reader
        .join()
        .map_err(|_| MlError::new("chironql.ml_worker_failed", "worker output reader panicked"))?
        .map_err(|error| MlError::new("chironql.ml_worker_failed", error.to_string()))?;
    input_writer
        .join()
        .map_err(|_| MlError::new("chironql.ml_worker_failed", "worker input writer panicked"))?
        .map_err(|error| MlError::new("chironql.ml_worker_failed", error.to_string()))?;
    let stderr = error_reader
        .join()
        .map_err(|_| MlError::new("chironql.ml_worker_failed", "worker error reader panicked"))?
        .map_err(|error| MlError::new("chironql.ml_worker_failed", error.to_string()))?;
    if output.len() > 8 * 1024 * 1024 || stderr.len() > 64 * 1024 {
        return Err(MlError::new(
            "chironql.ml_worker_failed",
            "worker output exceeded its size limit",
        ));
    }
    let message: Value = serde_json::from_slice(&output).map_err(|_| {
        MlError::new(
            "chironql.ml_worker_failed",
            "worker did not return a valid JSON response",
        )
    })?;
    if !status.success() || message["ok"] != true {
        let error = message["error"]
            .as_str()
            .unwrap_or("worker exited without a result");
        return Err(MlError::new("chironql.ml_worker_failed", error));
    }
    Ok(message["result"].clone())
}

fn sql_type(data_type: &RelationalType) -> MlResult<String> {
    Ok(match data_type {
        RelationalType::Boolean => "BOOLEAN".into(),
        RelationalType::SmallInt => "SMALLINT".into(),
        RelationalType::Integer => "INTEGER".into(),
        RelationalType::BigInt => "BIGINT".into(),
        RelationalType::Real => "REAL".into(),
        RelationalType::Float => "DOUBLE PRECISION".into(),
        RelationalType::Decimal { precision, scale } => format!("DECIMAL({precision}, {scale})"),
        RelationalType::Text => "TEXT".into(),
        RelationalType::Varchar { length } => format!("VARCHAR({length})"),
        RelationalType::Date => "DATE".into(),
        RelationalType::TimestampUtc => "TIMESTAMP WITH TIME ZONE".into(),
        RelationalType::Uuid => "UUID".into(),
        _ => {
            return Err(MlError::new(
                "chironql.ml_invalid_schema",
                "source column type cannot be materialized",
            ));
        }
    })
}

fn prediction_value(
    value: &Value,
    task: MlTask,
    target_type: &RelationalType,
) -> MlResult<RelationalValue> {
    if task == MlTask::Regression {
        let value = value
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or_else(|| {
                MlError::new(
                    "chironql.ml_worker_failed",
                    "worker returned a non-numeric prediction",
                )
            })?;
        return Ok(RelationalValue::Float(value));
    }
    match target_type {
        RelationalType::Boolean => value.as_bool().map(RelationalValue::Boolean),
        RelationalType::SmallInt | RelationalType::Integer | RelationalType::BigInt => {
            value.as_i64().map(RelationalValue::Integer)
        }
        RelationalType::Text | RelationalType::Varchar { .. } => value
            .as_str()
            .map(|value| RelationalValue::Text(value.to_string())),
        _ => None,
    }
    .ok_or_else(|| {
        MlError::new(
            "chironql.ml_worker_failed",
            "worker returned an invalid class",
        )
    })
}

fn result_schema(definition: &MlMaterialize, snapshot: &SourceSnapshot) -> MlResult<String> {
    let mut columns = Vec::new();
    for name in snapshot
        .selected_columns
        .iter()
        .take(snapshot.selected_columns.len() - 1)
    {
        let column = snapshot
            .table
            .columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(name))
            .expect("validated source column");
        columns.push(format!("{name} {}", sql_type(&column.data_type)?));
    }
    let target_type = &snapshot
        .table
        .columns
        .iter()
        .find(|column| column.name.eq_ignore_ascii_case(&definition.target))
        .expect("validated target")
        .data_type;
    let prediction_type = if definition.task == MlTask::Regression {
        "DOUBLE PRECISION".to_string()
    } else {
        sql_type(target_type)?
    };
    columns.push(format!("actual {}", sql_type(target_type)?));
    columns.push(format!("prediction {prediction_type}"));
    columns.push("confidence DOUBLE PRECISION".into());
    columns.push("refresh_version BIGINT NOT NULL".into());
    columns.push(format!(
        "PRIMARY KEY ({})",
        snapshot.table.primary_key.join(", ")
    ));
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {} ({})",
        definition.view,
        columns.join(", ")
    ))
}

fn publish(
    db: &Db,
    definition: &MlMaterialize,
    snapshot: &SourceSnapshot,
    job_id: &str,
    result: &Value,
    audit: &AuditContext,
    duration_ms: i64,
) -> MlResult<(i64, usize)> {
    let predictions = result["predictions"].as_array().ok_or_else(|| {
        MlError::new(
            "chironql.ml_worker_failed",
            "worker returned no predictions",
        )
    })?;
    let confidences = result["confidence"].as_array().ok_or_else(|| {
        MlError::new(
            "chironql.ml_worker_failed",
            "worker returned no confidence array",
        )
    })?;
    if predictions.len() != snapshot.rows.len() || confidences.len() != snapshot.rows.len() {
        return Err(MlError::new(
            "chironql.ml_worker_failed",
            "worker returned a different number of rows",
        ));
    }
    let context_rows = result["context_rows"].as_u64().ok_or_else(|| {
        MlError::new(
            "chironql.ml_worker_failed",
            "worker omitted context row count",
        )
    })? as usize;
    if context_rows == 0 || context_rows > snapshot.labeled_rows {
        return Err(MlError::new(
            "chironql.ml_worker_failed",
            "worker reported an invalid context row count",
        ));
    }
    let target_type = &snapshot
        .table
        .columns
        .iter()
        .find(|column| column.name.eq_ignore_ascii_case(&definition.target))
        .expect("validated target")
        .data_type;
    let catalog = execute_sql(
        db,
        vec![statement(
            format!("SELECT version FROM {VIEWS_TABLE} WHERE name = $1"),
            vec![RelationalValue::Text(definition.view.clone())],
        )],
        audit,
    )?;
    let (_, catalog_rows) = rows(&catalog.results[0])?;
    let previous = catalog_rows
        .first()
        .ok_or_else(|| MlError::new("chironql.ml_storage_failed", "ML view definition vanished"))?;
    let version = one_integer(&previous[0])? + 1;
    let mut statements = vec![
        statement(result_schema(definition, snapshot)?, vec![]),
        statement(format!("DELETE FROM {}", definition.view), vec![]),
    ];
    let column_names = snapshot
        .selected_columns
        .iter()
        .take(snapshot.selected_columns.len() - 1)
        .cloned()
        .chain(["actual", "prediction", "confidence", "refresh_version"].map(str::to_string))
        .collect::<Vec<_>>();
    for (start, batch) in snapshot.rows.chunks(INSERT_BATCH_ROWS).enumerate() {
        let mut parameters = Vec::new();
        let mut tuples = Vec::new();
        for (offset, row) in batch.iter().enumerate() {
            let index = start * INSERT_BATCH_ROWS + offset;
            let prediction = prediction_value(&predictions[index], definition.task, target_type)?;
            let confidence = if confidences[index].is_null() {
                RelationalValue::Null
            } else {
                let value = confidences[index]
                    .as_f64()
                    .filter(|value| (0.0..=1.0).contains(value))
                    .ok_or_else(|| {
                        MlError::new("chironql.ml_worker_failed", "invalid prediction confidence")
                    })?;
                RelationalValue::Float(value)
            };
            parameters.extend(row.iter().cloned());
            parameters.push(prediction);
            parameters.push(confidence);
            parameters.push(RelationalValue::Integer(version));
            let first = parameters.len() - column_names.len() + 1;
            let placeholders = (first..first + column_names.len())
                .map(|index| format!("${index}"))
                .collect::<Vec<_>>()
                .join(", ");
            tuples.push(format!("({placeholders})"));
        }
        statements.push(statement(
            format!(
                "INSERT INTO {} ({}) VALUES {}",
                definition.view,
                column_names.join(", "),
                tuples.join(", ")
            ),
            parameters,
        ));
    }
    statements.push(statement(
        format!("UPDATE {VIEWS_TABLE} SET version = $1, source_version = $2, row_count = $3 WHERE name = $4"),
        vec![
            RelationalValue::Integer(version),
            RelationalValue::Integer(snapshot.source_version as i64),
            RelationalValue::Integer(snapshot.rows.len() as i64),
            RelationalValue::Text(definition.view.clone()),
        ],
    ));
    statements.push(statement(
        format!("UPDATE {JOBS_TABLE} SET status = 'succeeded', row_count = $1, context_rows = $2, duration_ms = $3 WHERE id = $4"),
        vec![
            RelationalValue::Integer(snapshot.rows.len() as i64),
            RelationalValue::Integer(context_rows as i64),
            RelationalValue::Integer(duration_ms),
            RelationalValue::Text(job_id.to_string()),
        ],
    ));
    execute_sql(db, statements, audit)?;
    Ok((version, context_rows))
}

fn mark_failed(db: &Db, job_id: &str, error: &MlError, audit: &AuditContext, duration_ms: i64) {
    let _ = execute_sql(
        db,
        vec![statement(
            format!(
                "UPDATE {JOBS_TABLE} SET status = 'failed', error = $1, duration_ms = $2 WHERE id = $3"
            ),
            vec![
                RelationalValue::Text(format!("{}: {}", error.code, error.message)),
                RelationalValue::Integer(duration_ms),
                RelationalValue::Text(job_id.into()),
            ],
        )],
        audit,
    );
}

fn run_job(
    db: Db,
    state: Arc<MlState>,
    worker: WorkerConfig,
    definition: MlMaterialize,
    snapshot: SourceSnapshot,
    job_id: String,
    audit: AuditContext,
) {
    let started = Instant::now();
    let operation = db.audit_network_operation(
        "ml_materialize",
        None,
        &audit.principal_id,
        audit.tenant_id.as_deref(),
        &audit.transport,
        Some(&job_id),
    );
    let outcome = (|| {
        execute_sql(
            &db,
            vec![statement(
                format!("UPDATE {JOBS_TABLE} SET status = 'running' WHERE id = $1"),
                vec![RelationalValue::Text(job_id.clone())],
            )],
            &audit,
        )?;
        let request = worker_request(&definition, &snapshot)?;
        let result = run_worker(&worker, &request)?;
        publish(
            &db,
            &definition,
            &snapshot,
            &job_id,
            &result,
            &audit,
            started.elapsed().as_millis() as i64,
        )
    })();
    match outcome {
        Ok((version, context_rows)) => {
            if let Ok(operation) = operation {
                let _ = operation.success(json!({
                    "view": definition.view,
                    "model": model_name(definition.model),
                    "source_version": snapshot.source_version,
                    "version": version,
                    "rows": snapshot.rows.len(),
                    "context_rows": context_rows,
                    "duration_ms": started.elapsed().as_millis(),
                }));
            }
        }
        Err(error) => {
            mark_failed(
                &db,
                &job_id,
                &error,
                &audit,
                started.elapsed().as_millis() as i64,
            );
            if let Ok(operation) = operation {
                let _ = operation.failure_with_details(
                    error.code,
                    json!({
                        "view": definition.view,
                        "model": model_name(definition.model),
                        "source_version": snapshot.source_version,
                        "duration_ms": started.elapsed().as_millis(),
                    }),
                );
            }
        }
    }
    state
        .inner
        .lock()
        .expect("ML view state mutex")
        .active_views
        .remove(&definition.view);
}

fn read_ready(db: &Db) -> MlResult<()> {
    let state = state_for(db);
    let mut guard = state.inner.lock().expect("ML view state mutex");
    ensure_catalog(
        db,
        &mut guard,
        &AuditContext {
            principal_id: "ml-recovery".into(),
            tenant_id: None,
            transport: "chironql-ml".into(),
            request_id: None,
        },
    )
}

pub(crate) fn get_job(db: &Db, job_id: &str) -> MlResult<Value> {
    if job_id.is_empty() || !job_id.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-') {
        return Err(MlError::new("chironql.ml_invalid_job", "invalid ML job ID"));
    }
    read_ready(db)?;
    let response = db
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                format!("SELECT id, view_name, status, source_version, row_count, context_rows, error, duration_ms FROM {JOBS_TABLE} WHERE id = $1"),
                vec![RelationalValue::Text(job_id.into())],
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .map_err(|error| MlError::new("chironql.ml_storage_failed", error.to_string()))?;
    let (columns, data) = rows(&response.results[0])?;
    let row = data
        .first()
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML job was not found"))?;
    let mut object = serde_json::Map::new();
    for (name, value) in columns.iter().zip(row) {
        object.insert(name.clone(), value_json(value)?);
    }
    Ok(Value::Object(object))
}

pub(crate) fn drop_view(
    db: &Db,
    name: &str,
    actor: &str,
    tenant_id: Option<&str>,
) -> MlResult<Value> {
    identifier(name)?;
    let state = state_for(db);
    let mut guard = state.inner.lock().expect("ML view state mutex");
    let audit = AuditContext {
        principal_id: actor.into(),
        tenant_id: tenant_id.map(str::to_string),
        transport: "chironql-ml".into(),
        request_id: None,
    };
    ensure_catalog(db, &mut guard, &audit)?;
    if guard.active_views.contains(name) {
        return Err(MlError::new(
            "chironql.ml_refresh_running",
            "cannot drop a view while its refresh is running",
        ));
    }
    let catalog = execute_sql(
        db,
        vec![statement(
            format!("SELECT name FROM {VIEWS_TABLE} WHERE name = $1"),
            vec![RelationalValue::Text(name.into())],
        )],
        &audit,
    )?;
    if rows(&catalog.results[0])?.1.is_empty() {
        return Err(MlError::new(
            "chironql.ml_not_found",
            "ML view was not found",
        ));
    }
    execute_sql(
        db,
        vec![
            statement(format!("DROP TABLE IF EXISTS {name}"), vec![]),
            statement(
                format!("DELETE FROM {VIEWS_TABLE} WHERE name = $1"),
                vec![RelationalValue::Text(name.into())],
            ),
        ],
        &audit,
    )?;
    Ok(json!({"name": name, "dropped": true}))
}

pub(crate) fn get_view(db: &Db, name: &str, limit: usize, cursor: Option<&str>) -> MlResult<Value> {
    identifier(name)?;
    if !(1..=1000).contains(&limit) {
        return Err(MlError::new(
            "chironql.ml_invalid_page",
            "limit must be between 1 and 1000",
        ));
    }
    read_ready(db)?;
    let catalog = db
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                format!(
                    "SELECT version, source_version, row_count FROM {VIEWS_TABLE} WHERE name = $1"
                ),
                vec![RelationalValue::Text(name.into())],
            )],
            idempotency_key: None,
            retry_id: None,
        })
        .map_err(|error| MlError::new("chironql.ml_storage_failed", error.to_string()))?;
    let (_, records) = rows(&catalog.results[0])?;
    let record = records
        .first()
        .ok_or_else(|| MlError::new("chironql.ml_not_found", "ML view was not found"))?;
    let version = one_integer(&record[0])?;
    if version == 0 {
        return Err(MlError::new(
            "chironql.ml_not_ready",
            "ML view has no successful generation yet",
        ));
    }
    let offset = if let Some(cursor) = cursor {
        let (cursor_version, cursor_offset) = cursor
            .split_once(':')
            .ok_or_else(|| MlError::new("chironql.ml_invalid_page", "invalid view cursor"))?;
        if cursor_version.parse::<i64>().ok() != Some(version) {
            return Err(MlError::new(
                "chironql.ml_stale_cursor",
                "view was refreshed; restart pagination",
            ));
        }
        cursor_offset
            .parse::<usize>()
            .map_err(|_| MlError::new("chironql.ml_invalid_page", "invalid view cursor"))?
    } else {
        0
    };
    let table = db
        .relational_tables()
        .into_iter()
        .find(|table| table.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| MlError::new("chironql.ml_storage_failed", "published ML table vanished"))?;
    let order = table.primary_key.join(", ");
    let response = db
        .execute_sql(SqlExecutionRequest {
            statements: vec![
                statement(
                    format!("SELECT version, source_version, row_count FROM {VIEWS_TABLE} WHERE name = $1"),
                    vec![RelationalValue::Text(name.into())],
                ),
                statement(
                    format!("SELECT * FROM {name} ORDER BY {order} LIMIT {} OFFSET {offset}", limit + 1),
                    vec![],
                ),
            ],
            idempotency_key: None,
            retry_id: None,
        })
        .map_err(|error| MlError::new("chironql.ml_storage_failed", error.to_string()))?;
    let (_, current_records) = rows(&response.results[0])?;
    let current = current_records
        .first()
        .ok_or_else(|| MlError::new("chironql.ml_storage_failed", "ML view definition vanished"))?;
    let current_version = one_integer(&current[0])?;
    if cursor.is_some() && current_version != version {
        return Err(MlError::new(
            "chironql.ml_stale_cursor",
            "view was refreshed; restart pagination",
        ));
    }
    let (columns, data) = rows(&response.results[1])?;
    let has_next = data.len() > limit;
    let page = data
        .iter()
        .take(limit)
        .map(|row| {
            let mut object = serde_json::Map::new();
            for (name, value) in columns.iter().zip(row) {
                object.insert(name.clone(), value_json(value)?);
            }
            Ok(Value::Object(object))
        })
        .collect::<MlResult<Vec<_>>>()?;
    Ok(json!({
        "name": name,
        "version": current_version,
        "source_version": one_integer(&current[1])?,
        "row_count": one_integer(&current[2])?,
        "columns": columns,
        "rows": page,
        "next": has_next.then(|| format!("{}:{}", current_version, offset + limit)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_interrupted_job_failed_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let id = "5d18a62b-e737-4103-849f-7640804f9a1f";
        {
            let db = Db::open(directory.path()).unwrap();
            read_ready(&db).unwrap();
            execute_sql(
                &db,
                vec![statement(
                    format!("INSERT INTO {JOBS_TABLE} (id, view_name, status, source_version) VALUES ($1, 'stale', 'running', 7)"),
                    vec![RelationalValue::Text(id.into())],
                )],
                &AuditContext {
                    principal_id: "ml-recovery-test".into(),
                    tenant_id: None,
                    transport: "chironql-ml".into(),
                    request_id: None,
                },
            )
            .unwrap();
        }
        let reopened = Db::open(directory.path()).unwrap();
        let job = get_job(&reopened, id).unwrap();
        assert_eq!(job["status"], "failed");
        assert_eq!(job["error"], "server_restarted");
        assert_eq!(job["source_version"], 7);
    }
}
