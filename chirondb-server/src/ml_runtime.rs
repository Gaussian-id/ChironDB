//! Optional tabular ML jobs over the durable relational engine.
//!
//! One SQL transaction publishes a complete replacement of each result table.
//! The relational engine supplies snapshot reads, WAL ordering, and atomic
//! visibility; this module owns only job orchestration and the worker process.

mod scheduler;
mod worker;

use chirondb_types::{MlRefreshMode, MlRefreshStatus};
use scheduler::read_ready;
pub(crate) use scheduler::{get_refresh_status, set_refresh_policy};
use std::{env, path::PathBuf};
use worker::WorkerConfig;

/// Recover persisted ML schedules before accepting protocol traffic.
pub fn initialize(db: &Db) -> Result<(), String> {
    scheduler::initialize(db).map_err(|error| format!("{}: {}", error.code, error.message))
}

use chirondb_core::{
    Db, MlSourceSnapshot, RelationalType, RelationalValue, SqlExecutionRequest, SqlResult,
    SqlStatementRequest, audit::AuditContext,
};
use serde_json::{Value, json};

use crate::chironql_parser::{MlMaterialize, MlModel, MlTask};

const MAX_SOURCE_ROWS: usize = 10_000;
const INSERT_BATCH_ROWS: usize = 400;

const VIEWS_TABLE: &str = "__chiron_ml_views";
const JOBS_TABLE: &str = "__chiron_ml_jobs";

#[derive(Debug)]
pub(crate) struct MlError {
    pub code: &'static str,
    pub message: String,
    transient: bool,
}

impl MlError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            transient: false,
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

struct SourceSnapshot {
    source: MlSourceSnapshot,
    labeled_rows: usize,
}

impl SourceSnapshot {
    fn source_version(&self) -> u64 {
        self.source.sequence
    }
}

fn local_preview(db: &Db) -> MlResult<()> {
    if db.identity_authority().is_some() || db.tenant_enforcement().blocks() {
        return Err(MlError::new(
            "chironql.ml_protected_denied",
            "tabular ML is available only in the local evaluation profile",
        ));
    }
    if db.is_shutting_down() {
        return Err(MlError::new(
            "chironql.ml_unavailable",
            "server is shutting down",
        ));
    }
    Ok(())
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
    .map_err(engine_error)
}

fn engine_error(error: chirondb_core::GaussError) -> MlError {
    use chirondb_core::GaussError;
    let (code, transient) = match &error {
        GaussError::SqlLimitExceeded(_) => ("chironql.ml_limit_exceeded", false),
        GaussError::ResourceExhausted(_) => ("chironql.ml_resource_exhausted", true),
        GaussError::CommitOutcomeUnknown { .. } => ("chironql.ml_commit_unknown", true),
        GaussError::Io(_) | GaussError::WalUnavailable(_) | GaussError::AuditUnavailable(_) => {
            ("chironql.ml_storage_unavailable", true)
        }
        _ => ("chironql.ml_storage_failed", false),
    };
    MlError {
        code,
        message: error.to_string(),
        transient,
    }
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

fn read_snapshot(db: &Db, definition: &MlMaterialize) -> MlResult<SourceSnapshot> {
    local_preview(db)?;
    let selected = definition
        .features
        .iter()
        .cloned()
        .chain([definition.target.clone()])
        .collect::<Vec<_>>();
    let source = db
        .ml_source_snapshot(&definition.source, &selected, MAX_SOURCE_ROWS)
        .map_err(engine_error)?;
    crate::chironql_ml::validate_source(definition, std::slice::from_ref(&source.metadata.table))
        .map_err(|message| MlError::new("chironql.ml_invalid_schema", message))?;
    let labeled_rows = source
        .rows
        .iter()
        .filter(|row| !matches!(row.last(), Some(RelationalValue::Null)))
        .count();
    if source.rows.is_empty() || labeled_rows == 0 || labeled_rows == source.rows.len() {
        return Err(MlError::new(
            "chironql.ml_invalid_rows",
            "source must contain labeled rows and NULL targets",
        ));
    }
    Ok(SourceSnapshot {
        source,
        labeled_rows,
    })
}

pub(crate) fn submit(
    db: &Db,
    definition: &MlMaterialize,
    actor: &str,
    tenant_id: Option<&str>,
) -> MlResult<MlSubmitted> {
    scheduler::submit(db, definition, actor, tenant_id)
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
        .source
        .rows
        .iter()
        .map(|row| {
            let mut object = serde_json::Map::new();
            for (name, value) in snapshot.source.selected_columns.iter().zip(row) {
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
        .source
        .selected_columns
        .iter()
        .take(snapshot.source.selected_columns.len() - 1)
    {
        let column = snapshot
            .source
            .metadata
            .table
            .columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(name))
            .expect("validated source column");
        columns.push(format!("{name} {}", sql_type(&column.data_type)?));
    }
    let target_type = &snapshot
        .source
        .metadata
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
        snapshot.source.metadata.table.primary_key.join(", ")
    ));
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {} ({})",
        definition.view,
        columns.join(", ")
    ))
}

fn output_schema_changed(db: &Db, definition: &MlMaterialize, snapshot: &SourceSnapshot) -> bool {
    let Some(existing) = db
        .relational_tables()
        .into_iter()
        .find(|table| table.name.eq_ignore_ascii_case(&definition.view))
    else {
        return false;
    };
    let source = &snapshot.source.metadata.table;
    let mut expected = snapshot
        .source
        .selected_columns
        .iter()
        .take(snapshot.source.selected_columns.len() - 1)
        .map(|name| {
            let column = source
                .columns
                .iter()
                .find(|column| column.name.eq_ignore_ascii_case(name))
                .expect("validated source column");
            (name.clone(), column.data_type.clone())
        })
        .collect::<Vec<_>>();
    let target = &source
        .columns
        .iter()
        .find(|column| column.name.eq_ignore_ascii_case(&definition.target))
        .expect("validated target")
        .data_type;
    expected.extend([
        ("actual".into(), target.clone()),
        (
            "prediction".into(),
            if definition.task == MlTask::Regression {
                RelationalType::Float
            } else {
                target.clone()
            },
        ),
        ("confidence".into(), RelationalType::Float),
        ("refresh_version".into(), RelationalType::BigInt),
    ]);
    existing.primary_key != source.primary_key
        || existing.columns.len() != expected.len()
        || existing
            .columns
            .iter()
            .zip(expected)
            .any(|(actual, (name, kind))| {
                !actual.name.eq_ignore_ascii_case(&name) || actual.data_type != kind
            })
}

struct Publication<'a> {
    definition: &'a MlMaterialize,
    snapshot: &'a SourceSnapshot,
    job_id: &'a str,
    audit: &'a AuditContext,
    duration_ms: i64,
    schedule: &'a scheduler::Schedule,
}

fn publish(db: &Db, result: &Value, publication: Publication<'_>) -> MlResult<(i64, usize)> {
    let Publication {
        definition,
        snapshot,
        job_id,
        audit,
        duration_ms,
        schedule,
    } = publication;
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
    if predictions.len() != snapshot.source.rows.len()
        || confidences.len() != snapshot.source.rows.len()
    {
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
        .source
        .metadata
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
    let mut statements = Vec::new();
    // Compatible source type changes may require a new output schema. Drop +
    // create is in the same publication transaction, preserving the old view
    // in every reader snapshot until the complete replacement commits.
    if output_schema_changed(db, definition, snapshot) {
        statements.push(statement(format!("DROP TABLE {}", definition.view), vec![]));
    }
    statements.push(statement(result_schema(definition, snapshot)?, vec![]));
    statements.push(statement(
        format!("DELETE FROM {}", definition.view),
        vec![],
    ));
    let column_names = snapshot
        .source
        .selected_columns
        .iter()
        .take(snapshot.source.selected_columns.len() - 1)
        .cloned()
        .chain(["actual", "prediction", "confidence", "refresh_version"].map(str::to_string))
        .collect::<Vec<_>>();
    for (start, batch) in snapshot.source.rows.chunks(INSERT_BATCH_ROWS).enumerate() {
        let mut parameters = Vec::new();
        let mut tuples = Vec::new();
        for (offset, row) in batch.iter().enumerate() {
            let index = start * INSERT_BATCH_ROWS + offset;
            let prediction = prediction_value(&predictions[index], definition.task, target_type)?;
            let confidence = if definition.task == MlTask::Regression
                || confidences[index].is_null()
            {
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
            RelationalValue::Integer(snapshot.source_version() as i64),
            RelationalValue::Integer(snapshot.source.rows.len() as i64),
            RelationalValue::Text(definition.view.clone()),
        ],
    ));
    statements.push(statement(
        format!("UPDATE {JOBS_TABLE} SET status = 'succeeded', row_count = $1, context_rows = $2, duration_ms = $3 WHERE id = $4"),
        vec![
            RelationalValue::Integer(snapshot.source.rows.len() as i64),
            RelationalValue::Integer(context_rows as i64),
            RelationalValue::Integer(duration_ms),
            RelationalValue::Text(job_id.to_string()),
        ],
    ));
    local_preview(db)?;
    statements.push(scheduler::save_statement(schedule)?);
    statements.push(scheduler::finish_provenance_statement(
        db,
        job_id,
        schedule.finished_at(),
        &snapshot.source.metadata.lineage,
    )?);
    let fence = chirondb_core::MlPublicationFence {
        schedule_name: definition.view.clone(),
        schedule_state: scheduler::stored_state(
            db,
            &definition.view,
            &snapshot.source.metadata.lineage,
        )?,
    };
    db.execute_ml_publication(
        SqlExecutionRequest {
            statements,
            idempotency_key: None,
            retry_id: audit.request_id.clone(),
        },
        audit,
        &snapshot.source.metadata,
        Some(&fence),
    )
    .and_then(|response| response.consume(Ok))
    .map_err(|error| {
        if matches!(error, chirondb_core::GaussError::InvalidRequest(_)) {
            MlError::new("chironql.ml_publication_rejected", error.to_string())
        } else {
            engine_error(error)
        }
    })?;
    Ok((version, context_rows))
}

pub(crate) fn get_job(db: &Db, job_id: &str) -> MlResult<Value> {
    if job_id.is_empty() || !job_id.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-') {
        return Err(MlError::new("chironql.ml_invalid_job", "invalid ML job ID"));
    }
    local_preview(db)?;
    read_ready(db)?;
    let response = db
        .execute_sql(SqlExecutionRequest {
            statements: vec![statement(
                format!("SELECT id, view_name, status, source_version, row_count, context_rows, error, duration_ms FROM {JOBS_TABLE} WHERE id = $1"),
                vec![RelationalValue::Text(job_id.into())],
            ), statement(format!("SELECT details FROM {} WHERE id = $1", scheduler::PROVENANCE_TABLE), vec![RelationalValue::Text(job_id.into())])],
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
    if let Some(row) = rows(&response.results[1])?.1.first() {
        let details: serde_json::Map<String, Value> = serde_json::from_str(one_text(&row[0])?)
            .map_err(|error| MlError::new("chironql.ml_storage_failed", error.to_string()))?;
        object.extend(details);
    } else {
        object.insert("requested_revision".into(), Value::Null);
        object.insert("source_revision".into(), Value::Null);
    }
    Ok(Value::Object(object))
}

pub(crate) fn drop_view(
    db: &Db,
    name: &str,
    actor: &str,
    tenant_id: Option<&str>,
) -> MlResult<Value> {
    scheduler::drop_view(db, name, actor, tenant_id)
}

pub(crate) fn get_view(db: &Db, name: &str, limit: usize, cursor: Option<&str>) -> MlResult<Value> {
    identifier(name)?;
    if !(1..=1000).contains(&limit) {
        return Err(MlError::new(
            "chironql.ml_invalid_page",
            "limit must be between 1 and 1000",
        ));
    }
    local_preview(db)?;
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
    fn fixed_limits_and_temporary_pressure_have_typed_retry_decisions() {
        let hard = engine_error(chirondb_core::GaussError::SqlLimitExceeded(
            "operator limit".into(),
        ));
        assert_eq!(hard.code, "chironql.ml_limit_exceeded");
        assert!(!hard.transient);
        // Equal text cannot turn transient admission into a permanent limit.
        let temporary = engine_error(chirondb_core::GaussError::ResourceExhausted(
            "operator limit".into(),
        ));
        assert!(temporary.transient);
    }

    #[test]
    fn marks_interrupted_job_failed_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let id = "5d18a62b-e737-4103-849f-7640804f9a1f";
        {
            let db = Db::open(directory.path()).unwrap();
            let runtime = scheduler::state_for(&db);
            scheduler::ensure_catalog_for_test(&db, &runtime).unwrap();
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
        initialize(&reopened).unwrap();
        let job = get_job(&reopened, id).unwrap();
        assert_eq!(job["status"], "failed");
        assert_eq!(job["error"], "server_restarted");
        assert_eq!(job["source_version"], 7);
    }
}
