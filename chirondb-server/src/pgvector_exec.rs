//! pgvector wire-compat: AST → engine dispatch + text-format egress.
//!
//! Covers backlog items B3 + B4 of `.SPEC/gaussdb-vector_cleaned.md`. Spec:
//! `.SPEC/gaussdb-vector_cleaned.md` §3 (statement surface) + §4 (operator class →
//! `DistanceMetric` map) + §3.0.1 (reject taxonomy).
//!
//! Scope:
//! - SELECT … ORDER BY <vec> <op> '[…]'::vector LIMIT k     → `Db::search`
//! - CREATE EXTENSION vector                                → no-op shim
//! - CREATE TABLE …(embedding vector(N), …)                 → `Db::create_collection`
//! - CREATE INDEX                                           → `0A000` (LS-VEC is automatic)
//! - INSERT INTO t VALUES (…)                               → `Db::upsert`
//! - DELETE FROM t [WHERE …]                                → `Db::delete[_by_filter]`
//! - DROP TABLE                                             → `Db::delete_collection`
//! - SET / SHOW                                             → session-state stubs
//!
//! Text format only (v1). Extended query protocol, binary format, COPY:
//! deferred per spec §7.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::Db;
use crate::pgvector_parser::{
    CreateIndex, CreateTable, Delete, DropTable, Expr, IndexMethod, Insert, OpClass, Select,
    SelectItem, SqlType, Statement, TxnKeyword, VectorOp,
};
use crate::rbac::Permission;
use crate::{CollectionConfig, DistanceMetric, Filter, GaussError, Point, SearchRequest};

// =========================================================================
// Public surface
// =========================================================================

/// One execution result, ready for the wire path to serialise.
#[derive(Clone, Debug)]
pub enum QueryResponse {
    /// `SELECT` result set. Columns are emitted as Postgres `RowDescription`,
    /// rows as text-format `DataRow`. Followed by `CommandComplete "SELECT n"`.
    RowSet {
        columns: Vec<ColumnSpec>,
        rows: Vec<Vec<Option<String>>>,
        tag: String,
    },
    /// `INSERT 0 n`, `DELETE n`, `CREATE TABLE`, etc. No row data.
    CommandTag(String),
    /// `;` alone — `EmptyQueryResponse`.
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnSpec {
    pub name: String,
    pub pg_type: PgType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgType {
    Text,
    Int4,
    Int8,
    Float4,
    Float8,
    Bool,
    Jsonb,
}

impl PgType {
    pub fn oid(self) -> u32 {
        match self {
            PgType::Text => 25,
            PgType::Int4 => 23,
            PgType::Int8 => 20,
            PgType::Float4 => 700,
            PgType::Float8 => 701,
            PgType::Bool => 16,
            PgType::Jsonb => 3802,
        }
    }
    pub fn typlen(self) -> i16 {
        match self {
            PgType::Int4 | PgType::Float4 => 4,
            PgType::Int8 | PgType::Float8 => 8,
            PgType::Bool => 1,
            PgType::Text | PgType::Jsonb => -1,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ExecError {
    Unsupported { message: String, hint: &'static str },
    InvalidArgument(String),
    NotFound(String),
    PermissionDenied(String),
    Unavailable(String),
    Engine(String),
}

impl ExecError {
    pub fn sqlstate(&self) -> &'static str {
        match self {
            ExecError::Unsupported { .. } => "0A000",
            ExecError::InvalidArgument(_) => "22023",
            ExecError::NotFound(_) => "42P01",
            ExecError::PermissionDenied(_) => "42501",
            ExecError::Unavailable(_) => "58030",
            ExecError::Engine(_) => "XX000",
        }
    }
    pub fn message(&self) -> String {
        match self {
            ExecError::Unsupported { message, .. } => message.clone(),
            ExecError::InvalidArgument(s)
            | ExecError::NotFound(s)
            | ExecError::PermissionDenied(s)
            | ExecError::Unavailable(s)
            | ExecError::Engine(s) => s.clone(),
        }
    }
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            ExecError::Unsupported { hint, .. } => Some(*hint),
            _ => None,
        }
    }
}

fn exec_error_from_engine(error: GaussError) -> ExecError {
    match error {
        GaussError::AuditUnavailable(message) => ExecError::Unavailable(message),
        other => ExecError::Engine(other.to_string()),
    }
}

/// Per-session state. Tracks the operator class set at `CREATE INDEX` time so
/// `SELECT` can pick the right `DistanceMetric` even when the collection was
/// created before the index DDL (matches pgvector semantics — the operator
/// class on the *index* drives the metric).
#[derive(Clone, Debug, Default)]
pub struct SessionState {
    /// `collection name → (column name → OpClass)` from `CREATE INDEX`.
    pub index_opclass: Arc<Mutex<HashMap<String, HashMap<String, OpClass>>>>,
    /// `collection name → primary-key column from CREATE TABLE`.
    pub primary_keys: Arc<Mutex<HashMap<String, String>>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Run one parsed statement through the engine.
pub fn execute(
    db: &Db,
    session: &SessionState,
    stmt: Statement,
) -> Result<QueryResponse, ExecError> {
    execute_inner(db, session, None, stmt)
}

pub fn execute_scoped(
    db: &Db,
    session: &SessionState,
    principal: &Permission,
    stmt: Statement,
) -> Result<QueryResponse, ExecError> {
    execute_inner(db, session, Some(principal), stmt)
}

fn execute_inner(
    db: &Db,
    session: &SessionState,
    principal: Option<&Permission>,
    stmt: Statement,
) -> Result<QueryResponse, ExecError> {
    match stmt {
        Statement::CreateExtensionVector { .. } => {
            Ok(QueryResponse::CommandTag("CREATE EXTENSION".to_string()))
        }
        Statement::CreateTable(ct) => exec_create_table(db, session, principal, ct),
        Statement::CreateIndex(ci) => exec_create_index(db, session, ci),
        Statement::Insert(ins) => exec_insert(db, session, principal, ins),
        Statement::Select(sel) => exec_select(db, session, principal, sel),
        Statement::Delete(del) => exec_delete(db, principal, del),
        Statement::DropTable(dt) => exec_drop_table(db, session, dt),
        Statement::Set { .. } => Ok(QueryResponse::CommandTag("SET".to_string())),
        Statement::Show { name } => Ok(QueryResponse::RowSet {
            columns: vec![ColumnSpec {
                name: name.clone(),
                pg_type: PgType::Text,
            }],
            rows: vec![vec![Some(show_value(&name))]],
            tag: "SHOW".to_string(),
        }),
        Statement::TransactionControl(kw) => Err(ExecError::Unsupported {
            message: match kw {
                TxnKeyword::Begin => {
                    "multi-statement transactions not supported v1; use autocommit or pgvector"
                        .to_string()
                }
                TxnKeyword::Commit => "COMMIT requires BEGIN; transactions not supported v1".into(),
                TxnKeyword::Rollback => {
                    "ROLLBACK requires BEGIN; transactions not supported v1".into()
                }
                TxnKeyword::Savepoint => "SAVEPOINT not supported v1".into(),
                TxnKeyword::Release => "RELEASE SAVEPOINT not supported v1".into(),
            },
            hint: "#transactions",
        }),
    }
}

// =========================================================================
// CREATE TABLE
// =========================================================================

fn exec_create_table(
    db: &Db,
    session: &SessionState,
    principal: Option<&Permission>,
    ct: CreateTable,
) -> Result<QueryResponse, ExecError> {
    let mut vector_dim: Option<usize> = None;
    let mut primary_key: Option<String> = None;
    for col in &ct.columns {
        if let SqlType::Vector(n) = col.data_type {
            if vector_dim.is_some() {
                return Err(ExecError::Unsupported {
                    message: "only one vector column per table is supported v1".to_string(),
                    hint: "#ddl",
                });
            }
            vector_dim = Some(n);
        }
        if col.primary_key {
            primary_key = Some(col.name.clone());
        }
    }
    let Some(dim) = vector_dim else {
        return Err(ExecError::Unsupported {
            message: "CREATE TABLE without a vector(N) column not supported v1".to_string(),
            hint: "#ddl",
        });
    };
    if let Some(pk) = primary_key.clone() {
        session
            .primary_keys
            .lock()
            .expect("primary_keys mutex poisoned")
            .insert(ct.name.clone(), pk);
    }

    let cfg = CollectionConfig {
        name: ct.name.clone(),
        vector_dim: dim,
        // pgvector default opclass is `vector_l2_ops` → `<->`. Track that as
        // the baseline; `CREATE INDEX … vector_<ip|cosine>_ops` rebuilds when
        // it disagrees, but only while the collection is empty.
        metric: DistanceMetric::L2,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: HashMap::new(),
        named_vector_dims: HashMap::new(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    };

    if ct.if_not_exists && db.list_collections().iter().any(|c| c.name == ct.name) {
        return Ok(QueryResponse::CommandTag("CREATE TABLE".to_string()));
    }

    if let Some(principal) = principal
        && let Some(limit) = principal.max_collections
    {
        let current = db
            .list_collections()
            .iter()
            .filter(|config| principal.allows_collection(&config.name))
            .count();
        if current >= limit {
            return Err(ExecError::PermissionDenied(
                "collection quota exceeded".to_string(),
            ));
        }
    }

    db.create_collection(cfg)
        .map(|_| QueryResponse::CommandTag("CREATE TABLE".to_string()))
        .map_err(exec_error_from_engine)
}

// =========================================================================
// CREATE INDEX
// =========================================================================

fn exec_create_index(
    _db: &Db,
    _session: &SessionState,
    ci: CreateIndex,
) -> Result<QueryResponse, ExecError> {
    let method = match ci.method {
        IndexMethod::Hnsw => "hnsw",
        IndexMethod::Rabitq => "rabitq",
        IndexMethod::Ivfflat => "ivfflat",
        IndexMethod::Unknown(ref name) => name,
    };
    Err(ExecError::Unsupported {
        message: format!(
            "CREATE INDEX USING {method} is unsupported; LS-VEC is automatic and HNSW is internal to the mutable tier"
        ),
        hint: "#index-am",
    })
}

// =========================================================================
// DROP TABLE
// =========================================================================

fn exec_drop_table(
    db: &Db,
    session: &SessionState,
    dt: DropTable,
) -> Result<QueryResponse, ExecError> {
    for name in &dt.names {
        let exists = db.list_collections().iter().any(|c| &c.name == name);
        if !exists {
            if dt.if_exists {
                continue;
            }
            return Err(ExecError::NotFound(format!(
                "relation `{name}` does not exist"
            )));
        }
        db.delete_collection(name).map_err(exec_error_from_engine)?;
        session
            .index_opclass
            .lock()
            .expect("index_opclass mutex poisoned")
            .remove(name);
        session
            .primary_keys
            .lock()
            .expect("primary_keys mutex poisoned")
            .remove(name);
    }
    Ok(QueryResponse::CommandTag("DROP TABLE".to_string()))
}

// =========================================================================
// INSERT
// =========================================================================

fn exec_insert(
    db: &Db,
    session: &SessionState,
    principal: Option<&Permission>,
    ins: Insert,
) -> Result<QueryResponse, ExecError> {
    let pk_col = session
        .primary_keys
        .lock()
        .expect("primary_keys mutex poisoned")
        .get(&ins.table)
        .cloned();

    let mut points = Vec::with_capacity(ins.rows.len());
    for row in &ins.rows {
        if !ins.columns.is_empty() && row.len() != ins.columns.len() {
            return Err(ExecError::InvalidArgument(format!(
                "INSERT row arity {} does not match column list {}",
                row.len(),
                ins.columns.len()
            )));
        }
        let mut id: Option<String> = None;
        let mut vector: Option<Vec<f32>> = None;
        let mut payload = serde_json::Map::new();
        for (idx, expr) in row.iter().enumerate() {
            let col_name = ins
                .columns
                .get(idx)
                .cloned()
                .unwrap_or_else(|| format!("col_{idx}"));
            match expr {
                Expr::VectorLiteral(v) => vector = Some(v.clone()),
                Expr::Integer(i) => {
                    if Some(&col_name) == pk_col.as_ref() {
                        id = Some(i.to_string());
                    }
                    payload.insert(col_name, serde_json::json!(i));
                }
                Expr::Number(f) => {
                    payload.insert(col_name, serde_json::json!(f));
                }
                Expr::String(s) => {
                    if Some(&col_name) == pk_col.as_ref() {
                        id = Some(s.clone());
                    }
                    payload.insert(col_name, serde_json::json!(s));
                }
                Expr::Bool(b) => {
                    payload.insert(col_name, serde_json::json!(b));
                }
                Expr::Null => {
                    payload.insert(col_name, serde_json::Value::Null);
                }
                Expr::Ident(s) => {
                    // Likely DEFAULT placeholder or unknown — keep string.
                    payload.insert(col_name, serde_json::json!(s));
                }
                other => {
                    return Err(ExecError::Unsupported {
                        message: format!("unsupported INSERT value: {other:?}"),
                        hint: "#dml",
                    });
                }
            }
        }
        let id = id.unwrap_or_else(|| uuid_like_id(&payload));
        let vector = vector.ok_or_else(|| {
            ExecError::InvalidArgument("INSERT missing vector column value".to_string())
        })?;
        points.push(Point {
            id,
            vector,
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: serde_json::Value::Object(payload),
        });
    }
    let n = points.len();
    match principal {
        Some(principal) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.upsert_scoped(&ins.table, points, true, &scope)
        }
        None => db.upsert(&ins.table, points),
    }
    .map_err(exec_error_from_engine)?;
    Ok(QueryResponse::CommandTag(format!("INSERT 0 {n}")))
}

fn uuid_like_id(payload: &serde_json::Map<String, serde_json::Value>) -> String {
    // Deterministic-but-unlikely-to-collide id from payload content + nanos.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = payload.iter().fold(0u64, |acc, (k, v)| {
        acc ^ hash_str(k) ^ hash_str(&v.to_string())
    });
    format!("auto-{nanos:x}-{h:x}")
}

fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// =========================================================================
// DELETE
// =========================================================================

fn exec_delete(
    db: &Db,
    principal: Option<&Permission>,
    del: Delete,
) -> Result<QueryResponse, ExecError> {
    let Some(where_clause) = del.where_clause else {
        // DELETE without WHERE — wipe collection. For B4 we honour this via
        // `delete_collection + recreate`; safer to require WHERE for v1.
        return Err(ExecError::Unsupported {
            message: "DELETE without WHERE not supported v1; specify a predicate".to_string(),
            hint: "#dml",
        });
    };
    // Fast path: DELETE FROM t WHERE id = literal.
    if let Some(id) = extract_id_eq(&where_clause) {
        let ids = [id];
        let n = match principal {
            Some(principal) => {
                let scope = principal.tenant_scope(principal.id.clone());
                db.delete_scoped(&del.table, &ids, &scope)
            }
            None => db.delete(&del.table, &ids),
        }
        .map_err(exec_error_from_engine)?;
        return Ok(QueryResponse::CommandTag(format!("DELETE {n}")));
    }
    let filter = expr_to_filter(&where_clause)?;
    let n = match principal {
        Some(principal) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.delete_by_filter_scoped(&del.table, &filter, &scope)
        }
        None => db.delete_by_filter(&del.table, &filter),
    }
    .map_err(exec_error_from_engine)?;
    Ok(QueryResponse::CommandTag(format!("DELETE {n}")))
}

fn extract_id_eq(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Compare {
            left,
            op: crate::pgvector_parser::CmpOp::Eq,
            right,
        } => {
            let name = match left.as_ref() {
                Expr::Ident(s) => s,
                _ => return None,
            };
            if !name.eq_ignore_ascii_case("id") {
                return None;
            }
            Some(match right.as_ref() {
                Expr::Integer(i) => i.to_string(),
                Expr::String(s) => s.clone(),
                _ => return None,
            })
        }
        _ => None,
    }
}

// =========================================================================
// SELECT
// =========================================================================

fn exec_select(
    db: &Db,
    session: &SessionState,
    principal: Option<&Permission>,
    sel: Select,
) -> Result<QueryResponse, ExecError> {
    let Some(order_by) = &sel.order_by else {
        return Err(ExecError::Unsupported {
            message: "SELECT without ORDER BY <vec> <op> '[…]'::vector not supported v1"
                .to_string(),
            hint: "#select-shapes",
        });
    };
    let (col, vec_op, query_vec) = match &order_by.expr {
        Expr::Distance { left, op, right } => {
            let col = match left.as_ref() {
                Expr::Ident(s) => s.clone(),
                Expr::QualifiedIdent(_, c) => c.clone(),
                _ => {
                    return Err(ExecError::Unsupported {
                        message: "ORDER BY left side must be a vector column".to_string(),
                        hint: "#select-shapes",
                    });
                }
            };
            let vec = match right.as_ref() {
                Expr::VectorLiteral(v) => v.clone(),
                _ => {
                    return Err(ExecError::Unsupported {
                        message: "ORDER BY right side must be a '[…]'::vector literal".to_string(),
                        hint: "#select-shapes",
                    });
                }
            };
            (col, *op, vec)
        }
        _ => {
            return Err(ExecError::Unsupported {
                message: "ORDER BY must be of the form `col <op> '[…]'::vector`".to_string(),
                hint: "#select-shapes",
            });
        }
    };
    let metric = match vec_op {
        VectorOp::L2 => DistanceMetric::L2,
        VectorOp::Dot => DistanceMetric::Dot,
        VectorOp::Cosine => DistanceMetric::Cosine,
        VectorOp::L1 => {
            return Err(ExecError::Unsupported {
                message: "L1 distance operator not supported".to_string(),
                hint: "#operators",
            });
        }
    };
    let opclass_metric = session_opclass_metric(session, &sel.table, &col);
    if let Some(existing) = opclass_metric
        && existing != metric
    {
        return Err(ExecError::InvalidArgument(format!(
            "operator metric {metric:?} does not match index operator class {existing:?}"
        )));
    }

    let k = sel.limit.unwrap_or(10).min(10_000) as usize;
    let filter = sel.where_clause.as_ref().map(expr_to_filter).transpose()?;

    let request = SearchRequest {
        graph: None,
        vector: query_vec.clone(),
        vector_name: None,
        k,
        filter,
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: None,
        with_payload: Some(true),
    };
    let response = match principal {
        Some(principal) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.search_scoped(&sel.table, request, &scope)
        }
        None => db.search(&sel.table, request),
    }
    .map_err(exec_error_from_engine)?;

    // Plan projection columns.
    let projection = plan_projection(&sel.projection, &col)?;
    let columns: Vec<ColumnSpec> = projection.iter().map(|p| p.spec.clone()).collect();
    let mut rows: Vec<Vec<Option<String>>> = Vec::with_capacity(response.hits.len());
    for hit in &response.hits {
        let mut row = Vec::with_capacity(projection.len());
        for p in &projection {
            row.push(render_field(&p.source, hit, metric, &col));
        }
        rows.push(row);
    }
    Ok(QueryResponse::RowSet {
        columns,
        rows,
        tag: format!("SELECT {}", response.hits.len()),
    })
}

fn session_opclass_metric(
    session: &SessionState,
    table: &str,
    col: &str,
) -> Option<DistanceMetric> {
    let map = session.index_opclass.lock().ok()?;
    let cols = map.get(table)?;
    cols.get(col).map(|oc| match oc {
        OpClass::VectorL2Ops => DistanceMetric::L2,
        OpClass::VectorIpOps => DistanceMetric::Dot,
        OpClass::VectorCosineOps => DistanceMetric::Cosine,
        OpClass::Unknown(_) => DistanceMetric::default(),
    })
}

#[derive(Clone, Debug)]
struct PlannedColumn {
    spec: ColumnSpec,
    source: ColumnSource,
}

#[derive(Clone, Debug)]
enum ColumnSource {
    Id,
    /// Distance column derived from the ORDER BY expression.
    Distance,
    Score,
    /// Payload field by name.
    Payload(String),
}

fn plan_projection(items: &[SelectItem], vec_col: &str) -> Result<Vec<PlannedColumn>, ExecError> {
    let mut out = Vec::new();
    for item in items {
        match item {
            SelectItem::Star => {
                out.push(PlannedColumn {
                    spec: ColumnSpec {
                        name: "id".to_string(),
                        pg_type: PgType::Text,
                    },
                    source: ColumnSource::Id,
                });
                out.push(PlannedColumn {
                    spec: ColumnSpec {
                        name: "score".to_string(),
                        pg_type: PgType::Float8,
                    },
                    source: ColumnSource::Score,
                });
            }
            SelectItem::Expr { expr, alias } => match expr {
                Expr::Ident(name) => {
                    let lower = name.to_ascii_lowercase();
                    if lower == "id" {
                        out.push(PlannedColumn {
                            spec: ColumnSpec {
                                name: alias.clone().unwrap_or_else(|| "id".to_string()),
                                pg_type: PgType::Text,
                            },
                            source: ColumnSource::Id,
                        });
                    } else if lower == vec_col.to_ascii_lowercase() {
                        // Projecting the vector column itself: emit JSON text.
                        out.push(PlannedColumn {
                            spec: ColumnSpec {
                                name: alias.clone().unwrap_or_else(|| name.clone()),
                                pg_type: PgType::Text,
                            },
                            source: ColumnSource::Payload(name.clone()),
                        });
                    } else {
                        out.push(PlannedColumn {
                            spec: ColumnSpec {
                                name: alias.clone().unwrap_or_else(|| name.clone()),
                                pg_type: PgType::Text,
                            },
                            source: ColumnSource::Payload(name.clone()),
                        });
                    }
                }
                Expr::Distance { .. } => {
                    out.push(PlannedColumn {
                        spec: ColumnSpec {
                            name: alias.clone().unwrap_or_else(|| "distance".to_string()),
                            pg_type: PgType::Float8,
                        },
                        source: ColumnSource::Distance,
                    });
                }
                Expr::Func { name, .. } => {
                    out.push(PlannedColumn {
                        spec: ColumnSpec {
                            name: alias.clone().unwrap_or_else(|| name.clone()),
                            pg_type: PgType::Text,
                        },
                        source: ColumnSource::Payload(name.clone()),
                    });
                }
                other => {
                    return Err(ExecError::Unsupported {
                        message: format!("projection expression {other:?} not supported"),
                        hint: "#select-shapes",
                    });
                }
            },
        }
    }
    Ok(out)
}

fn render_field(
    src: &ColumnSource,
    hit: &crate::SearchHit,
    metric: DistanceMetric,
    _vec_col: &str,
) -> Option<String> {
    match src {
        ColumnSource::Id => Some(hit.id.clone()),
        ColumnSource::Distance => Some(format_distance(metric, hit.score).to_string()),
        ColumnSource::Score => Some(hit.score.to_string()),
        ColumnSource::Payload(field) => {
            let v = hit.payload.get(field).cloned();
            match v {
                Some(serde_json::Value::Null) | None => None,
                Some(serde_json::Value::String(s)) => Some(s),
                Some(other) => Some(other.to_string()),
            }
        }
    }
}

/// Convert engine `score` into a pgvector-style distance per `.SPEC/gaussdb-vector_cleaned.md` §4.
/// - L2: engine returns `-l2`; pg expects `l2` → negate.
/// - Cosine: engine returns `cosine_similarity`; pg expects `1 - sim`.
/// - Dot: engine returns raw dot; pg expects `-dot`.
pub fn format_distance(metric: DistanceMetric, score: f32) -> f32 {
    match metric {
        DistanceMetric::L2 => -score,
        DistanceMetric::Cosine => 1.0 - score,
        DistanceMetric::Dot => -score,
    }
}

// =========================================================================
// WHERE → Filter (JSON shape consumed by chirondb_types::filter)
// =========================================================================

fn expr_to_filter(expr: &Expr) -> Result<Filter, ExecError> {
    let value = expr_to_filter_value(expr)?;
    Ok(Filter(value))
}

fn expr_to_filter_value(expr: &Expr) -> Result<serde_json::Value, ExecError> {
    match expr {
        Expr::And(a, b) => {
            let mut left = expr_to_filter_value(a)?;
            let right = expr_to_filter_value(b)?;
            merge_and(&mut left, right)?;
            Ok(left)
        }
        Expr::Or(_, _) => Err(ExecError::Unsupported {
            message: "OR in WHERE not supported v1; rewrite as IN list or split queries"
                .to_string(),
            hint: "#where",
        }),
        Expr::Not(inner) => {
            // Only NOT (col IN (…)) and NOT (col = val) supported. Map via `ne`/inverted set.
            match inner.as_ref() {
                Expr::InList { expr, list, .. } => in_list_to_value(expr, list, true),
                Expr::Compare {
                    left,
                    op: crate::pgvector_parser::CmpOp::Eq,
                    right,
                } => {
                    let field = field_name(left)?;
                    let value = literal_to_json(right)?;
                    Ok(json!({ field: { "ne": value } }))
                }
                _ => Err(ExecError::Unsupported {
                    message: "NOT only supported on `col IN (…)` or `col = literal`".to_string(),
                    hint: "#where",
                }),
            }
        }
        Expr::Compare { left, op, right } => compare_to_value(left, *op, right),
        Expr::InList {
            expr,
            list,
            negated,
        } => in_list_to_value(expr, list, *negated),
        other => Err(ExecError::Unsupported {
            message: format!("WHERE expression {other:?} not supported"),
            hint: "#where",
        }),
    }
}

/// Merge two filter objects by key-union. When the same key appears in both,
/// both values must be operator objects (e.g. `{gte: 100}` + `{lt: 200}`) and
/// we union their entries. Anything else is reported as a parser-style
/// ambiguity to surface to the client.
fn merge_and(into: &mut serde_json::Value, from: serde_json::Value) -> Result<(), ExecError> {
    let into_obj = into.as_object_mut().ok_or_else(|| ExecError::Unsupported {
        message: "AND merge target was not a filter object".to_string(),
        hint: "#where",
    })?;
    let from_obj = match from {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(ExecError::Unsupported {
                message: "AND merge source was not a filter object".to_string(),
                hint: "#where",
            });
        }
    };
    for (k, v) in from_obj {
        if let Some(existing) = into_obj.get_mut(&k) {
            if let (Some(eobj), Some(vobj)) = (existing.as_object_mut(), v.as_object()) {
                for (kk, vv) in vobj {
                    eobj.insert(kk.clone(), vv.clone());
                }
            } else {
                return Err(ExecError::Unsupported {
                    message: format!("conflicting AND clauses on field `{k}`"),
                    hint: "#where",
                });
            }
        } else {
            into_obj.insert(k, v);
        }
    }
    Ok(())
}

fn compare_to_value(
    left: &Expr,
    op: crate::pgvector_parser::CmpOp,
    right: &Expr,
) -> Result<serde_json::Value, ExecError> {
    use crate::pgvector_parser::CmpOp;
    let field = field_name(left)?;
    let entry = match op {
        CmpOp::Eq => literal_to_json(right)?,
        CmpOp::Ne => json!({ "ne": literal_to_json(right)? }),
        CmpOp::Lt => json!({ "lt": literal_to_number(right)? }),
        CmpOp::Le => json!({ "lte": literal_to_number(right)? }),
        CmpOp::Gt => json!({ "gt": literal_to_number(right)? }),
        CmpOp::Ge => json!({ "gte": literal_to_number(right)? }),
    };
    Ok(json!({ field: entry }))
}

fn in_list_to_value(
    expr: &Expr,
    list: &[Expr],
    negated: bool,
) -> Result<serde_json::Value, ExecError> {
    let field = field_name(expr)?;
    let mut values: Vec<serde_json::Value> = Vec::with_capacity(list.len());
    for v in list {
        values.push(literal_to_json(v)?);
    }
    let entry = if negated {
        json!({ "ne": values })
    } else {
        json!({ "in": values })
    };
    Ok(json!({ field: entry }))
}

fn field_name(expr: &Expr) -> Result<String, ExecError> {
    match expr {
        Expr::Ident(s) => Ok(s.clone()),
        Expr::QualifiedIdent(_, c) => Ok(c.clone()),
        _ => Err(ExecError::Unsupported {
            message: "WHERE: left side must be a column name".to_string(),
            hint: "#where",
        }),
    }
}

fn literal_to_json(expr: &Expr) -> Result<serde_json::Value, ExecError> {
    Ok(match expr {
        Expr::Integer(i) => json!(i),
        Expr::Number(f) => json!(f),
        Expr::String(s) => json!(s),
        Expr::Bool(b) => json!(b),
        Expr::Null => serde_json::Value::Null,
        other => {
            return Err(ExecError::Unsupported {
                message: format!("WHERE literal expected, got {other:?}"),
                hint: "#where",
            });
        }
    })
}

fn literal_to_number(expr: &Expr) -> Result<f64, ExecError> {
    Ok(match expr {
        Expr::Integer(i) => *i as f64,
        Expr::Number(f) => *f,
        other => {
            return Err(ExecError::Unsupported {
                message: format!("range comparison expects numeric, got {other:?}"),
                hint: "#where",
            });
        }
    })
}

// =========================================================================
// SHOW helpers
// =========================================================================

fn show_value(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "server_version" => crate::wire_postgres::SERVER_VERSION_STRING.to_string(),
        "client_encoding" | "server_encoding" => "UTF8".to_string(),
        "standard_conforming_strings" | "integer_datetimes" => "on".to_string(),
        "transaction_isolation" => "read committed".to_string(),
        "datestyle" => "ISO, MDY".to_string(),
        "timezone" => "UTC".to_string(),
        _ => String::new(),
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgvector_parser::parse;
    use tempfile::TempDir;

    fn fresh_db() -> (Db, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Db::open(dir.path()).unwrap();
        (db, dir)
    }

    fn one(s: &str) -> Statement {
        parse(s).unwrap().into_iter().next().unwrap()
    }

    #[test]
    fn round_trip_create_insert_select() {
        let (db, _g) = fresh_db();
        let session = SessionState::new();

        execute(
            &db,
            &session,
            one("CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(4));"),
        )
        .unwrap();

        execute(
            &db,
            &session,
            one("INSERT INTO items (id, embedding) VALUES (1, '[1.0, 0.0, 0.0, 0.0]'::vector);"),
        )
        .unwrap();
        execute(
            &db,
            &session,
            one("INSERT INTO items (id, embedding) VALUES (2, '[0.0, 1.0, 0.0, 0.0]'::vector);"),
        )
        .unwrap();

        let result = execute(
            &db,
            &session,
            one("SELECT id, embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector AS d FROM items ORDER BY embedding <-> '[1.0, 0.0, 0.0, 0.0]'::vector LIMIT 1;"),
        )
        .unwrap();

        match result {
            QueryResponse::RowSet { columns, rows, tag } => {
                assert_eq!(columns.len(), 2);
                assert_eq!(columns[0].name, "id");
                assert_eq!(columns[1].name, "d");
                assert_eq!(columns[1].pg_type, PgType::Float8);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0][0].as_deref(), Some("1"));
                let distance: f64 = rows[0][1].as_deref().unwrap().parse().unwrap();
                assert!(
                    distance.abs() < 1e-6,
                    "L2 to self should be ~0, got {distance}"
                );
                assert_eq!(tag, "SELECT 1");
            }
            other => panic!("expected RowSet, got {other:?}"),
        }
    }

    #[test]
    fn delete_by_id_works() {
        let (db, _g) = fresh_db();
        let session = SessionState::new();
        execute(
            &db,
            &session,
            one("CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(2));"),
        )
        .unwrap();
        execute(
            &db,
            &session,
            one("INSERT INTO items (id, embedding) VALUES (42, '[0.0, 0.0]'::vector);"),
        )
        .unwrap();
        match execute(&db, &session, one("DELETE FROM items WHERE id = 42;")).unwrap() {
            QueryResponse::CommandTag(tag) => assert_eq!(tag, "DELETE 1"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn drop_table_if_exists_is_idempotent() {
        let (db, _g) = fresh_db();
        let session = SessionState::new();
        execute(&db, &session, one("DROP TABLE IF EXISTS nope;")).unwrap();
    }

    #[test]
    fn create_index_hnsw_rejects_with_feature_not_supported() {
        let (db, _g) = fresh_db();
        let session = SessionState::new();
        execute(
            &db,
            &session,
            one("CREATE TABLE c (id INTEGER PRIMARY KEY, embedding vector(2));"),
        )
        .unwrap();
        let error = execute(
            &db,
            &session,
            one("CREATE INDEX ON c USING hnsw (embedding vector_cosine_ops);"),
        )
        .unwrap_err();
        assert_eq!(error.sqlstate(), "0A000");
        assert!(error.message().contains("LS-VEC is automatic"));
    }

    #[test]
    fn where_eq_and_range_filter_compiles() {
        let (db, _g) = fresh_db();
        let session = SessionState::new();
        execute(
            &db,
            &session,
            one("CREATE TABLE p (id INTEGER PRIMARY KEY, embedding vector(2), price INTEGER, category TEXT);"),
        )
        .unwrap();
        execute(
            &db,
            &session,
            one("INSERT INTO p (id, embedding, price, category) VALUES (1, '[0.0, 0.0]'::vector, 50, 'red');"),
        )
        .unwrap();
        execute(
            &db,
            &session,
            one("INSERT INTO p (id, embedding, price, category) VALUES (2, '[1.0, 0.0]'::vector, 200, 'blue');"),
        )
        .unwrap();
        let r = execute(
            &db,
            &session,
            one("SELECT id FROM p WHERE category = 'red' AND price < 100 ORDER BY embedding <-> '[0.0, 0.0]'::vector LIMIT 5;"),
        )
        .unwrap();
        match r {
            QueryResponse::RowSet { rows, .. } => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0][0].as_deref(), Some("1"));
            }
            other => panic!("{other:?}"),
        }
    }
}
