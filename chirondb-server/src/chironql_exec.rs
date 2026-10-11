//! ChironQL executor — AST to `chirondb_core::Db` calls.
//!
//! P1 of the ChironQL plan. Reads only; write statements parse but are
//! refused here until P4, with a code that says so rather than a generic
//! failure.
//!
//! This module is the single entry point every surface goes through — the
//! embedded console, the HTTP endpoint, the gRPC service and the SDKs. It
//! calls the same `Db` methods the REST handlers in `api.rs` call, which is
//! what makes the differential test meaningful: if ChironQL and REST disagree,
//! one of them is wrong.
//!
//! ## Trace
//!
//! Every execution builds a [`QueryTrace`] as it goes. It is always collected
//! (a handful of `Instant::now()` calls against a search that costs
//! milliseconds) and conditionally rendered, which is what makes "always shown
//! on failure" possible without re-running the query.
//!
//! Values in the trace are measured. A stage that did not run is absent, not
//! present with a zero duration, and no stage reports a recall figure — the
//! engine does not measure one per query.

pub use crate::chironql_output::QueryResult;
use crate::chironql_output::query::{self as receiving, JsonKey, QueryMemory};
use crate::chironql_output::retrieval;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::time::Instant;

use serde_json::{Value, json};

use chirondb_core::{Db, GaussError, MultiModelTransactionRequest};
use chirondb_types::RelationalValue;
use chirondb_types::chironql::{
    ChironQlError, ChironQlKind, ChironQlResponse, ChironQlStats, QueryTrace, stage,
};
use chirondb_types::graph::{
    EdgePropertyMode, EdgeToken, GraphCapability, GraphConstraint, GraphDeferredSessionId,
    GraphMutationReceipt, GraphQueryWarning, GraphRelationScope, GraphTraversalQueryRequest,
    GraphTraversalReturn, GraphWarning, RelateRequest, TraversalBudget, UpdateEdgeRequest,
};
use chirondb_types::model::{
    CollectionConfig, HybridSearchRequest, MultiSearchRequest, Point, RecommendRequest,
    SearchRequest, SearchResponse,
};
use chirondb_types::{RelationalType, SqlExecutionRequest, SqlResult, SqlStatementRequest};

use crate::chironql_parser::{
    self, CreateCollection, Get, GraphClause, GraphReturn, Hybrid, Multi, ParseError, Pipeline,
    PipelineField, PipelineJoinKind, Recommend, Relate, Scroll, Search, Statement, StatementClass,
    TransactionBlock, TransactionGraph, TransactionVector, Traverse, Unrelate, UpdateEdge,
    UpdatePayload, Upsert, VectorExpr,
};
use crate::rbac::Role;
use chirondb_core::tenant::TenantScope;

/// Session state a connection carries between statements.
#[derive(Clone, Debug, Default)]
pub struct Session {
    /// Set by `USE <collection>`.
    pub collection: Option<String>,
    /// Explicit two-phase graph bulk-load window. ChironQL syntax deliberately
    /// does not carry this opaque token; a stateful native session binds it.
    pub graph_deferred_session: Option<GraphDeferredSessionId>,
}

/// Everything one execution needs that is not the statement itself.
pub struct ExecContext<'a> {
    pub db: &'a Db,
    pub session: &'a mut Session,
    pub role: Role,
    /// Collections this caller may touch. `None` means unrestricted.
    ///
    /// Mirrors `Permission::allows_collection`, which the REST handlers
    /// already enforce. ChironQL must honour the same scoping or a restricted
    /// API key could reach a collection through the language that it cannot
    /// reach through `/v1/collections/...`.
    pub allowed_collections: Option<HashSet<String>>,
    /// Include the trace on the success path. Failures always carry it.
    pub want_trace: bool,
    /// Proceed with a statement that would otherwise stop and ask. See
    /// [`ChironQlRequest::confirm`](chirondb_types::chironql::ChironQlRequest).
    pub confirm: bool,
    /// Typed positional parameters shared by SQL and pipeline stages.
    pub parameters: Vec<RelationalValue>,
    /// Stable mutation identity forwarded to the core ledger.
    pub idempotency_key: Option<String>,
    /// Audit correlation forwarded to standalone relational writes.
    pub retry_id: Option<String>,
    /// Row-level tenant scope for this caller. Built from the authenticated
    /// principal, never from anything the caller sent, and passed to the
    /// engine's `_scoped` entry points so tenant rules apply here exactly as
    /// they do on every other surface.
    pub tenant: TenantScope,
}

impl ExecContext<'_> {
    fn allows_collection(&self, collection: &str) -> bool {
        self.allowed_collections
            .as_ref()
            .is_none_or(|allowed| allowed.contains(collection))
    }
}

type ExecResult = Result<ChironQlResponse, ChironQlError>;
type OwnedExecResult = Result<QueryResult, ChironQlError>;

/// Parse and execute one statement.
pub fn execute(ctx: &mut ExecContext<'_>, input: &str) -> ExecResult {
    execute_owned(ctx, input).map(QueryResult::into_dto)
}

/// Retain receiving/operation admission through transport consumption.
pub fn execute_owned(ctx: &mut ExecContext<'_>, input: &str) -> OwnedExecResult {
    let mut memory = QueryMemory::new().map_err(|e| receiving::error("", e))?;
    let value = execute_with_parser(ctx, input, chironql_parser::parse, &mut memory)?;
    memory
        .metadata(&value)
        .map_err(|e| receiving::error(&value.query_id, e))?;
    Ok(QueryResult::new(value, memory))
}

fn execute_with_parser(
    ctx: &mut ExecContext<'_>,
    input: &str,
    parser: fn(&str) -> Result<Statement, ParseError>,
    memory: &mut QueryMemory,
) -> ExecResult {
    let query_id = new_query_id();
    let started = Instant::now();
    let mut trace = QueryTrace::new(query_id.clone());

    // -- parse ------------------------------------------------------------
    let parse_started = Instant::now();
    let statement = match parser(input) {
        Ok(statement) => statement,
        Err(error) => {
            trace.push_failed(
                stage::PARSE,
                micros(parse_started),
                error.code,
                error.message.clone(),
            );
            return Err(parse_error(&query_id, error, trace));
        }
    };
    trace.push_ok(
        stage::PARSE,
        micros(parse_started),
        detail(ctx.role, json!({"statement": statement.kind_name()})),
    );
    let classify_started = Instant::now();
    trace.push_ok(
        stage::CLASSIFY,
        micros(classify_started),
        detail(
            ctx.role,
            json!({
                "class": match statement.class() {
                    StatementClass::Read => "read",
                    StatementClass::Write => "write",
                    StatementClass::Admin => "admin",
                },
                "domains": statement.domains(),
                "tables": statement.tables(),
                "collections": statement.collections(),
            }),
        ),
    );

    // -- authorize --------------------------------------------------------
    //
    // The real enforcement, before anything touches the engine. Every surface
    // passes through here, so a client-side prompt is ergonomics only.
    let authorize_started = Instant::now();
    let class = statement.class();
    let permitted = match class {
        StatementClass::Read => true,
        StatementClass::Write => ctx.role.allows_write(),
        StatementClass::Admin => ctx.role.allows_admin(),
    };
    if !permitted {
        let (kind, needs) = match class {
            StatementClass::Admin => ("an admin", "Admin operations need an admin role."),
            _ => ("a write", "Writes need a read_write role."),
        };
        let message = format!(
            "{} is {kind} statement and this session is {}",
            statement.kind_name(),
            role_name(ctx.role)
        );
        trace.push_failed(
            stage::AUTHORIZE,
            micros(authorize_started),
            "chironql.permission_denied",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.permission_denied".to_string(),
            hint: Some(needs.to_string()),
            position: None,
            affected_estimate: None,
            query_id,
            trace: Some(Box::new(trace)),
        });
    }
    if let Some(capability) = required_graph_capability(&statement)
        && !ctx.tenant.has_graph_capability(capability)
    {
        let message = format!(
            "{} needs explicit {} capability",
            statement.kind_name(),
            capability
        );
        trace.push_failed(
            stage::AUTHORIZE,
            micros(authorize_started),
            "chironql.permission_denied",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.permission_denied".to_string(),
            hint: Some(format!("Grant `{capability}` to this principal.")),
            position: None,
            affected_estimate: None,
            query_id,
            trace: Some(Box::new(trace)),
        });
    }
    // Collection DDL carries no tenant scope. `create_collection` and
    // `delete_collection` have no `_scoped` twin, so under `Enforced` there is
    // no rule for who owns a new collection or who may destroy one. That is a
    // gap, not a policy, so DDL refuses rather than guesses — the same
    // fail-closed stance as `Db::require_scoped_entry`.
    if statement.is_collection_ddl() && ctx.db.tenant_enforcement().blocks() {
        let message = format!(
            "{} has no tenant scope and tenant enforcement is on",
            statement.kind_name()
        );
        trace.push_failed(
            stage::AUTHORIZE,
            micros(authorize_started),
            "chironql.tenant_ddl_unsupported",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.tenant_ddl_unsupported".to_string(),
            hint: Some(
                "Administer collections with `chironctl` while enforcement is on.".to_string(),
            ),
            position: None,
            affected_estimate: None,
            query_id,
            trace: Some(Box::new(trace)),
        });
    }
    trace.push_ok(stage::AUTHORIZE, micros(authorize_started), None);

    if ctx.idempotency_key.is_some()
        && !matches!(statement, Statement::Sql(_) | Statement::Transaction(_))
    {
        return Err(ChironQlError {
            error: "idempotency_key requires a SQL mutation or atomic transaction".into(),
            code: "chironql.idempotency_unsupported".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id,
            trace: Some(Box::new(trace)),
        });
    }

    // -- dispatch ---------------------------------------------------------
    let outcome = dispatch(ctx, &statement, &query_id, &mut trace, memory);

    match outcome {
        Ok(mut response) => {
            response.query_id = query_id;
            response.domains = statement.domains();
            response.stats.took_ms = millis(started);
            response.trace = if ctx.want_trace { Some(trace) } else { None };
            Ok(response)
        }
        Err(mut error) => {
            error.query_id = query_id;
            error.trace = Some(Box::new(trace));
            Err(error)
        }
    }
}

fn dispatch(
    ctx: &mut ExecContext<'_>,
    statement: &Statement,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let value = match statement {
        Statement::MlMaterialize(definition) => {
            if ctx.db.tenant_enforcement().blocks() {
                return Err(ChironQlError {
                    error: "ML materialization requires the protected tenant executor".into(),
                    code: "chironql.ml_tenant_unsupported".into(),
                    hint: None,
                    position: None,
                    affected_estimate: None,
                    query_id: query_id.into(),
                    trace: None,
                });
            }
            let submitted = crate::ml_runtime::submit(
                ctx.db,
                definition,
                ctx.tenant.actor(),
                ctx.tenant.tenant_id(),
            )
            .map_err(|error| ChironQlError {
                error: error.message,
                code: error.code.into(),
                hint: None,
                position: None,
                affected_estimate: None,
                query_id: query_id.into(),
                trace: None,
            })?;
            Ok(rows_response(
                query_id,
                vec!["job_id".into(), "view".into(), "status".into()],
                vec![json!({
                    "job_id": submitted.job_id,
                    "view": submitted.view,
                    "status": submitted.status,
                })],
            ))
        }
        Statement::Security(_) => Err(ChironQlError {
            error: "security statements require the authenticated protected executor".into(),
            code: "chironql.permission_denied".into(),
            hint: Some("Connect with a catalog API key to a protected authority.".into()),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        }),
        Statement::Sql(statement) => exec_sql(ctx, statement, query_id, trace, memory),
        Statement::Pipeline(pipeline) => exec_pipeline(ctx, pipeline, query_id, trace, memory),
        Statement::Transaction(transaction) => {
            exec_transaction(ctx, transaction, query_id, trace, memory)
        }
        Statement::Use { collection } => {
            ctx.session.collection = Some(collection.clone());
            Ok(empty_response(query_id))
        }
        Statement::ShowCollections => exec_show_collections(ctx, query_id, trace),
        Statement::CreateCollection(create) => exec_create_collection(ctx, create, query_id, trace),
        Statement::DropCollection {
            collection,
            if_exists,
        } => exec_drop_collection(ctx, collection, *if_exists, query_id, trace),
        Statement::Describe { collection } => {
            let name = resolve_collection(ctx, collection.as_deref(), query_id, trace)?;
            exec_describe(ctx, &name, query_id, trace)
        }
        Statement::Search(search) => exec_search(ctx, search, query_id, trace, memory),
        Statement::Hybrid(hybrid) => exec_hybrid(ctx, hybrid, query_id, trace, memory),
        Statement::Multi(multi) => exec_multi(ctx, multi, query_id, trace, memory),
        Statement::Recommend(recommend) => exec_recommend(ctx, recommend, query_id, trace, memory),
        Statement::Count(count) => {
            let name = resolve_collection(ctx, count.collection.as_deref(), query_id, trace)?;
            let filter = record_filter(trace, ctx.role, count.filter.as_ref());
            let started = Instant::now();
            let response = ctx
                .db
                .count_scoped(&name, filter, &ctx.tenant)
                .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
            trace.push_ok(
                stage::ENGINE_SEARCH,
                micros(started),
                detail(ctx.role, json!({"count": response.count})),
            );
            let render_started = Instant::now();
            let rows = vec![json!({"count": response.count})];
            trace.push_ok(stage::RENDER, micros(render_started), None);
            Ok(ChironQlResponse {
                credential: None,
                kind: ChironQlKind::Rows,
                columns: vec!["count".to_string()],
                column_types: Vec::new(),
                rows,
                stats: ChironQlStats::default(),
                next: None,
                query_id: query_id.to_string(),
                domains: Vec::new(),
                snapshot_id: None,
                transaction_id: None,
                committed: None,
                trace: None,
            })
        }
        Statement::Scroll(scroll) => exec_scroll(ctx, scroll, query_id, trace, memory),
        Statement::Get(get) => exec_get(ctx, get, query_id, trace, memory),
        Statement::Upsert(upsert) => exec_upsert(ctx, upsert, query_id, trace),
        Statement::DeletePoints { collection, ids } => {
            exec_delete_points(ctx, collection.as_deref(), ids, query_id, trace)
        }
        Statement::DeleteWhere { collection, filter } => {
            exec_delete_where(ctx, collection.as_deref(), filter, query_id, trace)
        }
        Statement::UpdatePayload(update) => exec_update_payload(ctx, update, query_id, trace),
        Statement::Relate(relate) => exec_relate(ctx, relate, query_id, trace),
        Statement::Unrelate(unrelate) => exec_unrelate(ctx, unrelate, query_id, trace),
        Statement::UpdateEdge(update) => exec_update_edge(ctx, update, query_id, trace),
        Statement::Traverse(traverse) => exec_traverse(ctx, traverse, query_id, trace, memory),
    }?;
    if !matches!(
        statement,
        Statement::Sql(_)
            | Statement::Pipeline(_)
            | Statement::Transaction(_)
            | Statement::Search(_)
            | Statement::Hybrid(_)
            | Statement::Multi(_)
            | Statement::Recommend(_)
            | Statement::Get(_)
            | Statement::Scroll(_)
            | Statement::Traverse(_)
    ) {
        memory
            .response(&value)
            .map_err(|e| receiving::error(query_id, e))?;
    }
    Ok(value)
}

fn exec_transaction(
    ctx: &mut ExecContext<'_>,
    transaction: &TransactionBlock,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    if ctx.db.identity_authority().is_some() {
        return Err(ChironQlError {
            error: "atomic multi-model transactions are not enabled for protected storage yet"
                .into(),
            code: "chironql.protected_unsupported".into(),
            hint: Some(
                "Configure relational and graph authorization before enabling protected multi-model writes."
                    .into(),
            ),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }
    let collection =
        resolve_collection(ctx, Some(transaction.vector.collection()), query_id, trace)?;
    let (points, point_deletes) = match &transaction.vector {
        TransactionVector::Create { .. } => {
            return Err(ChironQlError {
                error: "atomic server-ID creation requires a protected installation".into(),
                code: "chironql.protected_required".into(),
                hint: None,
                position: None,
                affected_estimate: None,
                query_id: query_id.into(),
                trace: None,
            });
        }
        TransactionVector::Upsert(upsert) => {
            let mut points = Vec::with_capacity(upsert.points.len());
            for value in &upsert.points {
                points.push(
                    serde_json::from_value::<Point>(value.clone()).map_err(|error| {
                        ChironQlError {
                        error: format!("this is not a valid point: {error}"),
                        code: "chironql.invalid_point".into(),
                        hint: Some(
                            "A point needs an id and a vector: {id: 'chunk-1', vector: [1,0,0]}."
                                .into(),
                        ),
                        position: None,
                        affected_estimate: None,
                        query_id: query_id.into(),
                        trace: None,
                    }
                    })?,
                );
            }
            (points, Vec::new())
        }
        TransactionVector::DeletePoints { ids, .. } => (Vec::new(), ids.clone()),
    };
    let point_count = points.len();
    let point_delete_count = point_deletes.len();
    let mut relations = Vec::new();
    let mut edge_deletes = Vec::new();
    let mut edge_updates = Vec::new();
    for mutation in &transaction.graph {
        match mutation {
            TransactionGraph::CreateRelation { .. } => {
                unreachable!("CREATE is routed to the protected executor")
            }
            TransactionGraph::Relate(relation) => relations.push(RelateRequest {
                source_point_id: relation.source_id.clone(),
                target_point_id: relation.target_id.clone(),
                edge_type: relation.edge_type.clone(),
                properties: relation.properties.clone(),
                scope: GraphRelationScope::Local,
                idempotency_key: None,
            }),
            TransactionGraph::Unrelate(unrelate) => edge_deletes.extend(
                unrelate
                    .edge_ids
                    .iter()
                    .cloned()
                    .map(EdgeToken::from_encoded),
            ),
            TransactionGraph::UpdateEdge(update) => edge_updates.push((
                EdgeToken::from_encoded(update.edge_id.clone()),
                UpdateEdgeRequest {
                    mode: if update.replace {
                        EdgePropertyMode::Replace
                    } else {
                        EdgePropertyMode::Merge
                    },
                    properties: update.properties.clone(),
                },
            )),
        }
    }
    let request = MultiModelTransactionRequest {
        sql: SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: transaction.sql.sql.clone(),
                parameters: ctx.parameters.clone(),
            }],
            idempotency_key: ctx.idempotency_key.clone(),
            retry_id: ctx.retry_id.clone(),
        },
        collection,
        points,
        point_deletes,
        relations,
        edge_deletes,
        edge_updates,
    };
    let audit_context = chirondb_core::audit::AuditContext {
        principal_id: ctx.tenant.actor().to_string(),
        tenant_id: ctx.tenant.tenant_id().map(str::to_string),
        transport: "chironql".into(),
        request_id: Some(query_id.into()),
    };
    let started = Instant::now();
    let result = ctx
        .db
        .execute_multimodel_transaction_with_sql_rows_owned(
            request,
            &ctx.tenant,
            &audit_context,
            transaction.expected_sql_rows,
        )
        .map_err(|error| {
            engine_error_at(
                ctx.role,
                query_id,
                trace,
                started,
                stage::ENGINE_WRITE,
                error,
            )
        })?;
    let mut bytes = 4096 + (result.edge_ids.len() as u64) * (size_of::<Value>() as u64 + 1024);
    for edge in &result.edge_ids {
        bytes = receiving::add(bytes, edge.capacity() as u64)
            .map_err(|e| receiving::error(query_id, e))?;
    }
    if let Some(id) = &result.sql.transaction_id {
        bytes = receiving::add(bytes, id.capacity() as u64)
            .map_err(|e| receiving::error(query_id, e))?;
    }
    memory.ql(bytes, query_id)?;
    result
        .consume(|result| {
            Ok({
                let relational_affected = result
                    .sql
                    .results
                    .iter()
                    .map(|value| match value {
                        SqlResult::Mutation { affected_rows } => *affected_rows,
                        SqlResult::Rows { rows, .. } => rows.len() as u64,
                        SqlResult::Definition { affected_objects } => *affected_objects,
                        SqlResult::Explain { .. } => 0,
                    })
                    .sum::<u64>();
                let affected = relational_affected
                    .saturating_add(point_count as u64)
                    .saturating_add(point_delete_count as u64)
                    .saturating_add(transaction.graph.len() as u64);
                trace.push_ok(
                    stage::ENGINE_WRITE,
                    micros(started),
                    detail(
                        ctx.role,
                        json!({
                            "snapshot": result.sql.snapshot,
                            "committed": result.sql.committed,
                            "relational": relational_affected,
                            "points": point_count,
                            "point_deletes": point_delete_count,
                            "edges": transaction.graph.len(),
                        }),
                    ),
                );
                let mut response = affected_response(query_id, affected);
                response.stats = graph_mutation_stats(result.graph, Some(affected));
                if !result.edge_ids.is_empty() {
                    response.columns = vec!["edge_id".into()];
                    response.rows = result
                        .edge_ids
                        .into_iter()
                        .map(|id| {
                            Value::Object(
                                [("edge_id".into(), Value::String(id.into_encoded()))]
                                    .into_iter()
                                    .collect(),
                            )
                        })
                        .collect();
                }
                response.snapshot_id = Some(format!("multi-model:{}", result.sql.snapshot));
                response.transaction_id = result.sql.transaction_id;
                response.committed = Some(result.sql.committed);
                Ok(response)
            })
        })
        .map_err(|e| receiving::error(query_id, e))?
}

#[derive(Clone)]
pub(crate) struct PipelineRows {
    pub(crate) columns: Vec<String>,
    pub(crate) types: HashMap<String, RelationalType>,
    pub(crate) rows: Vec<serde_json::Map<String, Value>>,
}

fn exec_pipeline(
    ctx: &mut ExecContext<'_>,
    pipeline: &Pipeline,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    if pipeline.explain {
        memory.ql(16384, query_id)?;
        let mut plan = vec![
            "operator=multimodel_pipeline".to_string(),
            "domains=vector,relational".to_string(),
            format!("vector_stage={}", pipeline.vector.kind_name()),
            format!("relational_tables={}", pipeline.relational.tables.join(",")),
            format!("joins={}", pipeline.joins.len()),
            format!("limit={}", pipeline.limit),
            "snapshot=multimodel_read".to_string(),
            "memory=bounded_hash_join".to_string(),
        ];
        if pipeline.graph.is_some() {
            plan[1] = "domains=vector,graph,relational".to_string();
            plan.push("graph_stage=traverse".to_string());
        }
        let rows = plan.into_iter().map(|line| json!({"plan": line})).collect();
        let mut response = rows_response(query_id, vec!["plan".into()], rows);
        response.column_types = vec![RelationalType::Text];
        return Ok(response);
    }

    let snapshot_started = Instant::now();
    let snapshot = ctx
        .db
        .begin_multimodel_read()
        .map_err(|error| engine_error(ctx.role, query_id, trace, snapshot_started, error))?
        .ok_or_else(|| ChironQlError {
            error: "a committed mutation is still publishing its storage projection".into(),
            code: "chironql.snapshot_busy".into(),
            hint: Some("Retry the read after the current commit finishes publication.".into()),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        })?;
    let frontier = snapshot.frontier();
    trace.push_ok(
        stage::SNAPSHOT,
        micros(snapshot_started),
        detail(
            ctx.role,
            json!({"mode": "multimodel_read", "frontier": frontier}),
        ),
    );

    let vector_response = dispatch(ctx, &pipeline.vector, query_id, trace, memory)?;
    let vector_namespace = pipeline
        .vector
        .collection()
        .map(str::to_owned)
        .or_else(|| ctx.session.collection.clone())
        .ok_or_else(|| ChironQlError {
            error: "VECTOR stage needs a collection".into(),
            code: "chironql.no_collection".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        })?;
    let vector_rows = qualify_pipeline_rows(
        &pipeline.vector_alias,
        vector_response,
        Some(&vector_namespace),
        memory,
    )?;

    let graph_rows = if let Some(graph) = &pipeline.graph {
        memory.ql(4096 + pipeline.vector_alias.len() as u64, query_id)?;
        let anchor_key = format!("{}.id", pipeline.vector_alias);
        let anchor_bytes = vector_rows
            .rows
            .iter()
            .try_fold(4096_u64, |bytes, row| {
                let id = row
                    .get(&anchor_key)
                    .and_then(Value::as_str)
                    .map_or(0, str::len);
                receiving::add(bytes, size_of::<String>() as u64 + id as u64)
            })
            .map_err(|e| receiving::error(query_id, e))?;
        memory.ql(anchor_bytes, query_id)?;
        let anchors = vector_rows
            .rows
            .iter()
            .filter_map(|row| {
                row.get(&anchor_key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        let mut traverse = graph.traverse.clone();
        traverse.anchors = anchors;
        if traverse.anchors.is_empty() {
            memory.ql(4096 + traverse.collection.len() as u64, query_id)?;
            Some(PipelineRows {
                columns: vec![format!("{}.record_ref", graph.alias)],
                types: HashMap::from([(
                    format!("{}.record_ref", graph.alias),
                    RelationalType::RecordRef {
                        namespace: traverse.collection.clone(),
                    },
                )]),
                rows: Vec::new(),
            })
        } else {
            let response = exec_traverse(ctx, &traverse, query_id, trace, memory)?;
            memory
                .response(&response)
                .map_err(|e| receiving::error(query_id, e))?;
            Some(qualify_pipeline_rows(
                &graph.alias,
                response,
                Some(&traverse.collection),
                memory,
            )?)
        }
    } else {
        None
    };

    let relational_response = exec_sql(ctx, &pipeline.relational, query_id, trace, memory)?;
    let relational_snapshot = relational_response.snapshot_id.clone();
    let relational_rows = qualify_pipeline_rows(
        &pipeline.relational_alias,
        relational_response,
        None,
        memory,
    )?;

    let mut response = assemble_pipeline_response(
        pipeline,
        vector_rows,
        graph_rows,
        relational_rows,
        query_id,
        trace,
        ctx.role,
        memory,
    )?;
    let snapshot_valid = snapshot
        .validate()
        .map_err(|error| engine_error(ctx.role, query_id, trace, snapshot_started, error))?;
    if !snapshot_valid {
        return Err(ChironQlError {
            error: "the multi-model visibility frontier changed during execution".into(),
            code: "chironql.snapshot_changed".into(),
            hint: Some("Retry the query; no partial rows were published.".into()),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }
    trace.push_ok(
        stage::AUTHORIZATION_RECHECK,
        micros(snapshot_started),
        detail(ctx.role, json!({"frontier": frontier})),
    );
    let relational_snapshot = relational_snapshot.unwrap_or_else(|| "relational:unknown".into());
    response.snapshot_id = Some(format!("multimodel:{frontier}:{relational_snapshot}"));
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_pipeline_response(
    pipeline: &Pipeline,
    vector_rows: PipelineRows,
    graph_rows: Option<PipelineRows>,
    relational_rows: PipelineRows,
    query_id: &str,
    trace: &mut QueryTrace,
    role: Role,
    memory: &mut QueryMemory,
) -> ExecResult {
    memory.ql(
        4096 + pipeline.relational_alias.len() as u64
            + pipeline.graph.as_ref().map_or(0, |graph| graph.alias.len()) as u64,
        query_id,
    )?;
    let mut sources = HashMap::new();
    sources
        .try_reserve(2)
        .map_err(|_| receiving::error(query_id, receiving::full()))?;
    sources.insert(pipeline.relational_alias.clone(), relational_rows);
    if let (Some(graph), Some(rows)) = (&pipeline.graph, graph_rows) {
        sources.insert(graph.alias.clone(), rows);
    }
    let mut joined = vector_rows;
    for join in &pipeline.joins {
        let join_started = Instant::now();
        let right = sources.remove(&join.alias).ok_or_else(|| ChironQlError {
            error: format!(
                "stage {} is joined more than once or is not available",
                join.alias
            ),
            code: "chironql.invalid_pipeline_join".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        })?;
        joined = join_pipeline_rows(joined, right, join, query_id, memory)?;
        trace.push_ok(
            stage::JOIN,
            micros(join_started),
            detail(
                role,
                json!({"alias": join.alias, "rows": joined.rows.len()}),
            ),
        );
    }
    if !sources.is_empty() {
        return Err(ChironQlError {
            error: "every pipeline stage must be joined exactly once".into(),
            code: "chironql.missing_join".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }

    if let Some((field, ascending)) = &pipeline.order_by {
        memory.ql(
            (joined.rows.len() as u64)
                .checked_mul(2 * size_of::<(serde_json::Map<String, Value>, JsonKey)>() as u64)
                .and_then(|n| n.checked_add(4096))
                .ok_or_else(|| receiving::error(query_id, receiving::full()))?,
            query_id,
        )?;
        let key = pipeline_field_key(field);
        let mut keyed = Vec::new();
        keyed
            .try_reserve_exact(joined.rows.len())
            .map_err(|_| receiving::error(query_id, receiving::full()))?;
        for row in joined.rows {
            memory.check().map_err(|e| receiving::error(query_id, e))?;
            let encoded = JsonKey::new(row.get(&key).unwrap_or(&Value::Null))
                .map_err(|e| receiving::error(query_id, e))?;
            keyed.push((row, encoded));
        }
        keyed.sort_by(|(left, left_key), (right, right_key)| {
            let ordering = compare_json(
                left.get(&key).unwrap_or(&Value::Null),
                right.get(&key).unwrap_or(&Value::Null),
                left_key.text(),
                right_key.text(),
            );
            if *ascending {
                ordering
            } else {
                ordering.reverse()
            }
        });
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(keyed.len())
            .map_err(|_| receiving::error(query_id, receiving::full()))?;
        for (row, _) in keyed {
            sorted.push(row);
        }
        joined.rows = sorted;
    }
    let width = pipeline.projection.len();
    let mut metadata = 4096_u64
        + (width as u64)
            * (4 * size_of::<String>() as u64 + size_of::<RelationalType>() as u64 + 512);
    for field in &pipeline.projection {
        metadata = receiving::add(
            metadata,
            8 * (field.alias.len() + field.field.len() + 1) as u64,
        )
        .map_err(|e| receiving::error(query_id, e))?;
    }
    for data_type in joined.types.values() {
        metadata = receiving::add(metadata, receiving::type_heap(data_type))
            .map_err(|e| receiving::error(query_id, e))?;
    }
    memory.ql(metadata, query_id)?;
    let projection_keys = pipeline
        .projection
        .iter()
        .map(pipeline_field_key)
        .collect::<Vec<_>>();
    let mut labels = HashSet::new();
    let columns = pipeline
        .projection
        .iter()
        .map(|field| {
            if labels.insert(field.field.clone()) {
                field.field.clone()
            } else {
                pipeline_field_key(field)
            }
        })
        .collect::<Vec<_>>();
    let column_types = pipeline
        .projection
        .iter()
        .map(|field| {
            joined
                .types
                .get(&pipeline_field_key(field))
                .cloned()
                .ok_or_else(|| ChironQlError {
                    error: format!(
                        "pipeline projection {} has no stable public type",
                        pipeline_field_key(field)
                    ),
                    code: "chironql.pipeline_untyped_projection".into(),
                    hint: Some("Project typed scalar, RECORD_REF, score, or depth fields.".into()),
                    position: None,
                    affected_estimate: None,
                    query_id: query_id.into(),
                    trace: None,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = joined.rows.len().min(pipeline.limit);
    let mut bytes = (count as u64) * size_of::<Value>() as u64;
    for row in joined.rows.iter().take(count) {
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        for (column, key) in columns.iter().zip(&projection_keys) {
            bytes = receiving::add(bytes, 1024 + column.capacity() as u64)
                .map_err(|e| receiving::error(query_id, e))?;
            if let Some(value) = row.get(key) {
                bytes = receiving::add(
                    bytes,
                    memory
                        .json_heap(value)
                        .map_err(|e| receiving::error(query_id, e))?,
                )
                .map_err(|e| receiving::error(query_id, e))?;
            }
        }
    }
    memory.ql(bytes, query_id)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)
        .map_err(|_| receiving::error(query_id, receiving::full()))?;
    for row in joined.rows.into_iter().take(count) {
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        rows.push(Value::Object(
            columns
                .iter()
                .cloned()
                .zip(
                    projection_keys
                        .iter()
                        .map(|key| row.get(key).cloned().unwrap_or(Value::Null)),
                )
                .collect(),
        ));
    }
    let mut response = rows_response(query_id, columns, rows);
    response.column_types = column_types;
    Ok(response)
}

pub(crate) fn qualify_pipeline_rows(
    alias: &str,
    response: ChironQlResponse,
    record_namespace: Option<&str>,
    memory: &mut QueryMemory,
) -> Result<PipelineRows, ChironQlError> {
    let mut bytes = 4096_u64
        + (response.rows.len() as u64) * size_of::<serde_json::Map<String, Value>>() as u64
        + (response.columns.len() as u64) * 512;
    for column in &response.columns {
        bytes = receiving::add(bytes, 8 * (alias.len() + column.len() + 1) as u64)
            .map_err(|e| receiving::error(&response.query_id, e))?;
    }
    for value in &response.rows {
        memory
            .check()
            .map_err(|e| receiving::error(&response.query_id, e))?;
        if let Value::Object(row) = value {
            for key in row.keys() {
                bytes = receiving::add(bytes, 1024 + 2 * (alias.len() + key.len() + 1) as u64)
                    .map_err(|e| receiving::error(&response.query_id, e))?;
            }
            if let Some(namespace) = record_namespace {
                bytes = receiving::add(
                    bytes,
                    4096 + namespace.len() as u64
                        + row.get("id").and_then(Value::as_str).map_or(0, str::len) as u64,
                )
                .map_err(|e| receiving::error(&response.query_id, e))?;
            }
        }
    }
    memory.ql(bytes, &response.query_id)?;
    let mut columns = response
        .columns
        .iter()
        .map(|column| format!("{alias}.{column}"))
        .collect::<Vec<_>>();
    let mut types = response
        .columns
        .iter()
        .zip(response.column_types)
        .map(|(column, data_type)| (format!("{alias}.{column}"), data_type))
        .collect::<HashMap<_, _>>();
    if response.columns.iter().any(|column| column == "score") {
        types.insert(format!("{alias}.score"), RelationalType::Float);
    }
    if response.columns.iter().any(|column| column == "depth") {
        types.insert(format!("{alias}.depth"), RelationalType::Integer);
    }
    if response.columns.iter().any(|column| column == "id") {
        types.insert(format!("{alias}.id"), RelationalType::Text);
    }
    if let Some(namespace) = record_namespace {
        columns.push(format!("{alias}.record_ref"));
        types.insert(
            format!("{alias}.record_ref"),
            RelationalType::RecordRef {
                namespace: namespace.to_string(),
            },
        );
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(response.rows.len())
        .map_err(|_| receiving::error(&response.query_id, receiving::full()))?;
    for value in response.rows {
        memory
            .check()
            .map_err(|e| receiving::error(&response.query_id, e))?;
        let Value::Object(object) = value else {
            return Err(ChironQlError {
                error: "pipeline stage returned a non-object row".into(),
                code: "chironql.engine_error".into(),
                hint: None,
                position: None,
                affected_estimate: None,
                query_id: response.query_id,
                trace: None,
            });
        };
        let record = record_namespace.and_then(|namespace| {
            object.get("id").and_then(Value::as_str).map(|id| {
                Value::Object(
                    [
                        ("namespace".into(), Value::String(namespace.into())),
                        ("id".into(), Value::String(id.into())),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
        });
        let mut qualified = object
            .into_iter()
            .map(|(key, value)| (format!("{alias}.{key}"), value))
            .collect::<serde_json::Map<_, _>>();
        if let Some(record) = record {
            qualified.insert(format!("{alias}.record_ref"), record);
        }
        rows.push(qualified);
    }
    Ok(PipelineRows {
        columns,
        types,
        rows,
    })
}

fn join_pipeline_rows(
    left: PipelineRows,
    right: PipelineRows,
    join: &crate::chironql_parser::PipelineJoin,
    query_id: &str,
    memory: &mut QueryMemory,
) -> Result<PipelineRows, ChironQlError> {
    const MAX_PIPELINE_CELLS: usize = 1_000_000;
    let left_key = pipeline_field_key(&join.left);
    let right_key = pipeline_field_key(&join.right);
    let (left_key, right_key) = if right.columns.contains(&right_key) {
        (left_key, right_key)
    } else if right.columns.contains(&left_key) {
        (right_key, left_key)
    } else {
        return Err(ChironQlError {
            error: "join must compare one previously joined field with the named stage".into(),
            code: "chironql.invalid_pipeline_join".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    };
    if left.types.get(&left_key) != right.types.get(&right_key) {
        return Err(ChironQlError {
            error: format!("join fields {left_key} and {right_key} have different types"),
            code: "chironql.pipeline_type_mismatch".into(),
            hint: Some("Join RECORD_REF values with the same namespace.".into()),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }
    let width = left.columns.len() + right.columns.len();
    let input_cells = left
        .rows
        .len()
        .saturating_add(right.rows.len())
        .saturating_mul(width);
    if input_cells > MAX_PIPELINE_CELLS {
        return Err(ChironQlError {
            error: "pipeline join exceeds its bounded memory budget".into(),
            code: "chironql.resource_exhausted".into(),
            hint: Some("Reduce VECTOR, GRAPH, or final LIMIT.".into()),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }
    let buckets = right
        .rows
        .len()
        .checked_next_power_of_two()
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| receiving::error(query_id, receiving::full()))?;
    memory.ql(
        (buckets as u64)
            * (size_of::<(JsonKey, Vec<&serde_json::Map<String, Value>>)>() as u64 + 64)
            + (right.rows.len() as u64) * 6 * size_of::<&serde_json::Map<String, Value>>() as u64
            + 4096,
        query_id,
    )?;
    // Equality and hashing read only immutable text; the retained lease never
    // participates in the key.
    #[allow(clippy::mutable_key_type)]
    let mut right_index: HashMap<JsonKey, Vec<&serde_json::Map<String, Value>>> = HashMap::new();
    right_index
        .try_reserve(right.rows.len())
        .map_err(|_| receiving::error(query_id, receiving::full()))?;
    for row in &right.rows {
        let Some(value) = row.get(&right_key).filter(|value| !value.is_null()) else {
            continue;
        };
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        let key = JsonKey::new(value).map_err(|e| receiving::error(query_id, e))?;
        let group = right_index.entry(key).or_default();
        group
            .try_reserve(1)
            .map_err(|_| receiving::error(query_id, receiving::full()))?;
        group.push(row);
    }
    let mut rows = Vec::new();
    for left_row in left.rows {
        memory.check().map_err(|e| receiving::error(query_id, e))?;
        let mut matched = false;
        if let Some(value) = left_row.get(&left_key).filter(|value| !value.is_null())
            && let Some(matches) =
                right_index.get(&JsonKey::new(value).map_err(|e| receiving::error(query_id, e))?)
        {
            for right_row in matches {
                if rows.len().saturating_add(1).saturating_mul(width) > MAX_PIPELINE_CELLS {
                    return Err(ChironQlError {
                        error: "pipeline join result exceeds its bounded memory budget".into(),
                        code: "chironql.resource_exhausted".into(),
                        hint: Some("Reduce VECTOR, GRAPH, or final LIMIT.".into()),
                        position: None,
                        affected_estimate: None,
                        query_id: query_id.into(),
                        trace: None,
                    });
                }
                admit_join_row(memory, &left_row, Some(right_row), &right.columns, query_id)?;
                rows.try_reserve(1)
                    .map_err(|_| receiving::error(query_id, receiving::full()))?;
                matched = true;
                let mut combined = left_row.clone();
                combined.extend((*right_row).clone());
                rows.push(combined);
            }
        }
        if !matched && join.kind == PipelineJoinKind::Left {
            admit_join_row(memory, &left_row, None, &right.columns, query_id)?;
            rows.try_reserve(1)
                .map_err(|_| receiving::error(query_id, receiving::full()))?;
            let mut combined = left_row;
            for column in &right.columns {
                combined.insert(column.clone(), Value::Null);
            }
            rows.push(combined);
        }
    }
    let schema = 4096
        + (width as u64)
            * 6
            * (size_of::<String>() as u64 + size_of::<RelationalType>() as u64 + 64);
    memory.ql(schema, query_id)?;
    let mut columns = left.columns;
    columns
        .try_reserve_exact(right.columns.len())
        .map_err(|_| receiving::error(query_id, receiving::full()))?;
    columns.extend(right.columns);
    let mut types = left.types;
    types
        .try_reserve(right.types.len())
        .map_err(|_| receiving::error(query_id, receiving::full()))?;
    types.extend(right.types);
    Ok(PipelineRows {
        columns,
        types,
        rows,
    })
}

fn admit_join_row(
    memory: &mut QueryMemory,
    left: &serde_json::Map<String, Value>,
    right: Option<&&serde_json::Map<String, Value>>,
    columns: &[String],
    query_id: &str,
) -> Result<(), ChironQlError> {
    let mut bytes = 6 * size_of::<serde_json::Map<String, Value>>() as u64;
    for (key, value) in left
        .iter()
        .chain(right.into_iter().flat_map(|row| row.iter()))
    {
        bytes = receiving::add(bytes, 1024 + key.capacity() as u64)
            .and_then(|n| receiving::add(n, memory.json_heap(value)?))
            .map_err(|e| receiving::error(query_id, e))?;
    }
    if right.is_none() {
        for column in columns {
            bytes = receiving::add(bytes, 1024 + column.capacity() as u64)
                .map_err(|e| receiving::error(query_id, e))?;
        }
    }
    memory.ql(bytes, query_id)
}

fn pipeline_field_key(field: &PipelineField) -> String {
    format!("{}.{}", field.alias, field.field)
}

fn compare_json(left: &Value, right: &Value, left_encoded: &str, right_encoded: &str) -> Ordering {
    match (left, right) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Greater,
        (_, Value::Null) => Ordering::Less,
        (Value::Number(left), Value::Number(right)) => {
            match (left.as_i64(), right.as_i64(), left.as_u64(), right.as_u64()) {
                (Some(left), Some(right), _, _) => left.cmp(&right),
                (_, _, Some(left), Some(right)) => left.cmp(&right),
                (Some(left), None, _, Some(_)) if left < 0 => Ordering::Less,
                (None, Some(right), Some(_), _) if right < 0 => Ordering::Greater,
                _ => left
                    .as_f64()
                    .partial_cmp(&right.as_f64())
                    .unwrap_or(Ordering::Equal),
            }
        }
        (Value::String(left), Value::String(right)) => left.cmp(right),
        _ => left_encoded.cmp(right_encoded),
    }
}

fn exec_sql(
    ctx: &mut ExecContext<'_>,
    statement: &crate::chironql_parser::SqlStatement,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    if ctx.db.identity_authority().is_some() {
        return Err(ChironQlError {
            error: "native relational SQL requires a protected authorization context".into(),
            code: "chironql.protected_unsupported".into(),
            hint: Some(
                "Use the authenticated protected ChironQL, HTTP, gRPC, or ChironWire route.".into(),
            ),
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        });
    }
    let request = SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: statement.sql.clone(),
            parameters: ctx.parameters.clone(),
        }],
        idempotency_key: ctx.idempotency_key.clone(),
        retry_id: ctx.retry_id.clone(),
    };
    let audit_context = chirondb_core::audit::AuditContext {
        principal_id: ctx.tenant.actor().to_string(),
        tenant_id: ctx.tenant.tenant_id().map(str::to_string),
        transport: "chironql".into(),
        request_id: ctx.retry_id.clone(),
    };
    let started = Instant::now();
    let result = ctx
        .db
        .execute_sql_with_audit_owned(request, &audit_context)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        if statement.class == StatementClass::Read {
            stage::RELATIONAL_SCAN
        } else {
            stage::ENGINE_WRITE
        },
        micros(started),
        detail(
            ctx.role,
            json!({"snapshot": result.snapshot, "committed": result.committed}),
        ),
    );

    sql_execution_admitted(result, query_id, memory)
}

pub(crate) fn sql_execution_admitted(
    result: crate::SqlResponse,
    query_id: &str,
    memory: &mut QueryMemory,
) -> ExecResult {
    memory
        .sql(&result)
        .map_err(|e| receiving::error(query_id, e))?;
    result
        .consume(|value| Ok(sql_execution_response(value, query_id)))
        .map_err(|e| receiving::error(query_id, e))?
}

pub(crate) fn sql_execution_response(
    result: chirondb_core::SqlExecutionResponse,
    query_id: &str,
) -> ExecResult {
    if !result.committed && matches!(result.outcome, chirondb_core::SqlOutcome::Rejected) {
        let mut response = empty_response(query_id);
        response.transaction_id = result.transaction_id;
        response.committed = Some(false);
        return Ok(response);
    }
    let sql_result = result
        .results
        .into_iter()
        .next()
        .ok_or_else(|| ChironQlError {
            error: "relational executor returned no result".into(),
            code: "chironql.engine_error".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: query_id.into(),
            trace: None,
        })?;
    let mut response = match sql_result {
        SqlResult::Definition { affected_objects } => affected_response(query_id, affected_objects),
        SqlResult::Mutation { affected_rows } => affected_response(query_id, affected_rows),
        SqlResult::Rows {
            columns,
            column_types,
            rows,
        } => {
            let mut json_rows = Vec::new();
            json_rows
                .try_reserve_exact(rows.len())
                .map_err(|_| receiving::error(query_id, receiving::full()))?;
            for row in rows {
                let object = columns
                    .iter()
                    .cloned()
                    .zip(row.into_iter().map(relational_value_json))
                    .collect();
                json_rows.push(Value::Object(object));
            }
            let mut response = rows_response(query_id, columns, json_rows);
            response.column_types = column_types;
            response
        }
        SqlResult::Explain { plan } => {
            let rows = plan.into_iter().map(|line| json!({"plan": line})).collect();
            let mut response = rows_response(query_id, vec!["plan".into()], rows);
            response.column_types = vec![RelationalType::Text];
            response
        }
    };
    response.snapshot_id = Some(format!("relational:{}", result.snapshot));
    response.transaction_id = result.transaction_id;
    response.committed = Some(result.committed);
    Ok(response)
}

fn relational_value_json(value: RelationalValue) -> Value {
    match value {
        RelationalValue::Null => Value::Null,
        RelationalValue::Boolean(value) => json!(value),
        RelationalValue::Integer(value) => json!(value),
        RelationalValue::Float(value) => json!(value),
        RelationalValue::Decimal(value)
        | RelationalValue::Text(value)
        | RelationalValue::Date(value)
        | RelationalValue::TimestampUtc(value) => Value::String(value),
        RelationalValue::Bytes(value) => json!(value),
        RelationalValue::Uuid(value) => json!(value.to_string()),
        RelationalValue::Json(value) => value,
        RelationalValue::Vector(value) => json!(value),
        RelationalValue::RecordRef(value) => Value::Object(
            [
                ("namespace".into(), Value::String(value.namespace)),
                ("id".into(), Value::String(value.id)),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

fn exec_show_collections(
    ctx: &mut ExecContext<'_>,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let started = Instant::now();
    let collections: Vec<CollectionConfig> = ctx
        .db
        .list_collections()
        .into_iter()
        .filter(|config| ctx.allows_collection(&config.name))
        .collect();
    trace.push_ok(
        stage::ENGINE_SEARCH,
        micros(started),
        detail(ctx.role, json!({"collections": collections.len()})),
    );

    let render_started = Instant::now();
    let rows = collections
        .iter()
        .map(|config| {
            json!({
                "name": config.name,
                "dim": config.vector_dim,
                "metric": config.metric,
            })
        })
        .collect();
    trace.push_ok(stage::RENDER, micros(render_started), None);

    Ok(rows_response(
        query_id,
        vec!["name".to_string(), "dim".to_string(), "metric".to_string()],
        rows,
    ))
}

fn exec_describe(
    ctx: &mut ExecContext<'_>,
    collection: &str,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let started = Instant::now();
    let config = collection_config(ctx.db, collection)
        .ok_or_else(|| collection_not_found(query_id, collection))?;
    trace.push_ok(stage::ENGINE_SEARCH, micros(started), None);

    let render_started = Instant::now();
    let rows = config_rows(&config);
    trace.push_ok(stage::RENDER, micros(render_started), None);

    Ok(rows_response(query_id, config_columns(), rows))
}

/// One `field`/`value` row per configured setting.
///
/// `CREATE COLLECTION` echoes what it made through this too, so what a
/// collection reports and what you type to build one use the same names.
fn config_rows(config: &CollectionConfig) -> Vec<Value> {
    let mut rows = vec![
        json!({"field": "name", "value": json!(config.name)}),
        json!({"field": "vector_dim", "value": json!(config.vector_dim)}),
        json!({"field": "metric", "value": json!(config.metric)}),
        json!({"field": "shards", "value": json!(config.shards)}),
        json!({"field": "replicas", "value": json!(config.replicas)}),
    ];
    for (field, kind) in &config.payload_schema {
        rows.push(json!({"field": format!("payload.{field}"), "value": json!(kind)}));
    }
    for (name, dim) in &config.named_vector_dims {
        rows.push(json!({"field": format!("vector.{name}"), "value": json!(dim)}));
    }
    rows
}

fn config_columns() -> Vec<String> {
    vec!["field".to_string(), "value".to_string()]
}

/// `CREATE COLLECTION` — grammar supplies the name, the dimension and the
/// metric; `WITH` supplies whatever else `CollectionConfig` carries.
///
/// The `WITH` object is deserialized into the struct rather than parsed field
/// by field, so a field added to `CollectionConfig` is reachable immediately.
/// Unknown keys are refused rather than ignored: serde would drop a misspelt
/// `shardz` silently, and a setting that silently did not apply is worse than
/// a rejected statement.
fn exec_create_collection(
    ctx: &mut ExecContext<'_>,
    create: &CreateCollection,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let started = Instant::now();
    if !ctx.allows_collection(&create.name) {
        let message = format!(
            "collection '{}' is not available to this session",
            create.name
        );
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.collection_forbidden",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.collection_forbidden".to_string(),
            hint: Some("This API key is scoped to named collections.".to_string()),
            position: None,
            affected_estimate: None,
            query_id: query_id.to_string(),
            trace: None,
        });
    }

    let mut object = match create.options.clone() {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    for key in object.keys() {
        if key == "index_kind" {
            return Err(ddl_error(
                query_id,
                trace,
                started,
                "chironql.no_index_family",
                "`index_kind` is not a choice",
                "LS-VEC is the sole index path — there is no index family to select.",
            ));
        }
        if !COLLECTION_OPTION_KEYS.contains(&key.as_str()) {
            let known = COLLECTION_OPTION_KEYS.join(", ");
            return Err(ddl_error_owned(
                query_id,
                trace,
                started,
                "chironql.unknown_collection_option",
                format!("`{key}` is not a collection setting"),
                format!("Settings: {known}. The name, dimension and metric are positional."),
            ));
        }
    }

    object.insert("name".to_string(), json!(create.name));
    object.insert("vector_dim".to_string(), json!(create.dim));
    if let Some(metric) = create.metric {
        object.insert("metric".to_string(), json!(metric));
    }

    let config: CollectionConfig =
        serde_json::from_value(Value::Object(object)).map_err(|error| {
            ddl_error_owned(
                query_id,
                trace,
                started,
                "chironql.invalid_collection_options",
                format!("WITH does not describe a collection: {error}"),
                "DESCRIBE <collection> names every field and its shape.".to_string(),
            )
        })?;

    let created = ctx
        .db
        .create_collection(config)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(
            ctx.role,
            json!({"collection": created.name, "dim": created.vector_dim}),
        ),
    );

    let render_started = Instant::now();
    let rows = config_rows(&created);
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(rows_response(query_id, config_columns(), rows))
}

/// Settings `WITH` accepts, by their `CollectionConfig` field names.
///
/// `index_kind` is deliberately absent — it has its own rejection above.
const COLLECTION_OPTION_KEYS: &[&str] = &[
    "shards",
    "replicas",
    "quantization",
    "payload_schema",
    "named_vector_dims",
    "hnsw_m",
    "hnsw_ef_construction",
    "hnsw_ef_search",
    "recall_sla",
    "streamer_max_bytes",
];

/// `DROP COLLECTION` — counts first, then asks, then destroys.
///
/// The gate is the one `DELETE ... WHERE` uses, for the same reason: the
/// number belongs in front of whoever decides, and a surface with no prompt
/// (SDK, HTTP, a script) must be protected by the server rather than by a
/// client that might not ask.
fn exec_drop_collection(
    ctx: &mut ExecContext<'_>,
    collection: &str,
    if_exists: bool,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let started = Instant::now();
    // Scoping before existence, as in `resolve_collection`: a restricted
    // caller must not be able to probe for collections it may not see.
    if !ctx.allows_collection(collection) {
        let message = format!("collection '{collection}' is not available to this session");
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.collection_forbidden",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.collection_forbidden".to_string(),
            hint: Some("SHOW COLLECTIONS lists what this session may use.".to_string()),
            position: None,
            affected_estimate: None,
            query_id: query_id.to_string(),
            trace: None,
        });
    }

    if collection_config(ctx.db, collection).is_none() {
        if if_exists {
            trace.push_ok(
                stage::RESOLVE_COLLECTION,
                micros(started),
                detail(
                    ctx.role,
                    json!({"collection": collection, "existed": false}),
                ),
            );
            return Ok(affected_response(query_id, 0));
        }
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.collection_not_found",
            format!("collection '{collection}' not found"),
        );
        return Err(collection_not_found(query_id, collection));
    }
    trace.push_ok(
        stage::RESOLVE_COLLECTION,
        micros(started),
        detail(ctx.role, json!({"collection": collection})),
    );

    let count_started = Instant::now();
    let points = ctx
        .db
        .count_scoped(collection, None, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, count_started, error))?
        .count;
    trace.push_ok(
        stage::COUNT_MATCHES,
        micros(count_started),
        detail(ctx.role, json!({"points": points})),
    );

    if !ctx.confirm {
        let message = format!("this would drop '{collection}' and delete its {points} point(s)");
        trace.push_failed(
            stage::CONFIRM,
            0,
            "chironql.confirmation_required",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.confirmation_required".to_string(),
            hint: Some(
                "Nothing was dropped. Confirm to proceed - `--yes` on the command line, \
                 or `confirm: true` in the request."
                    .to_string(),
            ),
            position: None,
            affected_estimate: Some(points as u32),
            query_id: query_id.to_string(),
            trace: None,
        });
    }
    trace.push_ok(
        stage::CONFIRM,
        0,
        detail(ctx.role, json!({"confirmed": true})),
    );

    let drop_started = Instant::now();
    ctx.db
        .delete_collection(collection)
        .map_err(|error| engine_error(ctx.role, query_id, trace, drop_started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(drop_started),
        detail(ctx.role, json!({"dropped": collection, "points": points})),
    );

    // A session still pointing at what was just dropped would fail every later
    // statement with "not found" and no explanation.
    if ctx.session.collection.as_deref() == Some(collection) {
        ctx.session.collection = None;
    }

    Ok(affected_response(query_id, points as u64))
}

fn ddl_error(
    query_id: &str,
    trace: &mut QueryTrace,
    started: Instant,
    code: &'static str,
    message: &str,
    hint: &str,
) -> ChironQlError {
    ddl_error_owned(
        query_id,
        trace,
        started,
        code,
        message.to_string(),
        hint.to_string(),
    )
}

fn ddl_error_owned(
    query_id: &str,
    trace: &mut QueryTrace,
    started: Instant,
    code: &'static str,
    message: String,
    hint: String,
) -> ChironQlError {
    trace.push_failed(stage::ENGINE_WRITE, micros(started), code, message.clone());
    ChironQlError {
        error: message,
        code: code.to_string(),
        hint: Some(hint),
        position: None,
        affected_estimate: None,
        query_id: query_id.to_string(),
        trace: None,
    }
}

fn exec_search(
    ctx: &mut ExecContext<'_>,
    search: &Search,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, search.collection.as_deref(), query_id, trace)?;
    let vector_expr = search
        .vector
        .as_ref()
        .expect("parser guarantees SEARCH has a NEAR clause");
    let vector = resolve_vector(
        ctx,
        &collection,
        vector_expr,
        search.vector_name.as_deref(),
        query_id,
        trace,
    )?;
    let filter = record_filter(trace, ctx.role, search.filter.as_ref());

    let request = SearchRequest {
        graph: search
            .graph
            .as_ref()
            .map(|graph| graph_constraint(graph, search.budget_ms)),
        vector,
        vector_name: search.vector_name.clone(),
        k: search.limit.unwrap_or(10),
        filter,
        budget_ms: search.budget_ms,
        consistency: None,
        ef_search: search.ef_search,
        recall_target: search.recall_target,
        with_payload: search.with_payload,
    };

    let started = Instant::now();
    let response = ctx
        .db
        .search_scoped(&collection, request, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    push_search_stage(ctx.role, trace, started, &response);

    hits_response(query_id, response, search.recall_target, trace, memory)
}

fn exec_hybrid(
    ctx: &mut ExecContext<'_>,
    hybrid: &Hybrid,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, hybrid.collection.as_deref(), query_id, trace)?;
    let vector = match hybrid.vector.as_ref() {
        Some(expr) => Some(resolve_vector(
            ctx,
            &collection,
            expr,
            hybrid.vector_name.as_deref(),
            query_id,
            trace,
        )?),
        None => None,
    };
    let filter = record_filter(trace, ctx.role, hybrid.filter.as_ref());

    if let Some(text) = &hybrid.text {
        let started = Instant::now();
        let response = ctx
            .db
            .text_hybrid_search_scoped(
                &collection,
                crate::TextHybridSearchRequest {
                    vector: vector.unwrap_or_default(),
                    query: text.query.clone(),
                    text_field: text.field.clone(),
                    k: hybrid.limit.unwrap_or(10),
                    filter,
                    budget_ms: hybrid.budget_ms,
                },
                &ctx.tenant,
            )
            .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
        push_search_stage(ctx.role, trace, started, &response);
        return hits_response(query_id, response, None, trace, memory);
    }

    let request = HybridSearchRequest {
        graph: hybrid
            .graph
            .as_ref()
            .map(|graph| graph_constraint(graph, None)),
        vector,
        vector_name: hybrid.vector_name.clone(),
        sparse_vector: hybrid.sparse.clone(),
        k: hybrid.limit.unwrap_or(10),
        filter,
        budget_ms: hybrid.budget_ms,
        fusion: hybrid.fusion.unwrap_or_default(),
        dense_weight: hybrid.dense_weight.unwrap_or(1.0),
        sparse_weight: hybrid.sparse_weight.unwrap_or(1.0),
    };

    let started = Instant::now();
    let response = ctx
        .db
        .hybrid_search_scoped(&collection, request, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    push_search_stage(ctx.role, trace, started, &response);

    hits_response(query_id, response, None, trace, memory)
}

fn exec_multi(
    ctx: &mut ExecContext<'_>,
    multi: &Multi,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, multi.collection.as_deref(), query_id, trace)?;
    let filter = record_filter(trace, ctx.role, multi.filter.as_ref());
    let k = multi.limit.unwrap_or(10);

    let mut searches = Vec::with_capacity(multi.vectors.len());
    for expr in &multi.vectors {
        let vector = resolve_vector(ctx, &collection, expr, None, query_id, trace)?;
        searches.push(SearchRequest {
            graph: None,
            vector,
            vector_name: None,
            k,
            filter: filter.clone(),
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        });
    }

    let request = MultiSearchRequest {
        searches,
        fusion: multi.fusion,
        fused_k: Some(k),
        weights: multi.weights.clone(),
    };

    let started = Instant::now();
    let response = ctx
        .db
        .multi_search(&collection, request)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    let searched: usize = response.results.iter().map(|result| result.searched).sum();
    let degraded = response.results.iter().any(|result| result.degraded);
    trace.push_ok(
        stage::ENGINE_SEARCH,
        micros(started),
        detail(
            ctx.role,
            json!({"branches": response.results.len(), "scanned": searched, "degraded": degraded}),
        ),
    );

    // `Db::multi_search` fuses internally when a fusion is set; with none it
    // returns one result set per branch. Either way the first result set is
    // what a terminal wants to show, and the trace says how many there were.
    let fuse_started = Instant::now();
    let result_sets = response.results.len();
    let hits = response
        .results
        .into_iter()
        .next()
        .map(|result| result.hits)
        .unwrap_or_default();
    trace.push_ok(
        stage::FUSE,
        micros(fuse_started),
        detail(
            ctx.role,
            json!({"fusion": multi.fusion, "result_sets": result_sets}),
        ),
    );
    let render_started = Instant::now();
    let mut result =
        retrieval::hits(hits, query_id, memory).map_err(|e| receiving::error(query_id, e))?;
    trace.push_ok(stage::RENDER, micros(render_started), None);
    result.stats.searched = Some(searched);
    result.stats.degraded = Some(degraded);
    Ok(result)
}

fn exec_recommend(
    ctx: &mut ExecContext<'_>,
    recommend: &Recommend,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, recommend.collection.as_deref(), query_id, trace)?;
    let filter = record_filter(trace, ctx.role, recommend.filter.as_ref());

    let request = RecommendRequest {
        positive: recommend.positive.clone(),
        negative: recommend.negative.clone(),
        vector_name: recommend.vector_name.clone(),
        k: recommend.limit.unwrap_or(10),
        filter,
        budget_ms: None,
    };

    let started = Instant::now();
    let response = ctx
        .db
        .recommend(&collection, request)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    push_search_stage(ctx.role, trace, started, &response);

    hits_response(query_id, response, None, trace, memory)
}

fn exec_scroll(
    ctx: &mut ExecContext<'_>,
    scroll: &Scroll,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, scroll.collection.as_deref(), query_id, trace)?;
    let filter = record_filter(trace, ctx.role, scroll.filter.as_ref());

    let started = Instant::now();
    let response = ctx
        .db
        .scroll_scoped(
            &collection,
            scroll.after.as_deref(),
            scroll.limit.unwrap_or(10),
            filter,
            &ctx.tenant,
        )
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_SEARCH,
        micros(started),
        detail(ctx.role, json!({"returned": response.points.len()})),
    );

    let render_started = Instant::now();
    let result = retrieval::points(
        response.points,
        response.next_offset,
        false,
        query_id,
        memory,
    )
    .map_err(|e| receiving::error(query_id, e))?;
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(result)
}

fn exec_get(
    ctx: &mut ExecContext<'_>,
    get: &Get,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, get.collection.as_deref(), query_id, trace)?;

    let started = Instant::now();
    let points = ctx
        .db
        .get_points_scoped(&collection, &get.ids, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_SEARCH,
        micros(started),
        detail(
            ctx.role,
            json!({"requested": get.ids.len(), "found": points.len()}),
        ),
    );

    let render_started = Instant::now();
    let result = retrieval::points(points, None, false, query_id, memory)
        .map_err(|e| receiving::error(query_id, e))?;
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

fn exec_upsert(
    ctx: &mut ExecContext<'_>,
    upsert: &Upsert,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, upsert.collection.as_deref(), query_id, trace)?;

    // Point shape is validated here rather than in the parser, because only
    // the collection knows its dimension and named vector spaces.
    let mut points = Vec::with_capacity(upsert.points.len());
    for value in &upsert.points {
        match serde_json::from_value::<Point>(value.clone()) {
            Ok(point) => points.push(point),
            Err(error) => {
                return Err(ChironQlError {
                    error: format!("this is not a valid point: {error}"),
                    code: "chironql.invalid_point".to_string(),
                    hint: Some(
                        "A point needs an id and a vector: {id: 'phone', vector: [1,0,0]}."
                            .to_string(),
                    ),
                    position: None,
                    affected_estimate: None,
                    query_id: query_id.to_string(),
                    trace: None,
                });
            }
        }
    }

    // `Db::upsert_wait` answers with the collection's total point count, not
    // the number written — the same figure REST reports as `total`. The number
    // this statement affected is the number it submitted.
    let submitted = points.len() as u64;
    let started = Instant::now();
    let collection_total = ctx
        .db
        .upsert_scoped(&collection, points, upsert.wait, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(
            ctx.role,
            json!({
                "written": submitted,
                "collection_total": collection_total,
                "wait": upsert.wait,
            }),
        ),
    );

    Ok(affected_response(query_id, submitted))
}

fn exec_delete_points(
    ctx: &mut ExecContext<'_>,
    collection: Option<&str>,
    ids: &[String],
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, collection, query_id, trace)?;

    let started = Instant::now();
    let deleted = ctx
        .db
        .delete_scoped(&collection, ids, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(
            ctx.role,
            json!({"requested": ids.len(), "deleted": deleted}),
        ),
    );

    Ok(affected_response(query_id, deleted as u64))
}

/// `DELETE ... WHERE` counts before it deletes.
///
/// Without `confirm`, the count is all that runs: the caller is refused with
/// `chironql.confirmation_required` and the number attached, so whatever is
/// asking - a prompt, a UI dialog, a script - can decide with a real figure
/// rather than a guess. The gate lives here rather than in the REPL so every
/// surface inherits it, including SDK and HTTP callers that have no prompt.
fn exec_delete_where(
    ctx: &mut ExecContext<'_>,
    collection: Option<&str>,
    filter: &chirondb_types::Filter,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, collection, query_id, trace)?;
    let filter = record_filter(trace, ctx.role, Some(filter))
        .expect("record_filter returns Some for Some input");

    let count_started = Instant::now();
    let matched = ctx
        .db
        .count_scoped(&collection, Some(filter.clone()), &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, count_started, error))?
        .count;
    trace.push_ok(
        stage::COUNT_MATCHES,
        micros(count_started),
        detail(ctx.role, json!({"matched": matched})),
    );

    if !ctx.confirm {
        let message = format!("this would delete {matched} point(s) from '{collection}'");
        trace.push_failed(
            stage::CONFIRM,
            0,
            "chironql.confirmation_required",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.confirmation_required".to_string(),
            hint: Some(
                "Nothing was deleted. Confirm to proceed - `--yes` on the command line, \
                 or `confirm: true` in the request."
                    .to_string(),
            ),
            position: None,
            affected_estimate: Some(matched as u32),
            query_id: query_id.to_string(),
            trace: None,
        });
    }
    trace.push_ok(
        stage::CONFIRM,
        0,
        detail(ctx.role, json!({"confirmed": true})),
    );

    let started = Instant::now();
    let deleted = ctx
        .db
        .delete_by_filter_scoped(&collection, &filter, &ctx.tenant)
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(ctx.role, json!({"matched": matched, "deleted": deleted})),
    );

    Ok(affected_response(query_id, deleted as u64))
}

fn exec_update_payload(
    ctx: &mut ExecContext<'_>,
    update: &UpdatePayload,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, update.collection.as_deref(), query_id, trace)?;

    let started = Instant::now();
    // `REPLACE` swaps the whole payload; without it the fields are merged.
    let merge = !update.replace;
    ctx.db
        .set_payload_scoped(
            &collection,
            &update.id,
            update.payload.clone(),
            merge,
            &ctx.tenant,
        )
        .map_err(|error| engine_error(ctx.role, query_id, trace, started, error))?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(ctx.role, json!({"id": update.id, "merge": merge})),
    );

    Ok(affected_response(query_id, 1))
}

fn exec_relate(
    ctx: &mut ExecContext<'_>,
    relate: &Relate,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, Some(&relate.collection), query_id, trace)?;
    let request = RelateRequest {
        source_point_id: relate.source_id.clone(),
        target_point_id: relate.target_id.clone(),
        edge_type: relate.edge_type.clone(),
        properties: relate.properties.clone(),
        scope: GraphRelationScope::Local,
        idempotency_key: relate.idempotency_key.clone(),
    };
    let started = Instant::now();
    let result = if relate.deferred_endpoints {
        let Some(session_id) = ctx.session.graph_deferred_session.as_ref() else {
            let message = "WITH DEFERRED ENDPOINTS needs an open graph session".to_string();
            trace.push_failed(
                stage::ENGINE_WRITE,
                micros(started),
                "chironql.deferred_session_required",
                message.clone(),
            );
            return Err(ChironQlError {
                error: message,
                code: "chironql.deferred_session_required".to_string(),
                hint: Some(
                    "Open and bind a native deferred graph session before this statement."
                        .to_string(),
                ),
                position: None,
                affected_estimate: None,
                query_id: query_id.to_string(),
                trace: None,
            });
        };
        ctx.db
            .relate_deferred_scoped(&collection, session_id, request, relate.wait, &ctx.tenant)
    } else {
        ctx.db
            .relate_scoped(&collection, request, relate.wait, &ctx.tenant)
    }
    .map_err(|error| {
        engine_error_at(
            ctx.role,
            query_id,
            trace,
            started,
            stage::ENGINE_WRITE,
            error,
        )
    })?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(
            ctx.role,
            json!({
                "edges": 1,
                "wait": relate.wait,
                "deferred_endpoints": relate.deferred_endpoints,
                "replayed": result.receipt.replayed,
            }),
        ),
    );

    let render_started = Instant::now();
    let mut response = rows_response(
        query_id,
        vec!["edge_id".to_string()],
        vec![json!({"edge_id": result.edge_id.as_str()})],
    );
    response.stats = graph_mutation_stats(result.receipt, Some(1));
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(response)
}

fn exec_unrelate(
    ctx: &mut ExecContext<'_>,
    unrelate: &Unrelate,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, Some(&unrelate.collection), query_id, trace)?;
    let tokens = unrelate
        .edge_ids
        .iter()
        .cloned()
        .map(EdgeToken::from_encoded)
        .collect::<Vec<_>>();
    let started = Instant::now();
    let (receipt, affected) = ctx
        .db
        .unrelate_many_scoped(&collection, &tokens, unrelate.wait, &ctx.tenant)
        .map_err(|error| {
            engine_error_at(
                ctx.role,
                query_id,
                trace,
                started,
                stage::ENGINE_WRITE,
                error,
            )
        })?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(ctx.role, json!({"edges": affected, "wait": unrelate.wait})),
    );
    let mut response = affected_response(query_id, affected as u64);
    response.stats = graph_mutation_stats(receipt, Some(affected as u64));
    Ok(response)
}

fn exec_update_edge(
    ctx: &mut ExecContext<'_>,
    update: &UpdateEdge,
    query_id: &str,
    trace: &mut QueryTrace,
) -> ExecResult {
    let collection = resolve_collection(ctx, Some(&update.collection), query_id, trace)?;
    let token = EdgeToken::from_encoded(update.edge_id.clone());
    let request = UpdateEdgeRequest {
        mode: if update.replace {
            EdgePropertyMode::Replace
        } else {
            EdgePropertyMode::Merge
        },
        properties: update.properties.clone(),
    };
    let started = Instant::now();
    let receipt = ctx
        .db
        .update_edge_scoped(&collection, &token, request, update.wait, &ctx.tenant)
        .map_err(|error| {
            engine_error_at(
                ctx.role,
                query_id,
                trace,
                started,
                stage::ENGINE_WRITE,
                error,
            )
        })?;
    trace.push_ok(
        stage::ENGINE_WRITE,
        micros(started),
        detail(
            ctx.role,
            json!({"edges": 1, "wait": update.wait, "replace": update.replace}),
        ),
    );
    let mut response = affected_response(query_id, 1);
    response.stats = graph_mutation_stats(receipt, Some(1));
    Ok(response)
}

fn exec_traverse(
    ctx: &mut ExecContext<'_>,
    traverse: &Traverse,
    query_id: &str,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let collection = resolve_collection(ctx, Some(&traverse.collection), query_id, trace)?;
    let defaults = TraversalBudget::default();
    let request = GraphTraversalQueryRequest {
        traversal: chirondb_types::graph::GraphTraverseRequest {
            anchors: traverse.anchors.clone(),
            edge_types: traverse.edge_types.clone(),
            direction: traverse.direction,
            node_filter: traverse.node_filter.clone(),
            edge_filter: traverse.edge_filter.clone(),
            budget: TraversalBudget {
                max_depth: traverse.depth,
                max_time_ms: traverse.budget_ms.unwrap_or(defaults.max_time_ms),
                ..defaults
            },
        },
        returns: match traverse.returns {
            GraphReturn::Nodes => GraphTraversalReturn::Nodes,
            GraphReturn::Edges => GraphTraversalReturn::Edges,
            GraphReturn::Paths => GraphTraversalReturn::Paths,
        },
        limit: traverse.limit,
        with_payload: traverse.with_payload,
    };
    let started = Instant::now();
    let response = ctx
        .db
        .traverse_query_scoped(&collection, request, &ctx.tenant)
        .map_err(|error| {
            engine_error_at(
                ctx.role,
                query_id,
                trace,
                started,
                stage::GRAPH_EXPAND,
                error,
            )
        })?;
    trace.push_ok(
        stage::GRAPH_EXPAND,
        micros(started),
        detail(
            ctx.role,
            json!({
                "hops_completed": response.stats.hops_completed,
                "nodes_visited": response.stats.nodes_visited,
                "edges_examined": response.stats.visible_edges_examined,
                "truncation": response.truncation,
            }),
        ),
    );

    let render_started = Instant::now();
    let result = retrieval::graph(response, traverse.with_payload, query_id, memory)
        .map_err(|e| receiving::error(query_id, e))?;
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Shared stages
// ---------------------------------------------------------------------------

fn required_graph_capability(statement: &Statement) -> Option<GraphCapability> {
    match statement {
        Statement::Transaction(_) => Some(GraphCapability::Write),
        Statement::Relate(_) | Statement::Unrelate(_) | Statement::UpdateEdge(_) => {
            Some(GraphCapability::Write)
        }
        Statement::Traverse(_) => Some(GraphCapability::Read),
        Statement::Search(search) if search.graph.is_some() => Some(GraphCapability::Read),
        Statement::Hybrid(hybrid) if hybrid.graph.is_some() => Some(GraphCapability::Read),
        Statement::Pipeline(pipeline) if pipeline.graph.is_some() => Some(GraphCapability::Read),
        _ => None,
    }
}

fn graph_constraint(clause: &GraphClause, budget_ms: Option<u64>) -> GraphConstraint {
    let defaults = TraversalBudget::default();
    GraphConstraint {
        anchors: clause.anchors.clone(),
        edge_types: clause.edge_types.clone(),
        direction: clause.direction,
        node_filter: None,
        edge_filter: None,
        budget: TraversalBudget {
            max_depth: clause.within_hops,
            max_time_ms: budget_ms.unwrap_or(defaults.max_time_ms),
            ..defaults
        },
        allow_degraded: clause.allow_degraded,
    }
}

/// The collection named in the statement, else the session's, else an error
/// that says how to set one.
fn resolve_collection(
    ctx: &mut ExecContext<'_>,
    named: Option<&str>,
    query_id: &str,
    trace: &mut QueryTrace,
) -> Result<String, ChironQlError> {
    let started = Instant::now();
    let Some(name) = named
        .map(str::to_string)
        .or_else(|| ctx.session.collection.clone())
    else {
        let message = "no collection given and no session collection is set".to_string();
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.no_collection",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.no_collection".to_string(),
            hint: Some("Name it in the statement, or set one with `USE <collection>`.".to_string()),
            position: None,
            affected_estimate: None,
            query_id: query_id.to_string(),
            trace: None,
        });
    };

    // Scoping is checked before existence is revealed: a restricted caller
    // gets the same answer whether or not the collection exists, so the error
    // cannot be used to enumerate collections it may not see.
    if !ctx.allows_collection(&name) {
        let message = format!("collection '{name}' is not available to this session");
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.collection_forbidden",
            message.clone(),
        );
        return Err(ChironQlError {
            error: message,
            code: "chironql.collection_forbidden".to_string(),
            hint: Some("SHOW COLLECTIONS lists what this session may use.".to_string()),
            position: None,
            affected_estimate: None,
            query_id: query_id.to_string(),
            trace: None,
        });
    }

    let Some(config) = collection_config(ctx.db, &name) else {
        trace.push_failed(
            stage::RESOLVE_COLLECTION,
            micros(started),
            "chironql.collection_not_found",
            format!("collection '{name}' not found"),
        );
        return Err(collection_not_found(query_id, &name));
    };

    trace.push_ok(
        stage::RESOLVE_COLLECTION,
        micros(started),
        detail(
            ctx.role,
            json!({"collection": config.name, "dim": config.vector_dim}),
        ),
    );
    Ok(name)
}

/// A literal vector passes through; `@id` costs one point fetch, which is why
/// it gets its own stage in the trace rather than hiding inside the search.
fn resolve_vector(
    ctx: &mut ExecContext<'_>,
    collection: &str,
    expr: &VectorExpr,
    clause_vector_name: Option<&str>,
    query_id: &str,
    trace: &mut QueryTrace,
) -> Result<Vec<f32>, ChironQlError> {
    match expr {
        VectorExpr::Literal(values) => Ok(values.clone()),
        VectorExpr::Parameter(index) => match ctx.parameters.get(*index) {
            Some(RelationalValue::Vector(values)) => Ok(values.clone()),
            Some(_) => Err(ChironQlError {
                error: format!("parameter ${} must be a vector", index + 1),
                code: "chironql.parameter_type".into(),
                hint: Some("Bind a typed vector value for a NEAR parameter.".into()),
                position: None,
                affected_estimate: None,
                query_id: query_id.into(),
                trace: None,
            }),
            None => Err(ChironQlError {
                error: format!("missing parameter ${}", index + 1),
                code: "chironql.missing_parameter".into(),
                hint: None,
                position: None,
                affected_estimate: None,
                query_id: query_id.into(),
                trace: None,
            }),
        },
        VectorExpr::Point { id, vector_name } => {
            let started = Instant::now();
            let wanted = vector_name.as_deref().or(clause_vector_name);
            let points =
                ctx.db
                    .get_points_scoped(collection, std::slice::from_ref(id), &ctx.tenant);
            let points = match points {
                Ok(points) => points,
                Err(error) => {
                    return Err(engine_error(ctx.role, query_id, trace, started, error));
                }
            };
            let Some(point) = points.into_iter().next() else {
                let message = format!("point '{id}' not found in '{collection}'");
                trace.push_failed(
                    stage::RESOLVE_VECTOR,
                    micros(started),
                    "chironql.point_not_found",
                    message.clone(),
                );
                return Err(ChironQlError {
                    error: message,
                    code: "chironql.point_not_found".to_string(),
                    hint: Some("Check the id with GET <collection> POINTS <id>.".to_string()),
                    position: None,
                    affected_estimate: None,
                    query_id: query_id.to_string(),
                    trace: None,
                });
            };

            let vector = match wanted {
                Some(name) => match point.vectors.get(name) {
                    Some(vector) => vector.clone(),
                    None => {
                        let message = format!("point '{id}' has no vector named '{name}'");
                        trace.push_failed(
                            stage::RESOLVE_VECTOR,
                            micros(started),
                            "chironql.vector_not_found",
                            message.clone(),
                        );
                        return Err(ChironQlError {
                            error: message,
                            code: "chironql.vector_not_found".to_string(),
                            hint: Some(
                                "DESCRIBE the collection to see its named vector spaces."
                                    .to_string(),
                            ),
                            position: None,
                            affected_estimate: None,
                            query_id: query_id.to_string(),
                            trace: None,
                        });
                    }
                },
                None => point.vector.clone(),
            };

            trace.push_ok(
                stage::RESOLVE_VECTOR,
                micros(started),
                detail(
                    ctx.role,
                    json!({"id": id, "dim": vector.len(), "vector_name": wanted}),
                ),
            );
            Ok(vector)
        }
    }
}

/// The filter is already compiled by the parser; this stage reports what it
/// compiled to, which is the part a user cannot see from their own query text.
fn record_filter(
    trace: &mut QueryTrace,
    role: Role,
    filter: Option<&chirondb_types::Filter>,
) -> Option<chirondb_types::Filter> {
    let filter = filter?;
    let started = Instant::now();
    let terms = filter.0.as_object().map(|object| object.len()).unwrap_or(0);
    let indexed = filter.indexed_predicates().is_some();
    trace.push_ok(
        stage::COMPILE_FILTER,
        micros(started),
        detail(role, json!({"terms": terms, "indexed": indexed})),
    );
    Some(filter.clone())
}

fn push_search_stage(
    role: Role,
    trace: &mut QueryTrace,
    started: Instant,
    response: &SearchResponse,
) {
    if let Some(graph) = response.graph.as_ref() {
        trace.push_ok(
            stage::GRAPH_ESTIMATE,
            graph.graph_estimate.elapsed_us,
            detail(role, json!(&graph.graph_estimate)),
        );
        trace.push_ok(
            stage::GRAPH_PLAN,
            graph.graph_plan.elapsed_us,
            detail(role, json!(&graph.graph_plan)),
        );
        trace.push_ok(
            stage::GRAPH_EXPAND,
            graph.graph_expand.elapsed_us,
            detail(role, json!(&graph.graph_expand)),
        );
        if let Some(fuse) = graph.fuse.as_ref() {
            let fuse_started = Instant::now();
            trace.push_ok(stage::FUSE, micros(fuse_started), detail(role, json!(fuse)));
        }
    }
    trace.push_ok(
        stage::ENGINE_SEARCH,
        micros(started),
        detail(
            role,
            json!({
                "hits": response.hits.len(),
                "scanned": response.searched,
                "degraded": response.degraded,
            }),
        ),
    );
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn hits_response(
    query_id: &str,
    response: SearchResponse,
    recall_target: Option<f32>,
    trace: &mut QueryTrace,
    memory: &mut QueryMemory,
) -> ExecResult {
    let render_started = Instant::now();
    if let Some(graph) = &response.graph {
        let warnings = receiving::add(
            graph.warnings.capacity() as u64,
            graph.warnings.len() as u64,
        )
        .and_then(|n| n.checked_mul(256).ok_or_else(receiving::full))
        .map_err(|e| receiving::error(query_id, e))?;
        memory.ql(warnings, query_id)?;
    }
    let mut result = retrieval::hits(response.hits, query_id, memory)
        .map_err(|e| receiving::error(query_id, e))?;
    result.stats.searched = Some(response.searched);
    result.stats.degraded = Some(response.degraded);
    result.stats.recall_target_requested = recall_target;
    if let Some(graph) = &response.graph {
        result
            .stats
            .warnings
            .try_reserve_exact(graph.warnings.len())
            .map_err(|_| receiving::error(query_id, receiving::full()))?;
        for warning in &graph.warnings {
            result
                .stats
                .warnings
                .push(graph_query_warning_code(*warning).into());
        }
    }
    result.stats.graph = response.graph;
    trace.push_ok(stage::RENDER, micros(render_started), None);
    Ok(result)
}

fn rows_response(query_id: &str, columns: Vec<String>, rows: Vec<Value>) -> ChironQlResponse {
    ChironQlResponse {
        credential: None,
        kind: ChironQlKind::Rows,
        columns,
        column_types: Vec::new(),
        rows,
        stats: ChironQlStats::default(),
        next: None,
        query_id: query_id.to_string(),
        domains: Vec::new(),
        snapshot_id: None,
        transaction_id: None,
        committed: None,
        trace: None,
    }
}

fn affected_response(query_id: &str, affected: u64) -> ChironQlResponse {
    ChironQlResponse {
        credential: None,
        kind: ChironQlKind::Affected,
        columns: Vec::new(),
        column_types: Vec::new(),
        rows: Vec::new(),
        stats: ChironQlStats {
            affected: Some(affected),
            ..ChironQlStats::default()
        },
        next: None,
        query_id: query_id.to_string(),
        domains: Vec::new(),
        snapshot_id: None,
        transaction_id: None,
        committed: None,
        trace: None,
    }
}

fn graph_mutation_stats(receipt: GraphMutationReceipt, affected: Option<u64>) -> ChironQlStats {
    ChironQlStats {
        affected,
        graph_epoch: Some(receipt.graph_epoch.raw()),
        operation_lsn: receipt.operation_lsn,
        durable: Some(receipt.durable),
        replayed: Some(receipt.replayed),
        ..ChironQlStats::default()
    }
}

fn graph_query_warning_code(warning: GraphQueryWarning) -> &'static str {
    match warning {
        GraphQueryWarning::DegradedPlan => "graph.degraded_plan",
        GraphQueryWarning::UncontractedFusion => "graph.uncontracted_fusion",
        GraphQueryWarning::ExactFallback => "graph.exact_fallback",
    }
}

pub(crate) fn graph_warning_code(warning: GraphWarning) -> &'static str {
    match warning {
        GraphWarning::ResultTruncated => "graph.result_truncated",
        GraphWarning::ConstraintTruncated => "graph.constraint_truncated",
        GraphWarning::Degraded => "graph.degraded_plan",
        GraphWarning::ExactFallback => "graph.exact_fallback",
        GraphWarning::HandleBackfillInProgress => "graph.backfill_in_progress",
    }
}

fn empty_response(query_id: &str) -> ChironQlResponse {
    ChironQlResponse {
        credential: None,
        kind: ChironQlKind::Empty,
        columns: Vec::new(),
        column_types: Vec::new(),
        rows: Vec::new(),
        stats: ChironQlStats::default(),
        next: None,
        query_id: query_id.to_string(),
        domains: Vec::new(),
        snapshot_id: None,
        transaction_id: None,
        committed: None,
        trace: None,
    }
}

// ---------------------------------------------------------------------------
// Errors and redaction
// ---------------------------------------------------------------------------

fn parse_error(query_id: &str, error: ParseError, trace: QueryTrace) -> ChironQlError {
    ChironQlError {
        error: error.message,
        code: error.code.to_string(),
        hint: error.hint.map(str::to_string),
        position: Some(error.position as u32),
        affected_estimate: None,
        query_id: query_id.to_string(),
        trace: Some(Box::new(trace)),
    }
}

fn collection_not_found(query_id: &str, collection: &str) -> ChironQlError {
    ChironQlError {
        error: format!("collection '{collection}' not found"),
        code: "chironql.collection_not_found".to_string(),
        hint: Some("SHOW COLLECTIONS lists what exists.".to_string()),
        position: None,
        affected_estimate: None,
        query_id: query_id.to_string(),
        trace: None,
    }
}

fn engine_error(
    role: Role,
    query_id: &str,
    trace: &mut QueryTrace,
    started: Instant,
    error: GaussError,
) -> ChironQlError {
    engine_error_at(role, query_id, trace, started, stage::ENGINE_SEARCH, error)
}

pub(crate) fn outcome_unknown_error(query_id: &str, transaction_id: &str) -> ChironQlError {
    ChironQlError {
        error: format!("transaction outcome is unknown: {transaction_id}"),
        code: "chironql.outcome_unknown".into(),
        hint: Some(format!(
            "Reconcile GET /v1/transactions/{transaction_id} or retry the identical mutation with the same idempotency_key."
        )),
        position: None,
        affected_estimate: None,
        query_id: query_id.into(),
        trace: None,
    }
}

pub(crate) fn commit_rejected_error(query_id: &str, transaction_id: &str) -> ChironQlError {
    ChironQlError {
        error: format!("transaction rejected; key remains consumed: {transaction_id}"),
        code: "chironql.transaction_rejected".into(),
        hint: Some(format!(
            "Reconcile GET /v1/transactions/{transaction_id}; this key cannot execute again."
        )),
        position: None,
        affected_estimate: None,
        query_id: query_id.into(),
        trace: None,
    }
}

fn engine_error_at(
    role: Role,
    query_id: &str,
    trace: &mut QueryTrace,
    started: Instant,
    failed_stage: &str,
    error: GaussError,
) -> ChironQlError {
    if let GaussError::CommitRejected { transaction_id } = &error {
        let error = commit_rejected_error(query_id, transaction_id);
        trace.push_failed(
            failed_stage,
            micros(started),
            &error.code,
            error.error.clone(),
        );
        return error;
    }
    if let GaussError::CommitOutcomeUnknown { transaction_id } = &error {
        let error = outcome_unknown_error(query_id, transaction_id);
        trace.push_failed(
            failed_stage,
            micros(started),
            &error.code,
            error.error.clone(),
        );
        return error;
    }
    let (code, message) = describe_engine_error(role, &error);
    trace.push_failed(failed_stage, micros(started), code, message.clone());
    ChironQlError {
        error: message,
        code: code.to_string(),
        hint: None,
        position: None,
        affected_estimate: None,
        query_id: query_id.to_string(),
        trace: None,
    }
}

/// Engine errors reach the caller with a stable code. Corruption variants
/// carry filesystem paths, so their message is redacted below admin — the
/// operator can read the real one in the server log, keyed by `query_id`.
fn describe_engine_error(role: Role, error: &GaussError) -> (&'static str, String) {
    match error {
        GaussError::Security(error) => (error.code(), error.to_string()),
        GaussError::Graph(error) => (error.code.as_str(), error.message.clone()),
        GaussError::CollectionNotFound(name) => (
            "chironql.collection_not_found",
            format!("collection '{name}' not found"),
        ),
        GaussError::PointNotFound(id) => (
            "chironql.point_not_found",
            format!("point '{id}' not found"),
        ),
        GaussError::DimensionMismatch { expected, actual } => (
            "chironql.dimension_mismatch",
            format!("this collection stores {expected}-dimensional vectors, got {actual}"),
        ),
        GaussError::SqlRowPreconditionFailed { .. } => {
            ("chironql.sql_row_precondition_failed", error.to_string())
        }
        GaussError::InvalidRequest(message) => ("chironql.invalid_request", message.clone()),
        GaussError::ResourceExhausted(message) => ("chironql.resource_exhausted", message.clone()),
        GaussError::WalUnavailable(message) => ("chironql.wal_unavailable", message.clone()),
        GaussError::AuditUnavailable(message) => ("chironql.audit_unavailable", message.clone()),
        GaussError::DataDirLocked { .. } => (
            "chironql.storage_unavailable",
            "data directory is in use".to_string(),
        ),
        GaussError::WalCorruption { .. } | GaussError::SegmentCorruption { .. } => {
            if role.allows_admin() {
                ("chironql.storage_corruption", error.to_string())
            } else {
                (
                    "chironql.storage_corruption",
                    "storage corruption detected; see the server log for the location".to_string(),
                )
            }
        }
        GaussError::Io(_) => {
            if role.allows_admin() {
                ("chironql.io_error", error.to_string())
            } else {
                (
                    "chironql.io_error",
                    "an I/O error occurred; see the server log".to_string(),
                )
            }
        }
        other => ("chironql.engine_error", other.to_string()),
    }
}

/// Trace detail is capped by role: reads see stages, timings and counts;
/// admins additionally see internal identifiers. Nothing here ever carries
/// credentials, filesystem paths, or environment values.
fn detail(role: Role, value: Value) -> Option<Value> {
    if role.allows_admin() {
        return Some(value);
    }
    let Value::Object(map) = value else {
        return Some(value);
    };
    let filtered: serde_json::Map<String, Value> = map
        .into_iter()
        .filter(|(key, _)| !ADMIN_ONLY_DETAIL_KEYS.contains(&key.as_str()))
        .collect();
    if filtered.is_empty() {
        None
    } else {
        Some(Value::Object(filtered))
    }
}

/// Detail keys that only an admin session sees. Kept small on purpose — the
/// default is that a key is visible, so anything internal must be listed here
/// deliberately when it is added.
const ADMIN_ONLY_DETAIL_KEYS: &[&str] = &["segment", "shard", "tier", "cache", "path"];

fn role_name(role: Role) -> &'static str {
    if role.allows_admin() {
        "admin"
    } else if role.allows_write() {
        "read_write"
    } else {
        "read_only"
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn collection_config(db: &Db, name: &str) -> Option<CollectionConfig> {
    db.list_collections()
        .into_iter()
        .find(|config| config.name == name)
}

fn micros(started: Instant) -> u64 {
    started.elapsed().as_micros() as u64
}

fn millis(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

/// Short, sortable, collision-resistant enough for correlating one query with
/// one log line. Not a security token.
fn new_query_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFFF;
    format!("q_{millis:011x}{seq:03x}")
}

#[cfg(test)]
mod graph_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_ids_are_unique_and_prefixed() {
        let first = new_query_id();
        let second = new_query_id();
        assert!(first.starts_with("q_"));
        assert_ne!(first, second);
    }

    #[test]
    fn non_admin_detail_drops_internal_keys() {
        let value = json!({"dim": 3, "segment": "seg-7", "path": "/var/lib/chirondb"});
        let filtered = detail(Role::ReadOnly, value).expect("detail");
        assert!(filtered.get("dim").is_some());
        assert!(filtered.get("segment").is_none());
        assert!(filtered.get("path").is_none());
    }

    #[test]
    fn admin_detail_is_unfiltered() {
        let value = json!({"dim": 3, "segment": "seg-7"});
        let filtered = detail(Role::Admin, value).expect("detail");
        assert_eq!(filtered.get("segment"), Some(&json!("seg-7")));
    }

    #[test]
    fn corruption_paths_are_redacted_below_admin() {
        let error = GaussError::SegmentCorruption {
            path: "/var/lib/chirondb/segments/7.seg".to_string(),
            message: "checksum mismatch".to_string(),
        };

        let (code, message) = describe_engine_error(Role::ReadOnly, &error);
        assert_eq!(code, "chironql.storage_corruption");
        assert!(!message.contains("/var/lib"), "leaked a path: {message}");

        let (_, admin_message) = describe_engine_error(Role::Admin, &error);
        assert!(admin_message.contains("/var/lib"));
    }

    #[test]
    fn engine_errors_keep_their_specific_codes() {
        let (code, _) = describe_engine_error(
            Role::ReadOnly,
            &GaussError::CollectionNotFound("products".to_string()),
        );
        assert_eq!(code, "chironql.collection_not_found");

        let (code, message) = describe_engine_error(
            Role::ReadOnly,
            &GaussError::DimensionMismatch {
                expected: 3,
                actual: 5,
            },
        );
        assert_eq!(code, "chironql.dimension_mismatch");
        assert!(message.contains('3') && message.contains('5'));
    }
}

#[cfg(test)]
mod query_ownership_tests;
