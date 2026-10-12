//! The protected language surface has no legacy role or system-context fallback.
use crate::chironql_output::query::{self as receiving, QueryMemory};
use crate::chironql_output::{QueryResult, retrieval};
use crate::{
    Db, GaussError, Result,
    chironql_parser::{
        self, GraphReturn, NamedSubject, Pipeline, SecurityCommand as Command, SecurityStatement,
        Statement, TransactionBlock, TransactionGraph, TransactionVector, VectorExpr,
    },
    security::*,
};
use chirondb_types::{
    RelationalValue, SqlExecutionRequest, SqlStatementRequest,
    chironql::*,
    graph::{
        EdgePropertyMode, EdgeToken, GraphRelationScope, GraphTraversalQueryRequest,
        GraphTraversalReturn, RelateRequest, TraversalBudget, UpdateEdgeRequest,
    },
    model::{ScrollRequest, SearchRequest},
};
use serde_json::{Value, json};
use std::{mem::size_of, time::Instant};

pub(crate) enum Output {
    Transaction(crate::chironql_output::AtomicOutput),
    Query(PublicationGuard, QueryResult),
    Data(AuthorizedOutput<ChironQlResponse>),
    Identity(AuthenticatedIdentity, ChironQlResponse),
    /// A mutation may revoke its own credential. Its acknowledgement contains
    /// only an opaque query ID and success, never catalog metadata or secrets.
    Acknowledgement(ChironQlResponse),
}

#[derive(Clone)]
pub(crate) enum PublicationGuard {
    Data(AccessContext),
    Multi(Vec<AccessContext>),
    Identity(AuthenticatedIdentity),
    Acknowledgement,
}
impl PublicationGuard {
    pub(crate) fn publish<T>(&self, publish: impl FnOnce() -> T) -> Result<T> {
        match self {
            Self::Data(context) => {
                let _permit = context.publication_permit()?;
                Ok(publish())
            }
            Self::Multi(contexts) => {
                let _permits = contexts
                    .iter()
                    .map(AccessContext::publication_permit)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(publish())
            }
            Self::Identity(identity) => {
                let _permit = identity.publication_permit()?;
                Ok(publish())
            }
            Self::Acknowledgement => Ok(publish()),
        }
    }
}
impl Output {
    pub(crate) fn guard(&self) -> PublicationGuard {
        match self {
            Self::Transaction(output) => PublicationGuard::Data(output.publication_context()),
            Self::Query(guard, _) => guard.clone(),
            Self::Data(output) => PublicationGuard::Data(output.publication_context()),
            Self::Identity(identity, _) => PublicationGuard::Identity(identity.clone()),
            Self::Acknowledgement(_) => PublicationGuard::Acknowledgement,
        }
    }
    pub(crate) fn publish<T>(self, publish: impl FnOnce(ChironQlResponse) -> T) -> Result<T> {
        match self {
            Self::Transaction(output) => output.publish(publish),
            Self::Query(guard, output) => guard.publish(|| output.consume(publish))?,
            Self::Data(output) => output.publish(publish),
            Self::Identity(identity, response) => {
                let _lease = identity.publication_permit()?;
                Ok(publish(response))
            }
            Self::Acknowledgement(response) => Ok(publish(response)),
        }
    }
}

fn response(query_id: &str, columns: &[&str], rows: Vec<Value>) -> ChironQlResponse {
    ChironQlResponse {
        kind: ChironQlKind::Rows,
        columns: columns.iter().map(|s| (*s).into()).collect(),
        column_types: Vec::new(),
        rows,
        stats: ChironQlStats::default(),
        next: None,
        query_id: query_id.into(),
        domains: Vec::new(),
        snapshot_id: None,
        transaction_id: None,
        committed: None,
        trace: None,
        credential: None,
    }
}
fn affected(query_id: &str, count: usize) -> ChironQlResponse {
    let mut value = response(query_id, &[], vec![]);
    value.kind = ChironQlKind::Affected;
    value.stats.affected = Some(count as u64);
    value
}
pub(crate) fn error(query_id: &str, code: &str) -> ChironQlError {
    let message = match code {
        "security.unauthenticated" => "missing or invalid credential",
        "security.forbidden" => "operation is not permitted",
        "security.not_found" => "resource was not found",
        "security.conflict" => "security revision or request identity conflicts",
        "security.unavailable" => "security authority is unavailable",
        "security.budget_exceeded" => "server resource limit exceeded",
        "chironql.confirmation_required" => "confirmation is required",
        "chironql.revision_required" => "expected security revision is required",
        "chironql.idempotency_unsupported" => {
            "idempotency_key requires a SQL mutation or atomic transaction"
        }
        "chironql.protected_unsupported" => "operation is unavailable on protected collections",
        _ => "invalid request",
    };
    ChironQlError {
        error: message.into(),
        code: code.into(),
        hint: None,
        position: None,
        affected_estimate: None,
        query_id: query_id.into(),
        trace: None,
    }
}
pub(crate) fn map_error(query_id: &str, failure: GaussError) -> ChironQlError {
    if let GaussError::CommitRejected { transaction_id } = &failure {
        return crate::chironql_exec::commit_rejected_error(query_id, transaction_id);
    }
    if let GaussError::CommitOutcomeUnknown { transaction_id } = &failure {
        return crate::chironql_exec::outcome_unknown_error(query_id, transaction_id);
    }
    if matches!(failure, GaussError::SqlRowPreconditionFailed { .. }) {
        let mut value = error(query_id, "chironql.sql_row_precondition_failed");
        value.error = failure.to_string();
        return value;
    }
    let code = match failure {
        GaussError::Security(ref security) => security.code(),
        GaussError::ResourceExhausted(_) => "security.budget_exceeded",
        GaussError::PointNotFound(_) | GaussError::CollectionNotFound(_) => "security.not_found",
        GaussError::InvalidRequest(_) | GaussError::DimensionMismatch { .. } => "security.invalid",
        _ => "security.unavailable",
    };
    error(query_id, code)
}

/// Exhaustive action catalog: adding a statement requires an explicit choice.
fn action(statement: &Statement) -> std::result::Result<Option<Action>, ()> {
    use Statement::*;
    Ok(match statement {
        Get(_) | Count(_) | Scroll(_) | Use { .. } => Some(Action::Read),
        Search(_) => Some(Action::Search),
        Hybrid(hybrid) if hybrid.text.is_some() => Some(Action::Search),
        DeletePoints { .. } | DeleteWhere { .. } => Some(Action::Delete),
        Traverse(_) => Some(Action::GraphRead),
        Security(statement) => match statement.command {
            Command::ShowCurrentUser { .. } => None,
            Command::ShowCatalogRevision | Command::CreateProtectedCollection { .. } => {
                Some(Action::IdentityManage)
            }
            Command::SetGraphLifecycle { .. } | Command::SetEdgeType { .. } => Some(Action::Schema),
            Command::SetCollectionPolicy { .. } | Command::ShowCollectionPolicy { .. } => {
                Some(Action::PolicyManage)
            }
            Command::ObjectPrivileges { .. } => Some(Action::GrantsManage),
            Command::AlterPoint { .. } => Some(Action::LabelsManage),
            Command::CreatePoints { .. } => Some(Action::Create),
            Command::UpdatePoints { .. } => Some(Action::Update),
            Command::CreateUser { .. }
            | Command::AlterUser { .. }
            | Command::RenameUser { .. }
            | Command::DropUser { .. }
            | Command::CreateRole { .. }
            | Command::RenameRole { .. }
            | Command::DropRole { .. }
            | Command::AssignRole { .. }
            | Command::RolePrivileges { .. }
            | Command::ShowUsers
            | Command::ShowRoles { .. }
            | Command::ShowRolePrivileges { .. }
            | Command::ShowCredentials { .. }
            | Command::IssueKey { .. }
            | Command::RotateKey { .. }
            | Command::RevokeKey { .. }
            | Command::ShowRevision { .. } => Some(Action::IdentityManage),
        },
        MlMaterialize(_)
        | Hybrid(_)
        | Multi(_)
        | Recommend(_)
        | ShowCollections
        | Describe { .. }
        | Upsert(_)
        | UpdatePayload(_)
        | Relate(_)
        | Unrelate(_)
        | UpdateEdge(_)
        | Sql(_)
        | Pipeline(_)
        | Transaction(_)
        | CreateCollection(_)
        | DropCollection { .. } => return Err(()),
    })
}

pub(crate) fn execute(
    db: &Db,
    token: &str,
    request: &ChironQlRequest,
) -> std::result::Result<Output, ChironQlError> {
    let query_id = uuid::Uuid::new_v4().to_string();
    let started = Instant::now();
    let authority = db
        .identity_authority()
        .ok_or_else(|| error(&query_id, "security.unavailable"))?;
    // Reauthenticate even when a transport has already admitted the request.
    let identity = authority
        .authenticate(token)
        .map_err(|e| map_error(&query_id, e.into()))?;
    let identity = db
        .management_identity(&identity)
        .map_err(|e| map_error(&query_id, e))?;
    let statement = chironql_parser::parse(&request.query).map_err(|e| {
        let mut result = error(&query_id, e.code);
        // This parser branch only uses static grammar messages, never input text.
        if e.code == "chironql.invalid_security_statement" {
            result.error = e.message;
        }
        result.position = Some(e.position.min(u32::MAX as usize) as u32);
        result
    })?;
    if request.idempotency_key.is_some()
        && !matches!(statement, Statement::Sql(_) | Statement::Transaction(_))
    {
        return Err(error(&query_id, "chironql.idempotency_unsupported"));
    }
    if let Statement::Pipeline(pipeline) = &statement {
        return execute_pipeline(db, &identity, request, pipeline, &query_id, started);
    }
    if let Statement::Transaction(transaction) = &statement {
        return execute_transaction(db, &identity, request, transaction, &query_id, started);
    }
    if let Statement::Sql(sql) = &statement {
        let mut memory = QueryMemory::new().map_err(|e| receiving::error(&query_id, e))?;
        memory.cancel_identity(&identity);
        let sql_request = crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.sql.clone(),
                parameters: request.parameters.clone(),
            }],
            idempotency_key: request.idempotency_key.clone(),
            retry_id: request.retry_id.clone(),
        };
        let result = db
            .execute_sql_authorized_owned(&identity, sql_request, "chironql-protected")
            .map_err(|failure| map_error(&query_id, failure))?;
        let reference = db
            .sql_reference_publication_context(&identity, &result.results)
            .map_err(|failure| map_error(&query_id, failure))?;
        let mut response =
            crate::chironql_exec::sql_execution_admitted(result, &query_id, &mut memory)?;
        response.domains = vec![ExecutionDomain::Relational];
        response.stats.took_ms = started.elapsed().as_secs_f64() * 1000.0;
        memory
            .metadata(&response)
            .map_err(|e| receiving::error(&query_id, e))?;
        let guard = match reference {
            Some(context) => PublicationGuard::Multi(vec![context]),
            None => PublicationGuard::Identity(identity),
        };
        return Ok(Output::Query(guard, QueryResult::new(response, memory)));
    }
    let required = action(&statement).map_err(|()| {
        let mut e = error(&query_id, "chironql.protected_unsupported");
        if matches!(statement, Statement::Upsert(_)) {
            e.hint = Some(
                "Use CREATE POINTS with server IDs or UPDATE POINTS with existing IDs.".into(),
            );
        }
        e
    })?;
    // Collection revision introspection supports delegated label/grant managers.
    let scoped_revision = matches!(
        &statement,
        Statement::Security(SecurityStatement {
            command: Command::ShowRevision {
                collection: Some(_)
            },
            ..
        })
    );
    if required == Some(Action::IdentityManage)
        && !scoped_revision
        && !identity.allows_installation(Action::IdentityManage)
    {
        return Err(error(&query_id, "security.forbidden"));
    }
    if let Statement::Security(statement) = &statement {
        if statement.requires_confirmation() && !request.confirm {
            return Err(error(&query_id, "chironql.confirmation_required"));
        }
        if statement.requires_revision() && statement.expected_revision.is_none() {
            return Err(error(&query_id, "chironql.revision_required"));
        }
        return execute_security(db, token, identity, statement, &query_id)
            .map_err(|failure| map_error(&query_id, failure));
    }
    let collection = statement
        .collection()
        .or(request.collection.as_deref())
        .ok_or_else(|| error(&query_id, "chironql.no_collection"))?;
    let context = db
        .bind_access(
            &identity,
            collection,
            &identity.principal().tenant,
            required.expect("data action"),
        )
        .map_err(|failure| map_error(&query_id, failure))?;
    let mut memory = QueryMemory::new().map_err(|e| receiving::error(&query_id, e))?;
    memory.cancel_identity(&identity);
    let result: Result<(AccessContext, ChironQlResponse)> = match statement {
        Statement::Traverse(traverse) => {
            let defaults = TraversalBudget::default();
            db.traverse_query_authorized(
                &context,
                GraphTraversalQueryRequest {
                    traversal: chirondb_types::graph::GraphTraverseRequest {
                        anchors: traverse.anchors,
                        edge_types: traverse.edge_types,
                        direction: traverse.direction,
                        node_filter: traverse.node_filter,
                        edge_filter: traverse.edge_filter,
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
                },
                identity.cancelled(),
            )
            .and_then(|output| {
                receive(output, &mut memory, |value, memory| {
                    retrieval::graph(value, traverse.with_payload, &query_id, memory)
                })
            })
        }
        Statement::Get(get) => db
            .get_points_authorized(&context, &get.ids)
            .and_then(|output| {
                receive(output, &mut memory, |points, memory| {
                    retrieval::points(points, None, true, &query_id, memory)
                })
            }),
        Statement::Count(count) => db
            .count_authorized(&context, count.filter)
            .and_then(|output| {
                receive(output, &mut memory, |count, memory| {
                    retrieval::count(count.count, &query_id, memory)
                })
            }),
        Statement::Scroll(scroll) => db
            .scroll_authorized(
                &context,
                ScrollRequest {
                    offset: scroll.after,
                    limit: scroll.limit.unwrap_or(100),
                    filter: scroll.filter,
                },
            )
            .and_then(|output| {
                receive(output, &mut memory, |page, memory| {
                    retrieval::points(page.points, page.next_offset, true, &query_id, memory)
                })
            }),
        Statement::Search(search) => {
            let Some(VectorExpr::Literal(vector)) = search.vector else {
                return Err(error(&query_id, "chironql.protected_unsupported"));
            };
            if search.graph.is_some() {
                return Err(error(&query_id, "chironql.protected_unsupported"));
            }
            db.search_authorized(
                &context,
                SearchRequest {
                    vector,
                    vector_name: search.vector_name,
                    k: search.limit.unwrap_or(10),
                    filter: search.filter,
                    graph: None,
                    budget_ms: search.budget_ms,
                    consistency: None,
                    ef_search: search.ef_search,
                    recall_target: search.recall_target,
                    with_payload: search.with_payload,
                },
                Some(identity.cancelled()),
            )
            .and_then(|output| {
                receive(output, &mut memory, |hits, memory| {
                    retrieval::hits(hits, &query_id, memory)
                })
            })
        }
        Statement::Hybrid(hybrid) => {
            let vector = match hybrid.vector {
                None => Vec::new(),
                Some(VectorExpr::Literal(vector)) => vector,
                _ => return Err(error(&query_id, "chironql.protected_unsupported")),
            };
            let text = hybrid.text.expect("text retrieval admitted by action");
            db.text_hybrid_search_authorized(
                &context,
                crate::TextHybridSearchRequest {
                    vector,
                    query: text.query,
                    text_field: text.field,
                    k: hybrid.limit.unwrap_or(10),
                    filter: hybrid.filter,
                    budget_ms: hybrid.budget_ms,
                },
                Some(identity.cancelled()),
            )
            .and_then(|output| {
                receive(output, &mut memory, |hits, memory| {
                    retrieval::hits(hits, &query_id, memory)
                })
            })
        }
        Statement::DeletePoints { ids, .. } => db
            .delete_points_authorized(&context, &ids)
            .and_then(|output| {
                receive(output, &mut memory, |count, memory| {
                    retrieval::affected(count, &query_id, memory)
                })
            }),
        Statement::DeleteWhere { filter, .. } => {
            if !request.confirm {
                let preview = db
                    .count_deletable_authorized(&context, filter)
                    .map_err(|failure| map_error(&query_id, failure))?;
                // Counts in an error would lose their publication barrier. Use
                // a constant confirmation message; the exact preview is verified
                // but is never attached to an unguarded error envelope.
                preview
                    .publish(|_| ())
                    .map_err(|failure| map_error(&query_id, failure))?;
                return Err(error(&query_id, "chironql.confirmation_required"));
            }
            db.delete_filter_authorized(&context, filter)
                .and_then(|output| {
                    receive(output, &mut memory, |count, memory| {
                        retrieval::affected(count, &query_id, memory)
                    })
                })
        }
        Statement::Use { .. } => {
            return Ok(Output::Identity(identity, response(&query_id, &[], vec![])));
        }
        _ => return Err(error(&query_id, "chironql.protected_unsupported")),
    };
    let (publication_context, mut value) =
        result.map_err(|failure| map_error(&query_id, failure))?;
    value.stats.took_ms = started.elapsed().as_secs_f64() * 1000.0;
    memory
        .metadata(&value)
        .map_err(|e| receiving::error(&query_id, e))?;
    Ok(Output::Query(
        PublicationGuard::Data(publication_context),
        QueryResult::new(value, memory),
    ))
}

fn receive<T>(
    output: AuthorizedOutput<T>,
    memory: &mut QueryMemory,
    render: impl FnOnce(T, &mut QueryMemory) -> Result<ChironQlResponse>,
) -> Result<(AccessContext, ChironQlResponse)> {
    // Mutations can retire the input context and return a fresh one. Keep the
    // core's actual context for the final publication, along with receiving memory.
    let context = output.publication_context();
    let value = output.publish(|value| render(value, memory))??;
    Ok((context, value))
}

fn execute_pipeline(
    db: &Db,
    identity: &AuthenticatedIdentity,
    request: &ChironQlRequest,
    pipeline: &Pipeline,
    query_id: &str,
    started: Instant,
) -> std::result::Result<Output, ChironQlError> {
    let mut memory = QueryMemory::new().map_err(|e| receiving::error(query_id, e))?;
    memory.cancel_identity(identity);
    if pipeline.graph.as_ref().is_some_and(|graph| {
        graph.traverse.returns != crate::chironql_parser::GraphReturn::Nodes
            || graph.traverse.with_payload
    }) {
        return Err(error(query_id, "chironql.protected_unsupported"));
    }
    if pipeline.explain {
        return Err(error(query_id, "chironql.protected_unsupported"));
    }
    match pipeline.vector.as_ref() {
        Statement::Search(search) if search.graph.is_none() => {}
        Statement::Hybrid(hybrid) if hybrid.text.is_some() => {}
        _ => return Err(error(query_id, "chironql.protected_unsupported")),
    }
    let vector_collection = pipeline
        .vector
        .collection()
        .or(request.collection.as_deref())
        .ok_or_else(|| error(query_id, "chironql.no_collection"))?;
    let vector_context = db
        .bind_access(
            identity,
            vector_collection,
            &identity.principal().tenant,
            Action::Search,
        )
        .map_err(|failure| map_error(query_id, failure))?;
    let graph_context = pipeline
        .graph
        .as_ref()
        .map(|graph| {
            db.bind_access(
                identity,
                &graph.traverse.collection,
                &identity.principal().tenant,
                Action::GraphRead,
            )
        })
        .transpose()
        .map_err(|failure| map_error(query_id, failure))?;
    let sql_request = SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: pipeline.relational.sql.clone(),
            parameters: request.parameters.clone(),
        }],
        idempotency_key: None,
        retry_id: request.retry_id.clone(),
    };
    // Bind every protected resource before the first stage can observe data.
    db.authorize_sql_request(identity, &sql_request)
        .map_err(|failure| map_error(query_id, failure))?;
    let snapshot = db
        .begin_multimodel_read()
        .map_err(|failure| map_error(query_id, failure))?
        .ok_or_else(|| error(query_id, "security.unavailable"))?;
    let frontier = snapshot.frontier();
    let vector_value = |expression: &VectorExpr| match expression {
        VectorExpr::Literal(vector) => Ok(vector.clone()),
        VectorExpr::Parameter(position) => match request.parameters.get(*position) {
            Some(RelationalValue::Vector(vector)) => Ok(vector.clone()),
            _ => Err(error(query_id, "security.invalid")),
        },
        _ => Err(error(query_id, "chironql.protected_unsupported")),
    };
    let vector_response = match pipeline.vector.as_ref() {
        Statement::Search(search) => db.search_authorized(
            &vector_context,
            SearchRequest {
                vector: search
                    .vector
                    .as_ref()
                    .map(vector_value)
                    .transpose()?
                    .ok_or_else(|| error(query_id, "chironql.protected_unsupported"))?,
                vector_name: search.vector_name.clone(),
                k: search.limit.unwrap_or(10),
                filter: search.filter.clone(),
                graph: None,
                budget_ms: search.budget_ms,
                consistency: None,
                ef_search: search.ef_search,
                recall_target: search.recall_target,
                with_payload: search.with_payload,
            },
            Some(identity.cancelled()),
        ),
        Statement::Hybrid(hybrid) => {
            let text = hybrid.text.as_ref().expect("text pipeline admitted above");
            db.text_hybrid_search_authorized(
                &vector_context,
                crate::TextHybridSearchRequest {
                    vector: hybrid
                        .vector
                        .as_ref()
                        .map(vector_value)
                        .transpose()?
                        .unwrap_or_default(),
                    query: text.query.clone(),
                    text_field: text.field.clone(),
                    k: hybrid.limit.unwrap_or(10),
                    filter: hybrid.filter.clone(),
                    budget_ms: hybrid.budget_ms,
                },
                Some(identity.cancelled()),
            )
        }
        _ => unreachable!("pipeline retrieval admitted above"),
    }
    .and_then(|output| output.publish(|hits| retrieval::hits(hits, query_id, &mut memory))?)
    .map_err(|failure| map_error(query_id, failure))?;
    let vector_rows = crate::chironql_exec::qualify_pipeline_rows(
        &pipeline.vector_alias,
        vector_response,
        Some(vector_collection),
        &mut memory,
    )?;
    let graph_rows = if let (Some(graph), Some(context)) = (&pipeline.graph, &graph_context) {
        memory.ql(4096 + pipeline.vector_alias.len() as u64, query_id)?;
        let anchor_key = format!("{}.id", pipeline.vector_alias);
        let anchor_bytes = vector_rows
            .rows
            .iter()
            .try_fold(4096_u64, |bytes, row| {
                receiving::add(
                    bytes,
                    size_of::<String>() as u64
                        + row
                            .get(&anchor_key)
                            .and_then(Value::as_str)
                            .map_or(0, str::len) as u64,
                )
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
            Some(crate::chironql_exec::qualify_pipeline_rows(
                &graph.alias,
                response(query_id, &["id", "depth"], Vec::new()),
                Some(&graph.traverse.collection),
                &mut memory,
            )?)
        } else {
            let defaults = TraversalBudget::default();
            let graph_result = db
                .traverse_authorized(
                    context,
                    chirondb_types::graph::GraphTraverseRequest {
                        anchors: traverse.anchors,
                        edge_types: traverse.edge_types,
                        direction: traverse.direction,
                        node_filter: traverse.node_filter,
                        edge_filter: traverse.edge_filter,
                        budget: TraversalBudget {
                            max_depth: traverse.depth,
                            max_time_ms: traverse.budget_ms.unwrap_or(defaults.max_time_ms),
                            ..defaults
                        },
                    },
                    identity.cancelled(),
                )
                .and_then(|output| {
                    output.publish(|value| {
                        retrieval::pipeline_nodes(
                            value,
                            traverse.limit.unwrap_or(usize::MAX),
                            query_id,
                            &mut memory,
                        )
                    })?
                })
                .map_err(|failure| map_error(query_id, failure))?;
            let graph_response = graph_result;
            Some(crate::chironql_exec::qualify_pipeline_rows(
                &graph.alias,
                graph_response,
                Some(&graph.traverse.collection),
                &mut memory,
            )?)
        }
    } else {
        None
    };
    let relational_response = db
        .execute_sql_authorized_owned(identity, sql_request, "chironql-protected-pipeline")
        .map_err(|failure| map_error(query_id, failure))?;
    let sql_reference = db
        .sql_reference_publication_context(identity, &relational_response.results)
        .map_err(|failure| map_error(query_id, failure))?;
    let relational_snapshot = relational_response.snapshot;
    let relational_rows = crate::chironql_exec::qualify_pipeline_rows(
        &pipeline.relational_alias,
        crate::chironql_exec::sql_execution_admitted(relational_response, query_id, &mut memory)?,
        None,
        &mut memory,
    )?;
    let mut trace = QueryTrace {
        query_id: query_id.into(),
        stages: Vec::new(),
    };
    let mut result = crate::chironql_exec::assemble_pipeline_response(
        pipeline,
        vector_rows,
        graph_rows,
        relational_rows,
        query_id,
        &mut trace,
        crate::rbac::Role::ReadOnly,
        &mut memory,
    )?;
    if !snapshot
        .validate()
        .map_err(|failure| map_error(query_id, failure))?
    {
        return Err(error(query_id, "security.conflict"));
    }
    result.domains = if pipeline.graph.is_some() {
        vec![
            ExecutionDomain::Relational,
            ExecutionDomain::Vector,
            ExecutionDomain::Graph,
        ]
    } else {
        vec![ExecutionDomain::Relational, ExecutionDomain::Vector]
    };
    result.snapshot_id = Some(format!(
        "multimodel:{frontier}:relational:{relational_snapshot}"
    ));
    result.stats.took_ms = started.elapsed().as_secs_f64() * 1000.0;
    if request.trace {
        result.trace = Some(trace);
    }
    let mut contexts = vec![vector_context];
    contexts.extend(graph_context);
    contexts.extend(sql_reference);
    memory
        .metadata(&result)
        .map_err(|e| receiving::error(query_id, e))?;
    Ok(Output::Query(
        PublicationGuard::Multi(contexts),
        QueryResult::new(result, memory),
    ))
}

fn execute_transaction(
    db: &Db,
    identity: &AuthenticatedIdentity,
    request: &ChironQlRequest,
    transaction: &TransactionBlock,
    query_id: &str,
    started: Instant,
) -> std::result::Result<Output, ChironQlError> {
    if let TransactionVector::Create {
        collection,
        template,
        records,
    } = &transaction.vector
    {
        let relations = transaction
            .graph
            .iter()
            .map(|mutation| match mutation {
                TransactionGraph::CreateRelation { relation, .. } => Ok(relation.clone()),
                _ => Err(error(query_id, "security.invalid")),
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let result = db
            .insert_multimodel_authorized_with_sql_rows_owned(
                identity,
                crate::MultiModelInsertRequest {
                    sql: SqlExecutionRequest {
                        statements: vec![SqlStatementRequest {
                            sql: transaction.sql.sql.clone(),
                            parameters: request.parameters.clone(),
                        }],
                        idempotency_key: request.idempotency_key.clone(),
                        retry_id: request.retry_id.clone(),
                    },
                    collection: collection.clone(),
                    template: template.clone(),
                    records: records.clone(),
                    relations,
                },
                "chironql-protected",
                transaction.expected_sql_rows,
            )
            .map_err(|failure| map_error(query_id, failure))?;
        return transaction_output(
            result,
            records.len(),
            transaction.graph.len(),
            query_id,
            started,
        );
    }
    let collection = transaction.vector.collection().to_string();
    let (points, point_deletes, vector_action) = match &transaction.vector {
        TransactionVector::Create { .. } => unreachable!("create was handled above"),
        TransactionVector::Upsert(upsert) => {
            let points = upsert
                .points
                .iter()
                .cloned()
                .map(serde_json::from_value)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| error(query_id, "security.invalid"))?;
            (points, Vec::new(), Action::Update)
        }
        TransactionVector::DeletePoints { ids, .. } => (Vec::new(), ids.clone(), Action::Delete),
    };
    let vector_context = db
        .bind_access(
            identity,
            &collection,
            &identity.principal().tenant,
            vector_action,
        )
        .map_err(|failure| map_error(query_id, failure))?;
    let graph_context = db
        .bind_access(
            identity,
            &collection,
            &identity.principal().tenant,
            Action::GraphWrite,
        )
        .map_err(|failure| map_error(query_id, failure))?;
    let sql = SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: transaction.sql.sql.clone(),
            parameters: request.parameters.clone(),
        }],
        idempotency_key: request.idempotency_key.clone(),
        retry_id: request.retry_id.clone(),
    };
    let mut relations = Vec::new();
    let mut edge_deletes = Vec::new();
    let mut edge_updates = Vec::new();
    for mutation in &transaction.graph {
        match mutation {
            TransactionGraph::CreateRelation { .. } => {
                return Err(error(query_id, "security.invalid"));
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
    let point_count = points.len() + point_deletes.len();
    let graph_count = transaction.graph.len();
    let result = db
        .execute_multimodel_transaction_authorized_with_sql_rows_owned(
            identity,
            &vector_context,
            &graph_context,
            crate::MultiModelTransactionRequest {
                sql,
                collection,
                points,
                point_deletes,
                relations,
                edge_deletes,
                edge_updates,
            },
            "chironql-protected",
            transaction.expected_sql_rows,
        )
        .map_err(|failure| map_error(query_id, failure))?;
    transaction_output(result, point_count, graph_count, query_id, started)
}

fn transaction_output(
    result: crate::MultiModelResponse,
    point_count: usize,
    graph_count: usize,
    query_id: &str,
    started: Instant,
) -> std::result::Result<Output, ChironQlError> {
    crate::chironql_output::AtomicOutput::new(result, point_count, graph_count, query_id, started)
        .map(Output::Transaction)
        .map_err(|failure| map_error(query_id, failure))
}

fn execute_security(
    db: &Db,
    token: &str,
    identity: AuthenticatedIdentity,
    statement: &SecurityStatement,
    query_id: &str,
) -> Result<Output> {
    let authority = db.identity_authority().ok_or(SecurityError::Unavailable)?;
    let expected = statement.expected_revision.unwrap_or(0);
    let bind = |collection: &str, action| {
        db.bind_access(&identity, collection, &identity.principal().tenant, action)
    };
    let rows = match &statement.command {
        Command::ShowCatalogRevision => Some(response(
            query_id,
            &["revision"],
            vec![json!({"revision":db.catalog_revision_authorized(&identity)?})],
        )),
        Command::ShowCollectionPolicy { collection } => {
            return db
                .collection_policy_authorized(&identity, collection)?
                .map(|(revision, policy)| {
                    response(
                        query_id,
                        &["revision", "policy"],
                        vec![json!({"revision":revision,"policy":policy})],
                    )
                })
                .map(Output::Data);
        }
        Command::ShowCurrentUser { privileges: false } => Some(response(
            query_id,
            &["id", "name", "enabled", "attributes", "roles"],
            vec![json!(authority.current_user(&identity)?)],
        )),
        Command::ShowCurrentUser { privileges: true } => {
            let mut privileges = std::collections::BTreeSet::new();
            for action in &identity.principal().installation_actions {
                privileges.insert(("system".to_string(), None, *action));
            }
            for scope in &identity.principal().grants {
                for collection in &scope.collections {
                    for action in &scope.actions {
                        if bind(collection, *action).is_ok() {
                            privileges.insert((
                                "collection".into(),
                                Some(collection.clone()),
                                *action,
                            ));
                        }
                    }
                }
            }
            for (table, action) in db.sql_table_privileges_authorized(&identity)? {
                privileges.insert(("table".into(), Some(table), action));
            }
            for role in identity.roles() {
                for scope in &role.grants {
                    for action in &scope.actions {
                        if bind(&scope.collection, *action)
                            .is_ok_and(|context| context.incarnation() == scope.incarnation)
                        {
                            privileges.insert((
                                "collection".into(),
                                Some(scope.collection.clone()),
                                *action,
                            ));
                        }
                    }
                }
            }
            Some(response(
                query_id,
                &["scope", "collection", "table", "action"],
                privileges
                    .into_iter()
                    .map(|(scope, resource, action)| {
                        let (collection, table) = if scope == "table" {
                            (None, resource)
                        } else {
                            (resource, None)
                        };
                        json!({"scope":scope,"collection":collection,"table":table,"action":action})
                    })
                    .collect(),
            ))
        }
        Command::ShowUsers => Some(response(
            query_id,
            &["id", "name", "enabled", "attributes", "roles"],
            authority
                .list_users(&identity)?
                .into_iter()
                .map(|user| json!(user))
                .collect(),
        )),
        Command::ShowRoles { with_users } => {
            let roles = authority.list_roles(&identity)?;
            let users = if *with_users {
                authority.list_users(&identity)?
            } else {
                vec![]
            };
            Some(response(
                query_id,
                &["role", "users"],
                roles
                    .into_iter()
                    .map(|role| {
                        let members: Vec<_> = users
                            .iter()
                            .filter(|user| user.roles.contains(&role.name))
                            .map(|user| &user.name)
                            .collect();
                        json!({"role":role.name,"users":members})
                    })
                    .collect(),
            ))
        }
        Command::ShowRolePrivileges { role } => {
            let role = authority
                .list_roles(&identity)?
                .into_iter()
                .find(|r| &r.name == role)
                .ok_or(SecurityError::NotFound)?;
            Some(response(
                query_id,
                &["name", "grants", "table_grants", "installation_actions"],
                vec![json!(role)],
            ))
        }
        Command::ShowCredentials { user } => Some(response(
            query_id,
            &["id", "principal", "revoked"],
            authority
                .list_credentials(&identity, user)?
                .into_iter()
                .map(|key| json!(key))
                .collect(),
        )),
        Command::ShowRevision { collection } => {
            let revision = match collection {
                None => identity.revision(),
                Some(name) => {
                    let context = [
                        Action::Schema,
                        Action::LabelsManage,
                        Action::GrantsManage,
                        Action::PolicyManage,
                    ]
                    .into_iter()
                    .find_map(|action| bind(name, action).ok())
                    .ok_or(SecurityError::Forbidden)?;
                    context.policy_revision()
                }
            };
            Some(response(
                query_id,
                &["revision"],
                vec![json!({"revision":revision})],
            ))
        }
        _ => None,
    };
    if let Some(rows) = rows {
        return Ok(Output::Identity(identity, rows));
    }
    match &statement.command {
        Command::CreateProtectedCollection { name, dim, metric } => {
            let config =
                serde_json::from_value(json!({"name":name,"vector_dim":dim,"metric":metric}))?;
            let config = db.create_protected_collection_authorized(&identity, expected, config)?;
            return Ok(Output::Identity(
                identity,
                response(query_id, &["name"], vec![json!({"name":config.name})]),
            ));
        }
        Command::SetGraphLifecycle {
            collection,
            enabled,
        } => {
            return db
                .set_graph_lifecycle_authorized(
                    &bind(collection, Action::Schema)?,
                    expected,
                    *enabled,
                )?
                .map(|(revision, result)| {
                    response(
                        query_id,
                        &["revision", "graph"],
                        vec![json!({"revision":revision,"graph":result})],
                    )
                })
                .map(Output::Data);
        }
        Command::SetEdgeType {
            collection,
            name,
            weight_property,
        } => {
            return db.configure_edge_type_authorized(
                &bind(collection, Action::Schema)?, expected,
                crate::graph::ConfigureEdgeTypeRequest { name: name.clone(), weight_property: weight_property.clone() },
            )?.map(|(revision, result)| response(query_id, &["revision", "edge_type", "receipt"],
                vec![json!({"revision":revision,"edge_type":result.edge_type,"receipt":result.receipt})])).map(Output::Data);
        }
        Command::SetCollectionPolicy { collection, policy } => {
            let revision = db.replace_collection_policy_authorized(
                &bind(collection, Action::PolicyManage)?,
                RevisionUpdate {
                    expected_revision: expected,
                    value: policy.clone(),
                },
            )?;
            return Ok(Output::Identity(
                identity,
                response(query_id, &["revision"], vec![json!({"revision":revision})]),
            ));
        }
        Command::ObjectPrivileges {
            collection,
            id,
            subject,
            actions,
            effect,
            grant,
        } => {
            let subject = match subject {
                NamedSubject::User(name) => Subject::Principal(name.clone()),
                NamedSubject::Group(name) => Subject::Group(name.clone()),
            };
            return db
                .change_object_privileges_authorized(
                    &bind(collection, Action::GrantsManage)?,
                    id,
                    expected,
                    PointPrivilegeChanges {
                        subject,
                        actions: actions.clone(),
                        effect: *effect,
                        grant: *grant,
                    },
                )?
                .map(|revision| {
                    response(query_id, &["revision"], vec![json!({"revision":revision})])
                })
                .map(Output::Data);
        }
        Command::AlterPoint {
            collection,
            id,
            owner,
            department,
            classification,
        } => {
            return db
                .alter_object_labels_authorized(
                    &bind(collection, Action::LabelsManage)?,
                    id,
                    expected,
                    PointLabelChanges {
                        owner: owner.clone(),
                        department: department.clone(),
                        classification: *classification,
                    },
                )?
                .map(|revision| {
                    response(query_id, &["revision"], vec![json!({"revision":revision})])
                })
                .map(Output::Data);
        }
        Command::CreatePoints {
            collection,
            template,
            points,
            request_id,
        } => {
            let points = points
                .iter()
                .map(|point| serde_json::from_value(point.clone()))
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| SecurityError::Invalid("invalid point".into()))?;
            return db
                .create_points_idempotent_authorized(
                    &bind(collection, Action::Create)?,
                    CreatePoints {
                        template: template.clone(),
                        points,
                        idempotency_key: request_id.clone(),
                    },
                )?
                .map(|ids| {
                    response(
                        query_id,
                        &["id"],
                        ids.into_iter().map(|id| json!({"id":id})).collect(),
                    )
                })
                .map(Output::Data);
        }
        Command::UpdatePoints { collection, points } => {
            let points = points
                .iter()
                .map(|point| serde_json::from_value(point.clone()))
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| SecurityError::Invalid("invalid point".into()))?;
            return db
                .update_points_authorized(&bind(collection, Action::Update)?, points, true)?
                .map(|count| affected(query_id, count))
                .map(Output::Data);
        }
        _ => {}
    }
    let mut credential = None;
    let revision = match &statement.command {
        Command::CreateUser { name, attributes } => {
            authority.create_user(&identity, expected, name, attributes.clone())?
        }
        Command::AlterUser { name, changes } => {
            authority.alter_user(&identity, expected, name, changes.clone())?
        }
        Command::RenameUser { name, new_name } => {
            authority.rename_user(&identity, expected, name, new_name)?
        }
        Command::DropUser { name } => authority.drop_user(&identity, expected, name)?,
        Command::CreateRole { name } => authority.create_role(&identity, expected, name)?,
        Command::RenameRole { name, new_name } => {
            authority.rename_role(&identity, expected, name, new_name)?
        }
        Command::DropRole { name } => authority.drop_role(&identity, expected, name)?,
        Command::AssignRole { role, user, grant } => {
            authority.assign_role(&identity, expected, role, user, *grant)?
        }
        Command::RolePrivileges {
            role,
            collection,
            table,
            actions,
            grant,
        } => match table {
            Some(table) => db.change_role_table_privileges_authorized(
                &identity,
                expected,
                role,
                table,
                actions.clone(),
                *grant,
            )?,
            None => db.change_role_privileges_authorized(
                &identity,
                expected,
                role,
                collection.as_deref(),
                actions.clone(),
                *grant,
            )?,
        },
        Command::IssueKey { user } => {
            let id = authority.resolve_user(&identity, user)?;
            let issued = authority.issue_credential(&identity, expected, &id)?;
            let revision = issued.revision;
            credential = Some(ChironQlCredential {
                id: issued.id,
                secret: issued.secret,
            });
            revision
        }
        Command::RotateKey { id } => {
            let issued = authority.rotate_credential(&identity, expected, id)?;
            let revision = issued.revision;
            credential = Some(ChironQlCredential {
                id: issued.id,
                secret: issued.secret,
            });
            revision
        }
        Command::RevokeKey { id } => authority.revoke_credential(&identity, expected, id)?,
        _ => return Err(SecurityError::Forbidden.into()),
    };
    let fresh = authority.authenticate(token).or_else(|failure| {
        let Some(issued) = &credential else {
            return Err(failure);
        };
        let fresh = authority.authenticate(&issued.secret)?;
        if fresh.principal().id != identity.principal().id {
            return Err(SecurityError::Forbidden);
        }
        Ok(fresh)
    });
    match fresh {
        Ok(fresh) => {
            let mut value = response(query_id, &["revision"], vec![json!({"revision":revision})]);
            value.credential = credential;
            Ok(Output::Identity(fresh, value))
        }
        Err(SecurityError::Unauthenticated) if credential.is_none() => {
            Ok(Output::Acknowledgement(affected(query_id, 1)))
        }
        Err(failure) => Err(failure.into()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeSet;
    pub(crate) fn identity_fixture() -> (
        tempfile::TempDir,
        std::sync::Arc<IdentityAuthority>,
        IssuedCredential,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let key = IdentityAuthority::bootstrap(
            directory.path(),
            PrincipalRecord {
                id: "root".into(),
                tenant: "acme".into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "Security".into(),
                    clearance: Classification::Restricted,
                },
                grants: vec![],
                delegation: vec![],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
            },
        )
        .unwrap();
        let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        (directory, authority, key)
    }

    #[test]
    fn computed_and_serialized_identity_outputs_cannot_publish_after_revoke() {
        let (_directory, authority, key) = identity_fixture();
        let actor = authority.authenticate(&key.secret).unwrap();
        let output = Output::Identity(
            actor.clone(),
            response("synthetic", &["name"], vec![json!({"name":"sensitive"})]),
        );
        let guard = output.guard();
        let serialized = output
            .publish(|value| serde_json::to_vec(&value).unwrap())
            .unwrap();
        authority
            .revoke_credential(&actor, actor.revision(), &key.id)
            .unwrap();
        let mut published = Vec::new();
        assert!(guard.publish(|| published.extend(serialized)).is_err());
        assert!(published.is_empty());
        assert!(actor.publication_permit().is_err());
    }

    #[test]
    fn protected_chironql_sql_enforces_table_grants_and_tenant_ownership() {
        let directory = tempfile::tempdir().unwrap();
        chirondb_core::storage_layout::initialize_empty(directory.path()).unwrap();
        let scope = |tenant: &str, actions: BTreeSet<Action>| ScopeGrant {
            tenants: BTreeSet::from([tenant.into()]),
            collections: BTreeSet::from(["accounts".into()]),
            actions,
        };
        let root_key = IdentityAuthority::bootstrap(
            directory.path(),
            PrincipalRecord {
                id: "root".into(),
                tenant: "acme".into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "Security".into(),
                    clearance: Classification::Restricted,
                },
                grants: vec![scope(
                    "acme",
                    BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
                )],
                delegation: vec![
                    scope("other-tenant", BTreeSet::from([Action::Read])),
                    scope(
                        "acme",
                        BTreeSet::from([
                            Action::Read,
                            Action::Create,
                            Action::Update,
                            Action::Delete,
                        ]),
                    ),
                ],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
            },
        )
        .unwrap();
        let authority = IdentityAuthority::open(directory.path()).unwrap().unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        authority
            .put_principal(
                &root,
                root.revision(),
                PrincipalRecord {
                    id: "other".into(),
                    tenant: "other-tenant".into(),
                    enabled: true,
                    attributes: SubjectAttributes {
                        department: "Other".into(),
                        clearance: Classification::Restricted,
                    },
                    grants: vec![scope("other-tenant", BTreeSet::from([Action::Read]))],
                    delegation: Vec::new(),
                    installation_actions: BTreeSet::new(),
                },
            )
            .unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        let other_key = authority
            .issue_credential(&root, root.revision(), "other")
            .unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        authority
            .put_principal(
                &root,
                root.revision(),
                PrincipalRecord {
                    id: "writer".into(),
                    tenant: "acme".into(),
                    enabled: true,
                    attributes: SubjectAttributes {
                        department: "Writers".into(),
                        clearance: Classification::Restricted,
                    },
                    grants: vec![scope(
                        "acme",
                        BTreeSet::from([
                            Action::Read,
                            Action::Create,
                            Action::Update,
                            Action::Delete,
                        ]),
                    )],
                    delegation: Vec::new(),
                    installation_actions: BTreeSet::new(),
                },
            )
            .unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        let writer_key = authority
            .issue_credential(&root, root.revision(), "writer")
            .unwrap();
        drop(authority);
        let db = Db::open(directory.path()).unwrap();
        let run = |token: &str, query: &str| {
            execute(
                &db,
                token,
                &ChironQlRequest {
                    query: query.into(),
                    ..ChironQlRequest::default()
                },
            )
        };
        for query in [
            "SQL CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL);",
            "SQL INSERT INTO accounts VALUES (1, 100);",
        ] {
            run(&root_key.secret, query)
                .unwrap()
                .publish(|response| response)
                .unwrap();
        }
        let selected = run(
            &root_key.secret,
            "SQL SELECT id, balance FROM accounts ORDER BY id;",
        )
        .unwrap()
        .publish(|response| response)
        .unwrap();
        assert_eq!(selected.domains, vec![ExecutionDomain::Relational]);
        assert_eq!(selected.rows, vec![json!({"id":1,"balance":100})]);

        let identity = db
            .identity_authority()
            .unwrap()
            .authenticate(&root_key.secret)
            .unwrap();
        let identity = db.management_identity(&identity).unwrap();
        let transaction = db
            .begin_sql_transaction_authorized(&identity, "protected-test")
            .unwrap();
        db.execute_sql_transaction_authorized(
            &identity,
            &transaction.handle,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "UPDATE accounts SET balance = 125 WHERE id = 1".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "protected-test",
        )
        .unwrap();
        let committed = db
            .commit_sql_transaction_authorized(&identity, &transaction.handle, "protected-test")
            .unwrap();
        assert!(committed.committed);
        let root_commit_handle = transaction.handle.clone();
        assert_eq!(committed.transaction_id, transaction.transaction_id);
        assert_eq!(
            db.commit_sql_transaction_authorized(
                &identity,
                &transaction.handle,
                "reconnected-client"
            )
            .unwrap(),
            committed
        );

        let transaction_id = committed.transaction_id.as_deref().unwrap();
        assert_eq!(
            db.transaction_status_authorized(&identity, transaction_id)
                .unwrap()
                .state,
            chirondb_core::TransactionState::Committed
        );
        let writer = db
            .identity_authority()
            .unwrap()
            .authenticate(&writer_key.secret)
            .unwrap();
        assert!(matches!(
            db.transaction_status_authorized(&writer, transaction_id),
            Err(GaussError::Security(SecurityError::NotFound))
        ));
        let selected = run(
            &root_key.secret,
            "SQL SELECT balance FROM accounts WHERE id = 1;",
        )
        .unwrap()
        .publish(|response| response)
        .unwrap();
        assert_eq!(selected.rows, vec![json!({"balance":125})]);

        let authority = db.identity_authority().unwrap();
        let keyed_update = ChironQlRequest {
            query: "SQL UPDATE accounts SET balance = 125 WHERE id = 1 RETURNING balance".into(),
            idempotency_key: Some("writer-update-1".into()),
            ..Default::default()
        };
        let first = execute(&db, &writer_key.secret, &keyed_update)
            .unwrap()
            .publish(|response| response)
            .unwrap();
        let replay = execute(&db, &writer_key.secret, &keyed_update).unwrap();
        let replay_guard = replay.guard();
        let replay = replay.publish(|response| response).unwrap();
        assert_eq!(first.transaction_id, replay.transaction_id);
        assert_eq!(first.rows, replay.rows);
        let writer = authority.authenticate(&writer_key.secret).unwrap();
        let completed = db
            .begin_sql_transaction_authorized(&writer, "protected-test")
            .unwrap();
        db.execute_sql_transaction_authorized(
            &writer,
            &completed.handle,
            SqlExecutionRequest {
                statements: vec![SqlStatementRequest {
                    sql: "UPDATE accounts SET balance = 125 WHERE id = 1".into(),
                    parameters: vec![],
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "protected-test",
        )
        .unwrap();
        let completed_receipt = db
            .commit_sql_transaction_authorized(&writer, &completed.handle, "protected-test")
            .unwrap();
        assert_eq!(completed_receipt.transaction_id, completed.transaction_id);
        let writer = authority.authenticate(&writer_key.secret).unwrap();
        let transaction = db
            .begin_sql_transaction_authorized(&writer, "protected-test")
            .unwrap();
        db.execute_sql_transaction_authorized(
            &writer,
            &transaction.handle,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "UPDATE accounts SET balance = 150 WHERE id = 1".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "protected-test",
        )
        .unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        let mut revoked = writer.principal().clone();
        revoked.grants[0].actions.remove(&Action::Update);
        authority
            .put_principal(&root, root.revision(), revoked)
            .unwrap();
        assert!(
            db.commit_sql_transaction_authorized(&writer, &transaction.handle, "protected-test",)
                .is_err()
        );
        assert!(execute(&db, &writer_key.secret, &keyed_update).is_err());
        let mut published = false;
        assert!(replay_guard.publish(|| published = true).is_err());
        assert!(!published);
        let denied_upsert = run(&writer_key.secret,
            "SQL INSERT INTO accounts VALUES (1, 999) ON CONFLICT (id) DO UPDATE SET balance = excluded.balance"
        ).err().expect("CREATE permission must not bypass revoked UPDATE via upsert");
        assert_eq!(denied_upsert.code, "security.forbidden");
        let fresh = authority.authenticate(&writer_key.secret).unwrap();
        assert!(
            db.commit_sql_transaction_authorized(&fresh, &completed.handle, "retry-after-revoke")
                .is_err()
        );
        assert_eq!(
            db.transaction_status_authorized(&fresh, &completed.handle)
                .unwrap()
                .state,
            chirondb_core::TransactionState::Committed
        );

        assert!(
            db.commit_sql_transaction_authorized(&fresh, &transaction.handle, "protected-test",)
                .is_err()
        );
        db.rollback_sql_transaction_authorized(&fresh, &transaction.handle, "protected-test")
            .unwrap();
        let selected = run(
            &root_key.secret,
            "SQL SELECT balance FROM accounts WHERE id = 1;",
        )
        .unwrap()
        .publish(|response| response)
        .unwrap();
        assert_eq!(selected.rows, vec![json!({"balance":125})]);

        let denied = run(
            &other_key.secret,
            "SQL SELECT id, balance FROM accounts ORDER BY id;",
        )
        .err()
        .unwrap();
        assert_eq!(denied.code, "security.not_found");
        run(&root_key.secret, "SQL DROP TABLE accounts")
            .unwrap()
            .publish(|response| response)
            .unwrap();
        let root = authority.authenticate(&root_key.secret).unwrap();
        assert_eq!(
            db.commit_sql_transaction_authorized(
                &root,
                &root_commit_handle,
                "reconcile-dropped-table"
            )
            .unwrap(),
            committed
        );
    }

    #[test]
    fn protected_pipeline_authorizes_before_read_and_rechecks_before_publish() {
        const CHILD: &str = "CHIRONDB_PROTECTED_PIPELINE_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("chironql_protected::tests::protected_pipeline_authorizes_before_read_and_rechecks_before_publish")
                .arg("--nocapture")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root_path = directory.path().canonicalize().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let data = root_path.join("data");
        let keyring = root_path.join("storage.json");
        let key_out = root_path.join("admin.key");
        chirondb_core::security::onboarding::initialize(
            &data, "acme", "root", &keyring, &key_out, false,
        )
        .unwrap();
        let root_secret = std::fs::read_to_string(&key_out).unwrap();
        let actions = BTreeSet::from([
            Action::Read,
            Action::Search,
            Action::Create,
            Action::Ingest,
            Action::Update,
            Action::Delete,
        ]);
        let db = Db::open(&data).unwrap();
        let authority = db.identity_authority().unwrap();
        let root = authority.authenticate(root_secret.trim()).unwrap();
        let revision = db.catalog_revision_authorized(&root).unwrap();
        db.create_protected_collection_authorized(
            &root,
            revision,
            serde_json::from_value(json!({"name":"docs","vector_dim":2})).unwrap(),
        )
        .unwrap();
        let root = db
            .management_identity(&authority.authenticate(root_secret.trim()).unwrap())
            .unwrap();
        let mut principal = root.principal().clone();
        principal.grants = vec![ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into()]),
            actions: actions.clone(),
        }];
        principal.delegation = vec![ScopeGrant {
            tenants: BTreeSet::from(["acme".into()]),
            collections: BTreeSet::from(["docs".into()]),
            actions,
        }];
        authority
            .put_principal(&root, root.revision(), principal)
            .unwrap();
        let root = db
            .management_identity(&authority.authenticate(root_secret.trim()).unwrap())
            .unwrap();
        let manage = db
            .bind_access(&root, "docs", "acme", Action::PolicyManage)
            .unwrap();
        db.replace_collection_policy_authorized(
            &manage,
            RevisionUpdate {
                expected_revision: manage.policy_revision(),
                value: CollectionPolicy {
                    department_actions: BTreeSet::new(),
                    owner_actions: BTreeSet::from([
                        Action::Read,
                        Action::Search,
                        Action::Update,
                        Action::Delete,
                    ]),
                    templates: std::collections::BTreeMap::from([(
                        "standard".into(),
                        IngestTemplate {
                            department: "Security".into(),
                            classification: Classification::Internal,
                            properties: std::collections::BTreeMap::from([(
                                "/text".into(),
                                PropertyRule {
                                    classification: Classification::Internal,
                                    actions: BTreeSet::from([
                                        PropertyAction::Read,
                                        PropertyAction::Query,
                                        PropertyAction::Write,
                                    ]),
                                },
                            )]),
                            representations: std::collections::BTreeMap::from([(
                                "dense".into(),
                                Representation {
                                    source_fields: BTreeSet::from(["/text".into()]),
                                    classification: Classification::Internal,
                                },
                            )]),
                        },
                    )]),
                },
            },
        )
        .unwrap();
        let root = db
            .management_identity(&authority.authenticate(root_secret.trim()).unwrap())
            .unwrap();
        let create = db
            .bind_access(&root, "docs", "acme", Action::Create)
            .unwrap();
        let point_id = db
            .create_points_authorized(
                &create,
                "standard",
                vec![NewPoint {
                    vector: vec![1.0, 0.0],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"text":"visible"}),
                }],
                true,
            )
            .unwrap()
            .publish(|ids| ids[0].clone())
            .unwrap();
        for request in [
            ChironQlRequest {
                query: "SQL CREATE TABLE docs (id TEXT PRIMARY KEY, chunk_ref RECORD_REF('docs') NOT NULL);".into(),
                ..Default::default()
            },
            ChironQlRequest {
                query: "SQL INSERT INTO docs (id, chunk_ref) VALUES ($1, RECORD_REF('docs', $2));"
                    .into(),
                parameters: vec![
                    RelationalValue::Text("row-1".into()),
                    RelationalValue::Text(point_id.clone()),
                ],
                ..Default::default()
            },
        ] {
            execute(&db, root_secret.trim(), &request)
                .unwrap()
                .publish(|response| response)
                .unwrap();
        }
        let output = execute(
            &db,
            root_secret.trim(),
            &ChironQlRequest {
                query: "PIPELINE\n  VECTOR v { SEARCH docs NEAR [1,0] LIMIT 1 }\n  RELATIONAL r { SQL SELECT id, chunk_ref FROM docs LIMIT 10 }\n  INNER JOIN r ON r.chunk_ref = v.record_ref\n  RETURN r.id, v.score\n  LIMIT 1;".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let guard = output.guard();
        let result = output.publish(|response| response).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.domains,
            vec![ExecutionDomain::Relational, ExecutionDomain::Vector]
        );

        let root = authority.authenticate(root_secret.trim()).unwrap();
        authority
            .revoke_credential(&root, root.revision(), root.credential_id())
            .unwrap();
        let mut published = false;
        assert!(guard.publish(|| published = true).is_err());
        assert!(!published);
    }
}

#[cfg(test)]
#[path = "chironql_protected/atomic_insert_tests.rs"]
mod atomic_insert_tests;
