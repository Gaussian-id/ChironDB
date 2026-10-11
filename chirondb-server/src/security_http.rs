//! HTTP admission for the durable protected authority. Legacy RBAC credentials
//! cannot fall through into this router; unsupported operations fail closed.
use crate::{Db, GaussError, model::*, security::*};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, Version, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete as route_delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::StreamExt;

#[derive(Clone)]
struct HttpState {
    db: Db,
    work: Arc<Semaphore>,
    observe_work: Arc<Semaphore>,
}
#[derive(Clone)]
struct Caller {
    identity: AuthenticatedIdentity,
    token: Arc<str>,
    // A disconnected request cannot release admission while its blocking job runs.
    work: Arc<OwnedSemaphorePermit>,
}
struct Failure(GaussError);
type HttpResult = Result<Response, Failure>;
impl From<GaussError> for Failure {
    fn from(value: GaussError) -> Self {
        Self(value)
    }
}
impl From<SecurityError> for Failure {
    fn from(value: SecurityError) -> Self {
        Self(value.into())
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, code) = match self.0 {
            GaussError::Security(error) => (
                match error {
                    SecurityError::Unauthenticated => StatusCode::UNAUTHORIZED,
                    SecurityError::Forbidden => StatusCode::FORBIDDEN,
                    SecurityError::NotFound => StatusCode::NOT_FOUND,
                    SecurityError::Conflict => StatusCode::CONFLICT,
                    SecurityError::Invalid(_) => StatusCode::BAD_REQUEST,
                    SecurityError::BudgetExceeded => StatusCode::TOO_MANY_REQUESTS,
                    SecurityError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                },
                error.code(),
            ),
            GaussError::PointNotFound(_) | GaussError::CollectionNotFound(_) => {
                (StatusCode::NOT_FOUND, "security.not_found")
            }
            GaussError::InvalidRequest(_) | GaussError::DimensionMismatch { .. } => {
                (StatusCode::BAD_REQUEST, "security.invalid")
            }
            GaussError::ResourceExhausted(_) => {
                (StatusCode::TOO_MANY_REQUESTS, "security.budget_exceeded")
            }
            _ => (StatusCode::SERVICE_UNAVAILABLE, "security.unavailable"),
        };
        (status, Json(json!({"error":{"code":code}}))).into_response()
    }
}

pub(crate) fn router(db: Db, options: crate::api::ServerOptions) -> Router {
    let _ = crate::observability::init_metrics();
    let routes = || {
        Router::new()
            .route("/chironql", post(chironql_execute))
            .route("/chironql/parse", post(chironql_parse))
            .route("/sql", post(sql_execute))
            .route("/transactions/{transaction_id}", get(transaction_status))
            .route("/sql/transactions", post(sql_transaction_begin))
            .route(
                "/sql/transactions/{handle}/execute",
                post(sql_transaction_execute),
            )
            .route(
                "/sql/transactions/{handle}/commit",
                post(sql_transaction_commit),
            )
            .route(
                "/sql/transactions/{handle}",
                route_delete(sql_transaction_rollback),
            )
            .route("/security/whoami", get(whoami))
            .route("/security/principals", put(principal))
            .route("/security/credentials", post(issue))
            .route("/security/sql-credentials", post(issue_sql))
            .route("/security/credentials/{id}/revoke", post(revoke))
            .route("/metrics", get(metrics))
            .route("/collections/{collection}/points", put(update))
            .route("/collections/{collection}/points/get", post(points))
            .route("/collections/{collection}/points/delete", post(delete))
            .route(
                "/collections/{collection}/points/delete/filter",
                post(delete_filter),
            )
            .route("/collections/{collection}/count", post(count))
            .route("/collections/{collection}/scroll", post(scroll))
            .route("/collections/{collection}/search", post(search))
            .route(
                "/collections/{collection}/text_hybrid_search",
                post(text_hybrid_search),
            )
            .route("/collections/{collection}/security/revision", get(revision))
            .route(
                "/collections/{collection}/security/objects/{id}/grants",
                put(grants),
            )
            .route(
                "/collections/{collection}/security/objects/{id}/labels",
                put(labels),
            )
    };
    let state = HttpState {
        work: db
            .identity_authority()
            .expect("protected authority")
            .work_pool(),
        observe_work: Arc::new(Semaphore::new(1)),
        db,
    };
    let protected = routes()
        .nest("/v1", routes())
        .fallback(|| async { Failure(SecurityError::Forbidden.into()) })
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state.clone());
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/v1/health", get(health))
        .with_state(state)
        .merge(protected);
    if let Some(cors) = crate::api::build_cors(&options.cors_origins) {
        router = router.layer(cors);
    }
    router
}

async fn health(State(state): State<HttpState>) -> Response {
    let ready = state.db.durability_ready();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"status": if ready {"ok"} else {"unavailable"}})),
    )
        .into_response()
}

async fn chironql_execute(
    State(state): State<HttpState>,
    Extension(caller): Extension<Caller>,
    Json(request): Json<chirondb_types::chironql::ChironQlRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        crate::chironql_protected::execute(&state.db, &caller.token, &request)
    })
    .await;
    match result {
        Ok(Ok(output)) => json_stream(tokio_stream::once(output).map(|output| {
            output
                .publish(|value| encode(&value))
                .map_err(std::io::Error::other)?
        })),
        Ok(Err(error)) => chironql_error(error),
        Err(_) => chironql_error(crate::chironql_protected::error("", "security.unavailable")),
    }
}

async fn sql_execute(
    State(state): State<HttpState>,
    Extension(caller): Extension<Caller>,
    Json(request): Json<crate::SqlExecutionRequest>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let response =
            state
                .db
                .execute_sql_authorized_owned(&caller.identity, request, "http-protected")?;
        let reference = state
            .db
            .sql_reference_publication_context(&caller.identity, &response.results)?;
        Ok::<_, GaussError>((caller.identity, reference, response))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_sql(result.0, result.1, result.2))
}

async fn transaction_status(
    State(state): State<HttpState>,
    Path(transaction_id): Path<String>,
    Extension(caller): Extension<Caller>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let status = state
            .db
            .transaction_status_authorized(&caller.identity, &transaction_id)?;
        Ok::<_, GaussError>((caller.identity, status))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(result.0, result.1))
}

async fn sql_transaction_begin(
    State(state): State<HttpState>,
    Extension(caller): Extension<Caller>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let response = state
            .db
            .begin_sql_transaction_authorized(&caller.identity, "http-protected")?;
        Ok::<_, GaussError>((caller.identity, response))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(result.0, result.1))
}

async fn sql_transaction_execute(
    State(state): State<HttpState>,
    Path(handle): Path<String>,
    Extension(caller): Extension<Caller>,
    Json(request): Json<crate::SqlExecutionRequest>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let response = state.db.execute_sql_transaction_authorized_owned(
            &caller.identity,
            &handle,
            request,
            "http-protected",
        )?;
        let reference = state
            .db
            .sql_reference_publication_context(&caller.identity, &response.results)?;
        Ok::<_, GaussError>((caller.identity, reference, response))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_sql(result.0, result.1, result.2))
}

async fn sql_transaction_commit(
    State(state): State<HttpState>,
    Path(handle): Path<String>,
    Extension(caller): Extension<Caller>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let response = state.db.commit_sql_transaction_authorized_owned(
            &caller.identity,
            &handle,
            "http-protected",
        )?;
        Ok::<_, GaussError>((caller.identity, response))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(result.0, result.1))
}

async fn sql_transaction_rollback(
    State(state): State<HttpState>,
    Path(handle): Path<String>,
    Extension(caller): Extension<Caller>,
) -> HttpResult {
    let result = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let response = state.db.rollback_sql_transaction_authorized(
            &caller.identity,
            &handle,
            "http-protected",
        )?;
        Ok::<_, GaussError>((caller.identity, response))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(result.0, result.1))
}

fn chironql_error(error: chirondb_types::chironql::ChironQlError) -> Response {
    let status = match error.code.as_str() {
        "security.unauthenticated" => StatusCode::UNAUTHORIZED,
        "security.forbidden" | "chironql.protected_unsupported" => StatusCode::FORBIDDEN,
        "security.not_found" => StatusCode::NOT_FOUND,
        "security.conflict"
        | "chironql.confirmation_required"
        | "chironql.revision_required"
        | "chironql.sql_row_precondition_failed" => StatusCode::CONFLICT,
        "security.budget_exceeded" => StatusCode::TOO_MANY_REQUESTS,
        "security.unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, Json(error)).into_response()
}

async fn chironql_parse(
    Extension(caller): Extension<Caller>,
    Json(request): Json<chirondb_types::chironql::ChironQlRequest>,
) -> Response {
    match crate::chironql_parser::parse(&request.query) {
        Ok(statement) => publish_identity(
            caller.identity,
            json!({
                "language_version":crate::chironql_parser::LANGUAGE_VERSION,
                "statement":statement.kind_name(),
                "class":match statement.class() {
                    crate::chironql_parser::StatementClass::Read => "read",
                    crate::chironql_parser::StatementClass::Write => "write",
                    crate::chironql_parser::StatementClass::Admin => "admin",
                },
                "domains": statement.domains(),
                "resources": {
                    "tables": statement.tables(),
                    "collections": statement.collections(),
                }
            }),
        ),
        Err(error) => chironql_error(crate::chironql_protected::error("", error.code)),
    }
}

pub(crate) fn credential(headers: &HeaderMap) -> Result<Arc<str>, SecurityError> {
    let mut selected = None;
    for name in [
        "authorization",
        "x-api-key",
        "x-gaussdb-api-key",
        "x-chirondb-api-key",
    ] {
        for value in headers.get_all(name) {
            if selected.is_some() {
                return Err(SecurityError::Unauthenticated);
            }
            let value = value.to_str().map_err(|_| SecurityError::Unauthenticated)?;
            let value = if name == "authorization" {
                value
                    .strip_prefix("Bearer ")
                    .ok_or(SecurityError::Unauthenticated)?
            } else {
                value
            };
            if value.is_empty() || value.len() > 256 || value.trim() != value {
                return Err(SecurityError::Unauthenticated);
            }
            selected = Some(Arc::from(value));
        }
    }
    selected.ok_or(SecurityError::Unauthenticated)
}

async fn authenticate(
    State(state): State<HttpState>,
    mut request: Request,
    next: Next,
) -> Response {
    let version = request.version();
    let result = (|| -> Result<Caller, Failure> {
        let observing = request.method() == axum::http::Method::GET
            && matches!(request.uri().path(), "/metrics" | "/v1/metrics");
        let work = if observing {
            state
                .observe_work
                .clone()
                .try_acquire_owned()
                .map_err(|_| SecurityError::BudgetExceeded)?
        } else {
            state
                .work
                .clone()
                .try_acquire_owned()
                .map_err(|_| SecurityError::BudgetExceeded)?
        };
        let token = credential(request.headers())?;
        let identity = state
            .db
            .identity_authority()
            .ok_or(SecurityError::Unavailable)?
            .authenticate(&token)?;
        let identity = state
            .db
            .management_identity(&identity)
            .map_err(|_| SecurityError::Unavailable)?;
        // The active organization comes exclusively from the catalog.
        if [
            "x-tenant-id",
            "x-principal-id",
            "x-chirondb-tenant-id",
            "x-gaussdb-tenant-id",
        ]
        .iter()
        .any(|name| request.headers().contains_key(*name))
        {
            return Err(SecurityError::Forbidden.into());
        }
        if observing && !identity.allows_installation(Action::Observe) {
            return Err(SecurityError::Forbidden.into());
        }
        Ok(Caller {
            identity,
            token,
            work: Arc::new(work),
        })
    })();
    let mut response = match result {
        Err(error) => error.into_response(),
        Ok(caller) => {
            let work = caller.work.clone();
            request.extensions_mut().insert(caller);
            let response = next.run(request).await;
            let (parts, body) = response.into_parts();
            Response::from_parts(
                parts,
                Body::from_stream(body.into_data_stream().map(move |frame| {
                    let _keep_work_alive = &work;
                    frame
                })),
            )
        }
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    // Rejections may occur before a request body is consumed. Explicitly close
    // HTTP/1 connections so clients cannot race a late close with another body.
    // Connection is a hop-by-hop header and must never be sent on HTTP/2.
    if matches!(version, Version::HTTP_10 | Version::HTTP_11)
        && (response.status().is_client_error() || response.status().is_server_error())
    {
        response.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
    }
    response
}

fn encode(value: &impl Serialize) -> std::io::Result<Bytes> {
    let owner = crate::response_buffer::ResponseBuffer::json(value, 8 * 1024 * 1024)
        .map_err(std::io::Error::other)?;
    Ok(Bytes::from_owner(owner))
}
struct Field<'a, T> {
    name: &'static str,
    value: &'a T,
}
impl<T: Serialize> Serialize for Field<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.name, self.value)?;
        map.end()
    }
}
fn json_stream(
    stream: impl tokio_stream::Stream<Item = std::io::Result<Bytes>> + Send + 'static,
) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        Body::from_stream(stream),
    )
        .into_response()
}
fn publish<T: Serialize + Send + 'static>(
    output: AuthorizedOutput<T>,
    field: Option<&'static str>,
) -> Response {
    // The callback runs when the transport polls the body, not when the handler
    // creates the response. An application-queued body cannot outlive revocation.
    json_stream(tokio_stream::once(output).map(move |output| {
        output
            .publish(|value| match field {
                Some(field) => encode(&Field {
                    name: field,
                    value: &value,
                }),
                None => encode(&value),
            })
            .map_err(std::io::Error::other)?
    }))
}
fn publish_identity<T: Serialize + Send + 'static>(
    identity: AuthenticatedIdentity,
    value: T,
) -> Response {
    json_stream(
        tokio_stream::once((identity, value)).map(|(identity, value)| {
            let _permit = identity
                .publication_permit()
                .map_err(std::io::Error::other)?;
            encode(&value)
        }),
    )
}

fn publish_sql(
    identity: AuthenticatedIdentity,
    reference: Option<AccessContext>,
    value: crate::SqlResponse,
) -> Response {
    json_stream(tokio_stream::once((identity, reference, value)).map(
        |(identity, reference, value)| {
            let _identity = identity
                .publication_permit()
                .map_err(std::io::Error::other)?;
            let _reference = reference
                .as_ref()
                .map(AccessContext::publication_permit)
                .transpose()
                .map_err(std::io::Error::other)?;
            encode(&value)
        },
    ))
}
async fn execute<T: Serialize + Send + 'static>(
    state: HttpState,
    caller: Caller,
    collection: String,
    action: Action,
    field: Option<&'static str>,
    operation: impl FnOnce(Db, AccessContext) -> crate::Result<AuthorizedOutput<T>> + Send + 'static,
) -> HttpResult {
    let output = tokio::task::spawn_blocking(move || {
        let _work = caller.work;
        let context = state.db.bind_access(
            &caller.identity,
            &collection,
            &caller.identity.principal().tenant,
            action,
        )?;
        operation(state.db, context)
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish(output, field))
}

async fn whoami(Extension(caller): Extension<Caller>) -> HttpResult {
    let mut value = json!({"principal":caller.identity.principal().id,"tenant":caller.identity.principal().tenant});
    if caller.identity.allows_installation(Action::IdentityManage) {
        value["identity_revision"] = json!(caller.identity.revision());
    }
    Ok(publish_identity(caller.identity, value))
}
async fn metrics(
    State(state): State<HttpState>,
    Extension(caller): Extension<Caller>,
) -> HttpResult {
    if !caller.identity.allows_installation(Action::Observe) {
        return Err(SecurityError::Forbidden.into());
    }
    let work = caller.work.clone();
    tokio::task::spawn_blocking(move || {
        let _work = work;
        state.db.refresh_metrics();
    })
    .await
    .map_err(|_| SecurityError::Unavailable)?;
    let stream = tokio_stream::once(caller.identity).map(|identity| {
        let _permit = identity
            .publication_permit()
            .map_err(std::io::Error::other)?;
        Ok::<_, std::io::Error>(Bytes::from(crate::observability::init_metrics().render()))
    });
    Ok((
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        Body::from_stream(stream),
    )
        .into_response())
}
async fn points(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<GetPointsRequest>,
) -> HttpResult {
    execute(s, c, name, Action::Read, Some("points"), move |db, ctx| {
        db.get_points_authorized(&ctx, &r.ids)
    })
    .await
}
async fn count(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<CountRequest>,
) -> HttpResult {
    execute(s, c, name, Action::Read, None, move |db, ctx| {
        db.count_authorized(&ctx, r.filter)
    })
    .await
}
async fn scroll(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<ScrollRequest>,
) -> HttpResult {
    execute(s, c, name, Action::Read, None, move |db, ctx| {
        db.scroll_authorized(&ctx, r)
    })
    .await
}
async fn search(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<SearchRequest>,
) -> HttpResult {
    execute(s, c, name, Action::Search, Some("hits"), move |db, ctx| {
        db.search_authorized(&ctx, r, None)
    })
    .await
}
async fn text_hybrid_search(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<TextHybridSearchRequest>,
) -> HttpResult {
    execute(s, c, name, Action::Search, Some("hits"), move |db, ctx| {
        db.text_hybrid_search_authorized(&ctx, r, None)
    })
    .await
}

async fn update(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<UpsertPoints>,
) -> HttpResult {
    if r.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
        return Err(SecurityError::BudgetExceeded.into());
    }
    let wait = r.wait;
    let mut response = execute(
        s,
        c,
        name,
        Action::Update,
        Some("updated"),
        move |db, ctx| db.update_points_authorized(&ctx, r.points, wait),
    )
    .await?;
    if !wait {
        *response.status_mut() = StatusCode::ACCEPTED;
    }
    Ok(response)
}
async fn delete(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<DeletePoints>,
) -> HttpResult {
    execute(
        s,
        c,
        name,
        Action::Delete,
        Some("deleted"),
        move |db, ctx| db.delete_points_authorized(&ctx, &r.ids),
    )
    .await
}
async fn delete_filter(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
    Json(r): Json<DeleteByFilterRequest>,
) -> HttpResult {
    execute(
        s,
        c,
        name,
        Action::Delete,
        Some("deleted"),
        move |db, ctx| db.delete_filter_authorized(&ctx, r.filter),
    )
    .await
}
async fn grants(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path((name, id)): Path<(String, String)>,
    Json(r): Json<RevisionUpdate<ObjectPermissions>>,
) -> HttpResult {
    execute(
        s,
        c,
        name,
        Action::GrantsManage,
        Some("revision"),
        move |db, ctx| db.replace_object_permissions_authorized(&ctx, &id, r),
    )
    .await
}
async fn labels(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path((name, id)): Path<(String, String)>,
    Json(r): Json<RevisionUpdate<ObjectLabels>>,
) -> HttpResult {
    execute(
        s,
        c,
        name,
        Action::LabelsManage,
        Some("revision"),
        move |db, ctx| db.replace_object_labels_authorized(&ctx, &id, r),
    )
    .await
}
async fn revision(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(name): Path<String>,
) -> HttpResult {
    let ctx = s.db.bind_access(
        &c.identity,
        &name,
        &c.identity.principal().tenant,
        Action::GrantsManage,
    )?;
    Ok(publish_identity(
        c.identity,
        json!({"revision":ctx.policy_revision()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    expected_revision: u64,
    principal: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    expected_revision: u64,
}
async fn principal(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Json(r): Json<RevisionUpdate<PrincipalRecord>>,
) -> HttpResult {
    if !c.identity.allows_installation(Action::IdentityManage) {
        return Err(SecurityError::Forbidden.into());
    }
    let revision = tokio::task::spawn_blocking(move || {
        let _work = c.work;
        s.db.identity_authority()
            .ok_or(SecurityError::Unavailable)?
            .put_principal(&c.identity, r.expected_revision, r.value)
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(Json(json!({"revision":revision})).into_response())
}
async fn issue(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Json(r): Json<Issue>,
) -> HttpResult {
    if !c.identity.allows_installation(Action::IdentityManage) {
        return Err(SecurityError::Forbidden.into());
    }
    let (identity, key) = tokio::task::spawn_blocking(move || -> Result<_, SecurityError> {
        let _work = c.work;
        let authority =
            s.db.identity_authority()
                .ok_or(SecurityError::Unavailable)?;
        let key = authority.issue_credential(&c.identity, r.expected_revision, &r.principal)?;
        Ok((authority.authenticate(&c.token)?, key))
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(
        identity,
        json!({"id":key.id,"secret":key.secret,"revision":key.revision}),
    ))
}
async fn issue_sql(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Json(r): Json<Issue>,
) -> HttpResult {
    if !c.identity.allows_installation(Action::IdentityManage) {
        return Err(SecurityError::Forbidden.into());
    }
    let (identity, credential) =
        tokio::task::spawn_blocking(move || -> Result<_, SecurityError> {
            let _work = c.work;
            let authority =
                s.db.identity_authority()
                    .ok_or(SecurityError::Unavailable)?;
            let credential =
                authority.issue_sql_credential(&c.identity, r.expected_revision, &r.principal)?;
            Ok((authority.authenticate(&c.token)?, credential))
        })
        .await
        .map_err(|_| SecurityError::Unavailable)??;
    Ok(publish_identity(identity, json!(credential)))
}
async fn revoke(
    State(s): State<HttpState>,
    Extension(c): Extension<Caller>,
    Path(id): Path<String>,
    Json(r): Json<Expected>,
) -> HttpResult {
    if !c.identity.allows_installation(Action::IdentityManage) {
        return Err(SecurityError::Forbidden.into());
    }
    let revision = tokio::task::spawn_blocking(move || {
        let _work = c.work;
        s.db.identity_authority()
            .ok_or(SecurityError::Unavailable)?
            .revoke_credential(&c.identity, r.expected_revision, &id)
    })
    .await
    .map_err(|_| SecurityError::Unavailable)??;
    Ok(Json(json!({"revision":revision})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_json_output_stops_at_limit_before_following_values() {
        use serde::ser::SerializeSeq;
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Overflow {
            value: String,
            followed: AtomicBool,
        }
        impl Serialize for Overflow {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&self.value)?;
                self.followed.store(true, Ordering::Relaxed);
                seq.serialize_element(&true)?;
                seq.end()
            }
        }
        let value = Overflow {
            value: "\n".repeat(4 * 1024 * 1024 + 1),
            followed: AtomicBool::new(false),
        };
        assert!(encode(&value).is_err());
        assert!(
            !value.followed.load(Ordering::Relaxed),
            "encoding must stop at the bound before allocating the rest of the response"
        );
    }
    use std::collections::BTreeSet;

    #[test]
    fn credentials_reject_duplicates_and_conflicting_aliases() {
        for alias in [
            "authorization",
            "x-api-key",
            "x-gaussdb-api-key",
            "x-chirondb-api-key",
        ] {
            let mut headers = HeaderMap::new();
            let value = if alias == "authorization" {
                "Bearer synthetic"
            } else {
                "synthetic"
            };
            headers.append(alias, value.parse().unwrap());
            assert_eq!(&*credential(&headers).unwrap(), "synthetic");
            headers.append(alias, value.parse().unwrap());
            assert!(credential(&headers).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer one".parse().unwrap());
        headers.insert("x-gaussdb-api-key", "two".parse().unwrap());
        assert!(credential(&headers).is_err());
    }

    #[tokio::test]
    async fn authorized_metrics_keep_a_bounded_lane_when_query_work_is_full() {
        let directory = tempfile::tempdir().unwrap();
        chirondb_core::storage_layout::initialize_empty(directory.path()).unwrap();
        let admin = IdentityAuthority::bootstrap(
            directory.path(),
            PrincipalRecord {
                id: "admin".into(),
                tenant: "acme".into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "Security".into(),
                    clearance: Classification::Restricted,
                },
                grants: vec![],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Observe]),
                delegation: vec![],
            },
        )
        .unwrap();
        let db = Db::open(directory.path()).unwrap();
        let authority = Arc::clone(db.identity_authority().unwrap());
        let admin_identity = authority.authenticate(&admin.secret).unwrap();
        authority
            .put_principal(
                &admin_identity,
                1,
                PrincipalRecord {
                    id: "reader".into(),
                    tenant: "acme".into(),
                    enabled: true,
                    attributes: SubjectAttributes {
                        department: "Finance".into(),
                        clearance: Classification::Internal,
                    },
                    grants: vec![],
                    installation_actions: BTreeSet::new(),
                    delegation: vec![],
                },
            )
            .unwrap();
        let admin_identity = authority.authenticate(&admin.secret).unwrap();
        let reader = authority
            .issue_credential(&admin_identity, 2, "reader")
            .unwrap();
        let work = authority.work_pool();
        let permits = work.available_permits();
        assert!(permits > 0);
        let held = work.try_acquire_many_owned(permits as u32).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router(db, crate::api::ServerOptions::default()))
                .await
                .unwrap();
        });
        let client = reqwest::Client::new();
        for path in ["/metrics", "/v1/metrics"] {
            let response = client
                .get(format!("{url}{path}"))
                .bearer_auth(&admin.secret)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.text().await.unwrap().contains("# TYPE"));
        }
        let response = client
            .get(format!("{url}/v1/security/whoami"))
            .bearer_auth(&admin.secret)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = client
            .get(format!("{url}/metrics"))
            .bearer_auth(&reader.secret)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = client
            .get(format!("{url}/metrics"))
            .bearer_auth("invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        server.abort();
        drop(held);
    }

    #[tokio::test]
    async fn queued_identity_body_cannot_publish_after_acknowledged_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let key = IdentityAuthority::bootstrap(
            dir.path(),
            PrincipalRecord {
                id: "security-admin".into(),
                tenant: "acme".into(),
                enabled: true,
                attributes: SubjectAttributes {
                    department: "Security".into(),
                    clearance: Classification::Restricted,
                },
                grants: vec![],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
                delegation: vec![],
            },
        )
        .unwrap();
        let authority = IdentityAuthority::open(dir.path()).unwrap().unwrap();
        let actor = authority.authenticate(&key.secret).unwrap();
        let queued = publish_identity(
            actor.clone(),
            json!({"secret":"must never leave application queue"}),
        );
        authority.revoke_credential(&actor, 1, &key.id).unwrap();
        assert!(
            axum::body::to_bytes(queued.into_body(), 1024)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn queued_typed_sql_body_rechecks_revocation_before_encoding() {
        let directory = tempfile::tempdir().unwrap();
        chirondb_core::storage_layout::initialize_empty(directory.path()).unwrap();
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
                grants: vec![ScopeGrant {
                    tenants: BTreeSet::from(["acme".into()]),
                    collections: BTreeSet::from(["outputs".into()]),
                    actions: BTreeSet::from([Action::Read, Action::Create]),
                }],
                delegation: vec![],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
            },
        )
        .unwrap();
        let db = Db::open(directory.path()).unwrap();
        let authority = Arc::clone(db.identity_authority().unwrap());
        let identity = db
            .management_identity(&authority.authenticate(&key.secret).unwrap())
            .unwrap();
        let request = |sql: &str| crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.into(),
                parameters: vec![],
            }],
            idempotency_key: None,
            retry_id: None,
        };
        db.execute_sql_authorized(
            &identity,
            request("CREATE TABLE outputs (id INTEGER PRIMARY KEY, text TEXT)"),
            "test",
        )
        .unwrap();
        db.execute_sql_authorized(
            &identity,
            request("INSERT INTO outputs VALUES (1, 'queued-private')"),
            "test",
        )
        .unwrap();
        let output = db
            .execute_sql_authorized_owned(&identity, request("SELECT * FROM outputs"), "test")
            .unwrap();
        let reference = db
            .sql_reference_publication_context(&identity, &output.results)
            .unwrap();
        let queued = publish_sql(identity.clone(), reference, output);
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        assert!(
            axum::body::to_bytes(queued.into_body(), 65536)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn protected_transaction_status_handler_returns_only_owned_decisions() {
        let directory = tempfile::tempdir().unwrap();
        chirondb_core::storage_layout::initialize_empty(directory.path()).unwrap();
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
                grants: vec![ScopeGrant {
                    tenants: BTreeSet::from(["acme".into()]),
                    collections: BTreeSet::from(["accounts".into()]),
                    actions: BTreeSet::from([Action::Read, Action::Create]),
                }],
                installation_actions: BTreeSet::from([Action::IdentityManage, Action::Schema]),
                delegation: Vec::new(),
            },
        )
        .unwrap();
        let db = Db::open(directory.path()).unwrap();
        let authority = Arc::clone(db.identity_authority().unwrap());
        let identity = authority.authenticate(&key.secret).unwrap();
        let identity = db.management_identity(&identity).unwrap();
        db.execute_sql_authorized(
            &identity,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: "CREATE TABLE accounts (id INTEGER PRIMARY KEY)".into(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            "protected-http-test",
        )
        .unwrap();
        let committed = db
            .execute_sql_authorized(
                &identity,
                crate::SqlExecutionRequest {
                    statements: vec![crate::SqlStatementRequest {
                        sql: "INSERT INTO accounts VALUES (1)".into(),
                        parameters: Vec::new(),
                    }],
                    idempotency_key: None,
                    retry_id: None,
                },
                "protected-http-test",
            )
            .unwrap();
        let transaction_id = committed.transaction_id.unwrap();
        // A real status request reauthenticates after the mutation request.
        let identity = authority.authenticate(&key.secret).unwrap();
        let identity = db.management_identity(&identity).unwrap();
        let work_pool = authority.work_pool();
        let caller = Caller {
            identity,
            token: Arc::from(key.secret),
            work: Arc::new(work_pool.clone().try_acquire_owned().unwrap()),
        };
        let Ok(response) = transaction_status(
            State(HttpState {
                db,
                work: work_pool,
                observe_work: Arc::new(Semaphore::new(1)),
            }),
            Path(transaction_id.clone()),
            Extension(caller),
        )
        .await
        else {
            panic!("owned transaction status was rejected");
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let status: chirondb_core::TransactionStatus = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.transaction_id.to_string(), transaction_id);
        assert_eq!(status.state, chirondb_core::TransactionState::Committed);
    }
}
