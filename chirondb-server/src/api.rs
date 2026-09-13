use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Extension, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{delete, get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_executor::block_on;
use serde_json::json;
use tokio::{net::TcpListener, sync::mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use std::collections::HashSet;

use chirondb_types::chironql::{ChironQlError, ChironQlRequest};
use chirondb_types::graph::{
    ConfigureEdgeTypeRequest, EdgePropertyMode, EdgeToken, GraphCapability, GraphDeferredSessionId,
    GraphTraversalQueryRequest, RelateRequest, UpdateEdgeRequest,
};

use crate::{
    Db, GaussError,
    auth::{AuthConfig, require_http_auth},
    chironql_exec::{self, ExecContext, Session},
    dispatch,
    events::{EventHub, ServerEvent},
    model::{
        CollectionConfig, CountRequest, DeleteByFilterRequest, DeletePoints, GetPointsRequest,
        HybridSearchRequest, MultiSearchRequest, PruneWalArchiveRequest, RecommendRequest,
        RerankRequest, RestoreRequest, ScrollRequest, SearchRequest, SetPayloadRequest,
        SnapshotRequest, StatusResponse, UpdatePayloadSchemaRequest, UpsertPoints,
    },
    observability,
    rbac::{Permission, authorize_graph},
    security_paths::StoragePolicy,
    segment::ColdObjectStoreConfig,
};

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub mcp: Option<crate::mcp::McpServer>,
    pub cors_origins: Vec<String>,
    pub ws_metrics_interval: Duration,
    pub events: EventHub,
    pub storage_policy: StoragePolicy,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            mcp: None,
            cors_origins: Vec::new(),
            ws_metrics_interval: Duration::from_millis(5000),
            events: EventHub::default(),
            storage_policy: StoragePolicy::default(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    db: Db,
    events: EventHub,
    ws_metrics_interval: Duration,
    storage_policy: StoragePolicy,
}

pub fn router(db: Db) -> Router {
    router_with_options(db, AuthConfig::disabled(), ServerOptions::default())
}

pub fn router_with_auth(db: Db, auth: AuthConfig) -> Router {
    router_with_options(db, auth, ServerOptions::default())
}

fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(metrics))
        .route(
            "/collections",
            get(list_collections).post(create_collection),
        )
        .route("/collections/{collection}", delete(delete_collection))
        .route(
            "/collections/{collection}/payload_schema",
            put(update_payload_schema),
        )
        .route("/collections/{collection}/points", put(upsert_points))
        .route("/collections/{collection}/points/get", post(get_points))
        .route(
            "/collections/{collection}/points/payload",
            post(set_payload),
        )
        .route(
            "/collections/{collection}/points/delete",
            post(delete_points),
        )
        .route(
            "/collections/{collection}/points/delete/filter",
            post(delete_by_filter),
        )
        .route("/chironql", post(chironql_execute))
        .route("/chironql/parse", post(chironql_parse))
        .route(
            "/collections/{collection}/graph",
            put(enable_graph).delete(drop_graph),
        )
        .route(
            "/collections/{collection}/graph/types",
            get(list_graph_types),
        )
        .route(
            "/collections/{collection}/graph/types/{edge_type}",
            put(configure_graph_type),
        )
        .route(
            "/collections/{collection}/graph/traverse",
            post(traverse_graph),
        )
        .route(
            "/collections/{collection}/graph/deferred-sessions",
            post(open_graph_deferred_session),
        )
        .route(
            "/collections/{collection}/graph/deferred-sessions/{session_id}/points",
            post(upsert_graph_deferred_points),
        )
        .route(
            "/collections/{collection}/graph/deferred-sessions/{session_id}/edges",
            post(relate_graph_deferred),
        )
        .route(
            "/collections/{collection}/graph/deferred-sessions/{session_id}/commit",
            post(commit_graph_deferred_session),
        )
        .route(
            "/collections/{collection}/graph/deferred-sessions/{session_id}/abort",
            post(abort_graph_deferred_session),
        )
        .route("/collections/{collection}/edges", post(relate_graph))
        .route(
            "/collections/{collection}/edges/{edge_id}",
            delete(unrelate_graph)
                .patch(merge_graph_edge_properties)
                .put(replace_graph_edge_properties),
        )
        .route("/collections/{collection}/search", post(search))
        .route("/collections/{collection}/search/batch", post(search_batch))
        .route(
            "/collections/{collection}/search/stream",
            post(search_stream),
        )
        .route(
            "/collections/{collection}/hybrid_search",
            post(hybrid_search),
        )
        .route(
            "/collections/{collection}/text_hybrid_search",
            post(text_hybrid_search),
        )
        .route("/collections/{collection}/multi_search", post(multi_search))
        .route("/collections/{collection}/recommend", post(recommend))
        .route("/collections/{collection}/rerank", post(rerank))
        .route("/collections/{collection}/count", post(count))
        .route("/collections/{collection}/index_status", get(index_status))
        .route("/collections/{collection}/scroll", post(scroll))
        .route("/collections/{collection}/compact", post(compact))
        .route("/collections/{collection}/calibrate", post(calibrate))
        .route(
            "/collections/{collection}/compact/stream",
            post(compact_stream),
        )
        .route("/collections/{collection}/cold/tier", post(tier_cold))
        .route(
            "/collections/{collection}/wal_archive/prune",
            post(prune_wal_archive),
        )
        .route("/admin/snapshot", post(snapshot))
        .route("/admin/snapshot/stream", post(snapshot_stream))
        .route("/admin/restore", post(restore))
        .route("/admin/restore/stream", post(restore_stream))
        .route("/admin/shard_move", post(shard_move))
        .route("/ws/events", get(ws_events))
        .route("/ws/metrics", get(ws_metrics))
}

pub fn router_with_options(db: Db, auth: AuthConfig, options: ServerOptions) -> Router {
    let _ = observability::init_metrics();
    let auth_db = db.clone();
    let state = AppState {
        db,
        events: options.events.clone(),
        ws_metrics_interval: options.ws_metrics_interval,
        storage_policy: options.storage_policy,
    };
    let public = Router::new()
        .route("/health", get(health))
        .route("/v1/health", get(health));
    let protected = protected_routes()
        .merge(Router::new().nest("/v1", protected_routes()))
        .route_layer(middleware::from_fn_with_state(
            (auth, auth_db),
            require_http_auth,
        ));

    let cors = build_cors(&options.cors_origins);

    let mut router = public
        .merge(protected)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    if let Some(mcp) = options.mcp {
        router = router.merge(mcp.router());
    }
    if let Some(cors) = cors {
        router = router.layer(cors);
    }
    router
}

fn build_cors(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    if origins.iter().any(|o| o == "*") {
        return Some(CorsLayer::permissive());
    }
    let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
    if parsed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any),
    )
}

pub async fn serve(db: Db, addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(db, listener).await
}

pub async fn serve_with_auth(db: Db, auth: AuthConfig, addr: SocketAddr) -> std::io::Result<()> {
    serve_with_options(db, auth, addr, ServerOptions::default()).await
}

pub async fn serve_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    options: ServerOptions,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router_with_options(db, auth, options)).await
}

pub async fn serve_tls_with_auth(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
) -> std::io::Result<()> {
    serve_tls_with_options(
        db,
        auth,
        addr,
        cert,
        key,
        client_ca,
        ServerOptions::default(),
    )
    .await
}

pub async fn serve_tls_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    options: ServerOptions,
) -> std::io::Result<()> {
    let config = RustlsConfig::from_config(Arc::new(
        crate::tls::server_config(cert, key, client_ca).await?,
    ));
    axum_server::bind_rustls(addr, config)
        .serve(router_with_options(db, auth, options).into_make_service())
        .await
}

pub async fn serve_tls_config_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    tls: crate::tls::ReloadingTlsConfig,
    options: ServerOptions,
) -> std::io::Result<()> {
    let config = RustlsConfig::from_config(tls.server_config());
    axum_server::bind_rustls(addr, config)
        .serve(router_with_options(db, auth, options).into_make_service())
        .await
}

pub async fn serve_listener(db: Db, listener: TcpListener) -> std::io::Result<()> {
    axum::serve(listener, router(db)).await
}

pub async fn serve_listener_with_auth(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
) -> std::io::Result<()> {
    axum::serve(listener, router_with_auth(db, auth)).await
}

async fn health(State(state): State<AppState>) -> Response {
    state.db.refresh_metrics();
    let ready = state.db.durability_ready();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
        "status": if ready { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        })),
    )
        .into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    state.db.refresh_metrics();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        observability::init_metrics().render(),
    )
        .into_response()
}

async fn create_collection(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Json(config): Json<CollectionConfig>,
) -> Result<Json<CollectionConfig>, Response> {
    let db = &state.db;
    if !perm.allows_collection(&config.name) {
        return Err((
            StatusCode::FORBIDDEN,
            "collection is outside the principal allowlist",
        )
            .into_response());
    }
    if let Some(limit) = perm.max_collections {
        let current_count = if perm.is_restricted() {
            db.list_collections()
                .iter()
                .filter(|c| perm.allows_collection(&c.name))
                .count()
        } else {
            db.list_collections().len()
        };
        if current_count >= limit {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": format!("collection quota exceeded: limit is {limit}")
                })),
            )
                .into_response());
        }
    }
    let created = db
        .create_collection(config)
        .map_err(ApiError::from)
        .map_err(IntoResponse::into_response)?;
    state.events.publish(ServerEvent::CollectionCreated {
        name: created.name.clone(),
    });
    Ok(Json(created))
}

async fn list_collections(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
) -> Json<Vec<CollectionConfig>> {
    let all = state.db.list_collections();
    if perm.is_restricted() {
        Json(
            all.into_iter()
                .filter(|c| perm.allows_collection(&c.name))
                .collect(),
        )
    } else {
        Json(all)
    }
}

async fn delete_collection(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = state.db.delete_collection(&collection)?;
    state
        .events
        .publish(ServerEvent::CollectionDeleted { name: name.clone() });
    Ok(Json(json!({ "deleted": name })))
}

async fn update_payload_schema(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    Json(request): Json<UpdatePayloadSchemaRequest>,
) -> Result<Json<CollectionConfig>, ApiError> {
    Ok(Json(state.db.update_payload_schema(
        &collection,
        request.payload_schema,
    )?))
}

async fn upsert_points(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpsertPoints>,
) -> impl IntoResponse {
    if request.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
        return ApiError::from(GaussError::ResourceExhausted(format!(
            "upsert contains {} points; maximum is {}",
            request.points.len(),
            crate::MAX_UPSERT_POINTS_PER_REQUEST
        )))
        .into_response();
    }
    let wait = request.wait;
    let scope = perm.tenant_scope(perm.id.clone());
    let structural = match structural_embedding_headers(&headers) {
        Ok(structural) => structural,
        Err(error) => return ApiError::from(error).into_response(),
    };
    if let Some(unsafe_reason) = structural {
        match state.db.upsert_structural_scoped(
            &collection,
            request.points,
            wait,
            &scope,
            unsafe_reason.as_deref(),
        ) {
            Ok(receipt) => {
                let status = if wait {
                    StatusCode::OK
                } else {
                    StatusCode::ACCEPTED
                };
                return (
                    status,
                    Json(json!({
                        "total": receipt.total,
                        "operation_lsn": receipt.operation_lsn,
                        "unsafe_override_audited": receipt.unsafe_override_audited,
                    })),
                )
                    .into_response();
            }
            Err(error) => return ApiError::from(error).into_response(),
        }
    }
    match state
        .db
        .upsert_scoped(&collection, request.points, wait, &scope)
    {
        Ok(total) => {
            let status = if wait {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (status, Json(json!({ "total": total }))).into_response()
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

const STRUCTURAL_POINTS_HEADER: &str = "x-chiron-structural-points";
const UNSAFE_STRUCTURAL_REASON_HEADER: &str = "x-chiron-unsafe-structural-embedding-reason";

/// `None` means this is a compatibility/generic point write. `Some(None)` is
/// a safe structural write; `Some(Some(reason))` is the explicit audited
/// exception. The reason is URL-safe base64 so Unicode text never becomes an
/// invalid HTTP header value.
fn structural_embedding_headers(headers: &HeaderMap) -> crate::Result<Option<Option<String>>> {
    let structural = match headers.get(STRUCTURAL_POINTS_HEADER) {
        None => false,
        Some(value) if value.as_bytes() == b"1" => true,
        Some(_) => {
            return Err(GaussError::InvalidRequest(format!(
                "{STRUCTURAL_POINTS_HEADER} must be 1"
            )));
        }
    };
    let encoded_reason = headers.get(UNSAFE_STRUCTURAL_REASON_HEADER);
    if !structural {
        if encoded_reason.is_some() {
            return Err(GaussError::InvalidRequest(format!(
                "{UNSAFE_STRUCTURAL_REASON_HEADER} requires {STRUCTURAL_POINTS_HEADER}: 1"
            )));
        }
        return Ok(None);
    }
    let Some(encoded_reason) = encoded_reason else {
        return Ok(Some(None));
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_reason.as_bytes())
        .map_err(|_| {
            GaussError::InvalidRequest(format!(
                "{UNSAFE_STRUCTURAL_REASON_HEADER} must be URL-safe base64 without padding"
            ))
        })?;
    let reason = String::from_utf8(decoded).map_err(|_| {
        GaussError::InvalidRequest(format!(
            "{UNSAFE_STRUCTURAL_REASON_HEADER} must decode to UTF-8"
        ))
    })?;
    Ok(Some(Some(reason)))
}

#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
struct GraphWaitQuery {
    wait: Option<bool>,
}

impl GraphWaitQuery {
    fn wait(self) -> bool {
        self.wait.unwrap_or(true)
    }
}

#[derive(Debug, serde::Deserialize)]
struct GraphTypeConfigurationBody {
    #[serde(default)]
    weight_property: Option<String>,
    #[serde(default = "default_graph_wait")]
    wait: bool,
}

#[derive(Debug, serde::Deserialize)]
struct GraphRelateBody {
    #[serde(flatten)]
    request: RelateRequest,
    #[serde(default = "default_graph_wait")]
    wait: bool,
}

#[derive(Debug, serde::Deserialize)]
struct GraphEdgePropertiesBody {
    #[serde(default)]
    properties: serde_json::Value,
    #[serde(default = "default_graph_wait")]
    wait: bool,
}

const fn default_graph_wait() -> bool {
    true
}

fn graph_mutation_status(wait: bool) -> StatusCode {
    if wait {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    }
}

fn require_graph_capability(
    db: &Db,
    perm: &Permission,
    capability: GraphCapability,
    collection: &str,
) -> Result<(), ApiError> {
    if let Err(error) = authorize_graph(perm, capability, collection) {
        db.audit_access_event(
            "authorization",
            "http_graph_authorize",
            "denied",
            Some(collection),
            &perm.id,
            perm.tenant_id.as_deref(),
            "http",
            None,
            Some("graph.permission_denied"),
        )?;
        return Err(ApiError::graph_forbidden(format!(
            "{} is required for collection '{collection}': {error:?}",
            capability.as_str()
        )));
    }
    Ok(())
}

async fn enable_graph(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Admin, &collection)?;
    let wait = wait.wait();
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state
        .db
        .set_graph_lifecycle_scoped(&collection, true, wait, &scope)?;
    Ok((graph_mutation_status(wait), Json(result)))
}

async fn drop_graph(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Admin, &collection)?;
    let wait = wait.wait();
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state
        .db
        .set_graph_lifecycle_scoped(&collection, false, wait, &scope)?;
    Ok((graph_mutation_status(wait), Json(result)))
}

async fn list_graph_types(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let edge_types = state.db.list_edge_types_scoped(&collection, &scope)?;
    Ok(Json(json!({ "edge_types": edge_types })))
}

async fn configure_graph_type(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, edge_type)): Path<(String, String)>,
    Json(body): Json<GraphTypeConfigurationBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(
        &state.db,
        &perm,
        GraphCapability::TypeConfigure,
        &collection,
    )?;
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state.db.configure_edge_type_scoped(
        &collection,
        ConfigureEdgeTypeRequest {
            name: edge_type,
            weight_property: body.weight_property,
        },
        body.wait,
        &scope,
    )?;
    Ok((graph_mutation_status(body.wait), Json(result)))
}

async fn relate_graph(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(body): Json<GraphRelateBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state
        .db
        .relate_scoped(&collection, body.request, body.wait, &scope)?;
    Ok((graph_mutation_status(body.wait), Json(result)))
}

async fn unrelate_graph(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, edge_id)): Path<(String, String)>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let wait = wait.wait();
    let scope = perm.tenant_scope(perm.id.clone());
    let edge_id = EdgeToken::from_encoded(edge_id);
    let (receipt, deleted) =
        state
            .db
            .unrelate_many_scoped(&collection, &[edge_id], wait, &scope)?;
    Ok((
        graph_mutation_status(wait),
        Json(json!({ "deleted": deleted, "receipt": receipt })),
    ))
}

async fn merge_graph_edge_properties(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, edge_id)): Path<(String, String)>,
    Json(body): Json<GraphEdgePropertiesBody>,
) -> Result<impl IntoResponse, ApiError> {
    update_graph_edge_properties(
        state,
        perm,
        collection,
        edge_id,
        body,
        EdgePropertyMode::Merge,
    )
    .await
}

async fn replace_graph_edge_properties(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, edge_id)): Path<(String, String)>,
    Json(body): Json<GraphEdgePropertiesBody>,
) -> Result<impl IntoResponse, ApiError> {
    update_graph_edge_properties(
        state,
        perm,
        collection,
        edge_id,
        body,
        EdgePropertyMode::Replace,
    )
    .await
}

async fn update_graph_edge_properties(
    state: AppState,
    perm: Permission,
    collection: String,
    edge_id: String,
    body: GraphEdgePropertiesBody,
    mode: EdgePropertyMode,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let receipt = state.db.update_edge_scoped(
        &collection,
        &EdgeToken::from_encoded(edge_id),
        UpdateEdgeRequest {
            mode,
            properties: body.properties,
        },
        body.wait,
        &scope,
    )?;
    Ok((graph_mutation_status(body.wait), Json(receipt)))
}

async fn traverse_graph(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<GraphTraversalQueryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state
        .db
        .traverse_query_scoped(&collection, request, &scope)?;
    Ok(Json(json!(result)))
}

async fn open_graph_deferred_session(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let wait = wait.wait();
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state
        .db
        .open_deferred_graph_session_scoped(&collection, wait, &scope)?;
    Ok((graph_mutation_status(wait), Json(result)))
}

async fn upsert_graph_deferred_points(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, session_id)): Path<(String, String)>,
    Json(request): Json<UpsertPoints>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    if request.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
        return Err(GaussError::ResourceExhausted(format!(
            "upsert contains {} points; maximum is {}",
            request.points.len(),
            crate::MAX_UPSERT_POINTS_PER_REQUEST
        ))
        .into());
    }
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state.db.upsert_deferred_scoped(
        &collection,
        &GraphDeferredSessionId::from_encoded(session_id),
        request.points,
        request.wait,
        &scope,
    )?;
    Ok((graph_mutation_status(request.wait), Json(result)))
}

async fn relate_graph_deferred(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, session_id)): Path<(String, String)>,
    Json(body): Json<GraphRelateBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let result = state.db.relate_deferred_scoped(
        &collection,
        &GraphDeferredSessionId::from_encoded(session_id),
        body.request,
        body.wait,
        &scope,
    )?;
    Ok((graph_mutation_status(body.wait), Json(result)))
}

async fn commit_graph_deferred_session(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, session_id)): Path<(String, String)>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    finish_graph_deferred_session(state, perm, collection, session_id, wait.wait(), true).await
}

async fn abort_graph_deferred_session(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path((collection, session_id)): Path<(String, String)>,
    Query(wait): Query<GraphWaitQuery>,
) -> Result<impl IntoResponse, ApiError> {
    finish_graph_deferred_session(state, perm, collection, session_id, wait.wait(), false).await
}

async fn finish_graph_deferred_session(
    state: AppState,
    perm: Permission,
    collection: String,
    session_id: String,
    wait: bool,
    commit: bool,
) -> Result<impl IntoResponse, ApiError> {
    require_graph_capability(&state.db, &perm, GraphCapability::Write, &collection)?;
    let scope = perm.tenant_scope(perm.id.clone());
    let session_id = GraphDeferredSessionId::from_encoded(session_id);
    let result = if commit {
        state
            .db
            .commit_deferred_graph_session_scoped(&collection, &session_id, wait, &scope)?
    } else {
        state
            .db
            .abort_deferred_graph_session_scoped(&collection, &session_id, wait, &scope)?
    };
    Ok((graph_mutation_status(wait), Json(result)))
}

async fn delete_points(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<DeletePoints>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    let deleted = state.db.delete_scoped(&collection, &request.ids, &scope)?;
    Ok(Json(json!({ "deleted": deleted })))
}

/// Run a CPU-bound DB operation on the blocking thread pool so the tokio worker
/// stays free to accept the next request.  Joins back into the async runtime;
/// a panic in the closure maps to a 500 (`GaussError::Io`).
async fn run_blocking<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> crate::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let result = tokio::task::spawn_blocking(f).await.map_err(|err| {
        ApiError::from(GaussError::Io(std::io::Error::other(format!(
            "search task panicked: {err}"
        ))))
    })?;
    result.map_err(ApiError::from)
}

async fn search(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<SearchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.graph.is_some() {
        require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    }
    // Phase 2A: `Db::search` is a synchronous, in-memory HNSW/RaBitQ
    // traversal — no async I/O, no non-`Send` guards, finishes in
    // microseconds to a few milliseconds. Calling it directly on the
    // axum task removes the `tokio::task::spawn_blocking` submit/join
    // overhead (~20–50 µs per request at c=80, 2–5% of wall time).
    // See `gaussdb_server::dispatch` for the contract.
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let response =
        dispatch::dispatch_search(move || db.search_scoped(&collection, request, &scope))
            .map_err(ApiError::from)?;
    Ok(Json(json!(response)))
}

/// PA-5: batch search alias. Accepts `{ "searches": [SearchRequest, ...] }`,
/// returns `{ "responses": [SearchResponse, ...] }`. Shape mirrors the
/// Qdrant client convention; internally maps to `Db::multi_search` with
/// no fusion. Branches execute in parallel via rayon.
///
/// Phase 2A: same dispatch path as [`search`] — direct call on the
/// axum task instead of `tokio::task::spawn_blocking`.
async fn search_batch(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<BatchSearchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.searches.iter().any(|search| search.graph.is_some()) {
        require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    }
    let db = state.db.clone();
    let multi = MultiSearchRequest {
        searches: request.searches,
        fusion: None,
        fused_k: None,
        weights: Vec::new(),
    };
    let scope = perm.tenant_scope(perm.id.clone());
    let response =
        dispatch::dispatch_multi_search(move || db.multi_search_scoped(&collection, multi, &scope))
            .map_err(ApiError::from)?;
    Ok(Json(json!({ "responses": response.results })))
}

#[derive(serde::Deserialize)]
struct BatchSearchRequest {
    searches: Vec<SearchRequest>,
}

/// PB-3: stream search hits as SSE events. Same total search latency as
/// `/search`, but the response headers and first-hit byte go out as soon
/// as the search completes, so high-k callers (k≥100) can start parsing
/// before the whole array materialises in the client.
///
/// Events:
///   - `data: <SearchHit JSON>` — one per hit, in top-k order
///   - `data: {"meta": {"searched": N, "degraded": bool, "elapsed_ms": N}}`
///     after the last hit
///   - `data: done` terminator
async fn search_stream(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<SearchRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, ApiError> {
    if request.graph.is_some() {
        require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    }
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let (tx, rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(128);
    tokio::task::spawn_blocking(
        move || match db.search_scoped(&collection, request, &scope) {
            Ok(response) => {
                for hit in &response.hits {
                    let payload = serde_json::to_string(hit).unwrap_or_else(|_| "{}".to_string());
                    let _ = block_on(tx.send(Ok(Event::default().data(payload))));
                }
                let meta = json!({
                    "meta": {
                        "searched": response.searched,
                        "degraded": response.degraded,
                        "elapsed_ms": response.elapsed_ms,
                    }
                });
                let _ = block_on(tx.send(Ok(Event::default().data(meta.to_string()))));
                let _ = block_on(tx.send(Ok(Event::default().data("done"))));
            }
            Err(error) => {
                let err = json!({ "error": error.to_string() });
                let _ = block_on(tx.send(Ok(Event::default().data(err.to_string()))));
                let _ = block_on(tx.send(Ok(Event::default().data("done"))));
            }
        },
    );
    Ok(Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()))
}

async fn text_hybrid_search(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<crate::TextHybridSearchRequest>,
) -> Result<Json<crate::SearchResponse>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    let response = run_blocking(move || {
        state
            .db
            .text_hybrid_search_scoped(&collection, request, &scope)
    })
    .await?;
    Ok(Json(response))
}

async fn hybrid_search(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<HybridSearchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.graph.is_some() {
        require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    }
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let response =
        run_blocking(move || db.hybrid_search_scoped(&collection, request, &scope)).await?;
    Ok(Json(json!(response)))
}

async fn multi_search(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<MultiSearchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.searches.iter().any(|search| search.graph.is_some()) {
        require_graph_capability(&state.db, &perm, GraphCapability::Read, &collection)?;
    }
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let response =
        run_blocking(move || db.multi_search_scoped(&collection, request, &scope)).await?;
    Ok(Json(json!(response)))
}

async fn recommend(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<RecommendRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let response = run_blocking(move || db.recommend_scoped(&collection, request, &scope)).await?;
    Ok(Json(json!(response)))
}

async fn rerank(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<RerankRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = state.db.clone();
    let scope = perm.tenant_scope(perm.id.clone());
    let response = run_blocking(move || db.rerank_scoped(&collection, request, &scope)).await?;
    Ok(Json(json!(response)))
}

async fn count(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<CountRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    Ok(Json(json!(state.db.count_scoped(
        &collection,
        request.filter,
        &scope
    )?)))
}

async fn index_status(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(json!(state.db.index_status(&collection)?)))
}

async fn scroll(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<ScrollRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    Ok(Json(json!(state.db.scroll_scoped(
        &collection,
        request.offset.as_deref(),
        request.limit,
        request.filter,
        &scope
    )?)))
}

async fn compact(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let resp = state.db.compact_collection(&collection)?;
    state.events.publish(ServerEvent::Compacted {
        collection: collection.clone(),
    });
    Ok(Json(json!(resp)))
}

/// PC-3: build the per-collection (ef_search, recall) calibration curve.
/// Body: `{ "k": usize, "samples": usize }` (both optional; defaults k=10,
/// samples=32). Returns `{ "curve": [[ef_search, recall], ...] }` sorted
/// ascending by ef_search.
async fn calibrate(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    Json(request): Json<CalibrateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = state.db.clone();
    let k = request.k.unwrap_or(10);
    let samples = request.samples.unwrap_or(32);
    let curve = run_blocking(move || db.calibrate_collection(&collection, k, samples)).await?;
    Ok(Json(json!({ "curve": curve })))
}

#[derive(serde::Deserialize, Default)]
struct CalibrateRequest {
    #[serde(default)]
    k: Option<usize>,
    #[serde(default)]
    samples: Option<usize>,
}

async fn tier_cold(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(json!(state.db.tier_collection_to_cold(&collection)?)))
}

async fn prune_wal_archive(
    State(state): State<AppState>,
    Path(collection): Path<String>,
    Json(request): Json<PruneWalArchiveRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(json!(
        state
            .db
            .prune_wal_archive(&collection, request.retain_last)?
    )))
}

async fn snapshot(
    State(state): State<AppState>,
    Json(request): Json<SnapshotRequest>,
) -> Result<Json<StatusResponse>, ApiError> {
    let path = storage_path(&state.storage_policy, &request.path)?;
    state.db.snapshot(&path)?;
    state.events.publish(ServerEvent::Snapshot {
        path: path.display().to_string(),
    });
    Ok(Json(StatusResponse {
        status: "snapshotted".to_string(),
    }))
}

async fn restore(
    State(state): State<AppState>,
    Json(request): Json<RestoreRequest>,
) -> Result<Json<StatusResponse>, ApiError> {
    let path = storage_path(&state.storage_policy, &request.path)?;
    let wal_restore_archive_dir = request
        .wal_restore_archive_dir
        .as_deref()
        .map(|path| storage_path(&state.storage_policy, path))
        .transpose()?;
    let wal_restore_object_store = restore_object_store_config(
        &state.storage_policy,
        request.wal_restore_object_store_dir.as_deref(),
        request.wal_restore_object_store_url.as_deref(),
    )?;
    state.db.restore_to_wal_targets_with_archive_sources(
        &path,
        &request.target_wal_lsns,
        &request.target_wal_unix_ms,
        wal_restore_archive_dir.as_deref(),
        wal_restore_object_store.as_ref(),
    )?;
    state.events.publish(ServerEvent::Restored {
        path: path.display().to_string(),
    });
    Ok(Json(StatusResponse {
        status: "restored".to_string(),
    }))
}

fn restore_object_store_config(
    storage_policy: &StoragePolicy,
    store_dir: Option<&str>,
    store_url: Option<&str>,
) -> Result<Option<ColdObjectStoreConfig>, ApiError> {
    let store_dir = store_dir.filter(|value| !value.is_empty());
    let store_url = store_url.filter(|value| !value.is_empty());
    if store_dir.is_some() && store_url.is_some() {
        return Err(GaussError::InvalidRequest(
            "set only one of wal_restore_object_store_dir or wal_restore_object_store_url"
                .to_string(),
        )
        .into());
    }
    if let Some(url) = store_url {
        let url = storage_policy
            .resolve_url(url)
            .map_err(storage_policy_error)?;
        return Ok(Some(ColdObjectStoreConfig::Url(url)));
    }
    store_dir
        .map(|dir| storage_path(storage_policy, dir).map(ColdObjectStoreConfig::LocalDir))
        .transpose()
}

fn storage_path(policy: &StoragePolicy, path: &str) -> Result<PathBuf, ApiError> {
    policy.resolve_path(path).map_err(storage_policy_error)
}

fn storage_policy_error(error: impl std::fmt::Display) -> ApiError {
    GaussError::InvalidRequest(error.to_string()).into()
}

async fn get_points(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<GetPointsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    let points = state
        .db
        .get_points_scoped(&collection, &request.ids, &scope)?;
    Ok(Json(json!({ "points": points })))
}

async fn set_payload(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<SetPayloadRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    let point = state.db.set_payload_scoped(
        &collection,
        &request.id,
        request.payload,
        request.merge,
        &scope,
    )?;
    Ok(Json(json!({ "point": point })))
}

async fn delete_by_filter(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Path(collection): Path<String>,
    Json(request): Json<DeleteByFilterRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = perm.tenant_scope(perm.id.clone());
    let deleted = state
        .db
        .delete_by_filter_scoped(&collection, &request.filter, &scope)?;
    Ok(Json(json!({ "deleted": deleted })))
}

async fn shard_move(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    state.db.audit_admin_event(
        "shard_move",
        json!({
            "mode": "single_node_noop",
            "transport": "http",
        }),
    )?;
    Ok(Json(json!({
        "status": "accepted",
        "mode": "single_node",
        "message": "single-node shard move is a no-op in this implementation"
    })))
}

// ---------- SSE progress endpoints ----------

fn sse_event(stage: &str, pct: u8) -> Result<Event, std::convert::Infallible> {
    Ok(Event::default().data(json!({ "stage": stage, "pct": pct }).to_string()))
}

fn sse_done(elapsed_ms: u128) -> Result<Event, std::convert::Infallible> {
    Ok(Event::default()
        .event("done")
        .data(json!({ "pct": 100, "elapsed_ms": elapsed_ms }).to_string()))
}

fn sse_error(message: String) -> Result<Event, std::convert::Infallible> {
    Ok(Event::default()
        .event("error")
        .data(json!({ "error": message }).to_string()))
}

fn progress_stream<F>(work: F) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>
where
    F: FnOnce(&mpsc::Sender<(String, u8)>) -> Result<(), GaussError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<(String, u8)>(16);
    let (out_tx, out_rx) = mpsc::channel::<Result<Event, std::convert::Infallible>>(32);
    let started = std::time::Instant::now();

    std::thread::spawn(move || {
        let stage_out = out_tx.clone();
        let forward = std::thread::spawn(move || {
            let mut rx = rx;
            while let Some((stage, pct)) = block_on(rx.recv()) {
                if block_on(stage_out.send(sse_event(&stage, pct))).is_err() {
                    break;
                }
            }
        });
        let result = work(&tx);
        drop(tx);
        let _ = forward.join();
        let elapsed = started.elapsed().as_millis();
        let final_event = match result {
            Ok(()) => sse_done(elapsed),
            Err(error) => sse_error(error.to_string()),
        };
        let _ = block_on(out_tx.send(final_event));
    });

    Sse::new(ReceiverStream::new(out_rx)).keep_alive(KeepAlive::default())
}

async fn compact_stream(
    State(state): State<AppState>,
    Path(collection): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let db = state.db.clone();
    let events = state.events.clone();
    let coll_name = collection.clone();
    progress_stream(move |tx: &mpsc::Sender<(String, u8)>| {
        let _ = block_on(tx.send(("starting".to_string(), 5)));
        let _ = block_on(tx.send(("sealing_wal".to_string(), 20)));
        let _ = block_on(tx.send(("building_index".to_string(), 60)));
        db.compact_collection(&coll_name)?;
        let _ = block_on(tx.send(("writing_segment".to_string(), 95)));
        events.publish(ServerEvent::Compacted {
            collection: coll_name,
        });
        Ok(())
    })
}

async fn snapshot_stream(
    State(state): State<AppState>,
    Json(request): Json<SnapshotRequest>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let db = state.db.clone();
    let events = state.events.clone();
    let path = storage_path(&state.storage_policy, &request.path);
    progress_stream(move |tx: &mpsc::Sender<(String, u8)>| {
        let path = path.map_err(ApiError::into_core)?;
        let _ = block_on(tx.send(("starting".to_string(), 5)));
        let _ = block_on(tx.send(("hardlink_copy".to_string(), 50)));
        db.snapshot(&path)?;
        let _ = block_on(tx.send(("marker_written".to_string(), 95)));
        events.publish(ServerEvent::Snapshot {
            path: path.display().to_string(),
        });
        Ok(())
    })
}

async fn restore_stream(
    State(state): State<AppState>,
    Json(request): Json<RestoreRequest>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let db = state.db.clone();
    let events = state.events.clone();
    let storage_policy = state.storage_policy.clone();
    let path = storage_path(&storage_policy, &request.path);
    let wal_restore_archive_dir = request
        .wal_restore_archive_dir
        .as_deref()
        .map(|path| storage_path(&storage_policy, path))
        .transpose();
    let store_dir = request.wal_restore_object_store_dir.clone();
    let store_url = request.wal_restore_object_store_url.clone();
    let target_lsns = request.target_wal_lsns.clone();
    let target_unix_ms = request.target_wal_unix_ms.clone();
    progress_stream(move |tx: &mpsc::Sender<(String, u8)>| {
        let path = path.map_err(ApiError::into_core)?;
        let wal_restore_archive_dir = wal_restore_archive_dir.map_err(ApiError::into_core)?;
        let _ = block_on(tx.send(("starting".to_string(), 5)));
        let wal_restore_object_store = match restore_object_store_config(
            &storage_policy,
            store_dir.as_deref(),
            store_url.as_deref(),
        ) {
            Ok(value) => value,
            Err(api_error) => return Err(api_error.into_core()),
        };
        let _ = block_on(tx.send(("copying_data".to_string(), 40)));
        db.restore_to_wal_targets_with_archive_sources(
            &path,
            &target_lsns,
            &target_unix_ms,
            wal_restore_archive_dir.as_deref(),
            wal_restore_object_store.as_ref(),
        )?;
        let _ = block_on(tx.send(("wal_replay".to_string(), 95)));
        events.publish(ServerEvent::Restored {
            path: path.display().to_string(),
        });
        Ok(())
    })
}

// ---------- WebSocket endpoints ----------

async fn ws_events(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| ws_events_loop(socket, state.events.clone()))
}

async fn ws_events_loop(mut socket: WebSocket, events: EventHub) {
    let mut rx = events.subscribe();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Ok(event) => {
                    let payload = match serde_json::to_string(&event) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if socket.send(Message::Text(payload.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}

async fn ws_metrics(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| {
        ws_metrics_loop(socket, state.db.clone(), state.ws_metrics_interval)
    })
}

async fn ws_metrics_loop(mut socket: WebSocket, db: Db, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    let handle = observability::init_metrics();
    loop {
        tokio::select! {
            _ = tick.tick() => {
                db.refresh_metrics();
                let snapshot = handle.render();
                let payload = json!({ "metrics": snapshot, "ts_ms": now_ms() }).to_string();
                if socket.send(Message::Text(payload.into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            }
        }
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

// ---------- Error ----------

// ---------------------------------------------------------------------------
// ChironQL
// ---------------------------------------------------------------------------

/// `POST /v1/chironql` - parse and execute one ChironQL statement.
///
/// Goes through the same `chironql_exec::execute` entry point as the embedded
/// console, so the two cannot drift. RBAC and collection scoping come from the
/// caller's `Permission`, exactly as they do for the REST handlers.
///
/// HTTP has no session: `USE` does not persist between requests, so the
/// collection travels in the request body. A `USE` statement is accepted and
/// answers with an empty result, but only a long-lived session (the console)
/// keeps it.
async fn chironql_execute(
    State(state): State<AppState>,
    Extension(perm): Extension<Permission>,
    Json(request): Json<ChironQlRequest>,
) -> Response {
    let db = state.db.clone();
    let mut session = Session {
        collection: request.collection.clone(),
        ..Session::default()
    };
    let mut ctx = ExecContext {
        db: &db,
        session: &mut session,
        role: perm.role,
        allowed_collections: collection_scope(&perm),
        want_trace: request.trace,
        confirm: request.confirm,
        // Built from the authenticated principal. Nothing the caller sent can
        // influence it.
        tenant: perm.tenant_scope(actor_name(&perm)),
    };

    match chironql_exec::execute(&mut ctx, &request.query) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => chironql_error_response(error),
    }
}

/// `POST /v1/chironql/parse` - validate without executing.
///
/// The UI workspace shows a generated query before running it; checking that
/// query is a parse, not an execution. Without this endpoint the UI would have
/// to reimplement the grammar in TypeScript, which is the outcome the
/// server-side parser exists to prevent. Nothing here touches `Db`.
async fn chironql_parse(Json(request): Json<ChironQlRequest>) -> Response {
    match crate::chironql_parser::parse(&request.query) {
        Ok(statement) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "kind": match statement.class() {
                    crate::chironql_parser::StatementClass::Read => "read",
                    crate::chironql_parser::StatementClass::Write => "write",
                    crate::chironql_parser::StatementClass::Admin => "admin",
                },
                "statement": statement.kind_name(),
                "collection": statement.collection(),
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": error.message,
                "code": error.code,
                "hint": error.hint,
                "position": error.position,
            })),
        )
            .into_response(),
    }
}

/// A stable, non-secret name for the audit record. The tenant identifies the
/// principal; the key value itself never appears in a log.
fn actor_name(perm: &Permission) -> String {
    perm.id.clone()
}

/// The collections this key may touch, or `None` when unrestricted.
fn collection_scope(perm: &Permission) -> Option<HashSet<String>> {
    if !perm.is_restricted() {
        return None;
    }
    Some(perm.allowed_collections().into_iter().collect())
}

/// ChironQL errors carry their own envelope - code, hint, caret position and
/// the trace up to the failing stage - so they do not go through `ApiError`,
/// which is shaped for `GaussError`.
fn chironql_error_response(error: ChironQlError) -> Response {
    let status = match error.code.as_str() {
        "chironql.permission_denied" => StatusCode::FORBIDDEN,
        "chironql.collection_not_found"
        | "chironql.collection_forbidden"
        | "chironql.point_not_found"
        | "chironql.vector_not_found"
        | "graph.endpoint_not_found"
        | "graph.edge_not_found"
        | "graph.type_unknown"
        | "graph.deferred_session_not_found" => StatusCode::NOT_FOUND,
        "chironql.not_implemented" => StatusCode::NOT_IMPLEMENTED,
        // The statement is well-formed and allowed; it is waiting on a
        // decision only the caller can make. 409 is the honest code for that.
        "chironql.confirmation_required" => StatusCode::CONFLICT,
        "chironql.storage_corruption" | "chironql.io_error" | "chironql.engine_error" => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        "chironql.resource_exhausted" => StatusCode::INSUFFICIENT_STORAGE,
        "graph.overloaded" => StatusCode::TOO_MANY_REQUESTS,
        "chironql.storage_unavailable" | "graph.slo_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        // Everything else is a parse reject or a bad request: the caller's text
        // is wrong, and the body says exactly where.
        _ => StatusCode::BAD_REQUEST,
    };
    tracing::warn!(
        status = status.as_u16(),
        code = %error.code,
        query_id = %error.query_id,
        error = %error.error,
        "chironql statement failed"
    );
    (status, Json(error)).into_response()
}

#[derive(Debug)]
enum ApiError {
    Core(GaussError),
    GraphForbidden(String),
}

impl ApiError {
    fn graph_forbidden(message: impl Into<String>) -> Self {
        Self::GraphForbidden(message.into())
    }

    fn into_core(self) -> GaussError {
        match self {
            Self::Core(error) => error,
            Self::GraphForbidden(message) => GaussError::InvalidRequest(message),
        }
    }
}

impl From<GaussError> for ApiError {
    fn from(value: GaussError) -> Self {
        Self::Core(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = match self {
            Self::Core(error) => error,
            Self::GraphForbidden(message) => {
                tracing::warn!(
                    status = StatusCode::FORBIDDEN.as_u16(),
                    code = "graph.permission_denied",
                    error = %message,
                    "graph request denied"
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "forbidden",
                        "code": "graph.permission_denied",
                        "message": message,
                    })),
                )
                    .into_response();
            }
        };
        let status = match &error {
            GaussError::CollectionNotFound(_) | GaussError::PointNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            GaussError::CollectionExists(_)
            | GaussError::DimensionMismatch { .. }
            | GaussError::InvalidCollectionName(_)
            | GaussError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            GaussError::Graph(error) => graph_http_status(error.code),
            GaussError::ResourceExhausted(_) => StatusCode::INSUFFICIENT_STORAGE,
            GaussError::WalUnavailable(_)
            | GaussError::AuditUnavailable(_)
            | GaussError::DataDirLocked { .. } => StatusCode::SERVICE_UNAVAILABLE,
            GaussError::WalCorruption { .. }
            | GaussError::SegmentCorruption { .. }
            | GaussError::Io(_)
            | GaussError::Json(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        tracing::warn!(status = status.as_u16(), error = %error, "request failed");
        let body = match &error {
            GaussError::Graph(graph) => Json(json!({
                "error": graph.to_string(),
                "code": graph.code.as_str(),
                "message": graph.message,
                "item_index": graph.item_index,
                "retry_after_ms": graph.retry_after_ms,
            })),
            _ => Json(json!({ "error": error.to_string() })),
        };
        (status, body).into_response()
    }
}

fn graph_http_status(code: chirondb_types::graph::GraphErrorCode) -> StatusCode {
    use chirondb_types::graph::GraphErrorCode;

    match code {
        GraphErrorCode::EndpointNotFound
        | GraphErrorCode::EdgeNotFound
        | GraphErrorCode::TypeNotFound
        | GraphErrorCode::DeferredSessionNotFound => StatusCode::NOT_FOUND,
        GraphErrorCode::Overloaded => StatusCode::TOO_MANY_REQUESTS,
        GraphErrorCode::Cancelled => StatusCode::REQUEST_TIMEOUT,
        GraphErrorCode::SloUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        GraphErrorCode::GraphDisabled
        | GraphErrorCode::EpochMismatch
        | GraphErrorCode::TooManyAnchors
        | GraphErrorCode::TooManyTypes
        | GraphErrorCode::BatchTooLarge
        | GraphErrorCode::DepthExceeded
        | GraphErrorCode::PropertyTooLarge
        | GraphErrorCode::BatchBytesExceeded
        | GraphErrorCode::InvalidBudget
        | GraphErrorCode::TenantMoveHasEdges
        | GraphErrorCode::EdgesExist
        | GraphErrorCode::DeferredEndpointsRemain
        | GraphErrorCode::AllocatorExhausted => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::ApiError;
    use crate::{GaussError, GraphError, GraphErrorCode};

    #[test]
    fn resource_exhaustion_maps_to_http_507() {
        let response =
            ApiError::from(GaussError::ResourceExhausted("retry".into())).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INSUFFICIENT_STORAGE
        );
    }

    #[test]
    fn data_directory_lock_maps_to_http_503() {
        let response = ApiError::from(GaussError::DataDirLocked {
            path: "/data/chirondb".into(),
            owner: None,
        })
        .into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn graph_errors_are_not_reported_as_internal_failures() {
        let response = ApiError::from(GaussError::from(GraphError::new(
            GraphErrorCode::GraphDisabled,
            "graph is disabled",
        )))
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
