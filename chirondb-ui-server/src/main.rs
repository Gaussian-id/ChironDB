use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::Message as TgMessage};
use uuid::Uuid;

mod static_assets;

#[derive(Debug, Parser)]
#[command(version, about = "Preview BFF + UI for ChironDB")]
struct Args {
    #[arg(long, env = "BIND_ADDR", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    #[arg(long, env = "GAUSSDB_URL", default_value = "http://127.0.0.1:7401")]
    gaussdb_url: String,
    #[arg(long, env = "GAUSSDB_API_KEY", default_value = "")]
    gaussdb_api_key: String,
    #[arg(long, env = "UI_USERNAME", default_value = "admin")]
    username: String,
    #[arg(long, env = "UI_PASSWORD", default_value = "admin")]
    password: String,
    /// Session TTL in seconds.
    #[arg(long, env = "SESSION_TTL_SECS", default_value_t = 8 * 3600)]
    session_ttl_secs: u64,
}

#[derive(Clone)]
struct AppState {
    upstream_http: String,
    upstream_ws: String,
    api_key: String,
    username: String,
    password_hash: String,
    sessions: Arc<RwLock<HashMap<String, u64>>>,
    session_ttl_secs: u64,
    http: reqwest::Client,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn upstream_ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        http_url.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let upstream_http = args.gaussdb_url.trim_end_matches('/').to_string();
    let upstream_ws = upstream_ws_url(&upstream_http);

    let state = AppState {
        upstream_http,
        upstream_ws,
        api_key: args.gaussdb_api_key,
        username: args.username,
        password_hash: hash_password(&args.password),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        session_ttl_secs: args.session_ttl_secs,
        http: reqwest::Client::builder()
            .user_agent("chirondb-ui-server/0.1")
            .build()
            .context("failed to build reqwest client")?,
    };

    let api_routes = Router::new()
        .route("/api/ws/{*path}", get(ws_proxy))
        .route("/api/{*path}", any(api_proxy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/", get(index))
        .merge(api_routes)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "chirondb-ui-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    ok: bool,
}

async fn login_page() -> Html<&'static str> {
    Html(static_assets::LOGIN_HTML)
}

async fn login(State(state): State<AppState>, Json(form): Json<LoginForm>) -> Response {
    if form.username != state.username || hash_password(&form.password) != state.password_hash {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
            .into_response();
    }
    let token = Uuid::new_v4().to_string();
    let expires = now_secs() + state.session_ttl_secs;
    state.sessions.write().await.insert(token.clone(), expires);

    let cookie = format!(
        "session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        token, state.session_ttl_secs
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie header value"),
    );
    (StatusCode::OK, headers, Json(LoginResponse { ok: true })).into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_session(&headers) {
        state.sessions.write().await.remove(&token);
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"),
    );
    (
        StatusCode::OK,
        response_headers,
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}

async fn index(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if let Some(token) = extract_session(&headers) {
        let sessions = state.sessions.read().await;
        if let Some(exp) = sessions.get(&token)
            && *exp > now_secs()
        {
            return Html(static_assets::INDEX_HTML).into_response();
        }
    }
    Redirect::to("/login").into_response()
}

fn extract_session(headers: &HeaderMap) -> Option<String> {
    headers.get(header::COOKIE).and_then(|raw| {
        let value = raw.to_str().ok()?;
        value
            .split(';')
            .filter_map(|kv| {
                let (k, v) = kv.trim().split_once('=')?;
                (k == "session").then(|| v.to_string())
            })
            .next()
    })
}

async fn require_session(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let token = extract_session(req.headers());
    let valid = if let Some(token) = token.as_ref() {
        let sessions = state.sessions.read().await;
        sessions
            .get(token)
            .map(|exp| *exp > now_secs())
            .unwrap_or(false)
    } else {
        false
    };
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "no session"})),
        )
            .into_response();
    }
    next.run(req).await
}

async fn api_proxy(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let mut url = format!(
        "{}/v1/{}",
        state.upstream_http,
        path.trim_start_matches('/')
    );
    if !query.is_empty() {
        let qs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }

    let mut req = state.http.request(method, &url);
    for (k, v) in headers.iter() {
        let name = k.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "host"
                | "cookie"
                | "content-length"
                | "authorization"
                | "x-gaussdb-api-key"
                | "connection"
        ) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(k.as_ref()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            req = req.header(name, value);
        }
    }
    if !state.api_key.is_empty() {
        req = req.header("x-gaussdb-api-key", state.api_key.as_str());
    }
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let mut out_headers = HeaderMap::new();
            for (k, v) in resp.headers().iter() {
                let lower = k.as_str().to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "content-length" | "transfer-encoding" | "connection"
                ) {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(k.as_ref()),
                    axum::http::HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    out_headers.insert(name, value);
                }
            }
            let body_stream = resp.bytes_stream();
            let body = Body::from_stream(body_stream);
            (
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                out_headers,
                body,
            )
                .into_response()
        }
        Err(error) => {
            tracing::warn!(%error, url=%url, "upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("upstream error: {error}")})),
            )
                .into_response()
        }
    }
}

fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn ws_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let upstream = format!("{}/ws/{}", state.upstream_ws, path.trim_start_matches('/'));
    let api_key = state.api_key.clone();
    ws.on_upgrade(move |socket| ws_bridge(socket, upstream, api_key))
}

async fn ws_bridge(client: WebSocket, upstream: String, api_key: String) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let req = match upstream.into_client_request() {
        Ok(mut r) => {
            if !api_key.is_empty()
                && let Ok(value) = HeaderValue::from_str(&api_key)
            {
                r.headers_mut().insert("x-gaussdb-api-key", value);
            }
            r
        }
        Err(error) => {
            tracing::warn!(%error, "invalid upstream ws url");
            return;
        }
    };
    let (upstream_ws, _) = match connect_async(req).await {
        Ok(pair) => pair,
        Err(error) => {
            tracing::warn!(%error, "upstream ws connect failed");
            return;
        }
    };
    let (mut up_sink, mut up_stream) = upstream_ws.split();
    let (mut client_sink, mut client_stream) = client.split();
    let client_to_up = async {
        while let Some(Ok(msg)) = client_stream.next().await {
            let out = match msg {
                Message::Text(t) => TgMessage::Text(t.to_string().into()),
                Message::Binary(b) => TgMessage::Binary(b),
                Message::Ping(p) => TgMessage::Ping(p),
                Message::Pong(p) => TgMessage::Pong(p),
                Message::Close(_) => TgMessage::Close(None),
            };
            if up_sink.send(out).await.is_err() {
                break;
            }
        }
    };
    let up_to_client = async {
        while let Some(Ok(msg)) = up_stream.next().await {
            let out = match msg {
                TgMessage::Text(t) => Message::Text(t.to_string().into()),
                TgMessage::Binary(b) => Message::Binary(b),
                TgMessage::Ping(p) => Message::Ping(p),
                TgMessage::Pong(p) => Message::Pong(p),
                TgMessage::Close(_) => Message::Close(None),
                TgMessage::Frame(_) => continue,
            };
            if client_sink.send(out).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = client_to_up => {},
        _ = up_to_client => {},
    }
}
