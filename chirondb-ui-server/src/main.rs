use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Extension, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use security::{Session, Sessions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message as TgMessage};

mod security;
mod static_assets;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Parser)]
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
    #[arg(long, env = "UI_PASSWORD")]
    password: String,
    /// Session TTL in seconds.
    #[arg(long, env = "SESSION_TTL_SECS", default_value_t = 8 * 3600)]
    session_ttl_secs: u64,
    /// Exact local browser origin; set https://... for a local TLS terminator.
    #[arg(long, env = "UI_BROWSER_ORIGIN")]
    browser_origin: Option<String>,
}

#[derive(Clone)]
struct AppState {
    upstream_http: String,
    upstream_ws: String,
    api_key: String,
    username: String,
    password_hash: String,
    sessions: Arc<Sessions>,
    browser_origin: String,
    secure_cookie: bool,
    work: Arc<Semaphore>,
    session_ttl_secs: u64,
    http: reqwest::Client,
}

#[derive(Clone)]
struct ActiveSession {
    session: Arc<Session>,
    _permit: Arc<OwnedSemaphorePermit>,
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn upstream_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("chirondb-ui-server/0.1")
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build upstream client")
}

fn loopback_host(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn validate_args(args: &Args) -> Result<()> {
    anyhow::ensure!(
        args.bind.ip().is_loopback(),
        "preview BFF must bind a loopback address"
    );
    anyhow::ensure!(
        args.password.len() >= 16
            && !matches!(args.password.as_str(), "admin" | "password" | "changeme"),
        "set a non-default UI_PASSWORD of at least 16 bytes"
    );
    anyhow::ensure!(
        !args.username.is_empty() && !args.gaussdb_api_key.is_empty(),
        "configure the local operator and its upstream credential"
    );
    anyhow::ensure!(
        (60..=8 * 3600).contains(&args.session_ttl_secs),
        "session TTL must be 60..=28800 seconds"
    );
    let upstream = reqwest::Url::parse(&args.gaussdb_url).context("invalid upstream URL")?;
    anyhow::ensure!(
        (upstream.scheme() == "https" || (upstream.scheme() == "http" && loopback_host(&upstream)))
            && upstream.username().is_empty()
            && upstream.password().is_none()
            && upstream.query().is_none()
            && upstream.fragment().is_none()
            && upstream.path() == "/",
        "upstream must be a credential-free HTTPS origin or loopback HTTP origin"
    );
    if let Some(origin) = &args.browser_origin {
        let url = reqwest::Url::parse(origin).context("invalid browser origin")?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https")
                && loopback_host(&url)
                && url.origin().ascii_serialization() == *origin,
            "browser origin must be an exact loopback HTTP/HTTPS origin without path or credentials"
        );
    }
    Ok(())
}

fn is_mutation(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

fn nominated_hop_header(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(header::CONNECTION).iter().any(|value| {
        value.to_str().ok().is_none_or(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(name))
        })
    })
}

fn valid_csrf(headers: &HeaderMap, session: &Session) -> bool {
    single_header(headers, "x-chirondb-csrf")
        .is_some_and(|value| bool::from(value.as_bytes().ct_eq(session.csrf.as_bytes())))
}

fn session_cookie(token: &str, max_age: u64, secure: bool) -> String {
    format!(
        "session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

async fn browser_guard(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let expected_host = state.browser_origin.split_once("://").map(|(_, host)| host);
    if single_header(req.headers(), "host") != expected_host {
        return StatusCode::FORBIDDEN.into_response();
    }
    let supplied_origin = single_header(req.headers(), "origin");
    let needs_origin = is_mutation(req.method()) || req.headers().contains_key(header::UPGRADE);
    if (needs_origin && supplied_origin != Some(state.browser_origin.as_str()))
        || (req.headers().contains_key("origin")
            && supplied_origin != Some(state.browser_origin.as_str()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let _preauth_permit = if req.uri().path() == "/login" {
        if is_mutation(req.method()) && !state.sessions.admit_login().await {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        match state.work.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        }
    } else {
        None
    };
    let Ok(mut response) = tokio::time::timeout(Duration::from_secs(30), next.run(req)).await
    else {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

fn upstream_path(base: &str, prefix: &str, path: &str) -> Option<String> {
    if path.len() > 8192
        || path.split('/').any(|part| {
            part.is_empty() || matches!(part, "." | "..") || part.contains(['\\', '\0'])
        })
    {
        return None;
    }
    let mut url = reqwest::Url::parse(base).ok()?;
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .push(prefix)
        .extend(path.split('/'));
    Some(url.to_string())
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
    validate_args(&args)?;
    let browser_origin = args
        .browser_origin
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.bind));
    let secure_cookie = browser_origin.starts_with("https://");
    let upstream_http = args.gaussdb_url.trim_end_matches('/').to_string();
    let upstream_ws = upstream_ws_url(&upstream_http);

    let state = AppState {
        upstream_http,
        upstream_ws,
        api_key: args.gaussdb_api_key,
        username: args.username,
        password_hash: hash_password(&args.password),
        sessions: Arc::new(Sessions::default()),
        session_ttl_secs: args.session_ttl_secs,
        browser_origin,
        secure_cookie,
        work: Arc::new(Semaphore::new(32)),
        http: upstream_client()?,
    };

    let app = application(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(bind = %args.bind, "chirondb-ui-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn application(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/api/ws/{*path}", get(ws_proxy))
        .route("/api/{*path}", any(api_proxy))
        .route("/session", get(session_info))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/login",
            get(login_page)
                .post(login)
                .layer(DefaultBodyLimit::max(8192)),
        )
        .route("/logout", post(logout))
        .route("/", get(index))
        .merge(api_routes)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), browser_guard))
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    ok: bool,
    csrf_token: String,
}

async fn login_page() -> Html<&'static str> {
    Html(static_assets::LOGIN_HTML)
}

async fn login(State(state): State<AppState>, Json(form): Json<LoginForm>) -> Response {
    if form.username != state.username
        || !bool::from(
            hash_password(&form.password)
                .as_bytes()
                .ct_eq(state.password_hash.as_bytes()),
        )
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"invalid credentials"})),
        )
            .into_response();
    }
    let Some((token, session)) = state
        .sessions
        .create(Duration::from_secs(state.session_ttl_secs))
        .await
    else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &token,
            state.session_ttl_secs,
            state.secure_cookie,
        ))
        .expect("generated cookie"),
    );
    (
        StatusCode::OK,
        headers,
        Json(LoginResponse {
            ok: true,
            csrf_token: session.csrf.clone(),
        }),
    )
        .into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = extract_session(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(session) = state.sessions.get(&token).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !valid_csrf(&headers, &session) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let drained = state.sessions.revoke(&token).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie("", 0, state.secure_cookie))
            .expect("generated cookie"),
    );
    (
        if drained {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        headers,
        Json(serde_json::json!({"ok":drained})),
    )
        .into_response()
}

async fn session_info(Extension(active): Extension<ActiveSession>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"csrf_token": active.session.csrf}))
}

async fn index(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if let Some(token) = extract_session(&headers)
        && state.sessions.get(&token).await.is_some()
    {
        return Html(static_assets::INDEX_HTML).into_response();
    }
    Redirect::to("/login").into_response()
}

fn extract_session(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for raw in headers.get_all(header::COOKIE) {
        for entry in raw.to_str().ok()?.split(';') {
            let Some((key, value)) = entry.trim().split_once('=') else {
                continue;
            };
            if key == "session" {
                if found.is_some() || value.len() != 64 {
                    return None;
                }
                found = Some(value.to_string());
            }
        }
    }
    found
}

async fn require_session(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_session(req.headers()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(session) = state.sessions.get(&token).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if is_mutation(req.method()) && !valid_csrf(req.headers(), &session) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = state.work.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let active = ActiveSession {
        session,
        _permit: Arc::new(permit),
    };
    req.extensions_mut().insert(active.clone());
    let Some(response) = active.session.run(next.run(req)).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, guarded_body(body, active))
}

fn guarded_body(body: Body, active: ActiveSession) -> Body {
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), active, MAX_BODY_BYTES),
        |(mut stream, active, remaining)| async move {
            let item = active.session.run(stream.next()).await.flatten()?;
            let size = item.as_ref().map(|bytes| bytes.len()).unwrap_or(0);
            if size > remaining {
                return None;
            }
            Some((item, (stream, active, remaining - size)))
        },
    );
    Body::from_stream(stream)
}

async fn api_proxy(
    State(state): State<AppState>,
    Extension(active): Extension<ActiveSession>,
    method: Method,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(mut url) = upstream_path(&state.upstream_http, "v1", &path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !query.is_empty() {
        let qs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }

    let mut req = state.http.request(method, &url);
    // Explicit forwarding vocabulary also strips future credential aliases,
    // Connection-nominated hop headers, cookies and all identity headers.
    for name in [
        "accept",
        "content-type",
        "if-match",
        "if-none-match",
        "idempotency-key",
    ] {
        if nominated_hop_header(&headers, name) {
            continue;
        }
        if let Some(value) = headers.get(name) {
            req = req.header(name, value);
        }
    }
    if !state.api_key.is_empty() {
        req = req.header("x-gaussdb-api-key", state.api_key.as_str());
    }
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    let Some(result) = active.session.run(req.send()).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match result {
        Ok(resp) => {
            let status = resp.status();
            let mut out_headers = HeaderMap::new();
            for name in ["content-type", "etag"] {
                if nominated_hop_header(resp.headers(), name) {
                    continue;
                }
                if let Some(value) = resp.headers().get(name) {
                    out_headers.insert(name, value.clone());
                }
            }
            out_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            let body_stream = resp.bytes_stream();
            let body = guarded_body(Body::from_stream(body_stream), active);
            (
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                out_headers,
                body,
            )
                .into_response()
        }
        Err(_) => {
            tracing::warn!("upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "upstream unavailable"})),
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
    Extension(active): Extension<ActiveSession>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(upstream) = upstream_path(&state.upstream_ws, "ws", &path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let api_key = state.api_key.clone();
    ws.max_message_size(MAX_BODY_BYTES)
        .max_frame_size(MAX_BODY_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = active._permit;
            active
                .session
                .run(ws_bridge(socket, upstream, api_key))
                .await;
        })
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
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_BODY_BYTES))
        .max_frame_size(Some(MAX_BODY_BYTES))
        .max_write_buffer_size(MAX_BODY_BYTES * 2);
    let (upstream_ws, _) = match tokio::time::timeout(
        Duration::from_secs(3),
        connect_async_with_config(req, Some(config), false),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => {
            tracing::warn!("upstream ws connect failed");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(origin: &str) -> AppState {
        AppState {
            upstream_http: origin.into(),
            upstream_ws: upstream_ws_url(origin),
            api_key: "configured-operator-secret".into(), // Synthetic example credential for an isolated proxy test.
            username: "operator".into(),
            password_hash: hash_password("local-operator-test"),
            sessions: Arc::new(Sessions::default()),
            session_ttl_secs: 60,
            browser_origin: origin.into(),
            secure_cookie: false,
            work: Arc::new(Semaphore::new(32)),
            http: upstream_client().unwrap(),
        }
    }

    #[tokio::test]
    async fn browser_routes_require_host_origin_csrf_and_revoke_cookie_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = application(state(&origin));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let credentials =
            serde_json::json!({"username":"operator", "password":"local-operator-test"});
        assert_eq!(
            client
                .get(&origin)
                .header("host", "attacker.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{origin}/login"))
                .header("content-type", "application/json")
                .body(credentials.to_string())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{origin}/login"))
                .header("origin", "http://attacker.example")
                .header("content-type", "application/json")
                .body(credentials.to_string())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = client
            .post(format!("{origin}/login"))
            .header("origin", &origin)
            .header("content-type", "application/json")
            .body(credentials.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie_header = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie_header.contains("HttpOnly; SameSite=Strict"));
        let cookie = cookie_header.split(';').next().unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();
        assert_eq!(
            client
                .get(format!("{origin}/session"))
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            client
                .post(format!("{origin}/logout"))
                .header("origin", &origin)
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .post(format!("{origin}/logout"))
                .header("origin", &origin)
                .header("cookie", cookie)
                .header("x-chirondb-csrf", csrf)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            client
                .get(format!("{origin}/session"))
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        server.abort();
    }

    #[test]
    fn operator_configuration_and_upstream_paths_are_closed_by_default() {
        let mut args = Args {
            bind: "127.0.0.1:8080".parse().unwrap(),
            gaussdb_url: "http://127.0.0.1:7401".into(),
            gaussdb_api_key: "configured-key".into(),
            username: "operator".into(),
            password: "local-operator-test".into(),
            session_ttl_secs: 60,
            browser_origin: None,
        };
        validate_args(&args).unwrap();
        args.bind = "0.0.0.0:8080".parse().unwrap();
        assert!(validate_args(&args).is_err());
        args.bind = "127.0.0.1:8080".parse().unwrap();
        args.password = "admin".into();
        assert!(validate_args(&args).is_err());
        args.password = "local-operator-test".into();
        args.gaussdb_url = "http://remote.example".into();
        assert!(validate_args(&args).is_err());
        assert!(session_cookie("synthetic", 60, true).ends_with("; Secure"));
        for path in ["../admin", "a/../admin", "/admin", "a//b", "a\\b"] {
            assert!(upstream_path("http://127.0.0.1", "v1", path).is_none());
        }
        assert_eq!(
            upstream_path("http://127.0.0.1", "v1", "collections/a?b").unwrap(),
            "http://127.0.0.1/v1/collections/a%3Fb"
        );
        let mut cookies = HeaderMap::new();
        cookies.insert(
            "cookie",
            HeaderValue::from_str(&format!(
                "session={}; session={}",
                "a".repeat(64),
                "b".repeat(64)
            ))
            .unwrap(),
        );
        assert!(extract_session(&cookies).is_none());
    }

    #[tokio::test]
    async fn configured_http_client_does_not_follow_upstream_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let followed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = followed.clone();
        let app = Router::new()
            .route(
                "/redirect",
                get(|| async { Redirect::temporary("/credential-sink") }),
            )
            .route(
                "/credential-sink",
                get(move || async move {
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                    "unexpected"
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = upstream_client()
            .unwrap()
            .get(format!("{origin}/redirect"))
            .header("x-gaussdb-api-key", "synthetic-secret")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_redirection());
        assert!(!followed.load(std::sync::atomic::Ordering::SeqCst));
        server.abort();
    }

    #[tokio::test]
    async fn logout_closes_a_live_websocket_and_releases_its_permit() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
        let upstream_app = Router::new().route(
            "/ws/echo",
            get(|ws: WebSocketUpgrade| async {
                ws.on_upgrade(|mut socket| async move {
                    socket
                        .send(Message::Text("connected".into()))
                        .await
                        .unwrap();
                    while socket.recv().await.is_some() {}
                })
            }),
        );
        let upstream_server =
            tokio::spawn(async move { axum::serve(upstream, upstream_app).await.unwrap() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let mut shared = state(&origin);
        shared.upstream_http = upstream_origin.clone();
        shared.upstream_ws = upstream_ws_url(&upstream_origin);
        let (token, session) = shared
            .sessions
            .create(Duration::from_secs(60))
            .await
            .unwrap();
        let csrf = session.csrf.clone();
        let inspected = shared.clone();
        let server =
            tokio::spawn(async move { axum::serve(listener, application(shared)).await.unwrap() });
        let cookie = format!("session={token}");
        let mut request = format!("{}/api/ws/echo", upstream_ws_url(&origin))
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", HeaderValue::from_str(&origin).unwrap());
        request
            .headers_mut()
            .insert("cookie", HeaderValue::from_str(&cookie).unwrap());
        let (mut socket, _) = connect_async_with_config(request, None, false)
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "connected"
        );
        assert!(inspected.work.available_permits() < 32);
        let response = reqwest::Client::new()
            .post(format!("{origin}/logout"))
            .header("origin", &origin)
            .header("cookie", &cookie)
            .header("x-chirondb-csrf", csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let received = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap();
        assert!(!matches!(
            received,
            Some(Ok(TgMessage::Text(_) | TgMessage::Binary(_)))
        ));
        assert_eq!(inspected.work.available_permits(), 32);
        server.abort();
        upstream_server.abort();
    }

    #[tokio::test]
    async fn proxy_replaces_all_credential_aliases_and_forwarded_identity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/v1/echo", get(|headers: HeaderMap| async move {
            Json(serde_json::json!({
                "chiron": headers.get("x-chirondb-api-key").and_then(|value| value.to_str().ok()),
                "gauss": headers.get("x-gaussdb-api-key").and_then(|value| value.to_str().ok()),
                "authorization": headers.get("authorization").and_then(|value| value.to_str().ok()),
                "identity": headers.get("x-forwarded-user").and_then(|value| value.to_str().ok()),
            }))
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = AppState {
            upstream_http: format!("http://{address}"),
            upstream_ws: format!("ws://{address}"),
            api_key: "configured-operator-secret".into(), // Synthetic example credential for an isolated proxy test.
            username: "operator".into(),
            password_hash: hash_password("local-operator-test"),
            sessions: Arc::new(Sessions::default()),
            session_ttl_secs: 60,
            browser_origin: format!("http://{address}"),
            secure_cookie: false,
            work: Arc::new(Semaphore::new(32)),
            http: upstream_client().unwrap(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-chirondb-api-key",
            HeaderValue::from_static("attacker-secret"),
        );
        headers.insert(
            "x-gaussdb-api-key",
            HeaderValue::from_static("attacker-secret"),
        );
        headers.insert("authorization", HeaderValue::from_static("Bearer attacker"));
        headers.insert(
            "x-forwarded-user",
            HeaderValue::from_static("administrator"),
        );
        let (_, session) = state
            .sessions
            .create(Duration::from_secs(60))
            .await
            .unwrap();
        let active = ActiveSession {
            session,
            _permit: Arc::new(state.work.clone().acquire_owned().await.unwrap()),
        };
        let response = api_proxy(
            State(state),
            Extension(active),
            Method::GET,
            Path("echo".into()),
            Query(HashMap::new()),
            headers,
            axum::body::Bytes::new(),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        server.abort();
        assert!(
            observed["chiron"].is_null() || observed["chiron"] == "configured-operator-secret",
            "forwarded attacker credential: {observed}"
        );
        assert!(observed["authorization"].is_null());
        assert!(observed["identity"].is_null());
        assert_eq!(observed["gauss"], "configured-operator-secret");
    }
}
