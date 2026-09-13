use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;
use tonic::{Request as GrpcRequest, Status, service::Interceptor};

use crate::{
    Db,
    rbac::{Action, Permission, RbacConfig, authorize},
};

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    keyring: Option<Arc<Keyring>>,
    rate_limiter: Option<RateLimiter>,
    rbac: Option<Arc<RbacConfig>>,
    work_limiter: WorkLimiter,
}

impl AuthConfig {
    pub fn disabled() -> Self {
        Self {
            keyring: None,
            rate_limiter: None,
            rbac: None,
            work_limiter: WorkLimiter::default(),
        }
    }

    pub fn from_optional_key(api_key: Option<String>) -> Self {
        Self::from_key_sources(api_key, None)
    }

    pub fn from_key_sources(api_key: Option<String>, api_key_file: Option<PathBuf>) -> Self {
        let keys = parse_keys(api_key.as_deref());
        let keyring = (!keys.is_empty() || api_key_file.is_some()).then(|| {
            Arc::new(Keyring {
                static_keys: keys,
                file: api_key_file,
            })
        });
        Self {
            keyring,
            rate_limiter: None,
            rbac: None,
            work_limiter: WorkLimiter::default(),
        }
    }

    /// Attach an RBAC config that enforces per-key roles and collection access.
    pub fn with_rbac(mut self, rbac: RbacConfig) -> Self {
        self.rbac = Some(Arc::new(rbac));
        self
    }

    pub fn with_validated_rbac(
        mut self,
        rbac: RbacConfig,
        require_ids: bool,
    ) -> Result<Self, String> {
        rbac.validate(require_ids)?;
        let accepted = self.accepted_keys();
        if accepted.is_empty() {
            return Err("RBAC requires an API key source".to_string());
        }
        for key in &accepted {
            if rbac.find_key(key).is_none() {
                return Err(
                    "API keyring contains a key without a matching RBAC principal".to_string(),
                );
            }
        }
        for entry in &rbac.keys {
            if !accepted.iter().any(|key| constant_time_eq(key, &entry.key)) {
                return Err(format!(
                    "RBAC principal {:?} has no matching key in the API keyring",
                    entry.id
                ));
            }
        }
        if !require_ids {
            for entry in &rbac.keys {
                if entry.id.is_none() {
                    tracing::warn!(
                        principal = %Permission::from_entry(entry).id,
                        "RBAC entry has no stable id; using a compatibility fingerprint"
                    );
                }
            }
        }
        self.rbac = Some(Arc::new(rbac));
        Ok(self)
    }

    /// Returns the `Permission` for the authenticated principal, or `None` if
    /// the key is not accepted.  When RBAC is disabled every accepted key gets
    /// unrestricted admin permission.
    pub fn permission_for(&self, candidate: Option<&str>) -> Option<Permission> {
        if !self.accepts(candidate) {
            return None;
        }
        match self.rbac.as_deref() {
            Some(rbac) => {
                let key = candidate?;
                rbac.find_key(key).map(Permission::from_entry)
            }
            None => Some(Permission::unrestricted_for(principal_key(candidate))),
        }
    }

    /// Returns the resolved `Permission` for `key`.  When RBAC is disabled or
    /// the key has no explicit RBAC entry, returns `Permission::unrestricted()`.
    /// This always succeeds (the key has already been authenticated upstream).
    pub fn permission_for_request(&self, key: Option<&str>) -> Option<Permission> {
        self.permission_for(key)
    }

    /// Returns `true` if `candidate` may perform `operation` on `collection`.
    ///
    /// When RBAC is disabled, all accepted keys are treated as unrestricted.
    pub fn check_access(
        &self,
        candidate: Option<&str>,
        operation: Action,
        collection: Option<&str>,
    ) -> bool {
        if !self.accepts(candidate) {
            return false;
        }
        self.permission_for(candidate)
            .is_some_and(|principal| authorize(&principal, operation, collection).is_ok())
    }

    pub fn has_rbac(&self) -> bool {
        self.rbac.is_some()
    }

    pub fn is_enabled(&self) -> bool {
        self.keyring.is_some()
    }

    pub fn with_rate_limit(mut self, requests_per_second: Option<u32>) -> Self {
        self.rate_limiter = requests_per_second
            .filter(|limit| *limit > 0)
            .map(RateLimiter::new);
        self
    }

    pub fn rate_limit_enabled(&self) -> bool {
        self.rate_limiter.is_some()
    }

    pub fn accepts(&self, candidate: Option<&str>) -> bool {
        let Some(keyring) = &self.keyring else {
            return true;
        };
        let Some(candidate) = candidate else {
            return false;
        };
        keyring.accepts(candidate)
    }

    pub fn allows_request(&self, candidate: Option<&str>) -> bool {
        let Some(principal) = self.permission_for(candidate) else {
            return false;
        };
        self.allows_principal_request(&principal)
    }

    pub fn allows_principal_request(&self, principal: &Permission) -> bool {
        let Some(rate_limiter) = &self.rate_limiter else {
            return true;
        };
        rate_limiter.allow(principal.rate_limit_key().to_string())
    }

    pub fn try_begin_work(&self, principal: &Permission) -> Option<WorkPermit> {
        self.work_limiter.try_acquire(principal.rate_limit_key())
    }

    fn accepted_keys(&self) -> Vec<Arc<str>> {
        let Some(keyring) = &self.keyring else {
            return Vec::new();
        };
        let mut keys = keyring.static_keys.clone();
        keys.extend(keyring.file_keys());
        keys
    }
}

#[derive(Debug)]
struct Keyring {
    static_keys: Vec<Arc<str>>,
    file: Option<PathBuf>,
}

impl Keyring {
    fn accepts(&self, candidate: &str) -> bool {
        let mut accepted = false;
        for key in &self.static_keys {
            accepted |= constant_time_eq(key, candidate);
        }
        for key in self.file_keys() {
            accepted |= constant_time_eq(&key, candidate);
        }
        accepted
    }

    fn file_keys(&self) -> Vec<Arc<str>> {
        let Some(path) = &self.file else {
            return Vec::new();
        };
        match std::fs::read_to_string(path) {
            Ok(raw) => parse_keys(Some(&raw)),
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "failed to read api key file");
                Vec::new()
            }
        }
    }
}

fn parse_keys(raw: Option<&str>) -> Vec<Arc<str>> {
    raw.into_iter()
        .flat_map(|raw| raw.split([',', '\n', '\r']))
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(Arc::<str>::from)
        .collect()
}

fn constant_time_eq(expected: &str, candidate: &str) -> bool {
    expected.as_bytes().ct_eq(candidate.as_bytes()).into()
}

pub type OperationType = Action;

fn canonical_http_path(path: &str) -> &str {
    path.strip_prefix("/v1")
        .filter(|p| p.starts_with('/'))
        .unwrap_or(path)
}

fn classify_http(method: &Method, path: &str) -> Option<Action> {
    let path = canonical_http_path(path);
    match (method, path) {
        (&Method::GET, "/metrics" | "/ws/events" | "/ws/metrics") => Some(Action::Read),
        (&Method::POST, "/chironql" | "/chironql/parse") => Some(Action::Read),
        (method, path)
            if is_graph_http_path(path)
                && matches!(
                    *method,
                    Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
                ) =>
        {
            // Graph roles and capabilities are deliberately checked by the
            // graph handler. Classifying these as a generic read keeps the
            // middleware's authentication/collection gate while preventing a
            // generic role rejection from bypassing the stable graph error
            // envelope or the stricter graph:write/admin/type grants.
            Some(Action::Read)
        }
        (&Method::POST, path) if path.starts_with("/admin/") => Some(Action::Admin),
        (_, "/mcp") => Some(Action::Read),
        (&Method::GET, "/collections") => Some(Action::Read),
        (&Method::POST, "/collections") => Some(Action::Write),
        (&Method::DELETE, path) if is_collection_root(path) => Some(Action::Write),
        (&Method::PUT, path)
            if has_collection_suffix(path, "/payload_schema")
                || has_collection_suffix(path, "/points") =>
        {
            Some(Action::Write)
        }
        (&Method::GET, path) if has_collection_suffix(path, "/index_status") => Some(Action::Read),
        (&Method::POST, path)
            if [
                "/points/get",
                "/search",
                "/search/batch",
                "/search/stream",
                "/hybrid_search",
                "/text_hybrid_search",
                "/multi_search",
                "/recommend",
                "/rerank",
                "/count",
                "/scroll",
            ]
            .iter()
            .any(|suffix| has_collection_suffix(path, suffix)) =>
        {
            Some(Action::Read)
        }
        (&Method::POST, path)
            if [
                "/points/payload",
                "/points/delete",
                "/points/delete/filter",
                "/compact",
                "/calibrate",
                "/compact/stream",
                "/cold/tier",
                "/wal_archive/prune",
            ]
            .iter()
            .any(|suffix| has_collection_suffix(path, suffix)) =>
        {
            Some(Action::Write)
        }
        _ => None,
    }
}

fn is_graph_http_path(path: &str) -> bool {
    path.strip_prefix("/collections/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(collection, rest)| {
            !collection.is_empty()
                && (rest == "graph"
                    || rest.starts_with("graph/")
                    || rest == "edges"
                    || rest.starts_with("edges/"))
        })
}

fn is_collection_root(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/collections/") else {
        return false;
    };
    !rest.is_empty() && !rest.contains('/')
}

fn has_collection_suffix(path: &str, suffix: &str) -> bool {
    path.strip_prefix("/collections/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(collection, rest)| !collection.is_empty() && format!("/{rest}") == suffix)
}

fn extract_collection_from_path(path: &str) -> Option<&str> {
    let path = canonical_http_path(path);
    let rest = path.strip_prefix("/collections/")?;
    let name = rest.split('/').next()?;
    if name.is_empty() { None } else { Some(name) }
}

pub async fn require_http_auth(
    State((auth, db)): State<(AuthConfig, Db)>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let key = extract_http_key(&headers);
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let Some(principal) = auth.permission_for(key) else {
        audit_http(
            &db,
            "authentication",
            "http_authenticate",
            "failure",
            None,
            "unknown",
            None,
            request_id.as_deref(),
            Some("invalid_credential"),
        )?;
        return Err((
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized",
        )
            .into_response());
    };
    // RBAC: check role and collection access when a config is present.
    let path = request.uri().path();
    let method = request.method();
    let Some(operation) = classify_http(method, path) else {
        return Err((StatusCode::FORBIDDEN, "route has no authorization policy").into_response());
    };
    let graph_route = is_graph_http_path(canonical_http_path(path));
    let collection = extract_collection_from_path(path).map(str::to_string);
    audit_http(
        &db,
        "authentication",
        "http_authenticate",
        "success",
        collection.as_deref(),
        &principal.id,
        principal.tenant_id.as_deref(),
        request_id.as_deref(),
        None,
    )?;
    // Direct graph routes perform the complete graph-specific role,
    // capability and collection check in their handler. Doing the generic
    // collection/role check first would leak a different error envelope and,
    // more importantly, make a point role look like the graph authority.
    if !graph_route && authorize(&principal, operation, collection.as_deref()).is_err() {
        audit_http(
            &db,
            "authorization",
            "http_authorize",
            "denied",
            collection.as_deref(),
            &principal.id,
            principal.tenant_id.as_deref(),
            request_id.as_deref(),
            Some("permission_denied"),
        )?;
        return Err((StatusCode::FORBIDDEN, "forbidden").into_response());
    }
    // Attach the resolved permission to request extensions so handlers can read it.
    let (mut parts, body) = request.into_parts();
    parts.extensions.insert(principal.clone());
    let request = Request::from_parts(parts, body);

    if auth.allows_principal_request(&principal) {
        let Some(_work_permit) = auth.try_begin_work(&principal) else {
            metrics::counter!("gaussdb_work_limited_requests_total", "transport" => "http")
                .increment(1);
            audit_http(
                &db,
                "resource",
                "http_work_limit",
                "denied",
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                request_id.as_deref(),
                Some("resource_exhausted"),
            )?;
            return Err((StatusCode::TOO_MANY_REQUESTS, "server overloaded").into_response());
        };
        let response = next.run(request).await;
        if operation == Action::Read {
            let (outcome, error_code) = if response.status().is_success() {
                ("success", None)
            } else {
                ("failure", Some("request_failed"))
            };
            audit_http(
                &db,
                "access",
                "http_read",
                outcome,
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                request_id.as_deref(),
                error_code,
            )?;
        }
        Ok(response)
    } else {
        metrics::counter!("gaussdb_rate_limited_requests_total", "transport" => "http")
            .increment(1);
        audit_http(
            &db,
            "resource",
            "http_rate_limit",
            "denied",
            collection.as_deref(),
            &principal.id,
            principal.tenant_id.as_deref(),
            request_id.as_deref(),
            Some("resource_exhausted"),
        )?;
        Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response())
    }
}

#[allow(clippy::result_large_err, clippy::too_many_arguments)]
fn audit_http(
    db: &Db,
    category: &str,
    operation: &str,
    outcome: &str,
    collection: Option<&str>,
    principal_id: &str,
    tenant_id: Option<&str>,
    request_id: Option<&str>,
    error_code: Option<&str>,
) -> Result<(), Response> {
    db.audit_access_event(
        category,
        operation,
        outcome,
        collection,
        principal_id,
        tenant_id,
        "http",
        request_id,
        error_code,
    )
    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "audit unavailable").into_response())
}

#[derive(Clone, Debug)]
pub struct GrpcAuthInterceptor {
    auth: AuthConfig,
    db: Db,
}

impl GrpcAuthInterceptor {
    pub fn new(auth: AuthConfig, db: Db) -> Self {
        Self { auth, db }
    }
}

impl Interceptor for GrpcAuthInterceptor {
    fn call(&mut self, mut request: GrpcRequest<()>) -> Result<GrpcRequest<()>, Status> {
        let key = extract_grpc_key(request.metadata());
        let Some(permission) = self.auth.permission_for(key) else {
            self.db
                .audit_access_event(
                    "authentication",
                    "grpc_authenticate",
                    "failure",
                    None,
                    "unknown",
                    None,
                    "grpc",
                    request
                        .metadata()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok()),
                    Some("invalid_credential"),
                )
                .map_err(|_| Status::unavailable("audit unavailable"))?;
            return Err(Status::unauthenticated("missing or invalid api key"));
        };
        self.db
            .audit_access_event(
                "authentication",
                "grpc_authenticate",
                "success",
                None,
                &permission.id,
                permission.tenant_id.as_deref(),
                "grpc",
                request
                    .metadata()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok()),
                None,
            )
            .map_err(|_| Status::unavailable("audit unavailable"))?;
        if !self.auth.allows_principal_request(&permission) {
            metrics::counter!("gaussdb_rate_limited_requests_total", "transport" => "grpc")
                .increment(1);
            self.db
                .audit_access_event(
                    "resource",
                    "grpc_rate_limit",
                    "denied",
                    None,
                    &permission.id,
                    permission.tenant_id.as_deref(),
                    "grpc",
                    request
                        .metadata()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok()),
                    Some("resource_exhausted"),
                )
                .map_err(|_| Status::unavailable("audit unavailable"))?;
            return Err(Status::resource_exhausted("rate limit exceeded"));
        }
        let Some(work_permit) = self.auth.try_begin_work(&permission) else {
            metrics::counter!("gaussdb_work_limited_requests_total", "transport" => "grpc")
                .increment(1);
            self.db
                .audit_access_event(
                    "resource",
                    "grpc_work_limit",
                    "denied",
                    None,
                    &permission.id,
                    permission.tenant_id.as_deref(),
                    "grpc",
                    request
                        .metadata()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok()),
                    Some("resource_exhausted"),
                )
                .map_err(|_| Status::unavailable("audit unavailable"))?;
            return Err(Status::resource_exhausted("server overloaded"));
        };
        // The resolved principal travels with the request so a handler can
        // build a tenant scope from it. Without this the gRPC path would have
        // no identity to scope by and would be unable to serve a
        // tenant-enforcing deployment at all.
        request.extensions_mut().insert(permission);
        request.extensions_mut().insert(Arc::new(work_permit));
        Ok(request)
    }
}

#[derive(Clone, Debug)]
struct RateLimiter {
    limit: u32,
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
}

#[derive(Clone, Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone, Debug)]
struct WorkLimiter {
    state: Arc<Mutex<WorkState>>,
    global_limit: usize,
    tenant_limit: usize,
}

#[derive(Debug, Default)]
struct WorkState {
    total: usize,
    per_tenant: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct WorkPermit {
    state: Arc<Mutex<WorkState>>,
    tenant: String,
}

impl Default for WorkLimiter {
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4);
        let global_limit = parallelism.saturating_mul(4).max(32);
        Self {
            state: Arc::new(Mutex::new(WorkState::default())),
            global_limit,
            tenant_limit: (global_limit / 4).max(2),
        }
    }
}

impl WorkLimiter {
    fn try_acquire(&self, tenant: &str) -> Option<WorkPermit> {
        let mut state = self.state.lock().ok()?;
        let tenant_count = state.per_tenant.get(tenant).copied().unwrap_or(0);
        if state.total >= self.global_limit || tenant_count >= self.tenant_limit {
            return None;
        }
        state.total += 1;
        *state.per_tenant.entry(tenant.to_string()).or_default() += 1;
        Some(WorkPermit {
            state: Arc::clone(&self.state),
            tenant: tenant.to_string(),
        })
    }
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_tenant.get_mut(&self.tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_tenant.remove(&self.tenant);
            }
        }
    }
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn allow(&self, principal: String) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let bucket = buckets.entry(principal).or_insert(Bucket {
            tokens: self.limit as f64,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.limit as f64).min(self.limit as f64);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn extract_http_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-chirondb-api-key")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("x-gaussdb-api-key")
                .and_then(|value| value.to_str().ok())
        })
        .or_else(|| {
            bearer_value(
                headers
                    .get(AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
            )
        })
}

fn extract_grpc_key(metadata: &tonic::metadata::MetadataMap) -> Option<&str> {
    metadata
        .get("x-chirondb-api-key")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            metadata
                .get("x-gaussdb-api-key")
                .and_then(|value| value.to_str().ok())
        })
        .or_else(|| {
            bearer_value(
                metadata
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
            )
        })
}

fn bearer_value(value: Option<&str>) -> Option<&str> {
    value
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
}

fn principal_key(key: Option<&str>) -> String {
    key.unwrap_or("anonymous").to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        AuthConfig, OperationType, classify_http, extract_collection_from_path, extract_http_key,
    };
    use crate::rbac::{ApiKeyEntry, Permission, RbacConfig, Role};
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn chirondb_api_key_header_precedes_legacy_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-gaussdb-api-key", HeaderValue::from_static("legacy"));
        headers.insert("x-chirondb-api-key", HeaderValue::from_static("primary"));
        assert_eq!(extract_http_key(&headers), Some("primary"));
        headers.remove("x-chirondb-api-key");
        assert_eq!(extract_http_key(&headers), Some("legacy"));
    }

    #[test]
    fn accepts_anything_when_disabled() {
        assert!(AuthConfig::disabled().accepts(None));
    }

    #[test]
    fn validates_configured_key() {
        let auth = AuthConfig::from_optional_key(Some("secret".to_string()));
        assert!(auth.accepts(Some("secret")));
        assert!(!auth.accepts(Some("other")));
        assert!(!auth.accepts(None));
    }

    #[test]
    fn accepts_multiple_configured_keys() {
        let auth = AuthConfig::from_optional_key(Some("old,new\nbackup".to_string()));
        assert!(auth.accepts(Some("old")));
        assert!(auth.accepts(Some("new")));
        assert!(auth.accepts(Some("backup")));
        assert!(!auth.accepts(Some("other")));
    }

    #[test]
    fn reloads_keys_from_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("keys.txt");
        std::fs::write(&path, "old\n").unwrap();
        let auth = AuthConfig::from_key_sources(None, Some(path.clone()));
        assert!(auth.accepts(Some("old")));
        assert!(!auth.accepts(Some("new")));

        std::fs::write(&path, "new\n").unwrap();
        assert!(!auth.accepts(Some("old")));
        assert!(auth.accepts(Some("new")));
    }

    #[test]
    fn rate_limit_is_per_principal() {
        let auth = AuthConfig::disabled().with_rate_limit(Some(1));
        assert!(auth.allows_request(Some("alpha")));
        assert!(!auth.allows_request(Some("alpha")));
        assert!(auth.allows_request(Some("beta")));
    }

    #[test]
    fn multiple_keys_for_one_tenant_share_rate_limit() {
        let rbac = RbacConfig {
            keys: ["key-a", "key-b"]
                .into_iter()
                .enumerate()
                .map(|(index, key)| ApiKeyEntry {
                    id: Some(format!("principal-{index}")),
                    key: key.to_string(),
                    tenant_id: Some("tenant-a".to_string()),
                    role: Role::ReadOnly,
                    allowed_collections: Vec::new(),
                    max_collections: None,
                    capabilities: Vec::new(),
                })
                .collect(),
        };
        let auth = AuthConfig::from_optional_key(Some("key-a,key-b".to_string()))
            .with_rbac(rbac)
            .with_rate_limit(Some(1));
        let first = auth.permission_for(Some("key-a")).unwrap();
        let second = auth.permission_for(Some("key-b")).unwrap();
        assert!(auth.allows_principal_request(&first));
        assert!(!auth.allows_principal_request(&second));
    }

    #[test]
    fn multiple_keys_for_one_tenant_share_execution_admission() {
        let mut first = Permission::unrestricted_for("principal-a".to_string());
        first.tenant_id = Some("tenant-a".to_string());
        let mut second = Permission::unrestricted_for("principal-b".to_string());
        second.tenant_id = Some("tenant-a".to_string());
        let mut other = Permission::unrestricted_for("principal-c".to_string());
        other.tenant_id = Some("tenant-b".to_string());
        let auth = AuthConfig::disabled();
        let mut held = Vec::new();
        while let Some(permit) = auth.try_begin_work(&first) {
            held.push(permit);
        }
        assert!(!held.is_empty());
        assert!(auth.try_begin_work(&second).is_none());
        assert!(auth.try_begin_work(&other).is_some());
    }

    fn rbac_config_with_two_keys() -> RbacConfig {
        RbacConfig {
            keys: vec![
                ApiKeyEntry {
                    id: Some("admin".to_string()),
                    key: "admin-key".to_string(),
                    tenant_id: Some("ops".to_string()),
                    role: Role::Admin,
                    allowed_collections: vec![],
                    max_collections: None,
                    capabilities: Vec::new(),
                },
                ApiKeyEntry {
                    id: Some("reader".to_string()),
                    key: "reader-key".to_string(),
                    tenant_id: None,
                    role: Role::ReadOnly,
                    allowed_collections: vec!["public".to_string()],
                    max_collections: None,
                    capabilities: Vec::new(),
                },
                ApiKeyEntry {
                    id: Some("writer".to_string()),
                    key: "writer-key".to_string(),
                    tenant_id: None,
                    role: Role::ReadWrite,
                    allowed_collections: vec![],
                    max_collections: None,
                    capabilities: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn rbac_admin_key_passes_all_operations() {
        let auth =
            AuthConfig::from_optional_key(Some("admin-key,reader-key,writer-key".to_string()))
                .with_rbac(rbac_config_with_two_keys());

        // Admin can do everything.
        assert!(auth.check_access(Some("admin-key"), OperationType::Admin, None));
        assert!(auth.check_access(Some("admin-key"), OperationType::Write, Some("any-col")));
        assert!(auth.check_access(Some("admin-key"), OperationType::Read, Some("any-col")));
    }

    #[test]
    fn rbac_read_only_key_denied_write_and_admin() {
        let auth =
            AuthConfig::from_optional_key(Some("admin-key,reader-key,writer-key".to_string()))
                .with_rbac(rbac_config_with_two_keys());

        assert!(!auth.check_access(Some("reader-key"), OperationType::Write, Some("public")));
        assert!(!auth.check_access(Some("reader-key"), OperationType::Admin, None));
        // Read on allowed collection succeeds.
        assert!(auth.check_access(Some("reader-key"), OperationType::Read, Some("public")));
        // Read on non-listed collection fails.
        assert!(!auth.check_access(Some("reader-key"), OperationType::Read, Some("private")));
    }

    #[test]
    fn rbac_write_key_allowed_write_denied_admin() {
        let auth =
            AuthConfig::from_optional_key(Some("admin-key,reader-key,writer-key".to_string()))
                .with_rbac(rbac_config_with_two_keys());

        assert!(auth.check_access(Some("writer-key"), OperationType::Write, Some("any-col")));
        assert!(auth.check_access(Some("writer-key"), OperationType::Read, Some("any-col")));
        assert!(!auth.check_access(Some("writer-key"), OperationType::Admin, None));
    }

    #[test]
    fn rbac_unknown_key_is_rejected() {
        let auth = AuthConfig::from_optional_key(Some("admin-key".to_string()))
            .with_rbac(rbac_config_with_two_keys());
        assert!(!auth.check_access(Some("unknown"), OperationType::Read, None));
    }

    #[test]
    fn permission_is_restricted_when_allowlist_is_non_empty() {
        let entry = ApiKeyEntry {
            id: Some("restricted".to_string()),
            key: "k".to_string(),
            tenant_id: None,
            role: Role::ReadOnly,
            allowed_collections: vec!["col".to_string()],
            max_collections: None,
            capabilities: Vec::new(),
        };
        let perm = Permission::from_entry(&entry);
        assert!(perm.is_restricted());
    }

    #[test]
    fn permission_is_unrestricted_when_allowlist_is_empty() {
        let entry = ApiKeyEntry {
            id: Some("unrestricted".to_string()),
            key: "k".to_string(),
            tenant_id: None,
            role: Role::ReadWrite,
            allowed_collections: vec![],
            max_collections: None,
            capabilities: Vec::new(),
        };
        let perm = Permission::from_entry(&entry);
        assert!(!perm.is_restricted());
    }

    #[test]
    fn operation_type_classification() {
        use axum::http::Method;
        let routes = [
            (Method::GET, "/collections", OperationType::Read),
            (Method::POST, "/collections", OperationType::Write),
            (Method::PUT, "/collections/col/points", OperationType::Write),
            (Method::POST, "/collections/col/search", OperationType::Read),
            (
                Method::POST,
                "/collections/col/search/batch",
                OperationType::Read,
            ),
            (
                Method::POST,
                "/collections/col/hybrid_search",
                OperationType::Read,
            ),
            (
                Method::POST,
                "/collections/col/multi_search",
                OperationType::Read,
            ),
            (
                Method::POST,
                "/collections/col/recommend",
                OperationType::Read,
            ),
            (Method::POST, "/collections/col/rerank", OperationType::Read),
            (Method::POST, "/collections/col/count", OperationType::Read),
            (Method::POST, "/collections/col/scroll", OperationType::Read),
            (Method::PUT, "/collections/col/graph", OperationType::Read),
            (
                Method::DELETE,
                "/collections/col/graph",
                OperationType::Read,
            ),
            (
                Method::GET,
                "/collections/col/graph/types",
                OperationType::Read,
            ),
            (
                Method::PUT,
                "/collections/col/graph/types/knows",
                OperationType::Read,
            ),
            (
                Method::POST,
                "/collections/col/graph/traverse",
                OperationType::Read,
            ),
            (Method::POST, "/collections/col/edges", OperationType::Read),
            (
                Method::PATCH,
                "/collections/col/edges/opaque-token",
                OperationType::Read,
            ),
            (
                Method::DELETE,
                "/collections/col/edges/opaque-token",
                OperationType::Read,
            ),
            (
                Method::POST,
                "/collections/col/compact",
                OperationType::Write,
            ),
            (Method::POST, "/admin/snapshot", OperationType::Admin),
            (Method::POST, "/admin/restore", OperationType::Admin),
        ];
        for (method, path, expected) in routes {
            assert_eq!(
                classify_http(&method, path),
                Some(expected),
                "{method} {path}"
            );
            assert_eq!(
                classify_http(&method, &format!("/v1{path}")),
                Some(expected),
                "{method} /v1{path}"
            );
        }
        assert_eq!(
            classify_http(&Method::GET, "/collections"),
            Some(OperationType::Read)
        );
        assert_eq!(
            classify_http(&Method::PUT, "/collections/col/points"),
            Some(OperationType::Write)
        );
        assert_eq!(
            classify_http(&Method::POST, "/collections/col/search"),
            Some(OperationType::Read)
        );
        assert_eq!(
            classify_http(&Method::POST, "/collections/col/compact"),
            Some(OperationType::Write)
        );
        assert_eq!(
            classify_http(&Method::POST, "/admin/snapshot"),
            Some(OperationType::Admin)
        );
        assert_eq!(
            classify_http(&Method::POST, "/collections/col/rerank"),
            Some(OperationType::Read)
        );
        assert_eq!(
            classify_http(&Method::POST, "/v1/collections/col/search"),
            Some(OperationType::Read)
        );
        assert_eq!(
            extract_collection_from_path("/v1/collections/col/search"),
            Some("col")
        );
        assert_eq!(
            classify_http(&Method::POST, "/collections/col/unknown"),
            None
        );
    }
}
