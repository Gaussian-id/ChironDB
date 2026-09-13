use std::{
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use prost::Message;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::{Code, Status};

use crate::{
    Db,
    auth::AuthConfig,
    grpc::{
        self,
        pb::{self, wire_request, wire_response},
    },
    model::{HybridSearchRequest, MultiSearchRequest, RecommendRequest},
    rbac::{Action, Permission, authorize, authorize_graph},
    security_paths::StoragePolicy,
    wire_postgres,
};

const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

pub async fn serve(db: Db, addr: SocketAddr) -> std::io::Result<()> {
    serve_with_auth(db, AuthConfig::disabled(), addr).await
}

pub async fn serve_with_auth(db: Db, auth: AuthConfig, addr: SocketAddr) -> std::io::Result<()> {
    serve_with_auth_and_policy(db, auth, addr, StoragePolicy::default()).await
}

pub async fn serve_with_auth_and_policy(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener_with_policy(db, auth, listener, storage_policy).await
}

pub async fn serve_tls_with_auth(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
) -> std::io::Result<()> {
    serve_tls_with_auth_and_policy(
        db,
        auth,
        addr,
        cert,
        key,
        client_ca,
        StoragePolicy::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_with_auth_and_policy(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_tls_listener_with_policy(db, auth, listener, cert, key, client_ca, storage_policy).await
}

pub async fn serve_listener(db: Db, listener: TcpListener) -> std::io::Result<()> {
    serve_listener_with_auth(db, AuthConfig::disabled(), listener).await
}

pub async fn serve_listener_with_auth(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
) -> std::io::Result<()> {
    serve_listener_with_policy(db, auth, listener, StoragePolicy::default()).await
}

pub async fn serve_listener_with_policy(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let db = db.clone();
        let auth = auth.clone();
        let storage_policy = storage_policy.clone();
        tokio::spawn(async move {
            if let Err(error) = dispatch_by_first_bytes(db, auth, storage_policy, stream).await {
                tracing::warn!(%error, %peer, "GaussWire connection failed");
            }
        });
    }
}

/// First-bytes sniff: peek 8 bytes, route to either Postgres v3 (pgvector
/// wire-compat per `.SPEC/gaussdb-vector_cleaned.md` §2.1) or the native protobuf
/// GaussWire path. For the native path the bytes are replayed via
/// `PrefixedStream` so existing frame readers see an unmodified byte stream.
async fn dispatch_by_first_bytes<S>(
    db: Db,
    auth: AuthConfig,
    storage_policy: StoragePolicy,
    mut stream: S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = [0_u8; 8];
    match stream.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(error) => return Err(error),
    }
    if wire_postgres::is_postgres_prefix(&prefix) {
        return wire_postgres::handle_connection(db, auth, stream, prefix).await;
    }
    let replay = PrefixedStream::new(prefix.to_vec(), stream);
    handle_connection(db, auth, storage_policy, replay).await
}

/// Wraps an `AsyncRead + AsyncWrite` so the first `prefix` bytes are returned
/// to readers before reading from the underlying transport. Used by the
/// GaussWire / Postgres protocol sniff to "unread" the peek bytes before
/// handing the connection to the native-protocol handler.
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.pos < me.prefix.len() {
            let remaining = &me.prefix[me.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn serve_tls_listener_with_auth(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
) -> std::io::Result<()> {
    serve_tls_listener_with_policy(
        db,
        auth,
        listener,
        cert,
        key,
        client_ca,
        StoragePolicy::default(),
    )
    .await
}

pub async fn serve_tls_config_with_auth_and_policy(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    tls: crate::tls::ReloadingTlsConfig,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_tls_listener_with_config(db, auth, listener, tls, storage_policy).await
}

pub async fn serve_tls_listener_with_config(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    tls: crate::tls::ReloadingTlsConfig,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    serve_tls_listener_with_acceptor(
        db,
        auth,
        listener,
        TlsAcceptor::from(tls.server_config()),
        storage_policy,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_listener_with_policy(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    crate::tls::install_default_crypto_provider();
    let acceptor = TlsAcceptor::from(Arc::new(
        crate::tls::server_config(cert, key, client_ca).await?,
    ));
    serve_tls_listener_with_acceptor(db, auth, listener, acceptor, storage_policy).await
}

async fn serve_tls_listener_with_acceptor(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    storage_policy: StoragePolicy,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let db = db.clone();
        let auth = auth.clone();
        let acceptor = acceptor.clone();
        let storage_policy = storage_policy.clone();
        tokio::spawn(async move {
            let result = async {
                let mut stream = stream;
                let mut prefix = [0_u8; 8];
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut prefix))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "TLS handshake preface timed out",
                        )
                    })??;
                let mut magic = u32::from_be_bytes(prefix[4..8].try_into().expect("fixed size"));
                if magic == wire_postgres::GSSENC_REQUEST_MAGIC {
                    stream.write_all(b"N").await?;
                    stream.flush().await?;
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut prefix))
                        .await
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "PostgreSQL SSLRequest timed out",
                            )
                        })??;
                    magic = u32::from_be_bytes(prefix[4..8].try_into().expect("fixed size"));
                }
                if magic == wire_postgres::SSL_REQUEST_MAGIC {
                    if u32::from_be_bytes(prefix[0..4].try_into().expect("fixed size")) != 8 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid PostgreSQL SSLRequest length",
                        ));
                    }
                    stream.write_all(b"S").await?;
                    stream.flush().await?;
                    let stream =
                        tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                            .await
                            .map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "PostgreSQL TLS handshake timed out",
                                )
                            })??;
                    return dispatch_by_first_bytes(db, auth, storage_policy, stream).await;
                }

                // Native ChironWire uses direct TLS on the same port. Replay
                // the bytes consumed for protocol detection into rustls.
                let replay = PrefixedStream::new(prefix.to_vec(), stream);
                let stream = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(replay))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "ChironWire TLS handshake timed out",
                        )
                    })??;
                dispatch_by_first_bytes(db, auth, storage_policy, stream).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, %peer, "GaussWire TLS connection failed");
            }
        });
    }
}

pub async fn send_request(
    addr: &str,
    request: pb::WireRequest,
) -> Result<pb::WireResponse, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(addr).await?;
    write_frame(&mut stream, &request).await?;
    let Some(frame) = read_frame(&mut stream).await? else {
        return Err("GaussWire server closed before response".into());
    };
    Ok(pb::WireResponse::decode(frame.as_slice())?)
}

pub async fn send_requests(
    addr: &str,
    requests: Vec<pb::WireRequest>,
) -> Result<Vec<pb::WireResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(addr).await?;
    for request in &requests {
        write_frame(&mut stream, request).await?;
    }

    let mut responses = Vec::with_capacity(requests.len());
    for _ in 0..requests.len() {
        let Some(frame) = read_frame(&mut stream).await? else {
            return Err("GaussWire server closed before all responses".into());
        };
        responses.push(pb::WireResponse::decode(frame.as_slice())?);
    }
    Ok(responses)
}

pub async fn send_request_tls(
    addr: &str,
    domain: &str,
    ca_cert: PathBuf,
    client_identity: Option<(PathBuf, PathBuf)>,
    request: pb::WireRequest,
) -> Result<pb::WireResponse, Box<dyn std::error::Error + Send + Sync>> {
    crate::tls::install_default_crypto_provider();
    let config = client_tls_config(ca_cert, client_identity).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await?;
    let domain = ServerName::try_from(domain.to_string())?;
    let mut stream = connector.connect(domain, stream).await?;
    write_frame(&mut stream, &request).await?;
    let Some(frame) = read_frame(&mut stream).await? else {
        return Err("GaussWire server closed before response".into());
    };
    Ok(pb::WireResponse::decode(frame.as_slice())?)
}

async fn handle_connection<S>(
    db: Db,
    auth: AuthConfig,
    storage_policy: StoragePolicy,
    stream: S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let (response_sender, response_receiver) = mpsc::channel(128);
    let writer_task = tokio::spawn(write_responses(writer, response_receiver));
    let mut read_tasks = JoinSet::new();

    while let Some(frame) = read_frame(&mut reader).await? {
        let request = match pb::WireRequest::decode(frame.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                send_wire_response(
                    &response_sender,
                    error_response(
                        0,
                        Status::invalid_argument(format!("decode failed: {error}")),
                    ),
                )
                .await?;
                continue;
            }
        };

        if is_read_only_operation(&request.operation) {
            let db = db.clone();
            let auth = auth.clone();
            let storage_policy = storage_policy.clone();
            let response_sender = response_sender.clone();
            read_tasks.spawn(async move {
                // Phase 2A: read-only ops (Search/HybridSearch/MultiSearch/
                // Recommend/Count/Scroll/GetPoints/Health/ListCollections).
                // Uses spawn_blocking so the tokio executor can interleave
                // other tasks (e.g. a fast Health overtaking a slow
                // MultiSearch on the same connection). The +20-50µs
                // spawn_blocking overhead is acceptable for correct
                // out-of-order response delivery.
                let response = dispatch_request_blocking(db, auth, storage_policy, request).await?;
                send_wire_response(&response_sender, response).await
            });
            continue;
        }

        drain_read_tasks(&mut read_tasks).await?;
        let response =
            dispatch_request_blocking(db.clone(), auth.clone(), storage_policy.clone(), request)
                .await?;
        send_wire_response(&response_sender, response).await?;
    }

    drain_read_tasks(&mut read_tasks).await?;
    drop(response_sender);
    writer_task.await.map_err(std::io::Error::other)??;
    Ok(())
}

async fn write_responses<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<pb::WireResponse>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(response) = receiver.recv().await {
        write_frame(&mut writer, &response).await?;
    }
    Ok(())
}

async fn send_wire_response(
    sender: &mpsc::Sender<pb::WireResponse>,
    response: pb::WireResponse,
) -> std::io::Result<()> {
    sender
        .send(response)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "GaussWire writer closed"))
}

async fn drain_read_tasks(tasks: &mut JoinSet<std::io::Result<()>>) -> std::io::Result<()> {
    while let Some(result) = tasks.join_next().await {
        result.map_err(std::io::Error::other)??;
    }
    Ok(())
}

fn is_read_only_operation(operation: &Option<wire_request::Operation>) -> bool {
    matches!(
        operation,
        Some(wire_request::Operation::Health(_))
            | Some(wire_request::Operation::ListCollections(_))
            | Some(wire_request::Operation::Search(_))
            | Some(wire_request::Operation::HybridSearch(_))
            | Some(wire_request::Operation::TextHybridSearch(_))
            | Some(wire_request::Operation::MultiSearch(_))
            | Some(wire_request::Operation::Recommend(_))
            | Some(wire_request::Operation::Count(_))
            | Some(wire_request::Operation::Scroll(_))
            | Some(wire_request::Operation::GetPoints(_))
    )
}

async fn dispatch_request_blocking(
    db: Db,
    auth: AuthConfig,
    storage_policy: StoragePolicy,
    request: pb::WireRequest,
) -> std::io::Result<pb::WireResponse> {
    tokio::task::spawn_blocking(move || dispatch_request(&db, &auth, &storage_policy, request))
        .await
        .map_err(std::io::Error::other)
}

fn dispatch_request(
    db: &Db,
    auth: &AuthConfig,
    storage_policy: &StoragePolicy,
    request: pb::WireRequest,
) -> pb::WireResponse {
    let request_id = request.request_id;
    let api_key = optional_api_key(&request.api_key);
    let Some(principal) = auth.permission_for(api_key) else {
        if db
            .audit_access_event(
                "authentication",
                "chironwire_authenticate",
                "failure",
                None,
                "unknown",
                None,
                "chironwire",
                Some(&request_id.to_string()),
                Some("invalid_credential"),
            )
            .is_err()
        {
            return error_response(request_id, Status::unavailable("audit unavailable"));
        }
        return error_response(
            request_id,
            Status::unauthenticated("missing or invalid api key"),
        );
    };
    let operation = match request.operation.as_ref() {
        Some(operation) => operation,
        None => {
            return error_response(
                request_id,
                Status::invalid_argument("operation is required"),
            );
        }
    };
    let (action, collection) = wire_policy(operation);
    let collection = collection.map(str::to_string);
    let is_chironql = matches!(operation, wire_request::Operation::Chironql(_));
    if db
        .audit_access_event(
            "authentication",
            "chironwire_authenticate",
            "success",
            collection.as_deref(),
            &principal.id,
            principal.tenant_id.as_deref(),
            "chironwire",
            Some(&request_id.to_string()),
            None,
        )
        .is_err()
    {
        return error_response(request_id, Status::unavailable("audit unavailable"));
    }
    if authorize(&principal, action, collection.as_deref()).is_err() {
        if db
            .audit_access_event(
                "authorization",
                "chironwire_authorize",
                "denied",
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                "chironwire",
                Some(&request_id.to_string()),
                Some("permission_denied"),
            )
            .is_err()
        {
            return error_response(request_id, Status::unavailable("audit unavailable"));
        }
        return error_response(
            request_id,
            Status::permission_denied("operation is not permitted"),
        );
    }
    if let Some(graph_collection) = wire_graph_collection(operation)
        && authorize_graph(
            &principal,
            crate::graph::GraphCapability::Read,
            graph_collection,
        )
        .is_err()
    {
        if db
            .audit_access_event(
                "authorization",
                "chironwire_graph_authorize",
                "denied",
                Some(graph_collection),
                &principal.id,
                principal.tenant_id.as_deref(),
                "chironwire",
                Some(&request_id.to_string()),
                Some("graph.permission_denied"),
            )
            .is_err()
        {
            return error_response(request_id, Status::unavailable("audit unavailable"));
        }
        return error_response(
            request_id,
            graph_permission_denied_status(crate::graph::GraphCapability::Read, graph_collection),
        );
    }
    if !auth.allows_principal_request(&principal) {
        metrics::counter!("gaussdb_rate_limited_requests_total", "transport" => "wire")
            .increment(1);
        return error_response(
            request_id,
            Status::resource_exhausted("rate limit exceeded"),
        );
    }
    let Some(_work_permit) = auth.try_begin_work(&principal) else {
        metrics::counter!("gaussdb_work_limited_requests_total", "transport" => "wire")
            .increment(1);
        return error_response(request_id, Status::resource_exhausted("server overloaded"));
    };

    let result = dispatch_operation(db, &principal, storage_policy, request.operation);
    if (action == Action::Read || is_chironql)
        && db
            .audit_access_event(
                "access",
                if is_chironql {
                    "chironwire_chironql"
                } else {
                    "chironwire_read"
                },
                if result.is_ok() { "success" } else { "failure" },
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                "chironwire",
                Some(&request_id.to_string()),
                result
                    .as_ref()
                    .err()
                    .and_then(status_detail_code)
                    .as_deref()
                    .or_else(|| result.as_ref().err().map(|_| "request_failed")),
            )
            .is_err()
    {
        return error_response(request_id, Status::unavailable("audit unavailable"));
    }
    match result {
        Ok(payload) => pb::WireResponse {
            request_id,
            error_code: String::new(),
            error_message: String::new(),
            error_details_json: None,
            payload: Some(payload),
        },
        Err(status) => error_response(request_id, status),
    }
}

fn wire_policy(operation: &wire_request::Operation) -> (Action, Option<&str>) {
    match operation {
        wire_request::Operation::Health(_) | wire_request::Operation::ListCollections(_) => {
            (Action::Read, None)
        }
        wire_request::Operation::CreateCollection(request) => (
            Action::Write,
            request.config.as_ref().map(|config| config.name.as_str()),
        ),
        wire_request::Operation::UpdatePayloadSchema(request) => {
            (Action::Write, Some(&request.collection))
        }
        wire_request::Operation::Upsert(request) => (Action::Write, Some(&request.collection)),
        wire_request::Operation::Delete(request) => (Action::Write, Some(&request.collection)),
        wire_request::Operation::Search(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::HybridSearch(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::TextHybridSearch(request) => {
            (Action::Read, Some(&request.collection))
        }
        wire_request::Operation::MultiSearch(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::Recommend(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::Count(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::Scroll(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::Compact(request) => (Action::Write, Some(&request.collection)),
        wire_request::Operation::TierCold(request) => (Action::Write, Some(&request.collection)),
        wire_request::Operation::PruneWalArchive(request) => {
            (Action::Write, Some(&request.collection))
        }
        wire_request::Operation::Snapshot(_)
        | wire_request::Operation::Restore(_)
        | wire_request::Operation::ShardMove(_) => (Action::Admin, None),
        wire_request::Operation::GetPoints(request) => (Action::Read, Some(&request.collection)),
        wire_request::Operation::SetPayload(request) => (Action::Write, Some(&request.collection)),
        wire_request::Operation::DeleteByFilter(request) => {
            (Action::Write, Some(&request.collection))
        }
        wire_request::Operation::Chironql(request) => (Action::Read, request.collection.as_deref()),
    }
}

/// Legacy native search frames predate ChironQL, but their additive graph
/// constraint fields still require the same explicit graph read grant.
fn wire_graph_collection(operation: &wire_request::Operation) -> Option<&str> {
    match operation {
        wire_request::Operation::Search(request)
            if request.query.as_ref().is_some_and(|query| {
                query
                    .graph_json
                    .as_deref()
                    .is_some_and(|raw| !raw.trim().is_empty())
            }) =>
        {
            Some(&request.collection)
        }
        wire_request::Operation::HybridSearch(request)
            if request
                .graph_json
                .as_deref()
                .is_some_and(|raw| !raw.trim().is_empty()) =>
        {
            Some(&request.collection)
        }
        wire_request::Operation::MultiSearch(request)
            if request.searches.iter().any(|query| {
                query
                    .graph_json
                    .as_deref()
                    .is_some_and(|raw| !raw.trim().is_empty())
            }) =>
        {
            Some(&request.collection)
        }
        _ => None,
    }
}

fn dispatch_operation(
    db: &Db,
    principal: &Permission,
    storage_policy: &StoragePolicy,
    operation: Option<wire_request::Operation>,
) -> Result<wire_response::Payload, Status> {
    let operation = operation.ok_or_else(|| Status::invalid_argument("operation is required"))?;
    match operation {
        wire_request::Operation::Health(_) => {
            if !db.durability_ready() {
                return Err(Status::unavailable(
                    "WAL durability is degraded or restore maintenance is active",
                ));
            }
            Ok(wire_response::Payload::Health(pb::HealthResponse {
                status: "ok".to_string(),
                data_dir: String::new(),
                collections: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
            }))
        }
        wire_request::Operation::CreateCollection(request) => {
            let config = request
                .config
                .ok_or_else(|| Status::invalid_argument("config is required"))
                .and_then(grpc::collection_config_from_proto)?;
            if let Some(limit) = principal.max_collections {
                let current = db
                    .list_collections()
                    .iter()
                    .filter(|config| principal.allows_collection(&config.name))
                    .count();
                if current >= limit {
                    return Err(Status::permission_denied("collection quota exceeded"));
                }
            }
            db.create_collection(config)
                .map(grpc::collection_config_to_proto)
                .map(wire_response::Payload::Collection)
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::ListCollections(_) => Ok(wire_response::Payload::ListCollections(
            pb::ListCollectionsResponse {
                collections: db
                    .list_collections()
                    .into_iter()
                    .filter(|config| principal.allows_collection(&config.name))
                    .map(grpc::collection_config_to_proto)
                    .collect(),
            },
        )),
        wire_request::Operation::UpdatePayloadSchema(request) => {
            let payload_schema = request
                .payload_schema
                .into_iter()
                .map(|(field, value_type)| {
                    grpc::payload_type_from_proto(&value_type).map(|value_type| (field, value_type))
                })
                .collect::<Result<_, _>>()?;
            db.update_payload_schema(&request.collection, payload_schema)
                .map(grpc::collection_config_to_proto)
                .map(wire_response::Payload::Collection)
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Upsert(request) => {
            if request.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
                return Err(Status::resource_exhausted(format!(
                    "upsert contains {} points; maximum is {}",
                    request.points.len(),
                    crate::MAX_UPSERT_POINTS_PER_REQUEST
                )));
            }
            let wait = !request.no_wait;
            let scope = principal.tenant_scope(principal.id.clone());
            let points = request
                .points
                .into_iter()
                .map(grpc::point_from_proto)
                .collect::<Result<Vec<_>, _>>()?;
            db.upsert_scoped(&request.collection, points, wait, &scope)
                .map(|total| {
                    wire_response::Payload::Upsert(pb::UpsertResponse {
                        total: total as u64,
                    })
                })
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Delete(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.delete_scoped(&request.collection, &request.ids, &scope)
                .map(|deleted| {
                    wire_response::Payload::Delete(pb::DeleteResponse {
                        deleted: deleted as u64,
                    })
                })
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Search(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            let query = request
                .query
                .ok_or_else(|| Status::invalid_argument("query is required"))?;
            db.search_scoped(
                &request.collection,
                grpc::search_request_from_proto(query)?,
                &scope,
            )
            .and_then(grpc::search_response_to_proto)
            .map(wire_response::Payload::Search)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::TextHybridSearch(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.text_hybrid_search_scoped(
                &request.collection,
                grpc::text_hybrid_from_proto(&request)?,
                &scope,
            )
            .and_then(grpc::search_response_to_proto)
            .map(wire_response::Payload::Search)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::HybridSearch(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.hybrid_search_scoped(
                &request.collection,
                HybridSearchRequest {
                    graph: grpc::graph_constraint_from_json(request.graph_json.as_deref())?,
                    vector: request.use_dense_vector.then_some(request.vector),
                    vector_name: grpc::optional_string(request.vector_name),
                    sparse_vector: request.sparse_vector.map(grpc::sparse_vector_from_proto),
                    k: grpc::k_or_default(request.k)?,
                    filter: grpc::filter_from_json(&request.filter_json)?,
                    budget_ms: request.budget_ms,
                    fusion: grpc::fusion_from_proto(&request.fusion)?,
                    dense_weight: grpc::weight_or_default(request.dense_weight),
                    sparse_weight: grpc::weight_or_default(request.sparse_weight),
                },
                &scope,
            )
            .and_then(grpc::search_response_to_proto)
            .map(wire_response::Payload::Search)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::MultiSearch(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            let searches = request
                .searches
                .into_iter()
                .map(grpc::search_request_from_proto)
                .collect::<Result<Vec<_>, _>>()?;
            db.multi_search_scoped(
                &request.collection,
                MultiSearchRequest {
                    searches,
                    fusion: grpc::optional_fusion_from_proto(&request.fusion)?,
                    fused_k: grpc::optional_usize_from_u64(request.fused_k, "fused_k")?,
                    weights: request.weights,
                },
                &scope,
            )
            .and_then(|response| {
                Ok(pb::MultiSearchResponse {
                    results: response
                        .results
                        .into_iter()
                        .map(grpc::search_response_to_proto)
                        .collect::<crate::Result<Vec<_>>>()?,
                    fused: response
                        .fused
                        .map(grpc::search_response_to_proto)
                        .transpose()?,
                })
            })
            .map(wire_response::Payload::MultiSearch)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Recommend(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.recommend_scoped(
                &request.collection,
                RecommendRequest {
                    positive: request.positive,
                    negative: request.negative,
                    vector_name: grpc::optional_string(request.vector_name),
                    k: grpc::k_or_default(request.k)?,
                    filter: grpc::filter_from_json(&request.filter_json)?,
                    budget_ms: request.budget_ms,
                },
                &scope,
            )
            .and_then(grpc::search_response_to_proto)
            .map(wire_response::Payload::Search)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Count(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.count_scoped(
                &request.collection,
                grpc::filter_from_json(&request.filter_json)?,
                &scope,
            )
            .map(|response| {
                wire_response::Payload::Count(pb::CountResponse {
                    count: response.count as u64,
                })
            })
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Scroll(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            let offset = grpc::optional_string(request.offset);
            db.scroll_scoped(
                &request.collection,
                offset.as_deref(),
                grpc::scroll_limit_or_default(request.limit)?,
                grpc::filter_from_json(&request.filter_json)?,
                &scope,
            )
            .and_then(|response| {
                Ok(pb::ScrollResponse {
                    points: response
                        .points
                        .into_iter()
                        .map(grpc::point_to_proto)
                        .collect::<crate::Result<Vec<_>>>()?,
                    next_offset: response.next_offset.unwrap_or_default(),
                })
            })
            .map(wire_response::Payload::Scroll)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::Compact(request) => db
            .compact_collection(&request.collection)
            .map(|response| {
                wire_response::Payload::Compact(pb::CompactResponse {
                    collection: response.collection,
                    segment_id: response.segment_id,
                    points: response.points as u64,
                    h2qg_cells: response.h2qg_cells as u64,
                    named_h2qg_fields: response.named_h2qg_fields as u64,
                    sparse_dimensions: response.sparse_dimensions as u64,
                    sparse_postings: response.sparse_postings as u64,
                    payload_fields: response.payload_fields as u64,
                    payload_values: response.payload_values as u64,
                    payload_postings: response.payload_postings as u64,
                    tombstones: response.tombstones as u64,
                    wal_archived_segments: response.wal_archived_segments as u64,
                    wal_archived_bytes: response.wal_archived_bytes,
                    wal_external_archived_segments: response.wal_external_archived_segments as u64,
                    wal_external_archived_bytes: response.wal_external_archived_bytes,
                    wal_archive_command_executed: response.wal_archive_command_executed,
                    wal_object_archived_segments: response.wal_object_archived_segments as u64,
                    wal_object_archived_bytes: response.wal_object_archived_bytes,
                    wal_auto_retained_archives: response.wal_auto_retained_archives as u64,
                    wal_auto_pruned_archives: response.wal_auto_pruned_archives as u64,
                    wal_auto_pruned_bytes: response.wal_auto_pruned_bytes,
                })
            })
            .map_err(grpc::status_from_error),
        wire_request::Operation::TierCold(request) => db
            .tier_collection_to_cold(&request.collection)
            .map(|response| {
                wire_response::Payload::ColdTier(pb::ColdTierResponse {
                    collection: response.collection,
                    segments: response.segments as u64,
                    files: response.files as u64,
                    bytes: response.bytes,
                    points: response.points as u64,
                })
            })
            .map_err(grpc::status_from_error),
        wire_request::Operation::PruneWalArchive(request) => db
            .prune_wal_archive(
                &request.collection,
                grpc::usize_from_u64(request.retain_last, "retain_last")?,
            )
            .map(|response| {
                wire_response::Payload::WalArchivePrune(pb::WalArchivePruneResponse {
                    collection: response.collection,
                    retained_archives: response.retained_archives as u64,
                    pruned_archives: response.pruned_archives as u64,
                    pruned_bytes: response.pruned_bytes,
                })
            })
            .map_err(grpc::status_from_error),
        wire_request::Operation::Snapshot(request) => db
            .snapshot(
                storage_policy
                    .resolve_path(request.path)
                    .map_err(|error| Status::failed_precondition(error.to_string()))?,
            )
            .map(|()| {
                wire_response::Payload::Status(pb::StatusResponse {
                    status: "snapshotted".to_string(),
                })
            })
            .map_err(grpc::status_from_error),
        wire_request::Operation::Restore(request) => {
            let path = storage_policy
                .resolve_path(&request.path)
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            let wal_restore_archive_dir = (!request.wal_restore_archive_dir.is_empty())
                .then(|| {
                    storage_policy
                        .resolve_path(&request.wal_restore_archive_dir)
                        .map_err(|error| Status::invalid_argument(error.to_string()))
                })
                .transpose()?;
            let wal_restore_object_store = grpc::restore_object_store_config(
                storage_policy,
                &request.wal_restore_object_store_dir,
                &request.wal_restore_object_store_url,
            )?;
            db.restore_to_wal_targets_with_archive_sources(
                path,
                &request.target_wal_lsns,
                &request.target_wal_unix_ms,
                wal_restore_archive_dir.as_deref(),
                wal_restore_object_store.as_ref(),
            )
            .map(|()| {
                wire_response::Payload::Status(pb::StatusResponse {
                    status: "restored".to_string(),
                })
            })
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::GetPoints(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            db.get_points_scoped(&request.collection, &request.ids, &scope)
                .and_then(|points| {
                    Ok(pb::GetPointsResponse {
                        points: points
                            .into_iter()
                            .map(grpc::point_to_proto)
                            .collect::<crate::Result<Vec<_>>>()?,
                    })
                })
                .map(wire_response::Payload::GetPoints)
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::SetPayload(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            let payload: serde_json::Value = if request.payload_json.is_empty() {
                serde_json::Value::Object(Default::default())
            } else {
                serde_json::from_str(&request.payload_json)
                    .map_err(|e| Status::invalid_argument(format!("invalid payload_json: {e}")))?
            };
            db.set_payload_scoped(
                &request.collection,
                &request.id,
                payload,
                request.merge,
                &scope,
            )
            .and_then(|point| {
                Ok(pb::SetPayloadResponse {
                    point: Some(grpc::point_to_proto(point)?),
                })
            })
            .map(wire_response::Payload::SetPayload)
            .map_err(grpc::status_from_error)
        }
        wire_request::Operation::DeleteByFilter(request) => {
            let scope = principal.tenant_scope(principal.id.clone());
            let filter: crate::Filter = serde_json::from_str(&request.filter_json)
                .map_err(|e| Status::invalid_argument(format!("invalid filter_json: {e}")))?;
            db.delete_by_filter_scoped(&request.collection, &filter, &scope)
                .map(|deleted| {
                    wire_response::Payload::DeleteByFilter(pb::DeleteByFilterResponse {
                        deleted: deleted as u64,
                    })
                })
                .map_err(grpc::status_from_error)
        }
        wire_request::Operation::ShardMove(_) => {
            db.audit_admin_event(
                "shard_move",
                serde_json::json!({
                    "mode": "single_node_noop",
                    "transport": "wire",
                }),
            )
            .map_err(grpc::status_from_error)?;
            Ok(wire_response::Payload::Status(pb::StatusResponse {
                status: "accepted_single_node_noop".to_string(),
            }))
        }
        wire_request::Operation::Chironql(request) => {
            let mut session = crate::chironql_exec::Session {
                collection: request.collection,
                graph_deferred_session: request
                    .deferred_session_id
                    .map(crate::graph::GraphDeferredSessionId::from_encoded),
            };
            let mut ctx = crate::chironql_exec::ExecContext {
                db,
                session: &mut session,
                role: principal.role,
                allowed_collections: principal
                    .is_restricted()
                    .then(|| principal.allowed_collections().into_iter().collect()),
                want_trace: request.trace,
                confirm: request.confirm,
                tenant: principal.tenant_scope(principal.id.clone()),
            };
            crate::chironql_exec::execute(&mut ctx, &request.query)
                .map(|response| {
                    wire_response::Payload::Chironql(pb::WireChironQlResponse {
                        kind: match response.kind {
                            chirondb_types::chironql::ChironQlKind::Rows => "rows",
                            chirondb_types::chironql::ChironQlKind::Affected => "affected",
                            chirondb_types::chironql::ChironQlKind::Empty => "empty",
                        }
                        .to_string(),
                        columns: response.columns,
                        rows_json: response.rows.iter().map(ToString::to_string).collect(),
                        stats_json: serde_json::to_string(&response.stats)
                            .unwrap_or_else(|_| "{}".to_string()),
                        next: response.next,
                        query_id: response.query_id,
                        trace_json: response
                            .trace
                            .as_ref()
                            .and_then(|trace| serde_json::to_string(trace).ok()),
                    })
                })
                .map_err(grpc::chironql_status)
        }
    }
}

async fn read_frame<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 4];
    if stream.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut len[1..]).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GaussWire frame too large: {len} bytes"),
        ));
    }
    let mut frame = vec![0_u8; len];
    stream.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn write_frame<S, M>(stream: &mut S, message: &M) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    M: Message,
{
    let mut frame = Vec::with_capacity(message.encoded_len());
    message.encode(&mut frame).map_err(std::io::Error::other)?;
    if frame.len() > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GaussWire frame too large: {} bytes", frame.len()),
        ));
    }
    stream
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&frame).await?;
    stream.flush().await
}

async fn client_tls_config(
    ca_cert: PathBuf,
    client_identity: Option<(PathBuf, PathBuf)>,
) -> std::io::Result<ClientConfig> {
    crate::tls::client_config(ca_cert, client_identity).await
}

fn error_response(request_id: u64, status: Status) -> pb::WireResponse {
    let error_details_json = (!status.details().is_empty())
        .then(|| String::from_utf8(status.details().to_vec()).ok())
        .flatten();
    pb::WireResponse {
        request_id,
        error_code: code_name(status.code()).to_string(),
        error_message: status.message().to_string(),
        error_details_json,
        payload: None,
    }
}

fn status_detail_code(status: &Status) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(status.details())
        .ok()?
        .get("code")?
        .as_str()
        .map(str::to_string)
}

fn graph_permission_denied_status(
    capability: crate::graph::GraphCapability,
    collection: &str,
) -> Status {
    let message = format!(
        "{} is required for collection '{collection}'",
        capability.as_str()
    );
    let details = serde_json::to_vec(&serde_json::json!({
        "error": "forbidden",
        "code": "graph.permission_denied",
        "message": message,
    }))
    .unwrap_or_default();
    Status::with_details(Code::PermissionDenied, message, details.into())
}

fn optional_api_key(api_key: &str) -> Option<&str> {
    (!api_key.trim().is_empty()).then_some(api_key)
}

fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::read_frame;

    #[tokio::test]
    async fn empty_stream_is_clean_eof_but_partial_frame_header_is_not() {
        let (mut client, mut server) = tokio::io::duplex(8);
        client.shutdown().await.unwrap();
        assert!(read_frame(&mut server).await.unwrap().is_none());

        let (mut client, mut server) = tokio::io::duplex(8);
        client.write_all(&[0, 0]).await.unwrap();
        client.shutdown().await.unwrap();
        let error = read_frame(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
