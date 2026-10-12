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
use tokio_util::sync::CancellationToken;
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

struct Outbound {
    response: pb::WireResponse,
    _output_admission: Option<crate::response_output::SharedAdmission>,
    guard: Option<crate::chironql_protected::PublicationGuard>,
    _work: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}
impl From<pb::WireResponse> for Outbound {
    fn from(response: pb::WireResponse) -> Self {
        Self {
            response,
            _output_admission: None,
            guard: None,
            _work: None,
        }
    }
}

struct GuardedWriter<'a, W> {
    writer: &'a mut W,
    guard: &'a crate::chironql_protected::PublicationGuard,
}
impl<W: AsyncWrite + Unpin> AsyncWrite for GuardedWriter<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.guard
            .publish(|| Pin::new(&mut *this.writer).poll_write(cx, bytes))
            .unwrap_or_else(|_| {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authorization revoked",
                )))
            })
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .publish(|| Pin::new(&mut *this.writer).poll_flush(cx))
            .unwrap_or_else(|_| {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authorization revoked",
                )))
            })
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().writer).poll_shutdown(cx)
    }
}

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

pub async fn serve_with_auth_and_policy_until(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    storage_policy: StoragePolicy,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener_with_policy_until(db, auth, listener, storage_policy, shutdown).await
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
    serve_listener_with_policy_until(db, auth, listener, storage_policy, CancellationToken::new())
        .await
}

pub async fn serve_listener_with_policy_until(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    storage_policy: StoragePolicy,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => accepted,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "ChironWire connection task panicked");
                }
                continue;
            }
        };
        let (stream, peer) = accepted?;
        let connection = if let Some(authority) = db.identity_authority() {
            let Ok(permit) = authority.wire_connection_pool().try_acquire_owned() else {
                continue;
            };
            Some(permit)
        } else {
            None
        };
        let db = db.clone();
        let auth = auth.clone();
        let storage_policy = storage_policy.clone();
        connections.spawn(async move {
            let _connection = connection;
            if let Err(error) =
                dispatch_by_first_bytes(db, auth, storage_policy, stream, false).await
            {
                tracing::warn!(%error, %peer, "GaussWire connection failed");
            }
        });
    }
    drain_connection_tasks(&mut connections).await;
    Ok(())
}

async fn drain_connection_tasks(connections: &mut JoinSet<()>) {
    let drain = async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "ChironWire connection task panicked during shutdown");
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
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
    tls_verified: bool,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = [0_u8; 8];
    let read = if db.identity_authority().is_some() {
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut prefix))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "protocol preface timed out")
            })?
    } else {
        stream.read_exact(&mut prefix).await
    };
    match read {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(error) => return Err(error),
    }
    if wire_postgres::is_postgres_prefix(&prefix) {
        if db.identity_authority().is_some() {
            if !tls_verified {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "protected PostgreSQL wire requires TLS",
                ));
            }
            return wire_postgres::handle_protected_connection(db, stream, prefix).await;
        }
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

pub async fn serve_tls_config_with_auth_and_policy_until(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    tls: crate::tls::ReloadingTlsConfig,
    storage_policy: StoragePolicy,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_tls_listener_with_acceptor_until(
        db,
        auth,
        listener,
        TlsAcceptor::from(tls.server_config()),
        storage_policy,
        shutdown,
    )
    .await
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
    serve_tls_listener_with_acceptor_until(
        db,
        auth,
        listener,
        acceptor,
        storage_policy,
        CancellationToken::new(),
    )
    .await
}

async fn serve_tls_listener_with_acceptor_until(
    db: Db,
    auth: AuthConfig,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    storage_policy: StoragePolicy,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => accepted,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "ChironWire TLS connection task panicked");
                }
                continue;
            }
        };
        let (stream, peer) = accepted?;
        let (connection, control_only) = if let Some(authority) = db.identity_authority() {
            match authority.wire_connection_pool().try_acquire_owned() {
                Ok(permit) => (Some(permit), false),
                Err(_) => match authority.wire_control_pool().try_acquire_owned() {
                    Ok(permit) => (Some(permit), true),
                    Err(_) => continue,
                },
            }
        } else {
            (None, false)
        };
        let db = db.clone();
        let auth = auth.clone();
        let acceptor = acceptor.clone();
        let storage_policy = storage_policy.clone();
        connections.spawn(async move {
            let _connection = connection;
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
                    if control_only {
                        return dispatch_cancel_connection(db, stream).await;
                    }
                    return dispatch_by_first_bytes(db, auth, storage_policy, stream, true).await;
                }

                if control_only {
                    return Err(std::io::Error::other(
                        "regular connection capacity exhausted",
                    ));
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
                // Direct TLS is ChironWire only. PostgreSQL must first send
                // SSLRequest on the plain socket, then complete TLS.
                dispatch_by_first_bytes(db, auth, storage_policy, stream, false).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, %peer, "GaussWire TLS connection failed");
            }
        });
    }
    drain_connection_tasks(&mut connections).await;
    Ok(())
}

async fn dispatch_cancel_connection<S>(db: Db, mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut prefix))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "cancel preface timed out")
        })??;
    if u32::from_be_bytes(prefix[..4].try_into().expect("fixed length")) != 16
        || u32::from_be_bytes(prefix[4..].try_into().expect("fixed magic"))
            != wire_postgres::CANCEL_REQUEST_MAGIC
    {
        wire_postgres::write_error_response(
            &mut stream,
            "FATAL",
            "53300",
            "regular connection capacity exhausted",
            None,
        )
        .await?;
        stream.shutdown().await?;
        return Ok(());
    }
    wire_postgres::handle_protected_connection(db, stream, prefix).await
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

    loop {
        let (frame, frame_permit) = if let Some(authority) = db.identity_authority() {
            match read_protected_frame(&mut reader, authority.frame_pool()).await? {
                Some((frame, permit)) => (Some(frame), Some(permit)),
                None => (None, None),
            }
        } else {
            (read_frame(&mut reader).await?, None)
        };
        let Some(frame) = frame else {
            break;
        };
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
        if db.is_shutting_down() {
            send_wire_response(
                &response_sender,
                error_response(
                    request.request_id,
                    Status::unavailable("server is shutting down"),
                ),
            )
            .await?;
            break;
        }

        // Unauthenticated frame buffers cannot consume authenticated work capacity.
        let work = if let Some(authority) = db.identity_authority() {
            if let Err(error) = authority.authenticate(&request.api_key) {
                send_wire_response(
                    &response_sender,
                    error_response(
                        request.request_id,
                        crate::grpc_protected::authentication_error(error),
                    ),
                )
                .await?;
                continue;
            }
            Some(Arc::new(
                authority
                    .work_pool()
                    .try_acquire_owned()
                    .map_err(|_| std::io::Error::other("server overloaded"))?,
            ))
        } else {
            None
        };
        drop(frame_permit);

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
                let response =
                    dispatch_request_blocking(db, auth, storage_policy, request, work).await?;
                send_wire_response(&response_sender, response).await
            });
            continue;
        }

        drain_read_tasks(&mut read_tasks).await?;
        let response = dispatch_request_blocking(
            db.clone(),
            auth.clone(),
            storage_policy.clone(),
            request,
            work,
        )
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
    mut receiver: mpsc::Receiver<Outbound>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(response) = receiver.recv().await {
        if let Some(guard) = &response.guard {
            let mut writer = GuardedWriter {
                writer: &mut writer,
                guard,
            };
            tokio::time::timeout(
                Duration::from_secs(10),
                write_frame(&mut writer, &response.response),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "wire output timed out")
            })??;
        } else {
            write_frame(&mut writer, &response.response).await?;
        }
    }
    Ok(())
}

async fn send_wire_response(
    sender: &mpsc::Sender<Outbound>,
    response: impl Into<Outbound>,
) -> std::io::Result<()> {
    sender
        .send(response.into())
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
    match operation {
        Some(wire_request::Operation::Sql(request)) => wire_sql_action(request) == Action::Read,
        Some(wire_request::Operation::SqlTransaction(request)) => {
            wire_sql_transaction_action(request) == Action::Read
        }
        Some(
            wire_request::Operation::Health(_)
            | wire_request::Operation::ListCollections(_)
            | wire_request::Operation::Search(_)
            | wire_request::Operation::HybridSearch(_)
            | wire_request::Operation::TextHybridSearch(_)
            | wire_request::Operation::MultiSearch(_)
            | wire_request::Operation::Recommend(_)
            | wire_request::Operation::Count(_)
            | wire_request::Operation::Scroll(_)
            | wire_request::Operation::GetPoints(_),
        ) => true,
        _ => false,
    }
}

fn wire_sql_action(request: &pb::WireSqlRequest) -> Action {
    match serde_json::from_str::<crate::SqlExecutionRequest>(&request.request_json) {
        Ok(request) if crate::RelationalEngine::request_is_read_only(&request).unwrap_or(false) => {
            Action::Read
        }
        _ => Action::Write,
    }
}

fn wire_sql_transaction_action(request: &pb::WireSqlTransactionRequest) -> Action {
    match request.action.as_str() {
        "begin" | "rollback" => Action::Read,
        "execute" => request
            .request_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<crate::SqlExecutionRequest>(json).ok())
            .filter(|request| {
                crate::RelationalEngine::request_is_read_only(request).unwrap_or(false)
            })
            .map_or(Action::Write, |_| Action::Read),
        _ => Action::Write,
    }
}

async fn dispatch_request_blocking(
    db: Db,
    auth: AuthConfig,
    storage_policy: StoragePolicy,
    request: pb::WireRequest,
    work: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> std::io::Result<Outbound> {
    tokio::task::spawn_blocking(move || {
        if db.identity_authority().is_some() {
            dispatch_protected_request(&db, request, work)
        } else {
            dispatch_request(&db, &auth, &storage_policy, request)
        }
    })
    .await
    .map_err(std::io::Error::other)
}

fn dispatch_protected_request(
    db: &Db,
    request: pb::WireRequest,
    work: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> Outbound {
    let id = request.request_id;
    let result = (|| {
        if work.is_none() {
            return Err(Status::unavailable("admission is missing"));
        }
        let authority = db
            .identity_authority()
            .ok_or_else(|| Status::unavailable("authority unavailable"))?;
        let identity = authority
            .authenticate(&request.api_key)
            .map_err(crate::grpc_protected::authentication_error)?;
        let identity = db
            .management_identity(&identity)
            .map_err(crate::grpc::status_from_error)?;
        let output_admission;
        let (payload, guard) = match request.operation {
            Some(wire_request::Operation::GetPoints(query)) => {
                let context = db
                    .bind_access(
                        &identity,
                        &query.collection,
                        &identity.principal().tenant,
                        crate::security::Action::Read,
                    )
                    .map_err(crate::grpc::status_from_error)?;
                let output = db
                    .get_points_authorized(&context, &query.ids)
                    .map_err(crate::grpc_protected::engine_error)?;
                let guard =
                    crate::chironql_protected::PublicationGuard::Data(output.publication_context());
                let (encoded, admission) = output
                    .publish(crate::response_output::points)
                    .map_err(crate::grpc_protected::engine_error)??;
                output_admission = Some(admission);
                (wire_response::Payload::GetPoints(encoded), guard)
            }
            Some(wire_request::Operation::Scroll(query)) => {
                let context = db
                    .bind_access(
                        &identity,
                        &query.collection,
                        &identity.principal().tenant,
                        crate::security::Action::Read,
                    )
                    .map_err(crate::grpc::status_from_error)?;
                let output = db
                    .scroll_authorized(
                        &context,
                        crate::model::ScrollRequest {
                            offset: crate::grpc::optional_string(query.offset),
                            limit: crate::grpc::scroll_limit_or_default(query.limit)?,
                            filter: crate::grpc::filter_from_json(&query.filter_json)?,
                        },
                    )
                    .map_err(crate::grpc_protected::engine_error)?;
                let guard =
                    crate::chironql_protected::PublicationGuard::Data(output.publication_context());
                let (encoded, admission) = output
                    .publish(crate::response_output::scroll)
                    .map_err(crate::grpc_protected::engine_error)??;
                output_admission = Some(admission);
                (wire_response::Payload::Scroll(encoded), guard)
            }
            Some(wire_request::Operation::TextHybridSearch(query)) => {
                let context = db
                    .bind_access(
                        &identity,
                        &query.collection,
                        &identity.principal().tenant,
                        crate::security::Action::Search,
                    )
                    .map_err(crate::grpc::status_from_error)?;
                let output = db
                    .text_hybrid_search_authorized(
                        &context,
                        crate::grpc::text_hybrid_from_proto(&query)?,
                        Some(identity.cancelled()),
                    )
                    .map_err(crate::grpc_protected::engine_error)?;
                let guard =
                    crate::chironql_protected::PublicationGuard::Data(output.publication_context());
                let (encoded, admission) = output
                    .publish(crate::grpc::protected_hits_to_proto)
                    .map_err(crate::grpc_protected::engine_error)??;
                output_admission = Some(admission);
                (wire_response::Payload::Search(encoded), guard)
            }
            Some(wire_request::Operation::Chironql(query)) => {
                if query.deferred_session_id.is_some() {
                    return Err(Status::permission_denied(
                        "deferred sessions are unavailable",
                    ));
                }
                let output = crate::chironql_protected::execute(
                    db,
                    &request.api_key,
                    &chirondb_types::chironql::ChironQlRequest {
                        query: query.query,
                        collection: query.collection,
                        trace: query.trace,
                        confirm: query.confirm,
                        parameters: query
                            .parameters_json
                            .as_deref()
                            .map(serde_json::from_str::<Vec<crate::RelationalValue>>)
                            .transpose()
                            .map_err(|_| {
                                Status::invalid_argument("invalid ChironQL parameters_json")
                            })?
                            .unwrap_or_default(),
                        idempotency_key: query.idempotency_key,
                        retry_id: query.retry_id,
                    },
                )
                .map_err(crate::grpc_protected::error_status)?;
                let guard = output.guard();
                let (encoded, admission) = output
                    .publish(crate::response_output::chironql)
                    .map_err(|_| Status::permission_denied("authorization was revoked"))??;
                output_admission = Some(admission);
                (
                    wire_response::Payload::Chironql(pb::WireChironQlResponse {
                        kind: encoded.kind,
                        columns: encoded.columns,
                        rows_json: encoded.rows_json,
                        stats_json: encoded.stats_json,
                        next: encoded.next,
                        query_id: encoded.query_id,
                        trace_json: encoded.trace_json,
                        credential_json: encoded.credential_json,
                        column_types_json: encoded.column_types_json,
                        domains: encoded.domains,
                        snapshot_id: encoded.snapshot_id,
                        transaction_id: encoded.transaction_id,
                        committed: encoded.committed,
                    }),
                    guard,
                )
            }
            Some(wire_request::Operation::Sql(sql)) => {
                let sql_request =
                    serde_json::from_str::<crate::SqlExecutionRequest>(&sql.request_json)
                        .map_err(|_| Status::invalid_argument("invalid SQL request"))?;
                let response = db
                    .execute_sql_authorized_owned(&identity, sql_request, "chironwire-protected")
                    .map_err(crate::grpc::status_from_error)?;
                let reference = db
                    .sql_reference_publication_context(&identity, &response.results)
                    .map_err(crate::grpc::status_from_error)?;
                let (response_json, admission) = crate::response_output::wire_json(&response)?;
                output_admission = Some(admission);
                (
                    wire_response::Payload::Sql(pb::WireSqlResponse { response_json }),
                    match reference {
                        Some(context) => crate::chironql_protected::PublicationGuard::Data(context),
                        None => crate::chironql_protected::PublicationGuard::Identity(identity),
                    },
                )
            }
            Some(wire_request::Operation::SqlTransaction(transaction)) => {
                let mut reference = None;
                let (response_json, admission) = match transaction.action.as_str() {
                    "begin" => crate::response_output::wire_json(
                        &db.begin_sql_transaction_authorized(&identity, "chironwire-protected")
                            .map_err(crate::grpc::status_from_error)?,
                    ),
                    "execute" => {
                        let handle = transaction.handle.as_deref().ok_or_else(|| {
                            Status::invalid_argument("transaction handle is required")
                        })?;
                        let sql_request = serde_json::from_str::<crate::SqlExecutionRequest>(
                            transaction.request_json.as_deref().ok_or_else(|| {
                                Status::invalid_argument("transaction request_json is required")
                            })?,
                        )
                        .map_err(|_| Status::invalid_argument("invalid SQL request"))?;
                        let response = db
                            .execute_sql_transaction_authorized_owned(
                                &identity,
                                handle,
                                sql_request,
                                "chironwire-protected",
                            )
                            .map_err(crate::grpc::status_from_error)?;
                        reference = db
                            .sql_reference_publication_context(&identity, &response.results)
                            .map_err(crate::grpc::status_from_error)?;
                        crate::response_output::wire_json(&response)
                    }
                    "commit" => {
                        let handle = transaction.handle.as_deref().ok_or_else(|| {
                            Status::invalid_argument("transaction handle is required")
                        })?;
                        crate::response_output::wire_json(
                            &db.commit_sql_transaction_authorized_owned(
                                &identity,
                                handle,
                                "chironwire-protected",
                            )
                            .map_err(crate::grpc::status_from_error)?,
                        )
                    }
                    "rollback" => {
                        let handle = transaction.handle.as_deref().ok_or_else(|| {
                            Status::invalid_argument("transaction handle is required")
                        })?;
                        crate::response_output::wire_json(
                            &db.rollback_sql_transaction_authorized(
                                &identity,
                                handle,
                                "chironwire-protected",
                            )
                            .map_err(crate::grpc::status_from_error)?,
                        )
                    }
                    action => {
                        return Err(Status::invalid_argument(format!(
                            "unknown SQL transaction action {action}"
                        )));
                    }
                }?;
                output_admission = Some(admission);
                (
                    wire_response::Payload::Sql(pb::WireSqlResponse { response_json }),
                    match reference {
                        Some(context) => crate::chironql_protected::PublicationGuard::Data(context),
                        None => crate::chironql_protected::PublicationGuard::Identity(identity),
                    },
                )
            }
            _ => {
                return Err(Status::permission_denied(
                    "operation is unavailable on protected authority",
                ));
            }
        };
        let response = pb::WireResponse {
            request_id: id,
            error_code: String::new(),
            error_message: String::new(),
            error_details_json: None,
            payload: Some(payload),
        };
        if response.encoded_len() > 8 * 1024 * 1024 {
            return Err(Status::resource_exhausted("output limit exceeded"));
        }
        Ok((response, guard, output_admission))
    })();
    match result {
        Ok((response, guard, admission)) => Outbound {
            response,
            _output_admission: admission,
            guard: Some(guard),
            _work: work,
        },
        Err(status) => Outbound {
            response: error_response(id, status),
            _output_admission: None,
            guard: None,
            _work: work,
        },
    }
}

fn dispatch_request(
    db: &Db,
    auth: &AuthConfig,
    storage_policy: &StoragePolicy,
    request: pb::WireRequest,
) -> Outbound {
    let mut output_admission = None;
    let response = dispatch_request_inner(db, auth, storage_policy, request, &mut output_admission);
    Outbound {
        response,
        _output_admission: output_admission,
        guard: None,
        _work: None,
    }
}

fn dispatch_request_inner(
    db: &Db,
    auth: &AuthConfig,
    storage_policy: &StoragePolicy,
    request: pb::WireRequest,
    output_admission: &mut Option<crate::response_output::SharedAdmission>,
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
    let is_health = matches!(operation, wire_request::Operation::Health(_));
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
    // The constant-time readiness probe must remain available while data work is
    // saturated. Authentication, authorization, rate limiting and audit still apply.
    let _work_permit = if is_health {
        None
    } else {
        let Some(permit) = auth.try_begin_work(&principal) else {
            metrics::counter!("gaussdb_work_limited_requests_total", "transport" => "wire")
                .increment(1);
            return error_response(request_id, Status::resource_exhausted("server overloaded"));
        };
        Some(permit)
    };

    let result = dispatch_operation(
        db,
        &principal,
        storage_policy,
        request.operation,
        output_admission,
    );
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
            Action::Admin,
            request.config.as_ref().map(|config| config.name.as_str()),
        ),
        wire_request::Operation::UpdatePayloadSchema(request) => {
            (Action::Admin, Some(&request.collection))
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
        wire_request::Operation::Compact(request) => (Action::Admin, Some(&request.collection)),
        wire_request::Operation::TierCold(request) => (Action::Admin, Some(&request.collection)),
        wire_request::Operation::PruneWalArchive(request) => {
            (Action::Admin, Some(&request.collection))
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
        wire_request::Operation::Sql(request) => (wire_sql_action(request), None),
        wire_request::Operation::SqlTransaction(request) => {
            (wire_sql_transaction_action(request), None)
        }
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
    output_admission: &mut Option<crate::response_output::SharedAdmission>,
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
            let parameters = request
                .parameters_json
                .as_deref()
                .map(serde_json::from_str::<Vec<crate::RelationalValue>>)
                .transpose()
                .map_err(|_| Status::invalid_argument("invalid ChironQL parameters_json"))?
                .unwrap_or_default();
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
                parameters,
                idempotency_key: request.idempotency_key,
                retry_id: request.retry_id,
                tenant: principal.tenant_scope(principal.id.clone()),
            };
            let value = crate::chironql_exec::execute_owned(&mut ctx, &request.query)
                .map_err(grpc::chironql_status)?;
            let (encoded, admission) = value
                .consume(crate::response_output::chironql)
                .map_err(crate::grpc_protected::engine_error)??;
            *output_admission = Some(admission);
            Ok(wire_response::Payload::Chironql(pb::WireChironQlResponse {
                kind: encoded.kind,
                columns: encoded.columns,
                rows_json: encoded.rows_json,
                stats_json: encoded.stats_json,
                next: encoded.next,
                query_id: encoded.query_id,
                trace_json: encoded.trace_json,
                credential_json: encoded.credential_json,
                column_types_json: encoded.column_types_json,
                domains: encoded.domains,
                snapshot_id: encoded.snapshot_id,
                transaction_id: encoded.transaction_id,
                committed: encoded.committed,
            }))
        }

        wire_request::Operation::Sql(request) => {
            let request = serde_json::from_str::<crate::SqlExecutionRequest>(&request.request_json)
                .map_err(|error| {
                    Status::invalid_argument(format!("invalid SQL request: {error}"))
                })?;
            let action = if db
                .sql_request_is_read_only(&request)
                .map_err(grpc::status_from_error)?
            {
                Action::Read
            } else {
                Action::Write
            };
            authorize(principal, action, None)
                .map_err(|_| Status::permission_denied("operation is not permitted"))?;
            let audit_context = chirondb_core::audit::AuditContext {
                principal_id: principal.id.clone(),
                tenant_id: principal.tenant_id.clone(),
                transport: "chironwire".to_string(),
                request_id: request.retry_id.clone(),
            };
            let response = db
                .execute_sql_with_audit_owned(request, &audit_context)
                .map_err(grpc::status_from_error)?;
            let (response_json, admission) = crate::response_output::wire_json(&response)?;
            *output_admission = Some(admission);
            Ok(wire_response::Payload::Sql(pb::WireSqlResponse {
                response_json,
            }))
        }
        wire_request::Operation::SqlTransaction(request) => {
            let audit_context = chirondb_core::audit::AuditContext {
                principal_id: principal.id.clone(),
                tenant_id: principal.tenant_id.clone(),
                transport: "chironwire".to_string(),
                request_id: request.handle.clone(),
            };
            let (response_json, admission) = match request.action.as_str() {
                "begin" => crate::response_output::wire_json(
                    &db.begin_sql_transaction(&audit_context)
                        .map_err(grpc::status_from_error)?,
                ),
                "execute" => {
                    let handle = request.handle.as_deref().ok_or_else(|| {
                        Status::invalid_argument("transaction handle is required")
                    })?;
                    let sql_request = serde_json::from_str::<crate::SqlExecutionRequest>(
                        request.request_json.as_deref().ok_or_else(|| {
                            Status::invalid_argument("transaction request_json is required")
                        })?,
                    )
                    .map_err(|error| {
                        Status::invalid_argument(format!("invalid SQL request: {error}"))
                    })?;
                    crate::response_output::wire_json(
                        &db.execute_sql_transaction_owned(handle, sql_request, &audit_context)
                            .map_err(grpc::status_from_error)?,
                    )
                }
                "commit" => {
                    let handle = request.handle.as_deref().ok_or_else(|| {
                        Status::invalid_argument("transaction handle is required")
                    })?;
                    crate::response_output::wire_json(
                        &db.commit_sql_transaction_owned(handle, &audit_context)
                            .map_err(grpc::status_from_error)?,
                    )
                }
                "rollback" => {
                    let handle = request.handle.as_deref().ok_or_else(|| {
                        Status::invalid_argument("transaction handle is required")
                    })?;
                    crate::response_output::wire_json(
                        &db.rollback_sql_transaction(handle, &audit_context)
                            .map_err(grpc::status_from_error)?,
                    )
                }
                action => {
                    return Err(Status::invalid_argument(format!(
                        "unknown SQL transaction action {action}"
                    )));
                }
            }?;
            *output_admission = Some(admission);
            Ok(wire_response::Payload::Sql(pb::WireSqlResponse {
                response_json,
            }))
        }
    }
}

async fn read_frame<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    read_frame_with_limit(stream, MAX_FRAME_LEN).await
}

async fn read_frame_with_limit<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let Some(len) = read_frame_length(stream, limit).await? else {
        return Ok(None);
    };
    let mut frame = vec![0_u8; len];
    stream.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn read_protected_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    pool: Arc<tokio::sync::Semaphore>,
) -> std::io::Result<Option<(Vec<u8>, tokio::sync::OwnedSemaphorePermit)>> {
    // Idle connections must not reserve a maximum-sized request buffer.
    let Some(len) = read_frame_length(stream, 8 * 1024 * 1024).await? else {
        return Ok(None);
    };
    let permit = pool
        .try_acquire_owned()
        .map_err(|_| std::io::Error::other("server overloaded"))?;
    let mut frame = vec![0_u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut frame))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "wire frame timed out"))??;
    Ok(Some((frame, permit)))
}

async fn read_frame_length<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> std::io::Result<Option<usize>> {
    let mut len = [0_u8; 4];
    if stream.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut len[1..]).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > limit.min(MAX_FRAME_LEN) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GaussWire frame too large: {len} bytes"),
        ));
    }
    Ok(Some(len))
}

async fn write_frame<S, M>(stream: &mut S, message: &M) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    M: Message,
{
    let length = message.encoded_len();
    if length > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("GaussWire frame too large: {length} bytes"),
        ));
    }
    let mut frame = crate::response_buffer::ResponseBuffer::allocate(length, MAX_FRAME_LEN)
        .map_err(std::io::Error::other)?;
    let mut remaining = frame.as_mut();
    message
        .encode(&mut remaining)
        .map_err(std::io::Error::other)?;
    if !remaining.is_empty() {
        return Err(std::io::Error::other(
            "wire message length changed during encoding",
        ));
    }
    stream.write_all(&(length as u32).to_be_bytes()).await?;
    stream.write_all(frame.as_ref()).await?;
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
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    use super::{read_frame, read_protected_frame, serve_listener_with_policy_until};

    #[test]
    fn legacy_health_preserves_authentication_when_data_work_is_saturated() {
        let data = tempfile::tempdir().unwrap();
        let db = crate::Db::open(data.path()).unwrap();
        let auth = crate::auth::AuthConfig::from_optional_key(Some("health-key".into()));
        let principal = auth.permission_for(Some("health-key")).unwrap();
        let mut permits = Vec::new();
        while let Some(permit) = auth.try_begin_work(&principal) {
            permits.push(permit);
        }
        assert!(!permits.is_empty());
        let policy = crate::security_paths::StoragePolicy::default();
        let request = |id, key: &str, operation| super::pb::WireRequest {
            request_id: id,
            api_key: key.into(),
            operation: Some(operation),
        };
        let health = super::dispatch_request(
            &db,
            &auth,
            &policy,
            request(
                1,
                "health-key",
                super::wire_request::Operation::Health(super::pb::HealthRequest {}),
            ),
        )
        .response;
        assert!(health.error_code.is_empty(), "{health:?}");
        assert!(matches!(
            health.payload,
            Some(super::wire_response::Payload::Health(_))
        ));
        let denied = super::dispatch_request(
            &db,
            &auth,
            &policy,
            request(
                2,
                "",
                super::wire_request::Operation::Health(super::pb::HealthRequest {}),
            ),
        )
        .response;
        assert_eq!(denied.error_code, "UNAUTHENTICATED");
        let query = super::dispatch_request(
            &db,
            &auth,
            &policy,
            request(
                3,
                "health-key",
                super::wire_request::Operation::ListCollections(
                    super::pb::ListCollectionsRequest {},
                ),
            ),
        )
        .response;
        assert_eq!(query.error_code, "RESOURCE_EXHAUSTED");
        assert!(auth.try_begin_work(&principal).is_none());
        drop(permits);
        assert!(auth.try_begin_work(&principal).is_some());
    }

    #[tokio::test]
    async fn wire_output_checks_size_before_encoder_and_fixed_frame_roundtrips() {
        struct Oversized;
        impl prost::Message for Oversized {
            fn encoded_len(&self) -> usize {
                super::MAX_FRAME_LEN + 1
            }
            fn encode_raw(&self, _: &mut impl prost::bytes::BufMut) {
                panic!("oversized output must not invoke encoder");
            }
            fn merge_field(
                &mut self,
                tag: u32,
                wire: prost::encoding::WireType,
                buffer: &mut impl prost::bytes::Buf,
                context: prost::encoding::DecodeContext,
            ) -> Result<(), prost::DecodeError> {
                prost::encoding::skip_field(wire, tag, buffer, context)
            }
            fn clear(&mut self) {}
        }
        let mut writer = Vec::new();
        let error = super::write_frame(&mut writer, &Oversized)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(writer.is_empty());
        let message = super::pb::WireResponse {
            request_id: 17,
            error_code: String::new(),
            error_message: String::new(),
            error_details_json: None,
            payload: Some(super::wire_response::Payload::Search(
                super::pb::SearchResponse {
                    hits: vec![super::pb::SearchHit {
                        id: "日本語".into(),
                        score: -0.0,
                        payload_json: "{\"text\":\"allowed\"}".into(),
                    }],
                    ..Default::default()
                },
            )),
        };
        super::write_frame(&mut writer, &message).await.unwrap();
        let length = u32::from_be_bytes(writer[..4].try_into().unwrap()) as usize;
        assert_eq!(length, prost::Message::encoded_len(&message));
        let decoded: super::pb::WireResponse = prost::Message::decode(&writer[4..]).unwrap();
        assert_eq!(decoded, message);
    }

    #[tokio::test]
    async fn protected_frames_reserve_after_header_and_release_on_abort() {
        let pool = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let (mut client, mut server) = tokio::io::duplex(32);
        let reader_pool = pool.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            started.send(()).unwrap();
            read_protected_frame(&mut server, reader_pool).await
        });
        ready.await.unwrap();
        assert_eq!(
            pool.available_permits(),
            1,
            "idle socket holds no frame slot"
        );
        client.write_all(&4u32.to_be_bytes()).await.unwrap();
        client.write_all(b"test").await.unwrap();
        let frame = reader.await.unwrap().unwrap().unwrap();
        assert_eq!(frame.0, b"test");
        assert_eq!(pool.available_permits(), 0);
        drop(frame);
        assert_eq!(pool.available_permits(), 1);

        let occupied = pool.clone().acquire_owned().await.unwrap();
        let (mut client, mut server) = tokio::io::duplex(8);
        client
            .write_all(&(8u32 * 1024 * 1024).to_be_bytes())
            .await
            .unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            read_protected_frame(&mut server, pool.clone()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "server overloaded",
            "reject before waiting for or allocating the payload"
        );
        drop(occupied);

        let (mut client, mut server) = tokio::io::duplex(8);
        client.write_all(&4096u32.to_be_bytes()).await.unwrap();
        let reader_pool = pool.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            started.send(()).unwrap();
            read_protected_frame(&mut server, reader_pool).await
        });
        ready.await.unwrap();
        assert_eq!(pool.available_permits(), 0);
        reader.abort();
        assert!(reader.await.unwrap_err().is_cancelled());
        assert_eq!(
            pool.available_permits(),
            1,
            "interrupted payload read releases reservation"
        );
    }

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

    #[tokio::test]
    async fn shutdown_cancels_an_idle_connection_within_the_protocol_deadline() {
        let directory = tempfile::TempDir::new().unwrap();
        let db = crate::Db::open(directory.path()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(async move {
            serve_listener_with_policy_until(
                db,
                crate::auth::AuthConfig::disabled(),
                listener,
                crate::security_paths::StoragePolicy::default(),
                server_shutdown,
            )
            .await
        });
        let _idle = tokio::net::TcpStream::connect(address).await.unwrap();
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(6), server)
            .await
            .expect("wire shutdown exceeded protocol deadline")
            .unwrap()
            .unwrap();
    }
}

#[cfg(test)]
mod protected_publication_tests {
    use super::*;
    #[tokio::test]
    async fn queued_wire_point_response_revoke_releases_receiving_admission() {
        let (_directory, authority, key) = crate::chironql_protected::tests::identity_fixture();
        let identity = authority.authenticate(&key.secret).unwrap();
        let (message, admission) = crate::response_output::points(vec![crate::Point {
            id: "visible".into(),
            vector: vec![1.0],
            vectors: Default::default(),
            sparse_vector: None,
            payload: serde_json::json!({"text":"visible"}),
        }])
        .unwrap();
        let weak = Arc::downgrade(&admission);
        let reply = Outbound {
            response: pb::WireResponse {
                request_id: 1,
                error_code: String::new(),
                error_message: String::new(),
                error_details_json: None,
                payload: Some(wire_response::Payload::GetPoints(message)),
            },
            _output_admission: Some(admission),
            guard: Some(crate::chironql_protected::PublicationGuard::Identity(
                identity.clone(),
            )),
            _work: Some(Arc::new(authority.work_pool().try_acquire_owned().unwrap())),
        };
        let (sender, receiver) = mpsc::channel(1);
        sender.send(reply).await.unwrap();
        drop(sender);
        assert!(weak.upgrade().is_some());
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        let mut bytes = Vec::new();
        assert!(write_responses(&mut bytes, receiver).await.is_err());
        assert!(bytes.is_empty());
        assert!(weak.upgrade().is_none());
        assert_eq!(
            authority.work_pool().available_permits(),
            crate::resource_profile::current().query_workers
        );
    }

    #[tokio::test]
    async fn queued_wire_sql_revoke_releases_json_and_codec_admission() {
        let (_directory, authority, key) = crate::chironql_protected::tests::identity_fixture();
        let identity = authority.authenticate(&key.secret).unwrap();
        let (json, admission) = crate::response_output::wire_json(
            &serde_json::json!({"results":[{"kind":"rows","rows":[["secret"]]}]}),
        )
        .unwrap();
        let weak = Arc::downgrade(&admission);
        let reply = Outbound {
            response: pb::WireResponse {
                request_id: 1,
                error_code: String::new(),
                error_message: String::new(),
                error_details_json: None,
                payload: Some(wire_response::Payload::Sql(pb::WireSqlResponse {
                    response_json: json,
                })),
            },
            _output_admission: Some(admission),
            guard: Some(crate::chironql_protected::PublicationGuard::Identity(
                identity.clone(),
            )),
            _work: None,
        };
        let (sender, receiver) = mpsc::channel(1);
        sender.send(reply).await.unwrap();
        drop(sender);
        assert!(weak.upgrade().is_some());
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        let mut bytes = Vec::new();
        assert!(write_responses(&mut bytes, receiver).await.is_err());
        assert!(bytes.is_empty());
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn queued_wire_reply_cannot_write_after_acknowledged_revocation() {
        let (_directory, authority, key) = crate::chironql_protected::tests::identity_fixture();
        let identity = authority.authenticate(&key.secret).unwrap();
        let guard = crate::chironql_protected::PublicationGuard::Identity(identity.clone());
        let mut bytes = Vec::new();
        let mut writer = GuardedWriter {
            writer: &mut bytes,
            guard: &guard,
        };
        writer.write_all(b"before-revoke").await.unwrap();
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        assert!(writer.write_all(b"after-revoke").await.is_err());
        assert!(writer.flush().await.is_err());
        assert_eq!(bytes, b"before-revoke");
    }
}
