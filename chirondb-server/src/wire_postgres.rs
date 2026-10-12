//! Postgres v3 frontend/backend protocol — pgvector wire compatibility layer.
//!
//! B1 of `.SPEC/gaussdb-vector_cleaned.md`. Spec: `.SPEC/gaussdb-vector_cleaned.md` §2.
//!
//! Scope of this module today:
//! - Postgres v3 message framing (1-byte type + 4-byte BE length + payload,
//!   StartupMessage has no type byte).
//! - StartupMessage parse + parameter capture.
//! - SSL request response: refuse with `'N'`, continue plaintext.
//! - AuthenticationCleartextPassword when auth is enabled; password is checked
//!   against the existing `AuthConfig` keyring. AuthenticationOk when auth is
//!   disabled.
//! - Required `ParameterStatus` keys: `server_version`, `client_encoding`,
//!   `DateStyle`, `TimeZone`, `integer_datetimes`, `server_encoding`,
//!   `standard_conforming_strings`.
//! - `BackendKeyData` with a random PID + secret.
//! - `ReadyForQuery 'I'` (idle, no transaction).
//! - `Query` routes the six-shape pgvector compatibility profile or native
//!   relational SQL to their shared `Db` engines and returns stable SQLSTATEs.
//! - `Terminate ('X')` for clean shutdown so `psql \q` lands clean.
//!
//! Native relational SQL also supports the PostgreSQL extended query lifecycle.
//! `COPY`, `NOTIFY`, and the replication subprotocol remain outside the profile.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{
    Arc, LazyLock, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Db;
use crate::auth::AuthConfig;
use crate::pg_catalog;
use crate::pgvector_exec::{self, ColumnSpec, ExecError, PgType, QueryResponse, SessionState};
use crate::pgvector_parser::{self, ParseError, Statement};
use crate::rbac::{Action, Permission, authorize};
mod frontend;
mod memory;
mod output;
mod protected;
mod scram;
pub use protected::handle_protected_connection;

/// Postgres v3.0 protocol version constant.
pub const PROTOCOL_V3: u32 = 196_608; // 0x00030000

/// `SSLRequest` magic. Sent by libpq before the real StartupMessage when
/// `sslmode=prefer` or `require`.
pub const SSL_REQUEST_MAGIC: u32 = 80_877_103;

/// `GSSENCRequest` magic. Also sent before the StartupMessage by libpq builds
/// that enable GSSAPI.
pub const GSSENC_REQUEST_MAGIC: u32 = 80_877_104;

/// PostgreSQL `CancelRequest` magic.
pub const CANCEL_REQUEST_MAGIC: u32 = 80_877_102;

/// Max length of any single message we accept. Mirrors the GaussWire path.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct BackendCancellation {
    active: AtomicBool,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug)]
struct BackendCancellationEntry {
    secret: u32,
    state: Weak<BackendCancellation>,
}

static BACKEND_CANCELLATIONS: LazyLock<Mutex<BTreeMap<u32, BackendCancellationEntry>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

struct BackendRegistration {
    pid: u32,
    secret: u32,
    state: Arc<BackendCancellation>,
    _memory: crate::response_buffer::ResponseReservation,
}

impl BackendRegistration {
    fn begin_query(&self) -> ActiveQuery<'_> {
        self.state.cancelled.store(false, Ordering::Release);
        self.state.active.store(true, Ordering::Release);
        ActiveQuery { state: &self.state }
    }
}

impl Drop for BackendRegistration {
    fn drop(&mut self) {
        let mut registry = BACKEND_CANCELLATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry
            .get(&self.pid)
            .is_some_and(|entry| entry.secret == self.secret)
        {
            registry.remove(&self.pid);
            if registry.is_empty() {
                *registry = BTreeMap::new();
            }
        }
    }
}

struct ActiveQuery<'a> {
    state: &'a BackendCancellation,
}

impl Drop for ActiveQuery<'_> {
    fn drop(&mut self) {
        self.state.active.store(false, Ordering::Release);
        // A timed-out handler can still have a blocking worker unwinding.
        // Preserve its cancellation until begin_query starts a new request.
    }
}

#[derive(Clone, Debug)]
struct NativePreparedStatement {
    sql: String,
    parameter_oids: Vec<u32>,
    analysis: crate::SqlStatementAnalysis,
    catalog: bool,
    session_compat: Option<SessionCompatStatement>,
    _memory: Option<Arc<memory::Charge>>,
}

#[derive(Clone, Debug)]
enum SessionCompatStatement {
    Set,
    Parsed(Statement),
}

#[derive(Debug)]
struct NativePortal {
    statement_name: String,
    statement: Arc<NativePreparedStatement>,
    parameters: Vec<crate::RelationalValue>,
    result_formats: Vec<i16>,
    described_response: Option<Arc<crate::SqlResponse>>,
    described_catalog_response: Option<pg_catalog::CatalogResponse>,
    described_metadata: bool,
    _memory: Option<Arc<memory::Charge>>,
}

struct NativeExecutionInput<'a> {
    parameters: &'a [crate::RelationalValue],
    result_formats: &'a [i16],
    cancellation: Arc<AtomicBool>,
    memory: &'a memory::SessionMemory,
}

#[derive(Clone, Debug)]
struct PgRelationalTransaction {
    handle: String,
    failed: bool,
}

/// An open private transaction belongs to its connection. Cleanup also runs on
/// I/O failure or future/task cancellation; it must not wait for a client reply.
struct ConnectionTransaction {
    value: Option<PgRelationalTransaction>,
    db: Db,
    audit: chirondb_core::audit::AuditContext,
    _memory: crate::response_buffer::ResponseReservation,
}
impl ConnectionTransaction {
    fn new(db: &Db, principal: &str, tenant: Option<&str>, transport: &str) -> io::Result<Self> {
        let bytes = 4096_u64
            .checked_add(principal.len() as u64)
            .and_then(|n| n.checked_add(tenant.map_or(0, str::len) as u64))
            .and_then(|n| n.checked_add(transport.len() as u64))
            .ok_or_else(|| io::Error::other("transaction owner memory limit exceeded"))?;
        let memory =
            crate::response_buffer::ResponseReservation::new(bytes).map_err(io::Error::other)?;
        Ok(Self {
            value: None,
            db: db.clone(),
            audit: chirondb_core::audit::AuditContext {
                principal_id: principal.into(),
                tenant_id: tenant.map(str::to_owned),
                transport: transport.into(),
                request_id: None,
            },
            _memory: memory,
        })
    }
}
impl std::ops::Deref for ConnectionTransaction {
    type Target = Option<PgRelationalTransaction>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl std::ops::DerefMut for ConnectionTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}
impl Drop for ConnectionTransaction {
    fn drop(&mut self) {
        if let Some(active) = self.value.take() {
            self.audit.request_id = Some(active.handle.clone());
            let _ = self
                .db
                .rollback_sql_transaction(&active.handle, &self.audit);
        }
    }
}

/// Postgres advertises this server_version to clients. Marked as a gaussdb-pgvector
/// shim so libpq/psycopg3/JDBC users can recognise it in `\conninfo` and logs.
pub const SERVER_VERSION_STRING: &str = "16.0 (gaussdb-pgvector-shim)";

/// Hint URL fragment for the unsupported-feature `Hint` field. Matches the
/// taxonomy laid out in `.SPEC/gaussdb-vector_cleaned.md` §3.0.1.
pub const COMPAT_HINT_BASE: &str = "https://docs.gaussdb/pgvector-compat";

/// Detect whether a buffered 8-byte prefix is a Postgres v3 client. Caller
/// keeps the bytes — the sniff is non-destructive.
pub fn is_postgres_prefix(prefix: &[u8; 8]) -> bool {
    let length = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    let magic = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    // length must include itself + the 4-byte magic, so >= 8. StartupMessage
    // bodies are bounded by MAX_MESSAGE_LEN.
    if (length as usize) < 8 || (length as usize) > MAX_MESSAGE_LEN {
        return false;
    }
    matches!(
        magic,
        PROTOCOL_V3 | SSL_REQUEST_MAGIC | GSSENC_REQUEST_MAGIC | CANCEL_REQUEST_MAGIC
    )
}

/// Drive one Postgres v3 connection through startup → idle → terminate.
///
/// `prefix` is the 8 bytes already consumed by the sniff in
/// `wire::serve_listener_with_auth`; the first 4 bytes are the StartupMessage
/// length (including itself), the next 4 are the protocol/magic word.
pub async fn handle_connection<S>(
    db: Db,
    auth: AuthConfig,
    stream: S,
    prefix: [u8; 8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut length = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    let mut magic = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);

    // Burn through any number of SSL / GSS / Cancel preludes that may precede
    // the actual StartupMessage. libpq sends exactly one prelude max, but we're
    // defensive against future libpq quirks.
    loop {
        match magic {
            SSL_REQUEST_MAGIC | GSSENC_REQUEST_MAGIC => {
                writer.write_all(b"N").await?;
                writer.flush().await?;
                // Next message must be StartupMessage (8-byte header + body).
                let mut hdr = [0_u8; 8];
                reader.read_exact(&mut hdr).await?;
                length = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                magic = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                continue;
            }
            CANCEL_REQUEST_MAGIC => {
                if length != 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid CancelRequest length {length}"),
                    ));
                }
                let mut payload = [0_u8; 8];
                reader.read_exact(&mut payload).await?;
                let pid = u32::from_be_bytes(payload[..4].try_into().expect("four bytes"));
                let secret = u32::from_be_bytes(payload[4..].try_into().expect("four bytes"));
                cancel_backend(pid, secret);
                return Ok(());
            }
            PROTOCOL_V3 => break,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported postgres protocol/magic 0x{other:08x}"),
                ));
            }
        }
    }

    // Read remaining StartupMessage body (length includes the 8 header bytes).
    if !(8..=MAX_MESSAGE_LEN).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid startup length {length}"),
        ));
    }
    let memory = memory::SessionMemory::new();
    let body = output::prepare(
        &mut writer,
        frontend::read(&mut reader, length - 8, MAX_MESSAGE_LEN).await,
    )
    .await?;
    let params = output::prepare(&mut writer, frontend::startup(body.as_ref(), &memory)).await?;
    drop(body);
    drop(params);

    // Auth: cleartext password = API key. If auth disabled, resolve the local
    // compatibility principal. Secure listener policy prevents this exchange
    // from running on a public plaintext socket.
    let principal = if auth.is_enabled() {
        write_auth_cleartext_password(&mut writer).await?;
        let password =
            output::prepare(&mut writer, read_password_message(&mut reader).await).await?;
        let bytes = password.as_ref().split(|&b| b == 0).next().unwrap_or(&[]);
        let password = std::str::from_utf8(bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "password is not valid UTF-8")
        })?;
        let principal = auth.permission_for(Some(password));
        if principal.is_none() {
            if db
                .audit_access_event(
                    "authentication",
                    "pgwire_authenticate",
                    "failure",
                    None,
                    "unknown",
                    None,
                    "pgwire",
                    None,
                    Some("invalid_credential"),
                )
                .is_err()
            {
                write_error_response(&mut writer, "FATAL", "58030", "audit unavailable", None)
                    .await?;
                writer.flush().await?;
                return Ok(());
            }
            write_error_response(
                &mut writer,
                "FATAL",
                "28P01",
                "password authentication failed",
                None,
            )
            .await?;
            writer.flush().await?;
            return Ok(());
        }
        principal.expect("checked above")
    } else {
        auth.permission_for(None).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "principal resolution failed",
            )
        })?
    };

    if db
        .audit_access_event(
            "authentication",
            "pgwire_authenticate",
            "success",
            None,
            &principal.id,
            principal.tenant_id.as_deref(),
            "pgwire",
            None,
            None,
        )
        .is_err()
    {
        write_error_response(&mut writer, "FATAL", "58030", "audit unavailable", None).await?;
        writer.flush().await?;
        return Ok(());
    }

    let _session_memory = match frontend::session(&memory) {
        Ok(memory) => memory,
        Err((state, message)) => {
            write_error_response(&mut writer, "FATAL", state, &message, None).await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    write_auth_ok(&mut writer).await?;
    write_required_parameter_status(&mut writer).await?;
    let backend = output::prepare(&mut writer, register_backend()).await?;
    write_backend_key_data(&mut writer, backend.pid, backend.secret).await?;
    write_ready_for_query(&mut writer, b'I').await?;
    writer.flush().await?;

    let session = SessionState::new();
    let mut prepared_statements = HashMap::<String, Arc<NativePreparedStatement>>::with_capacity(
        frontend::MAX_SESSION_OBJECTS,
    );
    let mut portals = HashMap::<String, NativePortal>::with_capacity(frontend::MAX_SESSION_OBJECTS);
    let mut extended_failed = false;
    let mut relational_transaction =
        ConnectionTransaction::new(&db, &principal.id, principal.tenant_id.as_deref(), "pgwire")?;

    // Main loop.
    loop {
        let mut hdr = [0_u8; 5];
        match reader.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let msg_type = hdr[0];
        let msg_len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if !(4..=MAX_MESSAGE_LEN).contains(&msg_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid pg message length {msg_len}"),
            ));
        }
        if matches!(msg_type, b'S' | b'H' | b'X') && msg_len != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control frame must be empty",
            ));
        }
        if msg_type == b'X' {
            return Ok(());
        }
        if extended_failed {
            if let Some(transaction) = relational_transaction.as_mut() {
                transaction.failed = true;
            }
            if msg_type != b'S' && msg_type != b'X' {
                frontend::discard(&mut reader, msg_len - 4).await?;
                continue;
            }
        }
        let payload = if msg_len > 4 {
            Some(
                output::prepare(
                    &mut writer,
                    frontend::read(&mut reader, msg_len - 4, MAX_MESSAGE_LEN).await,
                )
                .await?,
            )
        } else {
            None
        };
        let payload = payload.as_ref().map_or(&[][..], AsRef::as_ref);

        match msg_type {
            b'Q' => {
                // Simple query. Strip trailing NUL.
                let sql = parse_cstring_in_place(payload);
                // Retain the direct SQL request copy through synchronous engine
                // execution. Parser/catalog scratch keeps a separate lifetime.
                let _sql_copy_memory = match memory.reserve(sql.len().saturating_add(4096)) {
                    Ok(charge) => charge,
                    Err((state, message)) => {
                        if let Some(transaction) = relational_transaction.as_mut() {
                            transaction.failed = true;
                        }
                        write_error_response(&mut writer, "ERROR", state, &message, None).await?;
                        write_ready_for_query(
                            &mut writer,
                            if relational_transaction.is_some() {
                                b'E'
                            } else {
                                b'I'
                            },
                        )
                        .await?;
                        writer.flush().await?;
                        continue;
                    }
                };
                let _active_query = backend.begin_query();
                if !auth.allows_principal_request(&principal) {
                    write_error_response(
                        &mut writer,
                        "ERROR",
                        "53300",
                        "rate limit exceeded",
                        None,
                    )
                    .await?;
                } else if let Some(_work_permit) = auth.try_begin_work(&principal) {
                    match parse_deallocate_query(sql) {
                        Ok(Some(_))
                            if relational_transaction
                                .as_ref()
                                .is_some_and(|txn| txn.failed) =>
                        {
                            write_error_response(
                                &mut writer,
                                "ERROR",
                                "25P02",
                                "current transaction is aborted; commands ignored until end of transaction block",
                                None,
                            )
                            .await?;
                        }
                        Ok(Some(target)) => {
                            let found = apply_deallocate_target(
                                target,
                                &mut prepared_statements,
                                &mut portals,
                            );
                            if found {
                                write_command_complete(&mut writer, "DEALLOCATE").await?;
                            } else {
                                if let Some(transaction) = relational_transaction.as_mut() {
                                    transaction.failed = true;
                                }
                                write_error_response(
                                    &mut writer,
                                    "ERROR",
                                    "26000",
                                    "prepared statement does not exist",
                                    None,
                                )
                                .await?;
                            }
                        }
                        Err(message) => {
                            if let Some(transaction) = relational_transaction.as_mut() {
                                transaction.failed = true;
                            }
                            write_error_response(&mut writer, "ERROR", "42601", &message, None)
                                .await?;
                        }
                        Ok(None)
                            if relational_transaction.is_some()
                                || is_transaction_control_sql(sql) =>
                        {
                            handle_pg_relational_transaction_query(
                                &db,
                                &principal,
                                &mut relational_transaction,
                                &mut writer,
                                sql,
                                backend.state.cancelled.clone(),
                            )
                            .await?;
                        }
                        Ok(None) => {
                            handle_query(
                                &db,
                                &principal,
                                &session,
                                &memory,
                                &mut writer,
                                sql,
                                backend.state.cancelled.clone(),
                            )
                            .await?;
                        }
                    }
                } else {
                    metrics::counter!(
                        "gaussdb_work_limited_requests_total",
                        "transport" => "pgwire"
                    )
                    .increment(1);
                    write_error_response(&mut writer, "ERROR", "53300", "server overloaded", None)
                        .await?;
                }
                let transaction_status =
                    relational_transaction.as_ref().map_or(b'I', |transaction| {
                        if transaction.failed { b'E' } else { b'T' }
                    });
                write_ready_for_query(&mut writer, transaction_status).await?;
                writer.flush().await?;
            }
            b'X' => {
                // Terminate — clean shutdown.
                return Ok(());
            }
            b'P' => {
                match parse_native_parse_message_admitted(
                    payload,
                    &db,
                    relational_transaction.is_some(),
                    Some(&memory),
                ) {
                    Ok((name, statement)) => {
                        if prepared_statements.len() >= frontend::MAX_SESSION_OBJECTS
                            && !prepared_statements.contains_key(&name)
                        {
                            write_error_response(
                                &mut writer,
                                "ERROR",
                                "54000",
                                "prepared statement limit reached",
                                None,
                            )
                            .await?;
                            extended_failed = true;
                            continue;
                        }
                        prepared_statements.insert(name, statement);
                        write_message(&mut writer, b'1', &[]).await?;
                    }
                    Err((sqlstate, message)) => {
                        write_error_response(&mut writer, "ERROR", sqlstate, &message, None)
                            .await?;
                        extended_failed = true;
                    }
                }
            }
            b'B' => match parse_native_bind_message_admitted(
                payload,
                &prepared_statements,
                Some(&memory),
            ) {
                Ok((name, portal)) => {
                    if portals.len() >= frontend::MAX_SESSION_OBJECTS
                        && !portals.contains_key(&name)
                    {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "54000",
                            "portal limit reached",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                        continue;
                    }
                    portals.insert(name, portal);
                    write_message(&mut writer, b'2', &[]).await?;
                }
                Err((sqlstate, message)) => {
                    write_error_response(&mut writer, "ERROR", sqlstate, &message, None).await?;
                    extended_failed = true;
                }
            },
            b'D' => match parse_describe_message(payload) {
                Ok((b'S', name)) => {
                    if let Some(statement) = prepared_statements.get(name) {
                        write_parameter_description(&mut writer, &statement.parameter_oids).await?;
                        write_message(&mut writer, b'n', &[]).await?;
                    } else {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "26000",
                            "prepared statement does not exist",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                    }
                }
                Ok((b'P', name)) => {
                    let _active_query = backend.begin_query();
                    let Some(portal) = portals.get_mut(name) else {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "34000",
                            "portal does not exist",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                        continue;
                    };
                    if let Some(statement) = portal.statement.session_compat.clone() {
                        if authorize(&principal, Action::Read, None).is_err() {
                            write_permission_denied(&mut writer).await?;
                            extended_failed = true;
                            continue;
                        }
                        match execute_session_compat_statement(&db, &session, &principal, statement)
                        {
                            Ok(response) => {
                                let response = output::prepare(
                                    &mut writer,
                                    pg_catalog::CatalogResponse::retain_existing(response)
                                        .map_err(|_| output::full()),
                                )
                                .await?;
                                write_catalog_description_formatted(
                                    &mut writer,
                                    &response,
                                    &portal.result_formats,
                                )
                                .await?;
                                portal.described_catalog_response = Some(response);
                            }
                            Err(error) => {
                                write_exec_error(&mut writer, &error).await?;
                                extended_failed = true;
                            }
                        }
                        continue;
                    }
                    if portal.statement.catalog {
                        match execute_catalog_query(
                            &db,
                            &principal,
                            &mut writer,
                            &portal.statement.sql,
                            &portal.parameters,
                        )
                        .await?
                        {
                            Some(response) => {
                                write_catalog_description_formatted(
                                    &mut writer,
                                    &response,
                                    &portal.result_formats,
                                )
                                .await?;
                                portal.described_catalog_response = Some(response);
                            }
                            None => extended_failed = true,
                        }
                        continue;
                    }
                    if portal.statement.analysis.class != crate::SqlStatementClass::Read {
                        write_message(&mut writer, b'n', &[]).await?;
                        continue;
                    }
                    if authorize(&principal, Action::Read, None).is_err() {
                        write_permission_denied(&mut writer).await?;
                        extended_failed = true;
                        continue;
                    }
                    let audit_context = chirondb_core::audit::AuditContext {
                        principal_id: principal.id.clone(),
                        tenant_id: principal.tenant_id.clone(),
                        transport: "pgwire".to_string(),
                        request_id: None,
                    };
                    let (request, _request_memory) =
                        match frontend::request(&portal.statement.sql, &portal.parameters, &memory)
                        {
                            Ok(request) => request,
                            Err((state, message)) => {
                                write_error_response(&mut writer, "ERROR", state, &message, None)
                                    .await?;
                                extended_failed = true;
                                continue;
                            }
                        };
                    let response = if let Some(transaction) = relational_transaction.as_ref() {
                        db.execute_sql_transaction_cancellable_owned(
                            &transaction.handle,
                            request,
                            &audit_context,
                            backend.state.cancelled.clone(),
                        )
                    } else {
                        db.execute_sql_with_audit_cancellable_owned(
                            request,
                            &audit_context,
                            backend.state.cancelled.clone(),
                        )
                    };
                    match response {
                        Ok(response) => {
                            if let Some(columns) = output::prepare(
                                &mut writer,
                                native_result_columns(&response.results),
                            )
                            .await?
                            {
                                let formats = output::prepare(
                                    &mut writer,
                                    expand_result_formats(&portal.result_formats, columns.len()),
                                )
                                .await?;
                                write_row_description_formatted(&mut writer, &columns, &formats)
                                    .await?;
                            } else {
                                write_message(&mut writer, b'n', &[]).await?;
                            }
                            portal.described_response = Some(Arc::new(response));
                        }
                        Err(error) => {
                            if let Some(transaction) = relational_transaction.as_mut() {
                                transaction.failed = true;
                            }
                            write_native_relational_error(&mut writer, &error).await?;
                            extended_failed = true;
                        }
                    }
                }
                Ok(_) | Err(_) => {
                    write_error_response(
                        &mut writer,
                        "ERROR",
                        "08P01",
                        "Describe target must be S or P",
                        None,
                    )
                    .await?;
                    extended_failed = true;
                }
            },
            b'E' => match parse_execute_message(payload) {
                Ok((portal_name, 0)) => {
                    let _active_query = backend.begin_query();
                    let Some(portal) = portals.get(portal_name) else {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "34000",
                            "portal does not exist",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                        continue;
                    };
                    if let Some(response) = &portal.described_catalog_response {
                        write_catalog_response_formatted(
                            &mut writer,
                            response,
                            false,
                            &portal.result_formats,
                        )
                        .await?;
                    } else if portal.statement.catalog {
                        match execute_catalog_query(
                            &db,
                            &principal,
                            &mut writer,
                            &portal.statement.sql,
                            &portal.parameters,
                        )
                        .await?
                        {
                            Some(response) => {
                                write_catalog_response_formatted(
                                    &mut writer,
                                    &response,
                                    true,
                                    &portal.result_formats,
                                )
                                .await?
                            }
                            None => extended_failed = true,
                        }
                    } else if let Some(statement) = portal.statement.session_compat.clone() {
                        if authorize(&principal, Action::Read, None).is_err() {
                            write_permission_denied(&mut writer).await?;
                            extended_failed = true;
                            continue;
                        }
                        match execute_session_compat_statement(&db, &session, &principal, statement)
                        {
                            Ok(response) => {
                                write_catalog_response_formatted(
                                    &mut writer,
                                    &response,
                                    true,
                                    &portal.result_formats,
                                )
                                .await?
                            }
                            Err(error) => {
                                write_exec_error(&mut writer, &error).await?;
                                extended_failed = true;
                            }
                        }
                    } else if let Some(response) = &portal.described_response {
                        write_native_relational_results_formatted(
                            &mut writer,
                            &response.results,
                            &portal.statement.analysis,
                            false,
                            &portal.result_formats,
                        )
                        .await?;
                    } else if let Some(transaction) = relational_transaction.as_mut() {
                        let action = match portal.statement.analysis.class {
                            crate::SqlStatementClass::Read => Action::Read,
                            crate::SqlStatementClass::Write => Action::Write,
                            crate::SqlStatementClass::Admin => Action::Admin,
                        };
                        if authorize(&principal, action, None).is_err() {
                            transaction.failed = true;
                            extended_failed = true;
                            write_permission_denied(&mut writer).await?;
                            continue;
                        }
                        let audit_context = chirondb_core::audit::AuditContext {
                            principal_id: principal.id.clone(),
                            tenant_id: principal.tenant_id.clone(),
                            transport: "pgwire".to_string(),
                            request_id: Some(transaction.handle.clone()),
                        };
                        let (request, _request_memory) = match frontend::request(
                            &portal.statement.sql,
                            &portal.parameters,
                            &memory,
                        ) {
                            Ok(request) => request,
                            Err((state, message)) => {
                                transaction.failed = true;
                                extended_failed = true;
                                write_error_response(&mut writer, "ERROR", state, &message, None)
                                    .await?;
                                continue;
                            }
                        };
                        match db.execute_sql_transaction_cancellable_owned(
                            &transaction.handle,
                            request,
                            &audit_context,
                            backend.state.cancelled.clone(),
                        ) {
                            Ok(response) => {
                                write_native_relational_results_formatted(
                                    &mut writer,
                                    &response.results,
                                    &portal.statement.analysis,
                                    true,
                                    &portal.result_formats,
                                )
                                .await?;
                            }
                            Err(error) => {
                                transaction.failed = true;
                                extended_failed = true;
                                write_native_relational_error(&mut writer, &error).await?;
                            }
                        }
                    } else {
                        let succeeded = handle_native_relational_query(
                            &db,
                            &principal,
                            &mut writer,
                            &portal.statement.sql,
                            &portal.statement.analysis,
                            NativeExecutionInput {
                                parameters: &portal.parameters,
                                result_formats: &portal.result_formats,
                                cancellation: backend.state.cancelled.clone(),
                                memory: &memory,
                            },
                        )
                        .await?;
                        extended_failed = !succeeded;
                    }
                }
                Ok(_) => {
                    write_error_response(
                        &mut writer,
                        "ERROR",
                        "0A000",
                        "portal row limits are not supported; Execute max_rows must be zero",
                        None,
                    )
                    .await?;
                    extended_failed = true;
                }
                Err(message) => {
                    write_error_response(&mut writer, "ERROR", "08P01", &message, None).await?;
                    extended_failed = true;
                }
            },
            b'C' => match close_native_target(payload, &mut prepared_statements, &mut portals) {
                Ok(()) => write_message(&mut writer, b'3', &[]).await?,
                Err(message) => {
                    write_error_response(&mut writer, "ERROR", "08P01", &message, None).await?;
                    extended_failed = true;
                }
            },
            b'H' => writer.flush().await?,
            b'S' => {
                extended_failed = false;
                let status = relational_transaction.as_ref().map_or(b'I', |transaction| {
                    if transaction.failed { b'E' } else { b'T' }
                });
                write_ready_for_query(&mut writer, status).await?;
                writer.flush().await?;
            }
            b'F' => {
                write_error_response(
                    &mut writer,
                    "ERROR",
                    "0A000",
                    "PostgreSQL function-call protocol is not supported",
                    None,
                )
                .await?;
                extended_failed = true;
            }
            other => {
                write_error_response(
                    &mut writer,
                    "ERROR",
                    "08P01",
                    &format!("unrecognized message type 0x{other:02x}"),
                    None,
                )
                .await?;
                write_ready_for_query(&mut writer, b'I').await?;
                writer.flush().await?;
            }
        }
    }
}

/// Parse + execute one simple-query string, write the result back to the
/// frontend, then return. Multiple semicolon-separated statements are run as
/// one batch — pgvector / psql clients use that for `CREATE EXTENSION` +
/// `CREATE TABLE` setup blobs.
fn is_transaction_control_sql(sql: &str) -> bool {
    let normalized = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    normalized == "begin"
        || normalized == "begin transaction"
        || normalized == "start transaction"
        || normalized == "commit"
        || normalized == "end"
        || normalized == "rollback"
        || normalized.starts_with("savepoint ")
        || normalized.starts_with("rollback to ")
        || normalized.starts_with("release ")
}

async fn handle_pg_relational_transaction_query<W>(
    db: &Db,
    principal: &Permission,
    transaction: &mut Option<PgRelationalTransaction>,
    writer: &mut W,
    sql: &str,
    cancellation: Arc<AtomicBool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let normalized = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    let audit_context = chirondb_core::audit::AuditContext {
        principal_id: principal.id.clone(),
        tenant_id: principal.tenant_id.clone(),
        transport: "pgwire".to_string(),
        request_id: transaction
            .as_ref()
            .map(|transaction| transaction.handle.clone()),
    };
    if matches!(
        normalized.as_str(),
        "begin" | "begin transaction" | "start transaction"
    ) {
        if transaction.is_some() {
            write_error_response(
                writer,
                "ERROR",
                "25001",
                "a transaction is already active",
                None,
            )
            .await?;
            return Ok(());
        }
        if authorize(principal, Action::Read, None).is_err() {
            write_permission_denied(writer).await?;
            return Ok(());
        }
        match db.begin_sql_transaction(&audit_context) {
            Ok(response) => {
                *transaction = Some(PgRelationalTransaction {
                    handle: response.handle,
                    failed: false,
                });
                write_command_complete(writer, "BEGIN").await?;
            }
            Err(error) => write_native_relational_error(writer, &error).await?,
        }
        return Ok(());
    }

    let Some(active) = transaction.as_mut() else {
        write_error_response(writer, "ERROR", "25P01", "no transaction is active", None).await?;
        return Ok(());
    };
    if normalized == "rollback" {
        let handle = active.handle.clone();
        match db.rollback_sql_transaction(&handle, &audit_context) {
            Ok(_) => {
                *transaction = None;
                write_command_complete(writer, "ROLLBACK").await?;
            }
            Err(error) => write_native_relational_error(writer, &error).await?,
        }
        return Ok(());
    }
    if normalized == "commit" || normalized == "end" {
        let handle = active.handle.clone();
        if active.failed {
            let result = db.rollback_sql_transaction(&handle, &audit_context);
            *transaction = None;
            match result {
                Ok(_) => write_command_complete(writer, "ROLLBACK").await?,
                Err(error) => write_native_relational_error(writer, &error).await?,
            }
            return Ok(());
        }
        match db.commit_sql_transaction_cancellable_owned(
            &handle,
            &audit_context,
            cancellation.clone(),
        ) {
            Ok(_) => {
                *transaction = None;
                write_command_complete(writer, "COMMIT").await?;
            }
            Err(error) => {
                active.failed = true;
                write_native_relational_error(writer, &error).await?;
            }
        }
        return Ok(());
    }

    let rollback_to = normalized.starts_with("rollback to ");
    if active.failed && !rollback_to {
        write_error_response(
            writer,
            "ERROR",
            "25P02",
            "current transaction is aborted; commands are ignored until ROLLBACK",
            None,
        )
        .await?;
        return Ok(());
    }
    let catalog = match pg_catalog::recognizes(sql) {
        Ok(value) => value,
        Err(error) => {
            active.failed = true;
            write_native_relational_error(writer, &error).await?;
            return Ok(());
        }
    };
    if catalog {
        match execute_catalog_query(db, principal, writer, sql, &[]).await? {
            Some(response) => write_catalog_response(writer, &response, true).await?,
            None => active.failed = true,
        }
        return Ok(());
    }
    let analysis = crate::RelationalEngine::analyze_statement(sql);
    let (action, tag) = if normalized.starts_with("savepoint ") {
        (Action::Write, "SAVEPOINT")
    } else if rollback_to {
        (Action::Write, "ROLLBACK")
    } else if normalized.starts_with("release ") {
        (Action::Write, "RELEASE")
    } else {
        let analysis = match analysis {
            Ok(analysis) => analysis,
            Err(error) => {
                active.failed = true;
                write_native_relational_error(writer, &error).await?;
                return Ok(());
            }
        };
        let action = match analysis.class {
            crate::SqlStatementClass::Read => Action::Read,
            crate::SqlStatementClass::Write => Action::Write,
            crate::SqlStatementClass::Admin => Action::Admin,
        };
        if authorize(principal, action, None).is_err() {
            active.failed = true;
            write_permission_denied(writer).await?;
            return Ok(());
        }
        let response = db.execute_sql_transaction_cancellable_owned(
            &active.handle,
            crate::SqlExecutionRequest {
                statements: vec![crate::SqlStatementRequest {
                    sql: sql.to_string(),
                    parameters: Vec::new(),
                }],
                idempotency_key: None,
                retry_id: None,
            },
            &audit_context,
            cancellation.clone(),
        );
        match response {
            Ok(response) => {
                write_native_relational_results(writer, &response.results, &analysis, true).await?;
                return Ok(());
            }
            Err(error) => {
                active.failed = true;
                write_native_relational_error(writer, &error).await?;
                return Ok(());
            }
        }
    };
    if authorize(principal, action, None).is_err() {
        active.failed = true;
        write_permission_denied(writer).await?;
        return Ok(());
    }
    match db.execute_sql_transaction_cancellable_owned(
        &active.handle,
        crate::SqlExecutionRequest {
            statements: vec![crate::SqlStatementRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            }],
            idempotency_key: None,
            retry_id: None,
        },
        &audit_context,
        cancellation,
    ) {
        Ok(_) => {
            if rollback_to {
                active.failed = false;
            }
            write_command_complete(writer, tag).await?;
        }
        Err(error) => {
            active.failed = true;
            write_native_relational_error(writer, &error).await?;
        }
    }
    Ok(())
}

async fn handle_query<W>(
    db: &Db,
    principal: &Permission,
    session: &SessionState,
    memory: &memory::SessionMemory,
    writer: &mut W,
    sql: &str,
    cancellation: Arc<AtomicBool>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let trimmed = sql.trim();
    if trimmed.is_empty() || trimmed == ";" {
        write_message(writer, b'I', &[]).await?;
        return Ok(());
    }

    // pg_catalog intercept: many psql / driver probes hit JOIN-heavy SQL the
    // pgvector-subset parser rejects on purpose. The intercept serves a fixed
    // set of `pg_catalog.*` and `current_*` patterns from `Db` state before
    // the parser ever sees them.
    let catalog = match pg_catalog::recognizes(sql) {
        Ok(value) => value,
        Err(error) => {
            write_native_relational_error(writer, &error).await?;
            return Ok(());
        }
    };
    if catalog {
        if let Some(response) = execute_catalog_query(db, principal, writer, sql, &[]).await? {
            write_catalog_response(writer, &response, true).await?;
        }
        return Ok(());
    }

    let relational_analysis = crate::RelationalEngine::analyze_statement(trimmed).ok();
    let pgvector_shape = pgvector_parser::parse(trimmed).ok();
    let explicit_pgvector = pgvector_shape
        .as_ref()
        .is_some_and(|statements| statements.iter().any(pgvector_statement_is_explicit));
    let prefer_native = relational_analysis.as_ref().is_some_and(|analysis| {
        let (has_table, has_index, names_known_only_to_vector) =
            db.sql_catalog_membership(analysis);
        (!analysis.declares_vector && analysis.kind == crate::SqlStatementKind::CreateTable)
            || analysis.kind == crate::SqlStatementKind::AlterTable
            || (analysis.kind == crate::SqlStatementKind::DropIndex && has_index)
            || has_table
            || (!analysis.declares_vector
                && !analysis.tables.is_empty()
                && !explicit_pgvector
                && !names_known_only_to_vector)
    });
    if prefer_native {
        handle_native_relational_query(
            db,
            principal,
            writer,
            trimmed,
            &relational_analysis.expect("preference requires analysis"),
            NativeExecutionInput {
                parameters: &[],
                result_formats: &[],
                cancellation: cancellation.clone(),
                memory,
            },
        )
        .await?;
        return Ok(());
    }

    let stmts = match pgvector_parser::parse(sql) {
        Ok(stmts) => stmts,
        Err(err) => {
            write_parse_error(writer, &err).await?;
            return Ok(());
        }
    };

    if stmts.is_empty() {
        write_message(writer, b'I', &[]).await?;
        return Ok(());
    }

    for stmt in stmts {
        if cancellation.load(Ordering::Acquire) {
            write_error_response(writer, "ERROR", "57014", "query canceled", None).await?;
            return Ok(());
        }
        let action = statement_action(&stmt);
        let collection = statement_collection(&stmt).map(str::to_string);
        if !authorize_statement(principal, &stmt) {
            if db
                .audit_access_event(
                    "authorization",
                    "pgwire_statement",
                    "denied",
                    collection.as_deref(),
                    &principal.id,
                    principal.tenant_id.as_deref(),
                    "pgwire",
                    None,
                    Some("permission_denied"),
                )
                .is_err()
            {
                write_audit_unavailable(writer).await?;
                return Ok(());
            }
            write_permission_denied(writer).await?;
            return Ok(());
        }
        let mut mutation_audit = if action == Action::Read {
            if db
                .audit_access_event(
                    "access",
                    "pgwire_statement",
                    "started",
                    collection.as_deref(),
                    &principal.id,
                    principal.tenant_id.as_deref(),
                    "pgwire",
                    None,
                    None,
                )
                .is_err()
            {
                write_audit_unavailable(writer).await?;
                return Ok(());
            }
            None
        } else {
            match db.audit_network_operation(
                "pgwire_statement",
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                "pgwire",
                None,
            ) {
                Ok(operation) => Some(operation),
                Err(_) => {
                    write_audit_unavailable(writer).await?;
                    return Ok(());
                }
            }
        };
        let execution = pgvector_exec::execute_scoped(db, session, principal, stmt);
        let audit_result = match &execution {
            Ok(_) if action == Action::Read => db.audit_access_event(
                "access",
                "pgwire_statement",
                "success",
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                "pgwire",
                None,
                None,
            ),
            Err(_) if action == Action::Read => db.audit_access_event(
                "access",
                "pgwire_statement",
                "failure",
                collection.as_deref(),
                &principal.id,
                principal.tenant_id.as_deref(),
                "pgwire",
                None,
                Some("execution_error"),
            ),
            Ok(_) => {
                db.finish_committed_network_audit(
                    mutation_audit
                        .take()
                        .expect("write statement has durable audit intent"),
                    serde_json::Value::Null,
                );
                Ok(())
            }
            Err(_) => mutation_audit
                .take()
                .expect("write statement has durable audit intent")
                .failure("execution_error"),
        };
        if audit_result.is_err() {
            write_audit_unavailable(writer).await?;
            return Ok(());
        }
        match execution {
            Ok(QueryResponse::RowSet { columns, rows, tag }) => {
                write_row_description(writer, &columns).await?;
                for row in &rows {
                    write_data_row(writer, row).await?;
                }
                write_command_complete(writer, &tag).await?;
            }
            Ok(QueryResponse::CommandTag(tag)) => {
                write_command_complete(writer, &tag).await?;
            }
            Ok(QueryResponse::Empty) => {
                write_message(writer, b'I', &[]).await?;
            }
            Err(err) => {
                write_exec_error(writer, &err).await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn pgvector_statement_is_explicit(statement: &Statement) -> bool {
    match statement {
        Statement::CreateExtensionVector { .. } | Statement::CreateIndex(_) => true,
        Statement::CreateTable(table) => table
            .columns
            .iter()
            .any(|column| matches!(column.data_type, pgvector_parser::SqlType::Vector(_))),
        Statement::Insert(insert) => insert
            .rows
            .iter()
            .flatten()
            .any(pgvector_expression_is_explicit),
        Statement::Select(select) => {
            select.projection.iter().any(|item| match item {
                pgvector_parser::SelectItem::Star => false,
                pgvector_parser::SelectItem::Expr { expr, .. } => {
                    pgvector_expression_is_explicit(expr)
                }
            }) || select
                .where_clause
                .as_ref()
                .is_some_and(pgvector_expression_is_explicit)
                || select
                    .order_by
                    .as_ref()
                    .is_some_and(|order| pgvector_expression_is_explicit(&order.expr))
        }
        Statement::Delete(delete) => delete
            .where_clause
            .as_ref()
            .is_some_and(pgvector_expression_is_explicit),
        Statement::DropTable(_)
        | Statement::Set { .. }
        | Statement::Show { .. }
        | Statement::TransactionControl(_) => false,
    }
}

fn pgvector_expression_is_explicit(expression: &pgvector_parser::Expr) -> bool {
    match expression {
        pgvector_parser::Expr::VectorLiteral(_) | pgvector_parser::Expr::Distance { .. } => true,
        pgvector_parser::Expr::Aliased { inner, .. } | pgvector_parser::Expr::Not(inner) => {
            pgvector_expression_is_explicit(inner)
        }
        pgvector_parser::Expr::Func { name, args } => {
            matches!(name.as_str(), "vector_dims" | "vector_norm")
                || args.iter().any(pgvector_expression_is_explicit)
        }
        pgvector_parser::Expr::Compare { left, right, .. }
        | pgvector_parser::Expr::And(left, right)
        | pgvector_parser::Expr::Or(left, right) => {
            pgvector_expression_is_explicit(left) || pgvector_expression_is_explicit(right)
        }
        pgvector_parser::Expr::InList { expr, list, .. } => {
            pgvector_expression_is_explicit(expr)
                || list.iter().any(pgvector_expression_is_explicit)
        }
        pgvector_parser::Expr::Ident(_)
        | pgvector_parser::Expr::QualifiedIdent(_, _)
        | pgvector_parser::Expr::Number(_)
        | pgvector_parser::Expr::Integer(_)
        | pgvector_parser::Expr::String(_)
        | pgvector_parser::Expr::Bool(_)
        | pgvector_parser::Expr::Null => false,
    }
}

async fn execute_catalog_query<W>(
    db: &Db,
    principal: &Permission,
    writer: &mut W,
    sql: &str,
    parameters: &[crate::RelationalValue],
) -> io::Result<Option<pg_catalog::CatalogResponse>>
where
    W: AsyncWrite + Unpin,
{
    if authorize(principal, Action::Read, None).is_err() {
        if db
            .audit_access_event(
                "authorization",
                "pgwire_catalog",
                "denied",
                None,
                &principal.id,
                principal.tenant_id.as_deref(),
                "pgwire",
                None,
                Some("permission_denied"),
            )
            .is_err()
        {
            write_audit_unavailable(writer).await?;
            return Ok(None);
        }
        write_permission_denied(writer).await?;
        return Ok(None);
    }
    let response = match pg_catalog::intercept_owned(db, sql, parameters, |collection| {
        principal.allows_collection(collection)
    }) {
        Ok(response) => response,
        Err(error) => {
            write_native_relational_error(writer, &error).await?;
            return Ok(None);
        }
    };
    let Some(response) = response else {
        write_error_response(
            writer,
            "ERROR",
            "0A000",
            "prepared catalog query is no longer recognized",
            None,
        )
        .await?;
        return Ok(None);
    };
    if db
        .audit_access_event(
            "access",
            "pgwire_catalog",
            "success",
            None,
            &principal.id,
            principal.tenant_id.as_deref(),
            "pgwire",
            None,
            None,
        )
        .is_err()
    {
        write_audit_unavailable(writer).await?;
        return Ok(None);
    }
    Ok(Some(response))
}

async fn write_catalog_response<W>(
    writer: &mut W,
    response: &QueryResponse,
    include_row_description: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_catalog_response_formatted(writer, response, include_row_description, &[]).await
}

async fn write_catalog_response_formatted<W>(
    writer: &mut W,
    response: &QueryResponse,
    include_row_description: bool,
    requested_formats: &[i16],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match response {
        QueryResponse::RowSet { columns, rows, tag } => {
            let formats = output::prepare(
                writer,
                expand_result_formats(requested_formats, columns.len()),
            )
            .await?;
            if include_row_description {
                write_row_description_formatted(writer, columns, &formats).await?;
            }
            for row in rows {
                write_pg_data_row(writer, row, columns, &formats).await?;
            }
            write_command_complete(writer, tag).await
        }
        QueryResponse::CommandTag(tag) => write_command_complete(writer, tag).await,
        QueryResponse::Empty => write_message(writer, b'I', &[]).await,
    }
}

async fn write_catalog_description_formatted<W>(
    writer: &mut W,
    response: &QueryResponse,
    requested_formats: &[i16],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match response {
        QueryResponse::RowSet { columns, .. } => {
            let formats = output::prepare(
                writer,
                expand_result_formats(requested_formats, columns.len()),
            )
            .await?;
            write_row_description_formatted(writer, columns, &formats).await
        }
        QueryResponse::CommandTag(_) | QueryResponse::Empty => {
            write_message(writer, b'n', &[]).await
        }
    }
}

async fn handle_native_relational_query<W>(
    db: &Db,
    principal: &Permission,
    writer: &mut W,
    sql: &str,
    analysis: &crate::SqlStatementAnalysis,
    input: NativeExecutionInput<'_>,
) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let action = match analysis.class {
        crate::SqlStatementClass::Read => Action::Read,
        crate::SqlStatementClass::Write => Action::Write,
        crate::SqlStatementClass::Admin => Action::Admin,
    };
    if authorize(principal, action, None).is_err() {
        write_permission_denied(writer).await?;
        return Ok(false);
    }
    let (request, _request_memory) = match frontend::request(sql, input.parameters, input.memory) {
        Ok(request) => request,
        Err((state, message)) => {
            write_error_response(writer, "ERROR", state, &message, None).await?;
            return Ok(false);
        }
    };
    let audit_context = chirondb_core::audit::AuditContext {
        principal_id: principal.id.clone(),
        tenant_id: principal.tenant_id.clone(),
        transport: "pgwire".to_string(),
        request_id: None,
    };
    let response = match db.execute_sql_with_audit_cancellable_owned(
        request,
        &audit_context,
        input.cancellation,
    ) {
        Ok(response) => response,
        Err(error) => {
            write_native_relational_error(writer, &error).await?;
            return Ok(false);
        }
    };
    write_native_relational_results_formatted(
        writer,
        &response.results,
        analysis,
        true,
        input.result_formats,
    )
    .await?;
    Ok(true)
}

async fn write_native_relational_results<W>(
    writer: &mut W,
    results: &[crate::SqlResult],
    analysis: &crate::SqlStatementAnalysis,
    include_row_description: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_native_relational_results_formatted(
        writer,
        results,
        analysis,
        include_row_description,
        &[],
    )
    .await
}

async fn write_native_relational_results_formatted<W>(
    writer: &mut W,
    results: &[crate::SqlResult],
    analysis: &crate::SqlStatementAnalysis,
    include_row_description: bool,
    requested_formats: &[i16],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for result in results {
        match result {
            crate::SqlResult::Definition { .. } => {
                let tag = match analysis.kind {
                    crate::SqlStatementKind::CreateTable => "CREATE TABLE",
                    crate::SqlStatementKind::AlterTable => "ALTER TABLE",
                    crate::SqlStatementKind::DropTable => "DROP TABLE",
                    crate::SqlStatementKind::CreateIndex => "CREATE INDEX",
                    crate::SqlStatementKind::DropIndex => "DROP INDEX",
                    crate::SqlStatementKind::SetConstraints => "SET CONSTRAINTS",
                    _ => "DDL",
                };
                write_command_complete(writer, tag).await?;
            }
            crate::SqlResult::Mutation { affected_rows } => {
                let tag = match analysis.kind {
                    crate::SqlStatementKind::Insert => format!("INSERT 0 {affected_rows}"),
                    crate::SqlStatementKind::Update => format!("UPDATE {affected_rows}"),
                    crate::SqlStatementKind::Delete => format!("DELETE {affected_rows}"),
                    _ => format!("UPDATE {affected_rows}"),
                };
                write_command_complete(writer, &tag).await?;
            }
            crate::SqlResult::Rows {
                columns,
                column_types,
                rows,
            } => {
                let specs =
                    output::prepare(writer, output::Columns::sql(columns, column_types)).await?;
                let formats = output::prepare(
                    writer,
                    expand_result_formats(requested_formats, specs.len()),
                )
                .await?;
                if include_row_description {
                    write_row_description_formatted(writer, &specs, &formats).await?;
                }
                let row_count = rows.len();
                for row in rows {
                    write_relational_data_row(writer, row, &specs, &formats).await?;
                }
                let tag = match analysis.kind {
                    crate::SqlStatementKind::Insert => format!("INSERT 0 {row_count}"),
                    crate::SqlStatementKind::Update => format!("UPDATE {row_count}"),
                    crate::SqlStatementKind::Delete => format!("DELETE {row_count}"),
                    _ => format!("SELECT {row_count}"),
                };
                write_command_complete(writer, &tag).await?;
            }
            crate::SqlResult::Explain { plan } => {
                let specs = output::prepare(writer, output::Columns::explain()).await?;
                let formats =
                    output::prepare(writer, expand_result_formats(requested_formats, 1)).await?;
                if include_row_description {
                    write_row_description_formatted(writer, &specs, &formats).await?;
                }
                for line in plan {
                    output::send(writer, output::explain_row(line, formats[0])).await?;
                }
                write_command_complete(writer, &format!("EXPLAIN {}", plan.len())).await?;
            }
        }
    }
    Ok(())
}

fn relational_pg_type(data_type: &crate::RelationalType) -> PgType {
    match data_type {
        crate::RelationalType::Boolean => PgType::Bool,
        crate::RelationalType::SmallInt => PgType::Int2,
        crate::RelationalType::Integer => PgType::Int4,
        crate::RelationalType::BigInt => PgType::Int8,
        crate::RelationalType::Real => PgType::Float4,
        crate::RelationalType::Float => PgType::Float8,
        crate::RelationalType::Decimal { .. } => PgType::Numeric,
        crate::RelationalType::Varchar { .. } => PgType::Varchar,
        crate::RelationalType::Bytea => PgType::Bytea,
        crate::RelationalType::Date => PgType::Date,
        crate::RelationalType::TimestampUtc => PgType::TimestampTz,
        crate::RelationalType::Uuid => PgType::Uuid,
        crate::RelationalType::Jsonb | crate::RelationalType::RecordRef { .. } => PgType::Jsonb,
        crate::RelationalType::Text | crate::RelationalType::Vector { .. } => PgType::Text,
    }
}

fn relational_text_value(value: &crate::RelationalValue) -> Option<String> {
    match value {
        crate::RelationalValue::Null => None,
        crate::RelationalValue::Boolean(value) => Some(if *value { "t" } else { "f" }.to_string()),
        crate::RelationalValue::Integer(value) => Some(value.to_string()),
        crate::RelationalValue::Float(value) => Some(value.to_string()),
        crate::RelationalValue::Decimal(value)
        | crate::RelationalValue::Text(value)
        | crate::RelationalValue::Date(value)
        | crate::RelationalValue::TimestampUtc(value) => Some(value.clone()),
        crate::RelationalValue::Bytes(value) => Some(format!("\\x{}", encode_hex(value))),
        crate::RelationalValue::Uuid(value) => Some(value.to_string()),
        crate::RelationalValue::Json(value) => Some(value.to_string()),
        crate::RelationalValue::Vector(value) => serde_json::to_string(value).ok(),
        crate::RelationalValue::RecordRef(value) => serde_json::to_string(value).ok(),
    }
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

async fn write_native_relational_error<W>(
    writer: &mut W,
    error: &crate::GaussError,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let message = error.to_string();
    let sqlstate = match error {
        crate::GaussError::DuplicateKey => "23505",
        crate::GaussError::InvalidRequest(_) if message.contains("query canceled") => "57014",
        crate::GaussError::ResourceExhausted(_) => "53200",
        crate::GaussError::CommitOutcomeUnknown { .. } => "40003",
        crate::GaussError::CommitRejected { .. } => "40000",
        crate::GaussError::WalUnavailable(_) if message.contains("server is shutting down") => {
            "57P03"
        }
        crate::GaussError::AuditUnavailable(_)
        | crate::GaussError::WalUnavailable(_)
        | crate::GaussError::WalCorruption { .. } => "58030",
        crate::GaussError::InvalidRequest(_) if message.contains("serialization conflict") => {
            "40001"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("cannot affect row a second time")
                || message.contains("scalar subquery returned more than one row") =>
        {
            "21000"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("unknown column")
                || (message.contains("column ") && message.contains(" does not exist")) =>
        {
            "42703"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("column ") && message.contains(" already exists") =>
        {
            "42701"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("table ") && message.contains(" does not exist") =>
        {
            "42P01"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("table ") && message.contains(" already exists") =>
        {
            "42P07"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("constraint ") && message.contains(" does not exist") =>
        {
            "42704"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("constraint ") && message.contains(" already exists") =>
        {
            "42710"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("used by an index or constraint")
                || ((message.contains("cannot drop constraint")
                    || message.contains("cannot drop table")
                    || message.contains("cannot drop index"))
                    && message.contains("depends on it")) =>
        {
            "2BP01"
        }
        crate::GaussError::InvalidRequest(_)
            if message.contains("foreign key ")
                && message.contains(" restricts the referenced row change") =>
        {
            "23001"
        }
        crate::GaussError::InvalidRequest(_) if message.contains("foreign key") => "23503",
        crate::GaussError::InvalidRequest(_) if message.contains("unique constraint") => "23505",
        crate::GaussError::InvalidRequest(_) if message.contains("check constraint") => "23514",
        crate::GaussError::InvalidRequest(_) if message.contains("cannot be NULL") => "23502",
        crate::GaussError::InvalidRequest(_) if message.contains("unsupported SQL") => "0A000",
        _ => "22000",
    };
    write_error_response(writer, "ERROR", sqlstate, &message, None).await
}

fn authorize_statement(principal: &Permission, statement: &Statement) -> bool {
    match statement {
        Statement::CreateExtensionVector { .. } => {
            authorize(principal, Action::Write, None).is_ok()
        }
        Statement::CreateTable(statement) => {
            authorize(principal, Action::Admin, Some(&statement.name)).is_ok()
        }
        Statement::Insert(statement) => {
            authorize(principal, Action::Write, Some(&statement.table)).is_ok()
        }
        Statement::Select(statement) => {
            authorize(principal, Action::Read, Some(&statement.table)).is_ok()
        }
        Statement::Delete(statement) => {
            authorize(principal, Action::Write, Some(&statement.table)).is_ok()
        }
        Statement::CreateIndex(statement) => {
            authorize(principal, Action::Admin, Some(&statement.table)).is_ok()
        }
        Statement::DropTable(statement) => statement
            .names
            .iter()
            .all(|name| authorize(principal, Action::Admin, Some(name)).is_ok()),
        Statement::Set { .. } | Statement::Show { .. } => {
            authorize(principal, Action::Read, None).is_ok()
        }
        Statement::TransactionControl(_) => authorize(principal, Action::Write, None).is_ok(),
    }
}

fn statement_action(statement: &Statement) -> Action {
    match statement {
        Statement::Select(_) | Statement::Set { .. } | Statement::Show { .. } => Action::Read,
        Statement::CreateTable(_) | Statement::CreateIndex(_) | Statement::DropTable(_) => {
            Action::Admin
        }
        Statement::CreateExtensionVector { .. }
        | Statement::Insert(_)
        | Statement::Delete(_)
        | Statement::TransactionControl(_) => Action::Write,
    }
}

fn statement_collection(statement: &Statement) -> Option<&str> {
    match statement {
        Statement::CreateTable(statement) => Some(&statement.name),
        Statement::Insert(statement) => Some(&statement.table),
        Statement::Select(statement) => Some(&statement.table),
        Statement::Delete(statement) => Some(&statement.table),
        Statement::CreateIndex(statement) => Some(&statement.table),
        Statement::DropTable(statement) if statement.names.len() == 1 => {
            statement.names.first().map(String::as_str)
        }
        _ => None,
    }
}

async fn write_audit_unavailable<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_error_response(writer, "ERROR", "58030", "audit unavailable", None).await
}

async fn write_permission_denied<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_error_response(
        writer,
        "ERROR",
        "42501",
        "permission denied for ChironDB operation",
        None,
    )
    .await
}

async fn write_row_description<W: AsyncWrite + Unpin>(
    writer: &mut W,
    columns: &[ColumnSpec],
) -> io::Result<()> {
    let formats = output::prepare(writer, expand_result_formats(&[], columns.len())).await?;
    write_row_description_formatted(writer, columns, &formats).await
}
async fn write_row_description_formatted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    columns: &[ColumnSpec],
    formats: &[i16],
) -> io::Result<()> {
    output::send(writer, output::description(columns, formats)).await
}
async fn write_data_row<W: AsyncWrite + Unpin>(
    writer: &mut W,
    row: &[Option<String>],
) -> io::Result<()> {
    output::send(writer, output::simple_row(row)).await
}
fn expand_result_formats(requested: &[i16], column_count: usize) -> io::Result<output::Formats> {
    output::Formats::new(requested, column_count)
}
async fn write_pg_data_row<W: AsyncWrite + Unpin>(
    writer: &mut W,
    row: &[Option<String>],
    columns: &[ColumnSpec],
    formats: &[i16],
) -> io::Result<()> {
    output::send(writer, output::text_row(row, columns, formats)).await
}
async fn write_relational_data_row<W: AsyncWrite + Unpin>(
    writer: &mut W,
    row: &[crate::RelationalValue],
    columns: &[ColumnSpec],
    formats: &[i16],
) -> io::Result<()> {
    output::send(writer, output::sql_row(row, columns, formats)).await
}

fn encode_relational_binary(
    value: &crate::RelationalValue,
    pg_type: PgType,
) -> io::Result<Vec<u8>> {
    match (value, pg_type) {
        (crate::RelationalValue::Boolean(value), PgType::Bool) => Ok(vec![u8::from(*value)]),
        (crate::RelationalValue::Integer(value), PgType::Int2) => i16::try_from(*value)
            .map(|value| value.to_be_bytes().to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SMALLINT result overflow")),
        (crate::RelationalValue::Integer(value), PgType::Int4) => i32::try_from(*value)
            .map(|value| value.to_be_bytes().to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "INTEGER result overflow")),
        (crate::RelationalValue::Integer(value), PgType::Int8) => Ok(value.to_be_bytes().to_vec()),
        (crate::RelationalValue::Float(value), PgType::Float4) => {
            Ok((*value as f32).to_bits().to_be_bytes().to_vec())
        }
        (crate::RelationalValue::Float(value), PgType::Float8) => {
            Ok(value.to_bits().to_be_bytes().to_vec())
        }
        (crate::RelationalValue::Decimal(value), PgType::Numeric) => encode_pg_numeric(value),
        (crate::RelationalValue::Text(value), PgType::Text | PgType::Varchar) => {
            Ok(value.as_bytes().to_vec())
        }
        (crate::RelationalValue::Bytes(value), PgType::Bytea) => Ok(value.clone()),
        (crate::RelationalValue::Date(value), PgType::Date) => encode_pg_date(value),
        (crate::RelationalValue::TimestampUtc(value), PgType::TimestampTz) => {
            encode_pg_timestamptz(value)
        }
        (crate::RelationalValue::Uuid(value), PgType::Uuid) => Ok(value.as_bytes().to_vec()),
        (crate::RelationalValue::Json(value), PgType::Jsonb) => encode_pg_jsonb(&value.to_string()),
        (crate::RelationalValue::Vector(value), PgType::Text) => serde_json::to_vec(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        (crate::RelationalValue::RecordRef(value), PgType::Jsonb) => serde_json::to_string(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            .and_then(|value| encode_pg_jsonb(&value)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot encode {value:?} as PostgreSQL {pg_type:?}"),
        )),
    }
}

fn encode_pg_binary_text(pg_type: PgType, value: &str) -> io::Result<Vec<u8>> {
    match pg_type {
        PgType::Text | PgType::Varchar => Ok(value.as_bytes().to_vec()),
        PgType::Bool => match value {
            "t" | "true" | "1" => Ok(vec![1]),
            "f" | "false" | "0" => Ok(vec![0]),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid BOOLEAN result",
            )),
        },
        PgType::Int2 => parse_binary_number::<i16>(value, i16::to_be_bytes),
        PgType::Int4 => parse_binary_number::<i32>(value, i32::to_be_bytes),
        PgType::Int8 => parse_binary_number::<i64>(value, i64::to_be_bytes),
        PgType::Float4 => value
            .parse::<f32>()
            .map(|value| value.to_bits().to_be_bytes().to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid REAL result")),
        PgType::Float8 => value
            .parse::<f64>()
            .map(|value| value.to_bits().to_be_bytes().to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid DOUBLE result")),
        PgType::Numeric => encode_pg_numeric(value),
        PgType::Bytea => decode_bytea_text(value)
            .map_err(|(_, message)| io::Error::new(io::ErrorKind::InvalidData, message)),
        PgType::Date => encode_pg_date(value),
        PgType::TimestampTz => encode_pg_timestamptz(value),
        PgType::Uuid => uuid::Uuid::parse_str(value)
            .map(|value| value.as_bytes().to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UUID result")),
        PgType::Jsonb => encode_pg_jsonb(value),
        PgType::TextArray => encode_pg_array(value, PgType::Text),
        PgType::BoolArray => encode_pg_array(value, PgType::Bool),
        PgType::Int2Array => encode_pg_array(value, PgType::Int2),
    }
}

fn parse_binary_number<T>(
    value: &str,
    encode: impl FnOnce(T) -> <T as BinaryInteger>::Bytes,
) -> io::Result<Vec<u8>>
where
    T: std::str::FromStr + BinaryInteger,
{
    value
        .parse::<T>()
        .map(|value| encode(value).as_ref().to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid integer result"))
}

trait BinaryInteger {
    type Bytes: AsRef<[u8]>;
}

impl BinaryInteger for i16 {
    type Bytes = [u8; 2];
}
impl BinaryInteger for i32 {
    type Bytes = [u8; 4];
}
impl BinaryInteger for i64 {
    type Bytes = [u8; 8];
}

fn encode_pg_date(value: &str) -> io::Result<Vec<u8>> {
    let date = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid DATE result"))?;
    let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid PostgreSQL epoch");
    let days = i32::try_from(date.signed_duration_since(epoch).num_days())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DATE result is out of range"))?;
    Ok(days.to_be_bytes().to_vec())
}

fn encode_pg_timestamptz(value: &str) -> io::Result<Vec<u8>> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TIMESTAMPTZ result"))?
        .with_timezone(&chrono::Utc);
    let epoch = chrono::DateTime::from_timestamp(946_684_800, 0).expect("valid PostgreSQL epoch");
    let micros = timestamp
        .signed_duration_since(epoch)
        .num_microseconds()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TIMESTAMPTZ out of range"))?;
    Ok(micros.to_be_bytes().to_vec())
}

fn encode_pg_jsonb(value: &str) -> io::Result<Vec<u8>> {
    output::validate_json(value)?;
    let mut encoded = Vec::with_capacity(value.len() + 1);
    encoded.push(1);
    encoded.extend_from_slice(value.as_bytes());
    Ok(encoded)
}

fn encode_pg_numeric(value: &str) -> io::Result<Vec<u8>> {
    const NUMERIC_POS: u16 = 0x0000;
    const NUMERIC_NEG: u16 = 0x4000;
    if value.eq_ignore_ascii_case("nan") {
        let mut encoded = Vec::with_capacity(8);
        encoded.extend_from_slice(&0_i16.to_be_bytes());
        encoded.extend_from_slice(&0_i16.to_be_bytes());
        encoded.extend_from_slice(&0xC000_u16.to_be_bytes());
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        return Ok(encoded);
    }
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let unsigned = unsigned.strip_prefix('+').unwrap_or(unsigned);
    if unsigned.contains('e') || unsigned.contains('E') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exponent NUMERIC result is unsupported",
        ));
    }
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || integer
            .chars()
            .chain(fraction.chars())
            .any(|c| !c.is_ascii_digit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid NUMERIC result",
        ));
    }
    let dscale = u16::try_from(fraction.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUMERIC scale is too large"))?;
    let integer = integer.trim_start_matches('0');
    let mut integer_padded = String::new();
    if !integer.is_empty() {
        integer_padded.push_str(&"0".repeat((4 - integer.len() % 4) % 4));
        integer_padded.push_str(integer);
    }
    let mut fraction_padded = fraction.to_string();
    fraction_padded.push_str(&"0".repeat((4 - fraction_padded.len() % 4) % 4));
    let integer_groups = integer_padded.len() / 4;
    let mut digits = integer_padded
        .as_bytes()
        .chunks_exact(4)
        .chain(fraction_padded.as_bytes().chunks_exact(4))
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .expect("ASCII digits")
                .parse::<u16>()
                .expect("four digits fit u16")
        })
        .collect::<Vec<_>>();
    let mut weight = i16::try_from(integer_groups)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUMERIC is too large"))?
        - 1;
    while digits.first() == Some(&0) {
        digits.remove(0);
        weight -= 1;
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    if digits.is_empty() {
        weight = 0;
    }
    let ndigits = i16::try_from(digits.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUMERIC is too large"))?;
    let mut encoded = Vec::with_capacity(8 + digits.len() * 2);
    encoded.extend_from_slice(&ndigits.to_be_bytes());
    encoded.extend_from_slice(&weight.to_be_bytes());
    encoded.extend_from_slice(&(if negative { NUMERIC_NEG } else { NUMERIC_POS }).to_be_bytes());
    encoded.extend_from_slice(&dscale.to_be_bytes());
    for digit in digits {
        encoded.extend_from_slice(&digit.to_be_bytes());
    }
    Ok(encoded)
}

fn encode_pg_array(value: &str, element_type: PgType) -> io::Result<Vec<u8>> {
    let inner = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PostgreSQL array result",
            )
        })?;
    if inner.is_empty() {
        return Ok([
            0_i32.to_be_bytes(),
            0_i32.to_be_bytes(),
            element_type.oid().to_be_bytes(),
        ]
        .concat());
    }
    let elements = inner.split(',').collect::<Vec<_>>();
    let mut encoded_elements = Vec::with_capacity(elements.len());
    let mut has_null = false;
    for element in elements {
        if element == "NULL" {
            has_null = true;
            encoded_elements.push(None);
        } else {
            let element = element
                .trim_matches('"')
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
            encoded_elements.push(Some(encode_pg_binary_text(element_type, &element)?));
        }
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&1_i32.to_be_bytes());
    encoded.extend_from_slice(&i32::from(has_null).to_be_bytes());
    encoded.extend_from_slice(&element_type.oid().to_be_bytes());
    encoded.extend_from_slice(&(encoded_elements.len() as i32).to_be_bytes());
    encoded.extend_from_slice(&1_i32.to_be_bytes());
    for element in encoded_elements {
        match element {
            None => encoded.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(element) => {
                encoded.extend_from_slice(&(element.len() as i32).to_be_bytes());
                encoded.extend_from_slice(&element);
            }
        }
    }
    Ok(encoded)
}

async fn write_parse_error<W>(writer: &mut W, err: &ParseError) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let sqlstate = err.sqlstate();
    let message = err.to_string();
    let hint = err
        .hint()
        .map(|anchor| format!("{COMPAT_HINT_BASE}{anchor}"));
    write_error_response(writer, "ERROR", sqlstate, &message, hint.as_deref()).await
}

async fn write_exec_error<W>(writer: &mut W, err: &ExecError) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let hint = err
        .hint()
        .map(|anchor| format!("{COMPAT_HINT_BASE}{anchor}"));
    write_error_response(
        writer,
        "ERROR",
        err.sqlstate(),
        &err.message(),
        hint.as_deref(),
    )
    .await
}

fn parse_native_parse_message_admitted(
    payload: &[u8],
    db: &Db,
    transaction_active: bool,
    budget: Option<&memory::SessionMemory>,
) -> Result<(String, Arc<NativePreparedStatement>), (&'static str, String)> {
    let mut offset = 0;
    let name = read_frontend_str(payload, &mut offset)?;
    let sql = read_frontend_str(payload, &mut offset)?;
    let parameter_count = read_frontend_count(payload, &mut offset, "parameter")?;
    if payload.len() - offset != parameter_count * 4 {
        return Err(("08P01", "invalid Parse parameter list".into()));
    }
    // Admit frontend strings/OIDs before copying. Parser/analysis scratch has
    // a separate lifetime: charge its resulting metadata before publishing the
    // prepared statement, using actual capacities rather than a SQL-size ratio.
    let mut memory = budget
        .map(|budget| {
            budget.reserve(memory::checked_bytes(&[
                4096,
                name.len(),
                sql.len(),
                parameter_count * 4,
            ])?)
        })
        .transpose()?;
    let name = frontend::string(name)?;
    let sql = frontend::string(sql)?;
    let mut parameter_oids = frontend::vector(parameter_count)?;
    for _ in 0..parameter_count {
        parameter_oids.push(read_frontend_u32(payload, &mut offset)?);
    }
    if offset != payload.len() {
        return Err(("08P01", "trailing bytes in Parse message".to_string()));
    }
    let catalog = pg_catalog::recognizes(&sql).map_err(|error| ("53200", error.to_string()))?;
    let session_compat = parse_session_compat_statement(&sql);
    let analysis = if catalog || session_compat.is_some() || is_transaction_control_sql(&sql) {
        crate::SqlStatementAnalysis {
            class: crate::SqlStatementClass::Read,
            kind: crate::SqlStatementKind::Select,
            tables: Vec::new(),
            indexes: Vec::new(),
            declares_vector: false,
        }
    } else {
        crate::RelationalEngine::analyze_statement(&sql).map_err(|error| {
            (
                if matches!(error, crate::GaussError::ResourceExhausted(_)) {
                    "53200"
                } else {
                    "42601"
                },
                error.to_string(),
            )
        })?
    };
    let explicit_pgvector = pgvector_parser::parse(&sql)
        .ok()
        .is_some_and(|statements| statements.iter().any(pgvector_statement_is_explicit));
    let (has_table, has_index, names_known_only_to_vector) = db.sql_catalog_membership(&analysis);
    let native = catalog
        || session_compat.is_some()
        || (transaction_active && !analysis.declares_vector)
        || (!analysis.declares_vector && analysis.kind == crate::SqlStatementKind::CreateTable)
        || analysis.kind == crate::SqlStatementKind::AlterTable
        || (analysis.kind == crate::SqlStatementKind::DropIndex && has_index)
        || has_table
        || (!analysis.declares_vector && !explicit_pgvector && !names_known_only_to_vector);
    if !native {
        return Err((
            "0A000",
            "extended protocol is available for native relational SQL; the pgvector compatibility profile remains simple-query only".to_string(),
        ));
    }
    if let Some(memory) = &mut memory {
        let strings = |values: &Vec<String>| {
            values.iter().fold(
                values.capacity() * std::mem::size_of::<String>(),
                |bytes, value| bytes.saturating_add(value.capacity()),
            )
        };
        let compat = match &session_compat {
            Some(SessionCompatStatement::Parsed(Statement::Set { name, value })) => {
                name.capacity().saturating_add(value.capacity())
            }
            Some(SessionCompatStatement::Parsed(Statement::Show { name })) => name.capacity(),
            Some(SessionCompatStatement::Set) | None => 0,
            _ => return Err(("53200", "unsupported prepared metadata accounting".into())),
        };
        memory.grow(memory::checked_bytes(&[
            strings(&analysis.tables),
            strings(&analysis.indexes),
            compat,
        ])?)?;
    }
    Ok((
        name,
        Arc::new(NativePreparedStatement {
            sql,
            parameter_oids,
            analysis,
            catalog,
            session_compat,
            _memory: memory.map(Arc::new),
        }),
    ))
}

fn parse_session_compat_statement(sql: &str) -> Option<SessionCompatStatement> {
    let normalized = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    if normalized.starts_with("set time zone ")
        || normalized.starts_with("set client_encoding ")
        || normalized.starts_with("set client encoding ")
    {
        return Some(SessionCompatStatement::Set);
    }
    let mut statements = pgvector_parser::parse(sql).ok()?;
    if statements.len() != 1 {
        return None;
    }
    match statements.pop()? {
        // Constraint modes validate pending rows in the relational transaction.
        Statement::Set { name, .. } if name.eq_ignore_ascii_case("constraints") => None,
        statement @ (Statement::Set { .. } | Statement::Show { .. }) => {
            Some(SessionCompatStatement::Parsed(statement))
        }
        _ => None,
    }
}

fn execute_session_compat_statement(
    db: &Db,
    session: &SessionState,
    principal: &Permission,
    statement: SessionCompatStatement,
) -> Result<QueryResponse, ExecError> {
    match statement {
        SessionCompatStatement::Set => Ok(QueryResponse::CommandTag("SET".to_string())),
        SessionCompatStatement::Parsed(statement) => {
            pgvector_exec::execute_scoped(db, session, principal, statement)
        }
    }
}

fn parse_native_bind_message_admitted(
    payload: &[u8],
    statements: &HashMap<String, Arc<NativePreparedStatement>>,
    budget: Option<&memory::SessionMemory>,
) -> Result<(String, NativePortal), (&'static str, String)> {
    let mut offset = 0;
    let portal_name = read_frontend_str(payload, &mut offset)?;
    let statement_name = read_frontend_str(payload, &mut offset)?;
    let statement = statements
        .get(statement_name)
        .cloned()
        .ok_or_else(|| ("26000", "prepared statement does not exist".to_string()))?;
    let mut memory = budget
        .map(|budget| {
            budget.reserve(memory::checked_bytes(&[
                4096,
                portal_name.len(),
                statement_name.len(),
            ])?)
        })
        .transpose()?;
    let portal_name = frontend::string(portal_name)?;
    let statement_name = frontend::string(statement_name)?;
    let format_count = read_frontend_count(payload, &mut offset, "parameter format")?;
    if let Some(memory) = &mut memory {
        memory.grow(format_count * std::mem::size_of::<i16>())?;
    }
    let mut formats = frontend::vector(format_count)?;
    for _ in 0..format_count {
        let format = read_frontend_i16(payload, &mut offset)?;
        if !matches!(format, 0 | 1) {
            return Err(("08P01", "unknown parameter format code".to_string()));
        }
        formats.push(format);
    }
    let parameter_count = read_frontend_count(payload, &mut offset, "parameter")?;
    if !statement.parameter_oids.is_empty() && statement.parameter_oids.len() != parameter_count {
        return Err((
            "08P01",
            "Bind parameter count does not match Parse".to_string(),
        ));
    }
    if formats.len() > 1 && formats.len() != parameter_count {
        return Err((
            "08P01",
            "Bind parameter format count is invalid".to_string(),
        ));
    }
    if let Some(memory) = &mut memory {
        memory.grow(parameter_count * std::mem::size_of::<crate::RelationalValue>())?;
    }
    let mut parameters = frontend::vector(parameter_count)?;
    for index in 0..parameter_count {
        let length = read_frontend_i32(payload, &mut offset)?;
        if length == -1 {
            parameters.push(crate::RelationalValue::Null);
            continue;
        }
        if length < -1 {
            return Err(("08P01", "invalid Bind parameter length".to_string()));
        }
        let length = usize::try_from(length)
            .map_err(|_| ("08P01", "invalid Bind parameter length".to_string()))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| ("08P01", "truncated Bind parameter".to_string()))?;
        let bytes = &payload[offset..end];
        offset = end;
        let format = match formats.as_slice() {
            [] => 0,
            [format] => *format,
            many => many[index],
        };
        let oid = statement.parameter_oids.get(index).copied().unwrap_or(0);
        let value = if let Some(memory) = &mut memory {
            if oid == 3802 && (format == 0 || bytes.first() == Some(&1)) {
                let json = if format == 0 { bytes } else { &bytes[1..] };
                std::str::from_utf8(json)
                    .map_err(|_| ("22021", "JSONB parameter is not valid UTF-8".to_string()))?;
                crate::RelationalValue::Json(memory::decode_json(json, memory)?)
            } else {
                // Text/bytea allocate at most their encoded length. Date/time
                // normalization has fixed-size output, covered by 64 bytes.
                memory.grow(bytes.len().max(64))?;
                decode_pg_parameter(oid, format, bytes)?
            }
        } else {
            decode_pg_parameter(oid, format, bytes)?
        };
        parameters.push(value);
    }
    let result_format_count = read_frontend_count(payload, &mut offset, "result format")?;
    if let Some(memory) = &mut memory {
        memory.grow(result_format_count * std::mem::size_of::<i16>())?;
    }
    let mut result_formats = frontend::vector(result_format_count)?;
    for _ in 0..result_format_count {
        let format = read_frontend_i16(payload, &mut offset)?;
        if !matches!(format, 0 | 1) {
            return Err(("08P01", "unknown result format code".to_string()));
        }
        result_formats.push(format);
    }
    if offset != payload.len() {
        return Err(("08P01", "trailing bytes in Bind message".to_string()));
    }
    Ok((
        portal_name,
        NativePortal {
            statement_name,
            statement,
            parameters,
            result_formats,
            described_response: None,
            described_catalog_response: None,
            described_metadata: false,
            _memory: memory.map(Arc::new),
        },
    ))
}

fn decode_pg_parameter(
    oid: u32,
    format: i16,
    bytes: &[u8],
) -> Result<crate::RelationalValue, (&'static str, String)> {
    if format == 0 {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ("22021", "parameter is not valid UTF-8".to_string()))?;
        return match oid {
            16 => match text {
                "t" | "true" | "1" => Ok(crate::RelationalValue::Boolean(true)),
                "f" | "false" | "0" => Ok(crate::RelationalValue::Boolean(false)),
                _ => Err(("22P02", "invalid boolean parameter".to_string())),
            },
            20 | 21 | 23 => text
                .parse::<i64>()
                .map(crate::RelationalValue::Integer)
                .map_err(|_| ("22P02", "invalid integer parameter".to_string())),
            700 | 701 => text
                .parse::<f64>()
                .map(crate::RelationalValue::Float)
                .map_err(|_| ("22P02", "invalid floating-point parameter".to_string())),
            1700 => Ok(crate::RelationalValue::Decimal(text.to_string())),
            17 => decode_bytea_text(text).map(crate::RelationalValue::Bytes),
            1082 => Ok(crate::RelationalValue::Date(text.to_string())),
            2950 => uuid::Uuid::parse_str(text)
                .map(crate::RelationalValue::Uuid)
                .map_err(|_| ("22P02", "invalid UUID parameter".to_string())),
            1184 => decode_pg_timestamptz(text).map(crate::RelationalValue::TimestampUtc),
            3802 => serde_json::from_str(text)
                .map(crate::RelationalValue::Json)
                .map_err(|_| ("22P02", "invalid JSONB parameter".to_string())),
            _ => Ok(crate::RelationalValue::Text(text.to_string())),
        };
    }
    if format != 1 {
        return Err(("08P01", "unknown parameter format code".to_string()));
    }
    match oid {
        16 if bytes.len() == 1 => Ok(crate::RelationalValue::Boolean(bytes[0] != 0)),
        21 if bytes.len() == 2 => {
            Ok(crate::RelationalValue::Integer(
                i16::from_be_bytes([bytes[0], bytes[1]]) as i64,
            ))
        }
        23 if bytes.len() == 4 => Ok(crate::RelationalValue::Integer(i32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]) as i64)),
        20 if bytes.len() == 8 => Ok(crate::RelationalValue::Integer(i64::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))),
        700 if bytes.len() == 4 => Ok(crate::RelationalValue::Float(f32::from_bits(
            u32::from_be_bytes(bytes.try_into().expect("length checked")),
        ) as f64)),
        701 if bytes.len() == 8 => Ok(crate::RelationalValue::Float(f64::from_bits(
            u64::from_be_bytes(bytes.try_into().expect("length checked")),
        ))),
        2950 if bytes.len() == 16 => Ok(crate::RelationalValue::Uuid(
            uuid::Uuid::from_slice(bytes).expect("length checked"),
        )),
        17 => Ok(crate::RelationalValue::Bytes(bytes.to_vec())),
        25 | 1043 => std::str::from_utf8(bytes)
            .map(|value| crate::RelationalValue::Text(value.to_string()))
            .map_err(|_| ("22021", "text parameter is not valid UTF-8".to_string())),
        1082 if bytes.len() == 4 => {
            let days = i32::from_be_bytes(bytes.try_into().expect("length checked"));
            let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid epoch");
            epoch
                .checked_add_signed(chrono::Duration::days(i64::from(days)))
                .map(|date| crate::RelationalValue::Date(date.format("%Y-%m-%d").to_string()))
                .ok_or_else(|| ("22008", "date parameter is out of range".to_string()))
        }
        1184 if bytes.len() == 8 => {
            let micros = i64::from_be_bytes(bytes.try_into().expect("length checked"));
            let epoch = chrono::DateTime::from_timestamp(946_684_800, 0).expect("valid epoch");
            epoch
                .checked_add_signed(chrono::Duration::microseconds(micros))
                .map(|timestamp| {
                    crate::RelationalValue::TimestampUtc(
                        timestamp.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                    )
                })
                .ok_or_else(|| ("22008", "timestamp parameter is out of range".to_string()))
        }
        3802 if bytes.first() == Some(&1) => std::str::from_utf8(&bytes[1..])
            .map_err(|_| ("22021", "JSONB parameter is not valid UTF-8".to_string()))
            .and_then(|text| {
                serde_json::from_str(text)
                    .map(crate::RelationalValue::Json)
                    .map_err(|_| ("22P02", "invalid JSONB parameter".to_string()))
            }),
        _ => Err((
            "0A000",
            format!("binary parameter encoding for PostgreSQL OID {oid} is not supported"),
        )),
    }
}

fn decode_pg_timestamptz(text: &str) -> Result<String, (&'static str, String)> {
    // PostgreSQL drivers send ISO timestamps with an explicit offset. The
    // native engine deliberately stores only UTC RFC 3339 timestamps.
    let timestamp = chrono::DateTime::parse_from_rfc3339(text)
        .or_else(|_| chrono::DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f%#z"))
        .map_err(|_| ("22007", "invalid TIMESTAMPTZ parameter".to_string()))?;
    if timestamp.timestamp_subsec_nanos() % 1_000 != 0 {
        return Err((
            "0A000",
            "TIMESTAMPTZ parameter precision finer than microseconds is not supported".to_string(),
        ));
    }
    Ok(timestamp
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

fn decode_bytea_text(value: &str) -> Result<Vec<u8>, (&'static str, String)> {
    let hex = value.strip_prefix("\\x").ok_or_else(|| {
        (
            "22P02",
            "BYTEA parameter must use hex format \\x...".to_string(),
        )
    })?;
    if hex.len() % 2 != 0 {
        return Err((
            "22P02",
            "BYTEA parameter contains an incomplete byte".to_string(),
        ));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| ("22P02", "BYTEA parameter contains invalid hex".to_string()))?;
            u8::from_str_radix(pair, 16)
                .map_err(|_| ("22P02", "BYTEA parameter contains invalid hex".to_string()))
        })
        .collect()
}

fn parse_describe_message(payload: &[u8]) -> Result<(u8, &str), String> {
    let Some(kind) = payload.first().copied() else {
        return Err("Describe message is empty".to_string());
    };
    let mut offset = 1;
    let name = read_frontend_str(payload, &mut offset).map_err(|(_, message)| message)?;
    if offset != payload.len() {
        return Err("trailing bytes in Describe message".to_string());
    }
    Ok((kind, name))
}

fn native_result_columns(results: &[crate::SqlResult]) -> io::Result<Option<output::Columns>> {
    output::Columns::first(results)
}

fn parse_execute_message(payload: &[u8]) -> Result<(&str, u32), String> {
    let mut offset = 0;
    let name = read_frontend_str(payload, &mut offset).map_err(|(_, message)| message)?;
    let rows = read_frontend_u32(payload, &mut offset).map_err(|(_, message)| message)?;
    if offset != payload.len() {
        return Err("trailing bytes in Execute message".to_string());
    }
    Ok((name, rows))
}

fn close_native_target(
    payload: &[u8],
    statements: &mut HashMap<String, Arc<NativePreparedStatement>>,
    portals: &mut HashMap<String, NativePortal>,
) -> Result<(), String> {
    let Some(kind) = payload.first().copied() else {
        return Err("Close message is empty".to_string());
    };
    let mut offset = 1;
    let name = read_frontend_str(payload, &mut offset).map_err(|(_, message)| message)?;
    if offset != payload.len() {
        return Err("trailing bytes in Close message".to_string());
    }
    match kind {
        b'S' => {
            statements.remove(name);
            portals.retain(|_, portal| portal.statement_name != name);
        }
        b'P' => {
            portals.remove(name);
        }
        _ => return Err("Close target must be S or P".to_string()),
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SqlDeallocateTarget {
    All,
    Statement(String),
}

fn strip_sql_keyword<'a>(input: &'a str, keyword: &str) -> Option<&'a str> {
    let prefix = input.get(..keyword.len())?;
    if !prefix.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &input[keyword.len()..];
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then_some(rest.trim_start())
}

fn parse_deallocate_identifier(input: &str) -> Result<String, String> {
    if let Some(mut quoted) = input.strip_prefix('"') {
        let mut name = String::new();
        loop {
            let Some(position) = quoted.find('"') else {
                return Err("unterminated DEALLOCATE statement name".to_string());
            };
            name.push_str(&quoted[..position]);
            quoted = &quoted[position + 1..];
            if let Some(rest) = quoted.strip_prefix('"') {
                name.push('"');
                quoted = rest;
                continue;
            }
            if !quoted.trim().is_empty() {
                return Err("DEALLOCATE accepts exactly one statement name".to_string());
            }
            return Ok(name);
        }
    }

    if input.is_empty()
        || input
            .chars()
            .next()
            .is_none_or(|character| !(character.is_ascii_alphabetic() || character == '_'))
        || !input
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
    {
        return Err("invalid DEALLOCATE statement name".to_string());
    }
    Ok(input.to_ascii_lowercase())
}

fn parse_deallocate_query(sql: &str) -> Result<Option<SqlDeallocateTarget>, String> {
    let mut statement = sql.trim();
    if let Some(without_semicolon) = statement.strip_suffix(';') {
        statement = without_semicolon.trim_end();
    }
    let Some(mut target) = strip_sql_keyword(statement, "deallocate") else {
        return Ok(None);
    };
    if let Some(without_prepare) = strip_sql_keyword(target, "prepare") {
        target = without_prepare;
    }
    if target.eq_ignore_ascii_case("all") {
        return Ok(Some(SqlDeallocateTarget::All));
    }
    Ok(Some(SqlDeallocateTarget::Statement(
        parse_deallocate_identifier(target)?,
    )))
}

fn apply_deallocate_target(
    target: SqlDeallocateTarget,
    statements: &mut HashMap<String, Arc<NativePreparedStatement>>,
    portals: &mut HashMap<String, NativePortal>,
) -> bool {
    match target {
        SqlDeallocateTarget::All => {
            statements.clear();
            portals.clear();
            true
        }
        SqlDeallocateTarget::Statement(name) => {
            let found = statements.remove(&name).is_some();
            portals.retain(|_, portal| portal.statement_name != name);
            found
        }
    }
}

async fn write_parameter_description<W>(writer: &mut W, oids: &[u32]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let count = u16::try_from(oids.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "parameter count overflow"))?;
    let mut frame = output::prepare(writer, output::control(b't', 2 + oids.len() * 4)).await?;
    frame.as_mut()[5..7].copy_from_slice(&count.to_be_bytes());
    for (slot, oid) in frame.as_mut()[7..].chunks_exact_mut(4).zip(oids) {
        slot.copy_from_slice(&oid.to_be_bytes());
    }
    writer.write_all(frame.as_ref()).await
}

fn read_frontend_str<'a>(
    payload: &'a [u8],
    offset: &mut usize,
) -> Result<&'a str, (&'static str, String)> {
    let end = payload
        .get(*offset..)
        .and_then(|remaining| remaining.iter().position(|byte| *byte == 0))
        .ok_or_else(|| ("08P01", "unterminated frontend string".to_string()))?;
    let value = std::str::from_utf8(&payload[*offset..*offset + end])
        .map_err(|_| ("22021", "frontend string is not valid UTF-8".to_string()))?;
    *offset += end + 1;
    Ok(value)
}

fn read_frontend_count(
    payload: &[u8],
    offset: &mut usize,
    label: &str,
) -> Result<usize, (&'static str, String)> {
    let count = read_frontend_i16(payload, offset)?;
    usize::try_from(count).map_err(|_| ("08P01", format!("negative {label} count")))
}

fn read_frontend_i16(payload: &[u8], offset: &mut usize) -> Result<i16, (&'static str, String)> {
    let bytes = payload
        .get(*offset..*offset + 2)
        .ok_or_else(|| ("08P01", "truncated frontend i16".to_string()))?;
    *offset += 2;
    Ok(i16::from_be_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn read_frontend_i32(payload: &[u8], offset: &mut usize) -> Result<i32, (&'static str, String)> {
    let bytes = payload
        .get(*offset..*offset + 4)
        .ok_or_else(|| ("08P01", "truncated frontend i32".to_string()))?;
    *offset += 4;
    Ok(i32::from_be_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

fn read_frontend_u32(payload: &[u8], offset: &mut usize) -> Result<u32, (&'static str, String)> {
    read_frontend_i32(payload, offset).map(|value| value as u32)
}

#[allow(dead_code)]
fn _bind_pgtype_marker(_pt: PgType) {}

async fn write_auth_cleartext_password<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // 'R' AuthenticationRequest, code 3 = cleartext password.
    write_message(writer, b'R', &3_u32.to_be_bytes()).await
}

async fn write_auth_ok<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_message(writer, b'R', &0_u32.to_be_bytes()).await
}

async fn read_password_message<R>(
    reader: &mut R,
) -> io::Result<crate::response_buffer::ResponseBuffer>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0_u8; 5];
    reader.read_exact(&mut hdr).await?;
    if hdr[0] != b'p' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected PasswordMessage ('p'), got 0x{:02x}", hdr[0]),
        ));
    }
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if !(4..=MAX_MESSAGE_LEN).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PasswordMessage length {len}"),
        ));
    }
    frontend::read(reader, len - 4, MAX_MESSAGE_LEN).await
}

async fn write_required_parameter_status<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for (k, v) in [
        ("server_version", SERVER_VERSION_STRING),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("TimeZone", "UTC"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
        ("is_superuser", "off"),
        ("session_authorization", "gaussdb"),
        ("application_name", ""),
    ] {
        let mut frame =
            output::prepare(writer, output::control(b'S', k.len() + v.len() + 2)).await?;
        frame.as_mut()[5..5 + k.len()].copy_from_slice(k.as_bytes());
        frame.as_mut()[6 + k.len()..6 + k.len() + v.len()].copy_from_slice(v.as_bytes());
        writer.write_all(frame.as_ref()).await?;
    }
    Ok(())
}

/// Backend PID/secret values identify a live PostgreSQL-wire session for
/// `CancelRequest`. The secret prevents another client from cancelling a
/// session by guessing its public backend PID.
fn next_backend_key() -> io::Result<(u32, u32)> {
    let mut random = [0u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("backend cancellation secret unavailable"))?;
    let pid = u32::from_be_bytes(random[..4].try_into().expect("four bytes")) | 1;
    let secret = u32::from_be_bytes(random[4..].try_into().expect("four bytes"));
    Ok((pid, secret))
}

fn register_backend() -> io::Result<BackendRegistration> {
    // BTree nodes are released on removal, unlike retained HashMap buckets.
    // Admission precedes the registry node, state and cancellation flag.
    let memory = output::reserve(4096)?;
    loop {
        let (pid, secret) = next_backend_key()?;
        let state = Arc::new(BackendCancellation {
            active: AtomicBool::new(false),
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let mut registry = BACKEND_CANCELLATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.contains_key(&pid) {
            continue;
        }
        registry.insert(
            pid,
            BackendCancellationEntry {
                secret,
                state: Arc::downgrade(&state),
            },
        );
        return Ok(BackendRegistration {
            pid,
            secret,
            state,
            _memory: memory,
        });
    }
}

fn cancel_backend(pid: u32, secret: u32) {
    let state = {
        let mut registry = BACKEND_CANCELLATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.get(&pid) else {
            return;
        };
        if entry.secret != secret {
            return;
        }
        let Some(state) = entry.state.upgrade() else {
            registry.remove(&pid);
            if registry.is_empty() {
                *registry = BTreeMap::new();
            }
            return;
        };
        state
    };
    if state.active.load(Ordering::Acquire) {
        state.cancelled.store(true, Ordering::Release);
    }
}

async fn write_backend_key_data<W>(writer: &mut W, pid: u32, secret: u32) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; 8];
    buf[..4].copy_from_slice(&pid.to_be_bytes());
    buf[4..].copy_from_slice(&secret.to_be_bytes());
    write_message(writer, b'K', &buf).await
}

async fn write_ready_for_query<W>(writer: &mut W, status: u8) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_message(writer, b'Z', &[status]).await
}

async fn write_command_complete<W>(writer: &mut W, tag: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = tag
        .len()
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command tag overflow"))?;
    let mut frame = output::prepare(writer, output::control(b'C', length)).await?;
    frame.as_mut()[5..5 + tag.len()].copy_from_slice(tag.as_bytes());
    writer.write_all(frame.as_ref()).await
}

/// Write an `ErrorResponse` frame. `severity` is `"ERROR"` or `"FATAL"`.
/// `sqlstate` is the 5-char code (e.g. `"0A000"`). `message` is required.
/// `hint` adds the `H` field used by the §3.0.1 reject taxonomy.
pub async fn write_error_response<W>(
    writer: &mut W,
    severity: &str,
    sqlstate: &str,
    message: &str,
    hint: Option<&str>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let fields = [
        (b'S', Some(severity)),
        (b'V', Some(severity)),
        (b'C', Some(sqlstate)),
        (b'M', Some(message)),
        (b'H', hint),
    ];
    let length = fields
        .iter()
        .try_fold(1usize, |length, (_, value)| {
            value.map_or(Some(length), |value| {
                length
                    .checked_add(value.len())
                    .and_then(|n| n.checked_add(2))
            })
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "error response overflow"))?;
    let mut frame = output::prepare(writer, output::control(b'E', length)).await?;
    let mut offset = 5;
    for (code, value) in fields {
        if let Some(value) = value {
            frame.as_mut()[offset] = code;
            offset += 1;
            frame.as_mut()[offset..offset + value.len()].copy_from_slice(value.as_bytes());
            offset += value.len() + 1;
        }
    }
    writer.write_all(frame.as_ref()).await
}

/// Low-level: write a single Postgres v3 backend message
/// `<type:1><length:4 BE><payload>`. `length` includes itself.
pub async fn write_message<W>(writer: &mut W, msg_type: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() + 4 > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pg message too large ({} bytes)", payload.len() + 4),
        ));
    }
    writer.write_all(&[msg_type]).await?;
    writer
        .write_all(&((payload.len() + 4) as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    Ok(())
}

fn parse_cstring_in_place(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_recognises_v3_startup() {
        let mut buf = [0_u8; 8];
        buf[..4].copy_from_slice(&100_u32.to_be_bytes());
        buf[4..].copy_from_slice(&PROTOCOL_V3.to_be_bytes());
        assert!(is_postgres_prefix(&buf));
    }

    #[test]
    fn sniff_recognises_ssl_request() {
        let mut buf = [0_u8; 8];
        buf[..4].copy_from_slice(&8_u32.to_be_bytes());
        buf[4..].copy_from_slice(&SSL_REQUEST_MAGIC.to_be_bytes());
        assert!(is_postgres_prefix(&buf));
    }

    #[test]
    fn sniff_rejects_gausswire_prefix() {
        // Gauss native frame: length=42, then protobuf bytes (varint tag 0x08).
        let mut buf = [0_u8; 8];
        buf[..4].copy_from_slice(&42_u32.to_be_bytes());
        buf[4] = 0x08;
        buf[5] = 0xa1;
        buf[6] = 0x06;
        buf[7] = 0x12;
        assert!(!is_postgres_prefix(&buf));
    }

    #[test]
    fn cancel_registry_requires_matching_secret_and_active_query() {
        let backend = register_backend().unwrap();

        cancel_backend(backend.pid, backend.secret);
        assert!(!backend.state.cancelled.load(Ordering::Acquire));

        {
            let _active = backend.begin_query();
            cancel_backend(backend.pid, backend.secret.wrapping_add(1));
            assert!(!backend.state.cancelled.load(Ordering::Acquire));

            cancel_backend(backend.pid, backend.secret);
            assert!(backend.state.cancelled.load(Ordering::Acquire));
        }

        assert!(!backend.state.active.load(Ordering::Acquire));
        assert!(backend.state.cancelled.load(Ordering::Acquire));
        let _next_query = backend.begin_query();
        assert!(!backend.state.cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn sniff_rejects_oversize_length() {
        let mut buf = [0_u8; 8];
        buf[..4].copy_from_slice(&(MAX_MESSAGE_LEN as u32 + 1).to_be_bytes());
        buf[4..].copy_from_slice(&PROTOCOL_V3.to_be_bytes());
        assert!(!is_postgres_prefix(&buf));
    }

    #[test]
    fn deallocate_parser_accepts_driver_names_and_rejects_trailing_sql() {
        assert_eq!(
            parse_deallocate_query("DEALLOCATE \"_pg3_0\";").unwrap(),
            Some(SqlDeallocateTarget::Statement("_pg3_0".to_string()))
        );
        assert_eq!(
            parse_deallocate_query("deallocate prepare Driver_Name").unwrap(),
            Some(SqlDeallocateTarget::Statement("driver_name".to_string()))
        );
        assert_eq!(
            parse_deallocate_query("DeAlLoCaTe ALL").unwrap(),
            Some(SqlDeallocateTarget::All)
        );
        assert_eq!(parse_deallocate_query("SELECT 1").unwrap(), None);
        assert!(parse_deallocate_query("DEALLOCATE").is_err());
        assert!(parse_deallocate_query("DEALLOCATE one two").is_err());
        assert!(parse_deallocate_query("DEALLOCATE \"unterminated").is_err());
    }

    #[test]
    fn parse_startup_params_basic() {
        let mut body = Vec::new();
        body.extend_from_slice(b"user\0alice\0");
        body.extend_from_slice(b"database\0mydb\0");
        body.extend_from_slice(b"application_name\0psql\0");
        body.push(0); // terminator
        let memory = memory::SessionMemory::with_capacity(65536);
        let params = frontend::startup(&body, &memory).unwrap();
        assert_eq!(params.get("user").map(String::as_str), Some("alice"));
        assert_eq!(params.get("database").map(String::as_str), Some("mydb"));
        assert_eq!(
            params.get("application_name").map(String::as_str),
            Some("psql")
        );
    }

    #[tokio::test]
    async fn write_message_framing_is_length_prefixed() {
        let mut buf = Vec::new();
        write_message(&mut buf, b'Z', b"I").await.unwrap();
        // 'Z' + length(4 BE) + 'I' = 6 bytes
        assert_eq!(buf, vec![b'Z', 0, 0, 0, 5, b'I']);
    }

    #[tokio::test]
    async fn error_response_includes_sqlstate_and_hint() {
        let mut buf = Vec::new();
        write_error_response(
            &mut buf,
            "ERROR",
            "0A000",
            "JOIN not supported",
            Some("https://docs/x#joins"),
        )
        .await
        .unwrap();
        assert_eq!(buf[0], b'E');
        // Search for SQLSTATE field marker + code.
        let body = &buf[5..];
        assert!(body.windows(7).any(|w| w == b"C0A000\0"));
        assert!(body.windows(20).any(|w| w == b"MJOIN not supported\0"));
        assert!(body.windows(21).any(|w| w == b"Hhttps://docs/x#joins"));
    }

    #[tokio::test]
    async fn upsert_cardinality_error_uses_postgresql_sqlstate() {
        let mut buf = Vec::new();
        write_native_relational_error(
            &mut buf,
            &crate::GaussError::InvalidRequest(
                "ON CONFLICT DO UPDATE cannot affect row a second time".into(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(buf[0], b'E');
        assert!(buf[5..].windows(7).any(|window| window == b"C21000\0"));
    }

    #[tokio::test]
    async fn foreign_key_restrict_has_distinct_sqlstate_from_no_action() {
        for (message, expected) in [
            (
                "foreign key fk_child_parent restricts the referenced row change",
                b"C23001\0".as_slice(),
            ),
            (
                "foreign key fk_child_parent violated",
                b"C23503\0".as_slice(),
            ),
        ] {
            let mut buf = Vec::new();
            write_native_relational_error(
                &mut buf,
                &crate::GaussError::InvalidRequest(message.into()),
            )
            .await
            .unwrap();
            assert!(buf[5..].windows(7).any(|window| window == expected));
        }
    }

    #[tokio::test]
    async fn cancelled_query_uses_postgresql_sqlstate() {
        let mut buf = Vec::new();
        write_native_relational_error(
            &mut buf,
            &crate::GaussError::InvalidRequest("query canceled".into()),
        )
        .await
        .unwrap();
        assert_eq!(buf[0], b'E');
        assert!(buf[5..].windows(7).any(|window| window == b"C57014\0"));
    }

    #[tokio::test]
    async fn draining_uses_cannot_connect_now_without_hiding_wal_failures() {
        for (message, expected) in [
            (
                "server is shutting down; retry against a ready instance",
                b"C57P03\0".as_slice(),
            ),
            ("WAL synchronization failed", b"C58030\0".as_slice()),
        ] {
            let mut buf = Vec::new();
            write_native_relational_error(
                &mut buf,
                &crate::GaussError::WalUnavailable(message.into()),
            )
            .await
            .unwrap();
            assert_eq!(buf[0], b'E');
            assert!(buf[5..].windows(7).any(|window| window == expected));
        }
    }

    #[tokio::test]
    async fn referenced_schema_drop_uses_dependent_object_sqlstate() {
        for message in [
            "cannot drop constraint accounts_key because foreign key refs_account_fkey on table refs depends on it",
            "cannot drop table accounts because foreign key refs_account_fkey on table refs depends on it",
        ] {
            let mut buf = Vec::new();
            write_native_relational_error(
                &mut buf,
                &crate::GaussError::InvalidRequest(message.into()),
            )
            .await
            .unwrap();
            assert_eq!(buf[0], b'E');
            assert!(buf[5..].windows(7).any(|window| window == b"C2BP01\0"));
        }
    }

    #[tokio::test]
    async fn constraint_rename_errors_use_postgresql_object_sqlstates() {
        for (message, expected) in [
            ("constraint missing does not exist", b"C42704\0".as_slice()),
            (
                "constraint duplicate already exists",
                b"C42710\0".as_slice(),
            ),
        ] {
            let mut buf = Vec::new();
            write_native_relational_error(
                &mut buf,
                &crate::GaussError::InvalidRequest(message.into()),
            )
            .await
            .unwrap();
            assert_eq!(buf[0], b'E');
            assert!(buf[5..].windows(7).any(|window| window == expected));
        }
    }

    #[test]
    fn orm_scalar_types_use_stable_oids_and_decode_text_and_binary_parameters() {
        assert_eq!(
            relational_pg_type(&crate::RelationalType::SmallInt).oid(),
            21
        );
        assert_eq!(
            relational_pg_type(&crate::RelationalType::Integer).oid(),
            23
        );
        assert_eq!(relational_pg_type(&crate::RelationalType::BigInt).oid(), 20);
        assert_eq!(relational_pg_type(&crate::RelationalType::Real).oid(), 700);
        assert_eq!(relational_pg_type(&crate::RelationalType::Float).oid(), 701);
        assert_eq!(
            relational_pg_type(&crate::RelationalType::Varchar { length: 12 }).oid(),
            1043
        );
        assert_eq!(relational_pg_type(&crate::RelationalType::Bytea).oid(), 17);
        assert_eq!(relational_pg_type(&crate::RelationalType::Date).oid(), 1082);
        assert_eq!(
            relational_pg_type(&crate::RelationalType::Jsonb).oid(),
            3802
        );

        assert_eq!(
            decode_pg_parameter(17, 0, b"\\x00ff").unwrap(),
            crate::RelationalValue::Bytes(vec![0, 255])
        );
        assert_eq!(
            decode_pg_parameter(17, 1, &[0, 255]).unwrap(),
            crate::RelationalValue::Bytes(vec![0, 255])
        );
        assert_eq!(
            decode_pg_parameter(1082, 1, &1_i32.to_be_bytes()).unwrap(),
            crate::RelationalValue::Date("2000-01-02".into())
        );
        assert_eq!(
            decode_pg_parameter(1184, 1, &1_000_000_i64.to_be_bytes()).unwrap(),
            crate::RelationalValue::TimestampUtc("2000-01-01T00:00:01.000000Z".into())
        );
        let mut jsonb = vec![1];
        jsonb.extend_from_slice(br#"{"ready":true}"#);
        assert_eq!(
            decode_pg_parameter(3802, 1, &jsonb).unwrap(),
            crate::RelationalValue::Json(serde_json::json!({"ready": true}))
        );
    }

    #[test]
    fn driver_text_timestamptz_normalizes_offsets_to_native_utc() {
        for (input, expected) in [
            (
                "1999-12-31 23:59:59.123456+07:00",
                "1999-12-31T16:59:59.123456Z",
            ),
            ("2000-01-01 00:00:00-03:30", "2000-01-01T03:30:00.000000Z"),
            ("2000-01-01 00:00:00+00", "2000-01-01T00:00:00.000000Z"),
            ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00.000000Z"),
        ] {
            assert_eq!(
                decode_pg_parameter(1184, 0, input.as_bytes()).unwrap(),
                crate::RelationalValue::TimestampUtc(expected.into())
            );
        }
        for input in [
            "not a timestamp",
            "2000-01-01 00:00:00",
            "2026-02-30 00:00:00+00",
        ] {
            assert_eq!(decode_pg_timestamptz(input).unwrap_err().0, "22007");
        }
        assert_eq!(
            decode_pg_timestamptz("2000-01-01T00:00:00.123456789Z")
                .unwrap_err()
                .0,
            "0A000"
        );
    }

    #[tokio::test]
    async fn protected_cancel_preface_requires_exact_secret_and_active_query() {
        let directory = tempfile::tempdir().unwrap();
        let db = Db::open(directory.path()).unwrap();
        let backend = register_backend().unwrap();
        for (active, correct_secret) in [(false, true), (true, false), (true, true)] {
            let query = active.then(|| backend.begin_query());
            let (mut client, server) = tokio::io::duplex(64);
            client.write_all(&backend.pid.to_be_bytes()).await.unwrap();
            let secret = if correct_secret {
                backend.secret
            } else {
                backend.secret.wrapping_add(1)
            };
            client.write_all(&secret.to_be_bytes()).await.unwrap();
            let mut prefix = [0u8; 8];
            prefix[..4].copy_from_slice(&16u32.to_be_bytes());
            prefix[4..].copy_from_slice(&CANCEL_REQUEST_MAGIC.to_be_bytes());
            handle_protected_connection(db.clone(), server, prefix)
                .await
                .unwrap();
            assert_eq!(
                backend.state.cancelled.load(Ordering::Acquire),
                active && correct_secret
            );
            drop(query);
        }
    }

    #[test]
    fn binary_result_encoding_matches_postgresql_scalar_layouts() {
        assert_eq!(
            encode_relational_binary(&crate::RelationalValue::Integer(42), PgType::Int8).unwrap(),
            42_i64.to_be_bytes()
        );
        assert_eq!(encode_pg_binary_text(PgType::Bool, "t").unwrap(), [1]);
        assert_eq!(
            encode_pg_binary_text(PgType::Date, "2000-01-02").unwrap(),
            1_i32.to_be_bytes()
        );
        assert_eq!(
            encode_pg_binary_text(PgType::TimestampTz, "2000-01-01T00:00:01Z").unwrap(),
            1_000_000_i64.to_be_bytes()
        );
        assert_eq!(
            encode_pg_binary_text(PgType::Jsonb, r#"{"ready":true}"#).unwrap(),
            [vec![1], br#"{"ready":true}"#.to_vec()].concat()
        );
        assert_eq!(
            encode_pg_numeric("12345.67").unwrap(),
            [
                3_i16.to_be_bytes().as_slice(),
                1_i16.to_be_bytes().as_slice(),
                0_u16.to_be_bytes().as_slice(),
                2_u16.to_be_bytes().as_slice(),
                1_u16.to_be_bytes().as_slice(),
                2345_u16.to_be_bytes().as_slice(),
                6700_u16.to_be_bytes().as_slice(),
            ]
            .concat()
        );
        let text_array = encode_pg_array("{id,email}", PgType::Text).unwrap();
        assert_eq!(i32::from_be_bytes(text_array[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_be_bytes(text_array[8..12].try_into().unwrap()),
            25
        );
        assert_eq!(
            i32::from_be_bytes(text_array[12..16].try_into().unwrap()),
            2
        );
    }

    #[test]
    fn result_formats_expand_per_postgresql_bind_rules() {
        assert_eq!(expand_result_formats(&[], 2).unwrap(), [0, 0]);
        assert_eq!(expand_result_formats(&[1], 2).unwrap(), [1, 1]);
        assert_eq!(expand_result_formats(&[1, 0], 2).unwrap(), [1, 0]);
        assert!(expand_result_formats(&[1, 0, 1], 2).is_err());
    }
}
