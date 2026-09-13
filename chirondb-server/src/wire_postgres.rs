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
//! - `Query` handler stub: every statement currently returns SQLSTATE `0A000`
//!   with a hint pointing at `.SPEC/gaussdb-vector_cleaned.md`. B2/B3/B4/B5 replace
//!   this stub with the real parser → engine wiring.
//! - `Terminate ('X')` for clean shutdown so `psql \q` lands clean.
//!
//! Extended query protocol, `COPY`, `NOTIFY`, replication subprotocol: out of
//! scope per `.SPEC/gaussdb-vector_cleaned.md` §7.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Db;
use crate::auth::AuthConfig;
use crate::pg_catalog;
use crate::pgvector_exec::{self, ColumnSpec, ExecError, PgType, QueryResponse, SessionState};
use crate::pgvector_parser::{self, ParseError, Statement};
use crate::rbac::{Action, Permission, authorize};

/// Postgres v3.0 protocol version constant.
pub const PROTOCOL_V3: u32 = 196_608; // 0x00030000

/// `SSLRequest` magic. Sent by libpq before the real StartupMessage when
/// `sslmode=prefer` or `require`.
pub const SSL_REQUEST_MAGIC: u32 = 80_877_103;

/// `GSSENCRequest` magic. Also sent before the StartupMessage by libpq builds
/// that enable GSSAPI.
pub const GSSENC_REQUEST_MAGIC: u32 = 80_877_104;

/// `CancelRequest` magic. v1 doesn't implement cancel; we read + drop.
pub const CANCEL_REQUEST_MAGIC: u32 = 80_877_102;

/// Max length of any single message we accept. Mirrors the GaussWire path.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

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
                // v1: drain 8 bytes of (PID, secret) and close. Cancel not implemented.
                let mut payload = [0_u8; 8];
                reader.read_exact(&mut payload).await?;
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
    let mut body = vec![0_u8; length - 8];
    reader.read_exact(&mut body).await?;
    let params = parse_startup_params(&body)?;

    // Auth: cleartext password = API key. If auth disabled, resolve the local
    // compatibility principal. Secure listener policy prevents this exchange
    // from running on a public plaintext socket.
    let principal = if auth.is_enabled() {
        write_auth_cleartext_password(&mut writer).await?;
        let password = read_password_message(&mut reader).await?;
        let principal = auth.permission_for(Some(password.as_str()));
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

    write_auth_ok(&mut writer).await?;
    write_required_parameter_status(&mut writer).await?;
    write_backend_key_data(&mut writer).await?;
    write_ready_for_query(&mut writer, b'I').await?;
    writer.flush().await?;

    let session = SessionState::new();

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
        let mut payload = vec![0_u8; msg_len - 4];
        reader.read_exact(&mut payload).await?;

        match msg_type {
            b'Q' => {
                // Simple query. Strip trailing NUL.
                let sql = parse_cstring_in_place(&payload).to_string();
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
                    handle_query(&db, &principal, &session, &params, &mut writer, &sql).await?;
                } else {
                    metrics::counter!(
                        "gaussdb_work_limited_requests_total",
                        "transport" => "pgwire"
                    )
                    .increment(1);
                    write_error_response(&mut writer, "ERROR", "53300", "server overloaded", None)
                        .await?;
                }
                write_ready_for_query(&mut writer, b'I').await?;
                writer.flush().await?;
            }
            b'X' => {
                // Terminate — clean shutdown.
                return Ok(());
            }
            b'P' | b'B' | b'E' | b'D' | b'S' | b'C' | b'F' | b'H' => {
                // Extended query / COPY / Function call. Spec §3.0.1.
                write_error_response(
                    &mut writer,
                    "ERROR",
                    "0A000",
                    "extended query protocol not supported v1; use simple query mode",
                    Some(&format!("{COMPAT_HINT_BASE}#extended-protocol")),
                )
                .await?;
                write_ready_for_query(&mut writer, b'I').await?;
                writer.flush().await?;
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
async fn handle_query<W>(
    db: &Db,
    principal: &Permission,
    session: &SessionState,
    _params: &HashMap<String, String>,
    writer: &mut W,
    sql: &str,
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
    if let Some(response) = pg_catalog::intercept_scoped(db, sql, |collection| {
        principal.allows_collection(collection)
    }) {
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
                return Ok(());
            }
            write_permission_denied(writer).await?;
            return Ok(());
        }
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
            return Ok(());
        }
        match response {
            QueryResponse::RowSet { columns, rows, tag } => {
                write_row_description(writer, &columns).await?;
                for row in &rows {
                    write_data_row(writer, row).await?;
                }
                write_command_complete(writer, &tag).await?;
            }
            QueryResponse::CommandTag(tag) => write_command_complete(writer, &tag).await?,
            QueryResponse::Empty => write_message(writer, b'I', &[]).await?,
        }
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
            Ok(_) => mutation_audit
                .take()
                .expect("write statement has durable audit intent")
                .success(serde_json::Value::Null),
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

fn authorize_statement(principal: &Permission, statement: &Statement) -> bool {
    match statement {
        Statement::CreateExtensionVector { .. } => {
            authorize(principal, Action::Write, None).is_ok()
        }
        Statement::CreateTable(statement) => {
            authorize(principal, Action::Write, Some(&statement.name)).is_ok()
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
            authorize(principal, Action::Write, Some(&statement.table)).is_ok()
        }
        Statement::DropTable(statement) => statement
            .names
            .iter()
            .all(|name| authorize(principal, Action::Write, Some(name)).is_ok()),
        Statement::Set { .. } | Statement::Show { .. } => {
            authorize(principal, Action::Read, None).is_ok()
        }
        Statement::TransactionControl(_) => authorize(principal, Action::Write, None).is_ok(),
    }
}

fn statement_action(statement: &Statement) -> Action {
    match statement {
        Statement::Select(_) | Statement::Set { .. } | Statement::Show { .. } => Action::Read,
        Statement::CreateExtensionVector { .. }
        | Statement::CreateTable(_)
        | Statement::Insert(_)
        | Statement::Delete(_)
        | Statement::CreateIndex(_)
        | Statement::DropTable(_)
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

async fn write_row_description<W>(writer: &mut W, columns: &[ColumnSpec]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(columns.len() * 32);
    buf.extend_from_slice(&(columns.len() as u16).to_be_bytes());
    for col in columns {
        buf.extend_from_slice(col.name.as_bytes());
        buf.push(0); // name C-string
        buf.extend_from_slice(&0_u32.to_be_bytes()); // table OID
        buf.extend_from_slice(&0_u16.to_be_bytes()); // column attno
        buf.extend_from_slice(&col.pg_type.oid().to_be_bytes()); // type OID
        buf.extend_from_slice(&col.pg_type.typlen().to_be_bytes()); // typlen
        buf.extend_from_slice(&(-1_i32).to_be_bytes()); // typmod
        buf.extend_from_slice(&0_u16.to_be_bytes()); // format = text
    }
    write_message(writer, b'T', &buf).await
}

async fn write_data_row<W>(writer: &mut W, row: &[Option<String>]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(row.len() * 16);
    buf.extend_from_slice(&(row.len() as u16).to_be_bytes());
    for cell in row {
        match cell {
            None => buf.extend_from_slice(&(-1_i32).to_be_bytes()),
            Some(s) => {
                buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
                buf.extend_from_slice(s.as_bytes());
            }
        }
    }
    write_message(writer, b'D', &buf).await
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

#[allow(dead_code)]
fn _bind_pgtype_marker(_pt: PgType) {}

fn parse_startup_params(body: &[u8]) -> io::Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] == 0 {
            // Trailing extra NUL terminator.
            break;
        }
        let key_end = body[i..].iter().position(|&b| b == 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unterminated startup key")
        })?;
        let key = std::str::from_utf8(&body[i..i + key_end])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .to_string();
        i += key_end + 1;
        let value_end = body[i..].iter().position(|&b| b == 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unterminated startup value")
        })?;
        let value = std::str::from_utf8(&body[i..i + value_end])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .to_string();
        i += value_end + 1;
        params.insert(key, value);
    }
    Ok(params)
}

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

async fn read_password_message<R>(reader: &mut R) -> io::Result<String>
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
    let mut body = vec![0_u8; len - 4];
    reader.read_exact(&mut body).await?;
    // body is null-terminated UTF-8 password.
    let trimmed = body.split(|&b| b == 0).next().unwrap_or(&[]);
    Ok(String::from_utf8_lossy(trimmed).into_owned())
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
        let mut buf = Vec::with_capacity(k.len() + v.len() + 2);
        buf.extend_from_slice(k.as_bytes());
        buf.push(0);
        buf.extend_from_slice(v.as_bytes());
        buf.push(0);
        write_message(writer, b'S', &buf).await?;
    }
    Ok(())
}

/// Backend PID/secret values are opaque to the client unless they later send
/// `CancelRequest` — which v1 doesn't honor. We just need two distinct u32s
/// per connection that aren't trivially predictable. A monotonic counter XORed
/// with a per-connection nonce derived from `Instant::now()` is enough.
static BACKEND_COUNTER: AtomicU64 = AtomicU64::new(1);

async fn write_backend_key_data<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let counter = BACKEND_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mix = counter ^ nonce.rotate_left(13);
    let pid = (mix as u32) | 1;
    let secret = ((mix >> 32) as u32) ^ 0xA5A5_5A5A;
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
    let mut buf = Vec::with_capacity(tag.len() + 1);
    buf.extend_from_slice(tag.as_bytes());
    buf.push(0);
    write_message(writer, b'C', &buf).await
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
    let mut buf = Vec::with_capacity(64);
    push_field(&mut buf, b'S', severity);
    push_field(&mut buf, b'V', severity);
    push_field(&mut buf, b'C', sqlstate);
    push_field(&mut buf, b'M', message);
    if let Some(h) = hint {
        push_field(&mut buf, b'H', h);
    }
    buf.push(0);
    write_message(writer, b'E', &buf).await
}

fn push_field(buf: &mut Vec<u8>, code: u8, value: &str) {
    buf.push(code);
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
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
    fn sniff_rejects_oversize_length() {
        let mut buf = [0_u8; 8];
        buf[..4].copy_from_slice(&(MAX_MESSAGE_LEN as u32 + 1).to_be_bytes());
        buf[4..].copy_from_slice(&PROTOCOL_V3.to_be_bytes());
        assert!(!is_postgres_prefix(&buf));
    }

    #[test]
    fn parse_startup_params_basic() {
        let mut body = Vec::new();
        body.extend_from_slice(b"user\0alice\0");
        body.extend_from_slice(b"database\0mydb\0");
        body.extend_from_slice(b"application_name\0psql\0");
        body.push(0); // terminator
        let params = parse_startup_params(&body).unwrap();
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
}
