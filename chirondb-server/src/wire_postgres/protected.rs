//! Protected PostgreSQL session: no legacy key/RBAC or tenant-header fallback.
use super::*;
use chirondb_core::security::{AuthenticatedIdentity, SecurityError};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Duration, timeout};

const MAX_PROTECTED_FRAME: usize = 8 * 1024 * 1024;
use super::frontend::MAX_SESSION_OBJECTS;

pub async fn handle_protected_connection<S>(db: Db, stream: S, prefix: [u8; 8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let length = u32::from_be_bytes(prefix[..4].try_into().expect("fixed prefix")) as usize;
    let magic = u32::from_be_bytes(prefix[4..].try_into().expect("fixed prefix"));
    // The dispatcher requires verified TLS before entering this handler.
    // Cancellation is authorized by the target connection's random secret.
    if magic == CANCEL_REQUEST_MAGIC && length == 16 {
        let mut payload = [0u8; 8];
        timeout(Duration::from_secs(10), reader.read_exact(&mut payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "cancel request timed out"))??;
        cancel_backend(
            u32::from_be_bytes(payload[..4].try_into().expect("fixed pid")),
            u32::from_be_bytes(payload[4..].try_into().expect("fixed secret")),
        );
        // libpq waits for a clean TLS EOF as the CancelRequest acknowledgment.
        // Dropping the stream without close_notify is reported as a failure.
        writer.shutdown().await?;
        return Ok(());
    }
    if magic != PROTOCOL_V3 || !(8..=4096).contains(&length) {
        write_error_response(
            &mut writer,
            "FATAL",
            "08P01",
            "invalid startup message",
            None,
        )
        .await?;
        return Ok(());
    }
    let memory = memory::SessionMemory::new();
    let startup = output::prepare(
        &mut writer,
        frontend::read(&mut reader, length - 8, 4096).await,
    )
    .await?;
    let params = output::prepare(&mut writer, frontend::startup(startup.as_ref(), &memory)).await?;
    drop(startup);
    let username = params
        .get("user")
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing startup user"))?;
    let authority = db
        .identity_authority()
        .ok_or_else(|| io::Error::other("identity authority unavailable"))?;
    let actual = authority.sql_verifier_for_user(username);
    let verifier = actual
        .clone()
        .unwrap_or_else(|| authority.sql_decoy_verifier(username));
    let result = scram::authenticate(&mut reader, &mut writer, &verifier).await;
    let result = output::prepare(&mut writer, result).await?;
    if matches!(result, scram::ScramOutcome::UnsupportedMechanism) {
        write_error_response(
            &mut writer,
            "FATAL",
            "0A000",
            "SASL mechanism is unsupported",
            None,
        )
        .await?;
        writer.flush().await?;
        return Ok(());
    }
    let identity = if matches!(result, scram::ScramOutcome::Authenticated) && actual.is_some() {
        authority
            .authenticate_sql(username, &verifier.id)
            .ok()
            .and_then(|identity| db.management_identity(&identity).ok())
    } else {
        None
    };
    let Some(identity) = identity else {
        let _ = db.audit_access_event(
            "authentication",
            "pgwire_scram",
            "failure",
            None,
            "unknown",
            None,
            "pgwire",
            None,
            Some("invalid_credential"),
        );
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
    };
    drop(params);
    if db
        .audit_access_event(
            "authentication",
            "pgwire_scram",
            "success",
            None,
            &identity.principal().id,
            Some(&identity.principal().tenant),
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
            writer.shutdown().await?;
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
    let mut statements =
        HashMap::<String, Arc<NativePreparedStatement>>::with_capacity(MAX_SESSION_OBJECTS);
    let mut portals = HashMap::<String, NativePortal>::with_capacity(MAX_SESSION_OBJECTS);
    let mut transaction = ConnectionTransaction::new(
        &db,
        &identity.principal().id,
        Some(&identity.principal().tenant),
        "pgwire-protected",
    )?;
    let mut extended_failed = false;
    async {
        loop {
            let mut header = [0u8; 5];
            match reader.read_exact(&mut header).await {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            let size = u32::from_be_bytes(header[1..].try_into().expect("fixed header")) as usize;
            if !(4..=MAX_PROTECTED_FRAME).contains(&size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid frontend frame",
                ));
            }
            if matches!(header[0], b'S' | b'H' | b'X') && size != 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control frame must be empty",
                ));
            }
            if header[0] == b'X' {
                return Ok(());
            }
            if identity.publication_permit().is_err() {
                write_error_response(
                    &mut writer,
                    "FATAL",
                    "28000",
                    "authorization was revoked",
                    None,
                )
                .await?;
                writer.flush().await?;
                return Ok(());
            }
            if extended_failed {
                if let Some(active) = transaction.as_mut() {
                    active.failed = true;
                }
                if header[0] != b'S' {
                    // Discard failed extended-protocol messages without a
                    // payload-sized allocation. Sync must remain reachable.
                    frontend::discard(&mut reader, size - 4).await?;
                    continue;
                }
            }
            // Reserve the bounded shared frame slot before allocating or
            // reading a payload. Idle sockets and empty controls own no slot.
            let _frame = if size > 4 {
                match authority.frame_pool().try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        write_error_response(
                            &mut writer,
                            "FATAL",
                            "53300",
                            "frame capacity exhausted",
                            None,
                        )
                        .await?;
                        writer.shutdown().await?;
                        return Ok(());
                    }
                }
            } else {
                None
            };
            let payload = if size > 4 {
                Some(
                    output::prepare(
                        &mut writer,
                        frontend::read(&mut reader, size - 4, MAX_PROTECTED_FRAME).await,
                    )
                    .await?,
                )
            } else {
                None
            };
            let payload = payload.as_ref().map_or(&[][..], AsRef::as_ref);
            let rollback = header[0] == b'Q'
                && payload
                    .strip_suffix(&[0])
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .is_some_and(|sql| {
                        sql.trim()
                            .trim_end_matches(';')
                            .trim()
                            .eq_ignore_ascii_case("rollback")
                    });
            let work = if matches!(header[0], b'C' | b'H' | b'S') || rollback {
                None
            } else {
                match authority.work_pool().try_acquire_owned() {
                    Ok(permit) => Some(Arc::new(permit)),
                    Err(_) => {
                        if let Some(active) = transaction.as_mut() {
                            active.failed = true;
                        }
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "53300",
                            "server overloaded",
                            None,
                        )
                        .await?;
                        if header[0] == b'Q' {
                            write_ready_for_query(
                                &mut writer,
                                if transaction.is_some() { b'E' } else { b'I' },
                            )
                            .await?;
                        } else {
                            extended_failed = true;
                        }
                        writer.flush().await?;
                        continue;
                    }
                }
            };
            match header[0] {
                b'Q' => {
                    let sql = parse_cstring_in_place(payload);
                    let _active = backend.begin_query();
                    match parse_deallocate_query(sql) {
                        Ok(Some(target)) => {
                            if transaction.as_ref().is_some_and(|active| active.failed) {
                                write_error_response(
                                    &mut writer,
                                    "ERROR",
                                    "25P02",
                                    "transaction is aborted",
                                    None,
                                )
                                .await?;
                            } else if apply_deallocate_target(target, &mut statements, &mut portals)
                            {
                                write_command_complete(&mut writer, "DEALLOCATE").await?;
                            } else {
                                if let Some(active) = transaction.as_mut() {
                                    active.failed = true;
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
                            if let Some(active) = transaction.as_mut() {
                                active.failed = true;
                            }
                            write_error_response(&mut writer, "ERROR", "42601", &message, None)
                                .await?;
                        }
                        Ok(None) => timeout(
                            Duration::from_secs(30),
                            protected_query(
                                &db,
                                &identity,
                                &session,
                                &mut transaction,
                                &mut writer,
                                ProtectedQuery {
                                    sql,
                                    parameters: &[],
                                    formats: &[],
                                    include_description: true,
                                    cancellation: backend.state.cancelled.clone(),
                                    work: work.clone(),
                                    memory: &memory,
                                },
                            ),
                        )
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "query timed out")
                        })??,
                    }
                    write_ready_for_query(
                        &mut writer,
                        transaction
                            .as_ref()
                            .map_or(b'I', |t| if t.failed { b'E' } else { b'T' }),
                    )
                    .await?;
                    writer.flush().await?;
                }
                b'P' => match parse_native_parse_message_admitted(
                    payload,
                    &db,
                    transaction.is_some(),
                    Some(&memory),
                ) {
                    Ok((name, statement)) => {
                        if statements.len() >= MAX_SESSION_OBJECTS
                            && !statements.contains_key(&name)
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
                        statements.insert(name, statement);
                        write_message(&mut writer, b'1', &[]).await?;
                    }
                    Err((state, _)) => {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            state,
                            if state == "53200" {
                                "session memory capacity exhausted"
                            } else {
                                "unsupported prepared statement"
                            },
                            None,
                        )
                        .await?;
                        extended_failed = true;
                    }
                },
                b'B' => {
                    match parse_native_bind_message_admitted(payload, &statements, Some(&memory)) {
                        Ok((name, portal)) => {
                            if portals.len() >= MAX_SESSION_OBJECTS && !portals.contains_key(&name)
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
                        Err((state, _)) => {
                            write_error_response(
                                &mut writer,
                                "ERROR",
                                state,
                                if state == "53200" {
                                    "session memory capacity exhausted"
                                } else {
                                    "invalid bind"
                                },
                                None,
                            )
                            .await?;
                            extended_failed = true;
                        }
                    }
                }
                b'D' => match parse_describe_message(payload) {
                    Ok((b'S', name)) => {
                        if let Some(statement) = statements.get(name) {
                            write_parameter_description(&mut writer, &statement.parameter_oids)
                                .await?;
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
                        if let Some(portal) = portals.get_mut(name) {
                            let _active = backend.begin_query();
                            if portal.statement.session_compat.is_some() {
                                // SET is a command; SHOW is described by its
                                // side-effect-free Execute result below.
                                write_message(&mut writer, b'n', &[]).await?;
                                portal.described_metadata = false;
                            } else if portal.statement.catalog {
                                match protected_catalog(
                                    &db,
                                    &identity,
                                    &portal.statement.sql,
                                    &portal.parameters,
                                ) {
                                    Ok(Some(response)) => {
                                        let Ok(_guard) = identity.publication_permit() else {
                                            write_error_response(
                                                &mut writer,
                                                "ERROR",
                                                "28000",
                                                "authorization was revoked",
                                                None,
                                            )
                                            .await?;
                                            extended_failed = true;
                                            continue;
                                        };
                                        write_catalog_description_formatted(
                                            &mut writer,
                                            &response,
                                            &portal.result_formats,
                                        )
                                        .await?;
                                        // Describe is metadata only. Never cache rows across a
                                        // permission or data revision boundary.
                                        portal.described_metadata = true;
                                    }
                                    Ok(None) => {
                                        write_error_response(
                                            &mut writer,
                                            "ERROR",
                                            "0A000",
                                            "unsupported catalog query",
                                            None,
                                        )
                                        .await?;
                                        extended_failed = true;
                                    }
                                    Err(error) => {
                                        write_protected_error(&mut writer, &error).await?;
                                        extended_failed = true;
                                    }
                                }
                            } else if is_transaction_control_sql(&portal.statement.sql) {
                                // Describe must never execute a transaction control command.
                                write_message(&mut writer, b'n', &[]).await?;
                                portal.described_metadata = true;
                            } else if portal.statement.analysis.class
                                == crate::SqlStatementClass::Read
                            {
                                let request = sql_request(
                                    &portal.statement.sql,
                                    &portal.parameters,
                                    true,
                                    &memory,
                                );
                                let response = execute_protected_sql(
                                    &db,
                                    &identity,
                                    transaction.as_ref().map(|active| active.handle.as_str()),
                                    request,
                                    backend.state.cancelled.clone(),
                                    work.clone(),
                                )
                                .await;
                                match response {
                                    Ok(response) => {
                                        let Ok(_guard) = identity.publication_permit() else {
                                            write_error_response(
                                                &mut writer,
                                                "ERROR",
                                                "28000",
                                                "authorization was revoked",
                                                None,
                                            )
                                            .await?;
                                            extended_failed = true;
                                            continue;
                                        };
                                        if let Some(columns) = output::prepare(
                                            &mut writer,
                                            native_result_columns(&response.results),
                                        )
                                        .await?
                                        {
                                            let formats = output::prepare(
                                                &mut writer,
                                                expand_result_formats(
                                                    &portal.result_formats,
                                                    columns.len(),
                                                ),
                                            )
                                            .await?;
                                            write_row_description_formatted(
                                                &mut writer,
                                                &columns,
                                                &formats,
                                            )
                                            .await?;
                                        } else {
                                            write_message(&mut writer, b'n', &[]).await?;
                                        }
                                        // Execute reruns the query under current authority.
                                        portal.described_metadata = true;
                                    }
                                    Err(error) => {
                                        if let Some(active) = transaction.as_mut() {
                                            active.failed = true;
                                        }
                                        write_protected_error(&mut writer, &error).await?;
                                        extended_failed = true;
                                    }
                                }
                            } else {
                                write_message(&mut writer, b'n', &[]).await?;
                                // A write can have RETURNING rows. Until we can
                                // derive its metadata without mutation, Execute
                                // must still emit RowDescription before DataRow.
                                portal.described_metadata = false;
                            }
                        } else {
                            write_error_response(
                                &mut writer,
                                "ERROR",
                                "34000",
                                "portal does not exist",
                                None,
                            )
                            .await?;
                            extended_failed = true;
                        }
                    }
                    _ => {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "08P01",
                            "invalid Describe target",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                    }
                },
                b'E' => match parse_execute_message(payload) {
                    Ok((name, 0)) => {
                        if let Some(portal) = portals.get(name) {
                            let _active = backend.begin_query();
                            timeout(
                                Duration::from_secs(30),
                                protected_query(
                                    &db,
                                    &identity,
                                    &session,
                                    &mut transaction,
                                    &mut writer,
                                    ProtectedQuery {
                                        sql: &portal.statement.sql,
                                        parameters: &portal.parameters,
                                        formats: &portal.result_formats,
                                        include_description: !portal.described_metadata,
                                        cancellation: backend.state.cancelled.clone(),
                                        work: work.clone(),
                                        memory: &memory,
                                    },
                                ),
                            )
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "query timed out")
                            })??;
                        } else {
                            write_error_response(
                                &mut writer,
                                "ERROR",
                                "34000",
                                "portal does not exist",
                                None,
                            )
                            .await?;
                            extended_failed = true;
                        }
                    }
                    _ => {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "0A000",
                            "portal row limits are unsupported",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                    }
                },
                b'C' => match close_native_target(payload, &mut statements, &mut portals) {
                    Ok(()) => write_message(&mut writer, b'3', &[]).await?,
                    Err(_) => {
                        write_error_response(
                            &mut writer,
                            "ERROR",
                            "08P01",
                            "invalid Close target",
                            None,
                        )
                        .await?;
                        extended_failed = true;
                    }
                },
                b'H' => writer.flush().await?,
                b'S' => {
                    extended_failed = false;
                    write_ready_for_query(
                        &mut writer,
                        transaction
                            .as_ref()
                            .map_or(b'I', |t| if t.failed { b'E' } else { b'T' }),
                    )
                    .await?;
                    writer.flush().await?;
                }
                _ => {
                    write_error_response(
                        &mut writer,
                        "ERROR",
                        "0A000",
                        "unsupported frontend message",
                        None,
                    )
                    .await?;
                    extended_failed = true;
                }
            }
            drop(work);
        }
    }
    .await
}

struct ProtectedSqlRequest<'a> {
    sql: &'a str,
    parameters: &'a [crate::RelationalValue],
    readonly: bool,
    memory: &'a memory::SessionMemory,
}

fn sql_request<'a>(
    sql: &'a str,
    parameters: &'a [crate::RelationalValue],
    readonly: bool,
    memory: &'a memory::SessionMemory,
) -> ProtectedSqlRequest<'a> {
    ProtectedSqlRequest {
        sql,
        parameters,
        readonly,
        memory,
    }
}

impl ProtectedSqlRequest<'_> {
    fn into_owned(self) -> crate::Result<(crate::SqlExecutionRequest, memory::Charge)> {
        let (mut request, memory) = frontend::request(self.sql, self.parameters, self.memory)
            .map_err(|(_, message)| crate::GaussError::ResourceExhausted(message))?;
        request.retry_id = (!self.readonly).then(|| uuid::Uuid::new_v4().to_string());
        Ok((request, memory))
    }
}

fn protected_catalog(
    db: &Db,
    identity: &AuthenticatedIdentity,
    sql: &str,
    parameters: &[crate::RelationalValue],
) -> crate::Result<Option<pg_catalog::CatalogResponse>> {
    pg_catalog::intercept_authorized_owned(db, identity, sql, parameters)
}

struct ProtectedQuery<'a> {
    sql: &'a str,
    parameters: &'a [crate::RelationalValue],
    formats: &'a [i16],
    include_description: bool,
    cancellation: Arc<AtomicBool>,
    work: Option<Arc<OwnedSemaphorePermit>>,
    memory: &'a memory::SessionMemory,
}

struct CancelSqlOnDrop(Option<Arc<AtomicBool>>);

impl Drop for CancelSqlOnDrop {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.0 {
            cancellation.store(true, Ordering::Release);
        }
    }
}

async fn run_protected_sql_work<T: Send + 'static>(
    cancellation: Arc<AtomicBool>,
    work: Option<Arc<OwnedSemaphorePermit>>,
    operation: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> crate::Result<T> {
    // Keep TLS, cancellation and other sockets responsive during synchronous
    // engine work. A cancelled handler must not release admission while its
    // blocking worker is still unwinding.
    let mut cancel_on_drop = CancelSqlOnDrop(Some(cancellation));
    let result = tokio::task::spawn_blocking(move || {
        let _work = work;
        operation()
    })
    .await;
    cancel_on_drop.0 = None;
    result.map_err(|_| crate::GaussError::Io(io::Error::other("SQL worker failed")))?
}

async fn execute_protected_sql(
    db: &Db,
    identity: &AuthenticatedIdentity,
    handle: Option<&str>,
    request: ProtectedSqlRequest<'_>,
    cancellation: Arc<AtomicBool>,
    work: Option<Arc<OwnedSemaphorePermit>>,
) -> crate::Result<crate::SqlResponse> {
    let (request, memory) = request.into_owned()?;
    let db = db.clone();
    let identity = identity.clone();
    let handle = handle.map(str::to_owned);
    run_protected_sql_work(cancellation.clone(), work, move || {
        let _memory = memory;
        if let Some(handle) = handle {
            db.execute_sql_transaction_authorized_cancellable_owned(
                &identity,
                &handle,
                request,
                "pgwire-protected",
                cancellation,
            )
        } else {
            db.execute_sql_authorized_cancellable_owned(
                &identity,
                request,
                "pgwire-protected",
                cancellation,
            )
        }
    })
    .await
}

async fn protected_query<W: AsyncWrite + Unpin>(
    db: &Db,
    identity: &AuthenticatedIdentity,
    session: &SessionState,
    transaction: &mut Option<PgRelationalTransaction>,
    writer: &mut W,
    query: ProtectedQuery<'_>,
) -> io::Result<()> {
    let ProtectedQuery {
        sql,
        parameters,
        formats,
        include_description,
        cancellation,
        work,
        memory,
    } = query;
    let managed = match db.management_identity(identity) {
        Ok(managed) => managed,
        Err(error) => {
            write_protected_error(writer, &error).await?;
            return Ok(());
        }
    };
    let identity = &managed;
    let normalized = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    if normalized.is_empty() {
        write_message(writer, b'I', &[]).await?;
        return Ok(());
    }
    if matches!(
        normalized.as_str(),
        "begin" | "begin transaction" | "start transaction"
    ) {
        if transaction.is_some() {
            write_error_response(writer, "ERROR", "25001", "transaction already active", None)
                .await?;
            return Ok(());
        }
        match db.begin_sql_transaction_authorized(identity, "pgwire-protected") {
            Ok(response) => {
                *transaction = Some(PgRelationalTransaction {
                    handle: response.handle,
                    failed: false,
                });
                write_command_complete(writer, "BEGIN").await?;
            }
            Err(error) => write_protected_error(writer, &error).await?,
        }
        return Ok(());
    }
    if normalized == "rollback" || normalized == "commit" || normalized == "end" {
        let Some(active) = transaction.as_ref() else {
            write_error_response(writer, "ERROR", "25P01", "no transaction is active", None)
                .await?;
            return Ok(());
        };
        let handle = active.handle.clone();
        let result = if normalized == "rollback" || active.failed {
            db.rollback_sql_transaction_authorized(identity, &handle, "pgwire-protected")
                .map(|_| "ROLLBACK")
        } else {
            let db = db.clone();
            let identity = identity.clone();
            run_protected_sql_work(cancellation.clone(), work, move || {
                db.commit_sql_transaction_authorized_cancellable_owned(
                    &identity,
                    &handle,
                    "pgwire-protected",
                    cancellation,
                )
            })
            .await
            .map(|_| "COMMIT")
        };
        match result {
            Ok(tag) => {
                *transaction = None;
                write_command_complete(writer, tag).await?;
            }
            Err(error) => {
                if let Some(active) = transaction.as_mut() {
                    active.failed = true;
                }
                write_protected_error(writer, &error).await?;
            }
        }
        return Ok(());
    }
    let rollback_to = normalized.starts_with("rollback to ");
    if normalized.starts_with("savepoint ") || rollback_to || normalized.starts_with("release ") {
        let Some(active) = transaction.as_mut() else {
            write_error_response(writer, "ERROR", "25P01", "no transaction is active", None)
                .await?;
            return Ok(());
        };
        if active.failed && !rollback_to {
            write_error_response(writer, "ERROR", "25P02", "transaction is aborted", None).await?;
            return Ok(());
        }
        let tag = if rollback_to {
            "ROLLBACK"
        } else if normalized.starts_with("savepoint ") {
            "SAVEPOINT"
        } else {
            "RELEASE"
        };
        match execute_protected_sql(
            db,
            identity,
            Some(&active.handle),
            sql_request(sql, parameters, false, memory),
            cancellation,
            work,
        )
        .await
        {
            Ok(_) => {
                if rollback_to {
                    active.failed = false;
                }
                write_command_complete(writer, tag).await?;
            }
            Err(error) => {
                active.failed = true;
                write_protected_error(writer, &error).await?;
            }
        }
        return Ok(());
    }
    let catalog = match protected_catalog(db, identity, sql, parameters) {
        Ok(response) => response,
        Err(error) => {
            if let Some(active) = transaction.as_mut() {
                active.failed = true;
            }
            write_protected_error(writer, &error).await?;
            return Ok(());
        }
    };
    if let Some(response) = catalog {
        let Ok(_guard) = identity.publication_permit() else {
            write_error_response(writer, "ERROR", "28000", "authorization was revoked", None)
                .await?;
            return Ok(());
        };
        write_catalog_response_formatted(writer, &response, include_description, formats).await?;
        return Ok(());
    }
    if let Some(statement) = parse_session_compat_statement(sql) {
        let response = match statement {
            SessionCompatStatement::Set => QueryResponse::CommandTag("SET".into()),
            SessionCompatStatement::Parsed(Statement::Show { name }) => QueryResponse::RowSet {
                columns: vec![ColumnSpec {
                    name: name.clone(),
                    pg_type: PgType::Text,
                }],
                rows: vec![vec![Some(pgvector_exec::show_value(&name))]],
                tag: "SHOW".into(),
            },
            _ => QueryResponse::CommandTag("SET".into()),
        };
        let Ok(_guard) = identity.publication_permit() else {
            write_error_response(writer, "ERROR", "28000", "authorization was revoked", None)
                .await?;
            return Ok(());
        };
        write_catalog_response_formatted(writer, &response, include_description, formats).await?;
        return Ok(());
    }
    let mut vector_parsed = pgvector_parser::parse(sql).ok();
    let vector_shape =
        if let Some(parsed) = vector_parsed.as_ref().filter(|parsed| parsed.len() == 1) {
            match protected_vector_shape(db, identity, transaction.as_ref(), &parsed[0]) {
                Ok(value) => value,
                Err(error) => {
                    write_protected_error(writer, &error).await?;
                    return Ok(());
                }
            }
        } else {
            false
        };
    if vector_shape {
        let mut parsed = vector_parsed
            .take()
            .expect("vector shape requires parsed SQL");
        if transaction.is_some() {
            write_error_response(
                writer,
                "ERROR",
                "0A000",
                "pgvector SQL is unavailable inside a relational transaction",
                None,
            )
            .await?;
            return Ok(());
        }
        if !parameters.is_empty() {
            write_error_response(
                writer,
                "ERROR",
                "0A000",
                "parameterized pgvector SQL is unsupported",
                None,
            )
            .await?;
            return Ok(());
        }
        match pgvector_exec::execute_protected(db, session, identity, parsed.remove(0)) {
            Ok(response) => {
                let Ok(_permit) = identity.publication_permit() else {
                    write_error_response(
                        writer,
                        "ERROR",
                        "28000",
                        "authorization was revoked",
                        None,
                    )
                    .await?;
                    return Ok(());
                };
                write_catalog_response_formatted(writer, &response, include_description, formats)
                    .await?;
            }
            Err(error) => write_exec_error(writer, &error).await?,
        }
        return Ok(());
    }
    let analysis = match crate::RelationalEngine::analyze_statement(sql) {
        Ok(analysis) => analysis,
        Err(error) => {
            write_protected_error(writer, &error).await?;
            return Ok(());
        }
    };
    if analysis.declares_vector {
        write_error_response(
            writer,
            "ERROR",
            "0A000",
            "protected vector SQL is unavailable",
            None,
        )
        .await?;
        return Ok(());
    }
    let request = sql_request(
        sql,
        parameters,
        analysis.class == crate::SqlStatementClass::Read,
        memory,
    );
    if transaction.as_ref().is_some_and(|active| active.failed) {
        write_error_response(writer, "ERROR", "25P02", "transaction is aborted", None).await?;
        return Ok(());
    }
    let response = execute_protected_sql(
        db,
        identity,
        transaction.as_ref().map(|active| active.handle.as_str()),
        request,
        cancellation,
        work,
    )
    .await;
    match response {
        Ok(response) => {
            let reference = match db.sql_reference_publication_context(identity, &response.results)
            {
                Ok(reference) => reference,
                Err(error) => {
                    if let Some(active) = transaction.as_mut() {
                        active.failed = true;
                    }
                    write_protected_error(writer, &error).await?;
                    return Ok(());
                }
            };
            let Ok(_guard) = identity.publication_permit() else {
                if let Some(active) = transaction.as_mut() {
                    active.failed = true;
                }
                write_error_response(writer, "ERROR", "28000", "authorization was revoked", None)
                    .await?;
                return Ok(());
            };
            let Ok(_reference_guard) = reference
                .as_ref()
                .map(chirondb_core::security::AccessContext::publication_permit)
                .transpose()
            else {
                if let Some(active) = transaction.as_mut() {
                    active.failed = true;
                }
                write_error_response(writer, "ERROR", "28000", "authorization was revoked", None)
                    .await?;
                return Ok(());
            };
            write_native_relational_results_formatted(
                writer,
                &response.results,
                &analysis,
                include_description,
                formats,
            )
            .await?;
        }
        Err(error) => {
            if let Some(active) = transaction.as_mut() {
                active.failed = true;
            }
            write_protected_error(writer, &error).await?;
        }
    }
    let _ = session;
    Ok(())
}

fn protected_vector_shape(
    db: &Db,
    identity: &AuthenticatedIdentity,
    transaction: Option<&PgRelationalTransaction>,
    statement: &Statement,
) -> crate::Result<bool> {
    let relational = db.relational_tables();
    let native = |name: &str| -> crate::Result<bool> {
        if let Some(active) = transaction {
            db.sql_transaction_has_table_authorized(
                identity,
                &active.handle,
                "pgwire-protected",
                name,
            )
        } else {
            Ok(relational.iter().any(|table| table.name == name))
        }
    };
    match statement {
        Statement::CreateExtensionVector { .. } | Statement::CreateIndex(_) => Ok(true),
        Statement::CreateTable(table) => Ok(table
            .columns
            .iter()
            .any(|column| matches!(column.data_type, pgvector_parser::SqlType::Vector(_)))),
        Statement::Insert(insert) => Ok(!native(&insert.table)?),
        Statement::Select(select) => Ok(!native(&select.table)?
            && select
                .order_by
                .as_ref()
                .is_some_and(|order| matches!(order.expr, pgvector_parser::Expr::Distance { .. }))),
        Statement::Delete(delete) => Ok(!native(&delete.table)?),
        Statement::DropTable(drop) => {
            for name in &drop.names {
                if native(name)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

async fn write_protected_error<W: AsyncWrite + Unpin>(
    writer: &mut W,
    error: &crate::GaussError,
) -> io::Result<()> {
    match error {
        crate::GaussError::Security(SecurityError::NotFound) => {
            write_error_response(writer, "ERROR", "42P01", "relation does not exist", None).await
        }
        crate::GaussError::Security(SecurityError::Forbidden) => {
            write_error_response(writer, "ERROR", "42501", "operation is not permitted", None).await
        }
        crate::GaussError::Security(SecurityError::Unauthenticated | SecurityError::Conflict) => {
            write_error_response(writer, "ERROR", "28000", "authorization was revoked", None).await
        }
        crate::GaussError::Security(_) => {
            write_error_response(writer, "ERROR", "57P03", "service unavailable", None).await
        }
        _ => write_native_relational_error(writer, error).await,
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[tokio::test]
    async fn dropped_handler_cancels_worker_and_retains_admission_until_exit() {
        let backend = register_backend().unwrap();
        let cancellation = backend.state.cancelled.clone();
        let worker_cancel = cancellation.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (finished, stopped) = tokio::sync::oneshot::channel();
        let pool = Arc::new(tokio::sync::Semaphore::new(1));
        let work = Arc::new(pool.clone().try_acquire_owned().unwrap());
        let memory = memory::SessionMemory::with_capacity(4096);
        let charge = memory.reserve(1024).unwrap();
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let handler = tokio::spawn(async move {
            let _active = backend.begin_query();
            run_protected_sql_work(cancellation, Some(work), move || {
                let _memory = charge;
                started.send(()).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while !worker_cancel.load(Ordering::Acquire) && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                finished
                    .send(worker_cancel.load(Ordering::Acquire))
                    .unwrap();
                wait_for_release
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(())
            })
            .await
        });
        timeout(Duration::from_secs(3), ready)
            .await
            .unwrap()
            .unwrap();
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert!(
            timeout(Duration::from_secs(3), stopped)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(pool.available_permits(), 0);
        assert_eq!(memory.available(), (3072, 3072));
        release.send(()).unwrap();
        let returned = timeout(Duration::from_secs(3), pool.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(returned);
        assert_eq!(pool.available_permits(), 1);
        assert_eq!(memory.available(), (4096, 4096));
    }
}
