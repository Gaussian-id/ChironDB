//! ChironQL REPL — line loop, table rendering, trace rendering.
//!
//! P1 of the ChironQL plan. Written once against [`QuerySink`] so the embedded
//! server console and the standalone `chironql` client share one
//! implementation and differ only in transport:
//!
//! - [`LocalSink`] — in-process `Db` calls, used by `chirondb --console`.
//! - An HTTP sink lands with the standalone binary; it implements the same
//!   trait and this module does not change.
//!
//! The loop reads from any [`BufRead`] and writes to any [`Write`], which is
//! what makes a piped session testable without a terminal.
//!
//! ## Two loops
//!
//! [`run`] reads any [`BufRead`] and writes any [`Write`]: that is the piped
//! path, and it is what the tests drive. [`run_interactive`] uses `rustyline`
//! for history recall, Ctrl-R search and in-line cursor movement, which is what
//! makes a REPL usable for more than a demo.
//!
//! They share the statement assembly, the meta-commands and the rendering; only
//! the line source differs, because `rustyline` owns its own prompt.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use serde_json::Value;

use chirondb_core::Db;
use chirondb_types::chironql::{
    ChironQlError, ChironQlKind, ChironQlResponse, QueryTrace, StageOutcome,
};
use chirondb_types::relational::RelationalValue;

use crate::chironql_exec::{self, ExecContext, Session};
use crate::rbac::Role;
use chirondb_core::tenant::TenantScope;

/// How one statement should be run.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecuteOptions {
    /// Include the trace on success. Failures always carry it.
    pub trace: bool,
    /// Proceed with a statement that would otherwise stop and ask.
    pub confirm: bool,
}

/// Where a REPL sends statements. Two implementations, both real.
pub trait QuerySink {
    fn execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError>;
    /// Shown by `\role`, so a refused write is never a mystery.
    fn role(&self) -> Option<Role> {
        None
    }
    /// Set typed positional parameters for the next statement.
    fn set_parameters(&mut self, _parameters: Vec<RelationalValue>) -> Result<(), ChironQlError> {
        Err(ChironQlError {
            error: "this query transport does not support parameters".into(),
            code: "chironql.parameters_unsupported".into(),
            hint: None,
            position: None,
            affected_estimate: None,
            query_id: String::new(),
            trace: None,
        })
    }
    fn redact_query_input(&self) -> bool {
        false
    }
    fn write_output(&self, out: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
        out.write_all(bytes)
    }
}

struct SinkWriter<'a, S, W> {
    sink: &'a S,
    out: &'a mut W,
}
impl<S: QuerySink, W: Write> Write for SinkWriter<'_, S, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.sink.write_output(self.out, bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// In-process sink: no socket, no serialization, no auth round trip.
pub struct LocalSink {
    db: Db,
    session: Session,
    role: Role,
    tenant: TenantScope,
    token: Option<String>,
    key_out: Option<PathBuf>,
    publication: Option<crate::chironql_protected::PublicationGuard>,
    pending_confirmation: Option<(String, String)>,
    work: Option<tokio::sync::OwnedSemaphorePermit>,
    parameters: Vec<RelationalValue>,
}

impl LocalSink {
    pub fn new(db: Db, role: Role) -> Self {
        Self {
            db,
            session: Session::default(),
            role,
            // The console is the operator's own process, so it acts as system
            // machinery rather than as a tenant. `with_tenant` narrows it when
            // a session should be scoped.
            tenant: TenantScope::system(),
            token: None,
            key_out: None,
            publication: None,
            pending_confirmation: None,
            work: None,
            parameters: Vec::new(),
        }
    }

    /// Run this session as a specific tenant instead of as the operator.
    pub fn with_tenant(mut self, tenant: TenantScope) -> Self {
        self.tenant = tenant;
        self
    }

    pub fn with_collection(mut self, collection: Option<String>) -> Self {
        self.session.collection = collection;
        self
    }
    pub fn with_credential(mut self, token: String, key_out: Option<PathBuf>) -> Self {
        self.token = Some(token);
        self.key_out = key_out;
        self
    }

    fn protected_execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        use crate::{
            chironql_credentials::{KeyDestination, with_revision},
            chironql_parser::{SecurityCommand, Statement},
            chironql_protected,
        };
        self.publication = None;
        self.work = None;
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| chironql_protected::error("", "security.unauthenticated"))?;
        let authority = self
            .db
            .identity_authority()
            .ok_or_else(|| chironql_protected::error("", "security.unavailable"))?;
        let work = authority
            .work_pool()
            .try_acquire_owned()
            .map_err(|_| chironql_protected::error("", "security.budget_exceeded"))?;
        let parsed = crate::chironql_parser::parse(query).ok();
        let security = match &parsed {
            Some(Statement::Security(statement)) => Some(statement),
            _ => None,
        };
        let mut destination =
            if security.is_some_and(|s| s.issues_key()) {
                let path = self
                    .key_out
                    .as_deref()
                    .ok_or_else(|| chironql_protected::error("", "chironql.key_output_required"))?;
                Some(KeyDestination::create(path).map_err(|_| {
                    chironql_protected::error("", "chironql.key_output_unavailable")
                })?)
            } else {
                None
            };
        let pending = self
            .pending_confirmation
            .take()
            .filter(|(original, _)| options.confirm && original == query);
        let prepared = if let Some((_, prepared)) = pending {
            prepared
        } else if let Some(statement) =
            security.filter(|s| s.requires_revision() && s.expected_revision.is_none())
        {
            let revision_query = match &statement.command {
                SecurityCommand::CreateProtectedCollection { .. } => {
                    "SHOW CATALOG REVISION;".into()
                }
                SecurityCommand::SetGraphLifecycle { collection, .. }
                | SecurityCommand::SetEdgeType { collection, .. }
                | SecurityCommand::SetCollectionPolicy { collection, .. }
                | SecurityCommand::ObjectPrivileges { collection, .. }
                | SecurityCommand::AlterPoint { collection, .. } => {
                    format!("SHOW SECURITY REVISION ON COLLECTION '{collection}';")
                }
                _ => "SHOW SECURITY REVISION;".into(),
            };
            let revision = chironql_protected::execute(
                &self.db,
                token,
                &chirondb_types::chironql::ChironQlRequest {
                    query: revision_query,
                    ..Default::default()
                },
            )?
            .publish(|reply| {
                reply
                    .rows
                    .first()
                    .and_then(|row| row.get("revision"))
                    .and_then(Value::as_u64)
            })
            .map_err(|_| chironql_protected::error("", "security.conflict"))?
            .ok_or_else(|| chironql_protected::error("", "security.unavailable"))?;
            with_revision(query, revision)
        } else {
            query.into()
        };
        let result = chironql_protected::execute(
            &self.db,
            token,
            &chirondb_types::chironql::ChironQlRequest {
                query: prepared.clone(),
                collection: self.session.collection.clone(),
                trace: options.trace,
                confirm: options.confirm,
                parameters: std::mem::take(&mut self.parameters),
                idempotency_key: None,
                retry_id: None,
            },
        );
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                if error.code == "chironql.confirmation_required" {
                    self.pending_confirmation = Some((query.into(), prepared));
                }
                return Err(error);
            }
        };
        self.publication = Some(output.guard());
        let mut rotated = None;
        let response = output.publish(|mut response| {
            if let Some(credential) = response.credential.take() {
                let destination = destination.as_mut().ok_or_else(|| chironql_protected::error("", "chironql.key_output_required"))?;
                destination.save(&credential.secret).map_err(|_| chironql_protected::error("", "chironql.key_output_failed"))?;
                if matches!(security.map(|s| &s.command), Some(SecurityCommand::RotateKey { id }) if token.starts_with(&format!("chiron.{id}."))) {
                    rotated = Some(credential.secret);
                }
                response.rows.push(serde_json::json!({"credential_id":credential.id,"saved":true}));
                response.columns.extend(["credential_id".into(), "saved".into()]);
            }
            Ok(response)
        }).map_err(|_| chironql_protected::error("", "security.conflict"))??;
        if let Some(token) = rotated {
            self.token = Some(token);
        }
        if let Some(Statement::Use { collection }) = parsed {
            self.session.collection = Some(collection);
        }
        self.work = Some(work);
        Ok(response)
    }
}

impl QuerySink for LocalSink {
    fn redact_query_input(&self) -> bool {
        self.db.identity_authority().is_some()
    }
    fn execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        if self.db.identity_authority().is_some() {
            return self.protected_execute(query, options);
        }
        let mut ctx = ExecContext {
            db: &self.db,
            session: &mut self.session,
            role: self.role,
            // The console is not collection-scoped: it is the operator's own
            // process. HTTP callers get their key's allowlist instead.
            allowed_collections: None,
            want_trace: options.trace,
            confirm: options.confirm,
            parameters: std::mem::take(&mut self.parameters),
            idempotency_key: None,
            retry_id: None,
            tenant: self.tenant.clone(),
        };
        chironql_exec::execute(&mut ctx, query)
    }

    fn role(&self) -> Option<Role> {
        self.db.identity_authority().is_none().then_some(self.role)
    }
    fn set_parameters(&mut self, parameters: Vec<RelationalValue>) -> Result<(), ChironQlError> {
        self.parameters = parameters;
        Ok(())
    }
    fn write_output(&self, out: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(guard) = &self.publication {
            guard
                .publish(|| {
                    out.write_all(bytes)?;
                    out.flush()
                })
                .map_err(std::io::Error::other)?
        } else {
            out.write_all(bytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Table,
    Json,
}

#[derive(Clone, Debug)]
pub struct ReplOptions {
    /// Print prompts and the banner. False for piped input.
    pub interactive: bool,
    pub format: Format,
    /// Show the trace on success. Failures always show it.
    pub trace: bool,
    /// Answer yes to confirmations up front. Set by `--yes`. Without it a
    /// non-interactive session refuses a filtered delete rather than guessing.
    pub confirm: bool,
    pub banner: Option<String>,
}

impl Default for ReplOptions {
    fn default() -> Self {
        Self {
            interactive: true,
            format: Format::Table,
            trace: false,
            confirm: false,
            banner: None,
        }
    }
}

const PROMPT: &str = "chiron> ";
const CONTINUATION: &str = "    ...> ";
/// Payload cells are truncated in table output; `\format json` shows all of it.
const MAX_CELL: usize = 48;

/// Run the loop until end of input or `\q`. Returns the number of statements
/// that failed, so a caller can pick an exit code.
pub fn run<S, R, W>(
    sink: &mut S,
    input: R,
    out: &mut W,
    options: ReplOptions,
) -> std::io::Result<usize>
where
    S: QuerySink,
    R: BufRead,
    W: Write,
{
    let mut format = options.format;
    let mut trace_on = options.trace;
    let mut timing_on = false;
    let mut failures = 0usize;
    let mut buffer = String::new();
    let confirm = options.confirm;

    if options.interactive {
        if let Some(banner) = &options.banner {
            writeln!(out, "{banner}")?;
        }
        write!(out, "{PROMPT}")?;
        out.flush()?;
    }

    for line in input.lines() {
        let line = line?;
        let trimmed = line.trim();

        // Meta-commands are only meaningful at the start of a statement.
        if buffer.trim().is_empty() && is_meta(trimmed) {
            match meta_command(
                sink,
                trimmed,
                &mut format,
                &mut trace_on,
                &mut timing_on,
                out,
            )? {
                MetaOutcome::Continue => {}
                MetaOutcome::Quit => return Ok(failures),
                MetaOutcome::Statement(statement) => {
                    if !run_statement(
                        sink,
                        &statement,
                        settings(format, trace_on, timing_on, confirm),
                        None,
                        out,
                    )? {
                        failures += 1;
                        if !options.interactive {
                            return Ok(failures);
                        }
                    }
                }
            }
            if options.interactive {
                write!(out, "{PROMPT}")?;
                out.flush()?;
            }
            continue;
        }

        if !buffer.is_empty() {
            buffer.push('\n');
        }
        buffer.push_str(&line);
        if buffer.len() > 8 * 1024 * 1024 {
            return Err(std::io::Error::other("query exceeds server byte limit"));
        }

        // Statements end at `;`. Anything else continues.
        if crate::chironql_credentials::statement_terminator(&buffer).is_none() {
            if options.interactive && !buffer.trim().is_empty() {
                write!(out, "{CONTINUATION}")?;
                out.flush()?;
            } else if options.interactive {
                buffer.clear();
                write!(out, "{PROMPT}")?;
                out.flush()?;
            }
            continue;
        }

        while let Some(end) = crate::chironql_credentials::statement_terminator(&buffer) {
            let statement: String = buffer.drain(..=end).collect();
            if !statement.trim().is_empty()
                && !run_statement(
                    sink,
                    &statement,
                    settings(format, trace_on, timing_on, confirm),
                    None,
                    out,
                )?
            {
                failures += 1;
                if !options.interactive {
                    return Ok(failures);
                }
            }
        }

        if options.interactive {
            write!(out, "{PROMPT}")?;
            out.flush()?;
        }
    }

    // Trailing input without a `;` is still a statement worth running — a
    // piped heredoc that forgets the semicolon should not silently do nothing.
    if crate::chironql_parser::leading_keyword(&buffer).is_some()
        && !run_statement(
            sink,
            &buffer,
            settings(format, trace_on, timing_on, confirm),
            None,
            out,
        )?
    {
        failures += 1;
    }

    if options.interactive {
        writeln!(out)?;
    }
    Ok(failures)
}

/// Execute exactly one statement without the REPL's semicolon splitting.
///
/// `--exec` uses this path so a second statement cannot run after the first
/// one has already changed state. The language parser remains the authority
/// for deciding whether the supplied text contains exactly one statement.
pub fn run_one<S, W>(
    sink: &mut S,
    statement: &str,
    out: &mut W,
    options: ReplOptions,
) -> std::io::Result<usize>
where
    S: QuerySink,
    W: Write,
{
    let succeeded = run_statement(
        sink,
        statement,
        settings(options.format, options.trace, false, options.confirm),
        None,
        out,
    )?;
    Ok(usize::from(!succeeded))
}

/// Interactive loop with history and line editing.
///
/// `history_path` is where the session's history is persisted. The console and
/// the client use different files so a local operator session and a remote
/// client session do not interleave each other's recall.
///
/// Three ways out, all equivalent: `\q`, Ctrl-D, and Ctrl-C on an empty line.
/// Ctrl-C with a half-typed statement abandons the statement instead.
pub fn run_interactive<S>(
    sink: &mut S,
    options: ReplOptions,
    history_path: Option<PathBuf>,
) -> std::io::Result<usize>
where
    S: QuerySink,
{
    let mut editor = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(error) => {
            // No terminal to drive: fall back to the piped loop rather than
            // failing, so a caller that mis-detects a TTY still works.
            tracing::debug!(%error, "falling back to the non-interactive repl");
            let stdin = std::io::stdin();
            let mut stdout = std::io::stdout();
            return run(sink, stdin.lock(), &mut stdout, options);
        }
    };
    if let Some(path) = &history_path {
        let _ = editor.load_history(path);
    }

    let mut out = std::io::stdout();
    let mut format = options.format;
    let mut trace_on = options.trace;
    let mut timing_on = false;
    let mut failures = 0usize;
    let mut buffer = String::new();
    let confirm = options.confirm;

    if let Some(banner) = &options.banner {
        writeln!(out, "{banner}")?;
    }

    loop {
        let prompt = if buffer.is_empty() {
            PROMPT
        } else {
            CONTINUATION
        };
        match editor.readline(prompt) {
            Ok(line) => {
                let trimmed = line.trim();

                if buffer.trim().is_empty() && is_meta(trimmed) {
                    // `\q` in the history is never something you want to
                    // recall; every other meta-command is.
                    if !matches!(trimmed, "\\q" | "\\quit") {
                        let _ = editor.add_history_entry(trimmed);
                    }
                    match meta_command(
                        sink,
                        trimmed,
                        &mut format,
                        &mut trace_on,
                        &mut timing_on,
                        &mut out,
                    )? {
                        MetaOutcome::Continue => {}
                        MetaOutcome::Quit => break,
                        MetaOutcome::Statement(statement) => {
                            if !run_statement(
                                sink,
                                &statement,
                                settings(format, trace_on, timing_on, confirm),
                                None,
                                &mut out,
                            )? {
                                failures += 1;
                            }
                        }
                    }
                    continue;
                }

                if !buffer.is_empty() {
                    buffer.push('\n');
                }
                buffer.push_str(&line);

                if buffer.len() > 8 * 1024 * 1024 {
                    writeln!(out, "chironql.query_too_large")?;
                    buffer.clear();
                    failures += 1;
                    continue;
                }
                while let Some(end) = crate::chironql_credentials::statement_terminator(&buffer) {
                    let statement: String = buffer.drain(..=end).collect();
                    if !sink.redact_query_input() && !security_input(&statement) {
                        let _ = editor.add_history_entry(statement.trim());
                    }

                    // `readline` is how the confirmation is asked, so the prompt
                    // borrows the same editor the loop reads from.
                    let mut ask = |message: &str, _affected: u32| -> std::io::Result<bool> {
                        // The server already said what would happen and to what,
                        // so the question repeats its sentence rather than
                        // inventing a second description that could disagree.
                        let question = format!("{message}. Type yes to proceed: ");
                        match editor.readline(&question) {
                            Ok(answer) => Ok(answer.trim().eq_ignore_ascii_case("yes")),
                            // Ctrl-C or Ctrl-D at the question means no.
                            Err(_) => Ok(false),
                        }
                    };

                    if !run_statement(
                        sink,
                        &statement,
                        settings(format, trace_on, timing_on, confirm),
                        Some(&mut ask),
                        &mut out,
                    )? {
                        failures += 1;
                        buffer.clear();
                        break;
                    }
                }
                if crate::chironql_parser::leading_keyword(&buffer).is_none() {
                    buffer.clear();
                }
            }
            // Ctrl-C with a half-typed statement abandons the statement. On an
            // empty line there is nothing to abandon, so it means "let me out"
            // — which is the only reading that leaves a user a way out.
            Err(ReadlineError::Interrupted) => {
                if buffer.trim().is_empty() {
                    break;
                }
                buffer.clear();
                continue;
            }
            Err(ReadlineError::Eof) => break,
            Err(error) => {
                writeln!(out, " input error: {error}")?;
                break;
            }
        }
    }

    if let Some(path) = &history_path {
        // A history file that cannot be written is not worth failing a session
        // over; the user still got their answers.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = editor.save_history(path);
    }
    writeln!(out)?;
    Ok(failures)
}

fn settings(format: Format, trace: bool, timing: bool, confirm: bool) -> RunSettings {
    RunSettings {
        format,
        trace,
        timing,
        confirm,
    }
}

/// The session toggles a statement is run under. They change together and
/// travel together, so they are one value rather than four positional flags.
#[derive(Clone, Copy, Debug, Default)]
struct RunSettings {
    format: Format,
    trace: bool,
    timing: bool,
    confirm: bool,
}

/// Returns false when the statement failed.
/// Asks the human whether to proceed with a statement the server refused for
/// confirmation, given the server's own sentence and the count it carried.
/// Returns whether they said yes.
type ConfirmPrompt<'a> = dyn FnMut(&str, u32) -> std::io::Result<bool> + 'a;

fn run_statement<S, W>(
    sink: &mut S,
    statement: &str,
    settings: RunSettings,
    prompt: Option<&mut ConfirmPrompt<'_>>,
    out: &mut W,
) -> std::io::Result<bool>
where
    S: QuerySink,
    W: Write,
{
    let RunSettings {
        format,
        trace: trace_on,
        timing: timing_on,
        confirm,
    } = settings;
    let started = Instant::now();
    let options = ExecuteOptions {
        trace: trace_on,
        confirm,
    };

    let mut outcome = sink.execute(statement, options);

    // A filtered delete stops and asks. The server has already counted what
    // the filter matches, so the question carries a real number. Only an
    // interactive session can answer it; a piped one falls through and reports
    // the refusal, which is what `--yes` exists to skip.
    if let Err(error) = &outcome
        && error.code == "chironql.confirmation_required"
        && let Some(ask) = prompt
    {
        let affected = error.affected_estimate.unwrap_or_default();
        if ask(&error.error, affected)? {
            outcome = sink.execute(
                statement,
                ExecuteOptions {
                    trace: trace_on,
                    confirm: true,
                },
            );
        } else {
            writeln!(out)?;
            writeln!(out, " cancelled — nothing was deleted")?;
            return Ok(true);
        }
    }

    let mut guarded = SinkWriter { sink, out };
    let out = &mut guarded;
    match outcome {
        Ok(response) => {
            if response.credential.is_some() {
                writeln!(
                    out,
                    "credential response suppressed: configure a private key destination"
                )?;
                return Ok(false);
            }
            match format {
                Format::Json => writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&response).unwrap_or_default()
                )?,
                Format::Table => {
                    render_table(&response, out)?;
                    render_footer(&response, out)?;
                    if let Some(trace) = &response.trace {
                        render_trace(trace, out)?;
                    }
                }
            }
            if timing_on {
                writeln!(
                    out,
                    " client {:.1} ms",
                    started.elapsed().as_secs_f64() * 1000.0
                )?;
            }
            Ok(true)
        }
        Err(error) => {
            match format {
                Format::Json => writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&error).unwrap_or_default()
                )?,
                // The trace is printed on failure whether or not it was asked
                // for. This is the moment it exists for.
                Format::Table => render_error(
                    &error,
                    if sink.redact_query_input() || security_input(statement) {
                        ""
                    } else {
                        statement
                    },
                    out,
                )?,
            }
            Ok(false)
        }
    }
}

fn security_input(query: &str) -> bool {
    let upper = query.to_ascii_uppercase();
    if upper.contains("PASSWORD") || upper.contains("CHIRON.") {
        return true;
    }
    matches!(
        crate::chironql_parser::parse(query),
        Ok(crate::chironql_parser::Statement::Security(_))
    ) || crate::chironql_parser::leading_keyword(query).is_some_and(|(first, _, next)| {
        matches!(
            first.as_str(),
            "GRANT" | "REVOKE" | "DENY" | "ISSUE" | "ROTATE" | "RENAME"
        ) || matches!(first.as_str(), "CREATE" | "ALTER" | "DROP")
            && matches!(next.as_str(), "USER" | "ROLE")
    })
}

/// Whether a line is a meta-command rather than the start of a statement.
///
/// Everything meta is spelled with a leading backslash except `clear;`, which
/// is written like a statement, semicolon included, because that is how the
/// rest of this prompt is driven. The semicolon is what makes it a request: a
/// bare `clear` is ordinary input and the screen is left alone, so nothing is
/// wiped that was not asked for in the same shape as everything else typed
/// here.
fn is_meta(line: &str) -> bool {
    line.starts_with('\\') || line.eq_ignore_ascii_case("clear;")
}

enum MetaOutcome {
    Continue,
    Quit,
    Statement(String),
}

fn meta_command<S, W>(
    sink: &mut S,
    line: &str,
    format: &mut Format,
    trace_on: &mut bool,
    timing_on: &mut bool,
    out: &mut W,
) -> std::io::Result<MetaOutcome>
where
    S: QuerySink,
    W: Write,
{
    let mut parts = line.split_whitespace();
    let command = parts.next().unwrap_or_default();
    let argument = parts.next();

    match command {
        "\\q" | "\\quit" => return Ok(MetaOutcome::Quit),
        "\\h" | "\\?" | "\\help" => {
            write!(out, "{HELP}")?;
            writeln!(
                out,
                " ChironQL {} — statements, clause names and error codes are stable at this\n \
                 version; anything removed goes through a deprecation cycle first.",
                crate::chironql_parser::LANGUAGE_VERSION
            )?;
        }
        "\\l" => return Ok(MetaOutcome::Statement("SHOW COLLECTIONS;".to_string())),
        command
            if command.eq_ignore_ascii_case("clear;")
                || command.eq_ignore_ascii_case("\\clear") =>
        {
            // Flushed explicitly: the sequence carries no newline, and the
            // console's writer is line-buffered over stdout. Left in the
            // buffer it would appear only when something else printed a line —
            // or never, since leaving the console exits the process.
            write!(out, "{}", crate::branding::clear())?;
            out.flush()?;
        }
        "\\d" => match argument {
            Some(collection) => {
                return Ok(MetaOutcome::Statement(format!("DESCRIBE {collection};")));
            }
            None => return Ok(MetaOutcome::Statement("SHOW COLLECTIONS;".to_string())),
        },
        "\\c" | "\\use" => match argument {
            Some(collection) => return Ok(MetaOutcome::Statement(format!("USE {collection};"))),
            None => writeln!(out, " \\c needs a collection name")?,
        },
        "\\trace" => {
            *trace_on = match argument {
                Some("on") => true,
                Some("off") => false,
                _ => !*trace_on,
            };
            writeln!(out, " trace {}", on_off(*trace_on))?;
        }
        "\\timing" => {
            *timing_on = !*timing_on;
            writeln!(out, " timing {}", on_off(*timing_on))?;
        }
        "\\params" => {
            let json = line
                .strip_prefix(command)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("[]");
            match serde_json::from_str::<Vec<RelationalValue>>(json) {
                Ok(parameters) => match sink.set_parameters(parameters) {
                    Ok(()) => writeln!(out, " parameters set for next statement")?,
                    Err(error) => writeln!(out, " {}: {}", error.code, error.error)?,
                },
                Err(error) => writeln!(
                    out,
                    " chironql.invalid_parameters: expected a tagged RelationalValue JSON array ({error})"
                )?,
            }
        }
        "\\format" => match argument {
            Some("json") => {
                *format = Format::Json;
                writeln!(out, " format json")?;
            }
            Some("table") => {
                *format = Format::Table;
                writeln!(out, " format table")?;
            }
            _ => writeln!(out, " \\format table|json")?,
        },
        "\\role" => match sink.role() {
            Some(role) => writeln!(out, " {}", role_name(role))?,
            None => writeln!(out, " role is enforced by the server for this connection")?,
        },
        other => writeln!(out, " unknown command {other} — try \\h")?,
    }
    Ok(MetaOutcome::Continue)
}

const HELP: &str = "\
 Read         SEARCH · HYBRID · MULTI · RECOMMEND · COUNT · SCROLL · GET
 Relational   SQL SELECT/EXPLAIN · SQL INSERT/UPDATE/DELETE · SQL CREATE/DROP TABLE
 Multi-model  PIPELINE vector → [graph] → relational · EXPLAIN PIPELINE
 Introspect   SHOW COLLECTIONS · DESCRIBE · USE
 Write        UPSERT · UPDATE ... SET PAYLOAD · DELETE ... POINTS
              DELETE ... WHERE   (counts first, then asks)
 Admin        CREATE COLLECTION ... DIM <n> [METRIC …] [WITH {…}]
              DROP COLLECTION ... [IF EXISTS]   (counts first, then asks)

 Protected    GET · COUNT · SCROLL · SEARCH NEAR [vector]
              CREATE PROTECTED COLLECTION ... DIM <n> [METRIC …]
              SHOW CATALOG REVISION · SHOW COLLECTION ... SECURITY POLICY
              ALTER COLLECTION ... SET SECURITY POLICY {...}
              CREATE POINTS ... USING TEMPLATE ... REQUEST 'retry-id'
              UPDATE POINTS ... · DELETE ...
 Security     CREATE / ALTER / RENAME / DROP USER · CREATE / RENAME / DROP ROLE
              GRANT / REVOKE ROLE · GRANT / REVOKE actions
              GRANT / DENY point access · ALTER POINT security labels
 Inspect      SHOW CURRENT USER [PRIVILEGES] · SHOW USERS
              SHOW ROLES WITH USERS · SHOW ROLE ... PRIVILEGES
 Keys         ISSUE API KEY FOR USER · ROTATE / REVOKE API KEY
              SHOW API KEYS FOR USER (issuance requires --key-out)

 Protected operations require explicit capabilities. Legacy UPSERT, collection
 lifecycle and retrieval modes without a protected path are rejected there.
 Snapshots, restore and compaction stay in `chironctl`.

 \\h           this help
 clear;       clear the screen (also \\clear)
 \\l           list collections
 \\d [coll]    describe a collection
 \\c <coll>    use a collection for later statements
 \\trace       show the server's execution trace (always shown on failure)
 \\timing      show client-side elapsed time
 \\params [...] set typed positional parameters for the next statement
 \\format      table | json
 \\role        the role this session runs as
 \\q           quit

 Statements end with `;` and may span lines. Scripts stop on the first failure.
 Security changes support IF REVISION <n>; conflicts are not retried.
 Reference: docs/HTTP_API.md#protected-chironql-administration-language-12
";

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_table<W: Write>(response: &ChironQlResponse, out: &mut W) -> std::io::Result<()> {
    // A write reports its count in the footer; there is no result set to draw,
    // and "(no rows)" next to "1 affected" reads as though nothing happened.
    if matches!(response.kind, ChironQlKind::Empty | ChironQlKind::Affected) {
        return Ok(());
    }
    if response.rows.is_empty() {
        writeln!(out)?;
        writeln!(out, " (no rows)")?;
        return Ok(());
    }

    let headers: Vec<String> = response.columns.clone();
    let body: Vec<Vec<String>> = response
        .rows
        .iter()
        .map(|row| {
            headers
                .iter()
                .map(|column| cell(row.get(column).unwrap_or(&Value::Null)))
                .collect()
        })
        .collect();

    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            body.iter()
                .map(|row| row[index].chars().count())
                .chain(std::iter::once(header.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    writeln!(out)?;
    write!(out, " ")?;
    for (index, header) in headers.iter().enumerate() {
        write!(out, "{:<width$} ", header, width = widths[index])?;
    }
    writeln!(out)?;
    write!(out, " ")?;
    for width in &widths {
        write!(out, "{} ", "─".repeat(*width))?;
    }
    writeln!(out)?;
    for row in &body {
        write!(out, " ")?;
        for (index, value) in row.iter().enumerate() {
            write!(out, "{:<width$} ", value, width = widths[index])?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn cell(value: &Value) -> String {
    let rendered = match value {
        Value::Null => "NULL".to_string(),
        Value::String(text) => text.clone(),
        // Floats render at a fixed width so a score column lines up; integers
        // stay exact. `number.is_f64()` is what separates an engine score from
        // a count, so a 0.0 score prints as `0.0000` rather than `-0`.
        Value::Number(number) if number.is_f64() => number
            .as_f64()
            .map(|float| format!("{:.4}", if float == 0.0 { 0.0 } else { float }))
            .unwrap_or_else(|| number.to_string()),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    };
    truncate(&rendered, MAX_CELL)
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Only fields the server actually returned. No recall figure, and no
/// `ef_search` — the search response does not carry one, and printing the
/// requested value here would read as an achieved one.
fn render_footer<W: Write>(response: &ChironQlResponse, out: &mut W) -> std::io::Result<()> {
    let mut parts = Vec::new();
    match response.kind {
        ChironQlKind::Rows => parts.push(format!(
            "{} row{}",
            response.rows.len(),
            if response.rows.len() == 1 { "" } else { "s" }
        )),
        ChironQlKind::Affected => {
            if let Some(affected) = response.stats.affected {
                parts.push(format!("{affected} affected"));
            }
        }
        ChironQlKind::Empty => {}
    }
    parts.push(format!("{:.1} ms", response.stats.took_ms));
    if let Some(searched) = response.stats.searched {
        parts.push(format!("{searched} points scanned"));
    }
    if response.stats.degraded == Some(true) {
        parts.push("DEGRADED".to_string());
    }
    if let Some(target) = response.stats.recall_target_requested {
        parts.push(format!("recall target {target} (requested)"));
    }
    if let Some(next) = &response.next {
        parts.push(format!("next {next}"));
    }
    parts.push(response.query_id.clone());

    writeln!(out)?;
    writeln!(out, " {}", parts.join(" · "))?;
    Ok(())
}

fn render_trace<W: Write>(trace: &QueryTrace, out: &mut W) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, " trace  {}", trace.query_id)?;
    let width = trace
        .stages
        .iter()
        .map(|stage| stage.name.chars().count())
        .max()
        .unwrap_or(0);
    for stage in &trace.stages {
        let millis = stage.elapsed_us as f64 / 1000.0;
        let (outcome, note) = match &stage.outcome {
            StageOutcome::Ok => ("ok  ".to_string(), detail_note(stage.detail.as_ref())),
            StageOutcome::Failed { code, message } => {
                ("FAIL".to_string(), format!("{code} — {message}"))
            }
        };
        writeln!(
            out,
            "   {:<width$} {:>7.2} ms  {}  {}",
            stage.name,
            millis,
            outcome,
            note,
            width = width
        )?;
    }
    Ok(())
}

fn detail_note(detail: Option<&Value>) -> String {
    let Some(Value::Object(map)) = detail else {
        return String::new();
    };
    map.iter()
        .map(|(key, value)| match value {
            Value::String(text) => format!("{key}={text}"),
            other => format!("{key}={other}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_error<W: Write>(
    error: &ChironQlError,
    statement: &str,
    out: &mut W,
) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, " ✗ {}", error.error)?;

    let failed_stage = error
        .trace
        .as_ref()
        .and_then(|trace| trace.failed_stage())
        .map(|stage| stage.name.clone());
    match failed_stage {
        Some(stage) => writeln!(out, "   at {stage} · {}", error.code)?,
        None => writeln!(out, "   {}", error.code)?,
    }
    if let Some(hint) = &error.hint {
        writeln!(out, "   hint: {hint}")?;
    }

    // Caret into the user's own text, on the line the error points at.
    if let Some(position) = error.position
        && let Some((line, column, text)) = locate(statement, position as usize)
    {
        writeln!(out)?;
        writeln!(out, "   {text}")?;
        writeln!(out, "   {}^", " ".repeat(column))?;
        let _ = line;
    }

    if let Some(trace) = &error.trace {
        render_trace(trace, out)?;
    }
    Ok(())
}

/// Maps a byte offset to (line number, column, that line's text).
fn locate(source: &str, position: usize) -> Option<(usize, usize, String)> {
    let position = position.min(source.len());
    let mut offset = 0usize;
    for (index, line) in source.split('\n').enumerate() {
        let end = offset + line.len();
        if position <= end {
            let column = source[offset..position].chars().count();
            return Some((index + 1, column, line.trim_end().to_string()));
        }
        offset = end + 1;
    }
    None
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn role_name(role: Role) -> &'static str {
    if role.allows_admin() {
        "admin"
    } else if role.allows_write() {
        "read_write"
    } else {
        "read_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chirondb_types::chironql::{ChironQlStats, stage};
    use serde_json::json;

    /// A sink that records what it was asked and replays canned answers, so
    /// the loop and the rendering can be tested without an engine.
    struct FakeSink {
        seen: Vec<String>,
        answers: Vec<Result<ChironQlResponse, ChironQlError>>,
    }

    impl FakeSink {
        fn ok(rows: Vec<Value>) -> ChironQlResponse {
            ChironQlResponse {
                credential: None,
                kind: ChironQlKind::Rows,
                columns: vec!["id".to_string(), "score".to_string()],
                column_types: Vec::new(),
                rows,
                stats: ChironQlStats {
                    took_ms: 3.1,
                    searched: Some(1412),
                    degraded: Some(false),
                    ..Default::default()
                },
                next: None,
                query_id: "q_test".to_string(),
                domains: Vec::new(),
                snapshot_id: None,
                transaction_id: None,
                committed: None,
                trace: None,
            }
        }
    }

    impl QuerySink for FakeSink {
        fn execute(
            &mut self,
            query: &str,
            _options: ExecuteOptions,
        ) -> Result<ChironQlResponse, ChironQlError> {
            self.seen.push(query.trim().to_string());
            if self.answers.is_empty() {
                return Ok(Self::ok(Vec::new()));
            }
            self.answers.remove(0)
        }

        fn role(&self) -> Option<Role> {
            Some(Role::ReadOnly)
        }
    }

    fn piped(
        input: &str,
        answers: Vec<Result<ChironQlResponse, ChironQlError>>,
    ) -> (String, usize, Vec<String>) {
        let mut sink = FakeSink {
            seen: Vec::new(),
            answers,
        };
        let mut out = Vec::new();
        let failures = run(
            &mut sink,
            input.as_bytes(),
            &mut out,
            ReplOptions {
                interactive: false,
                ..Default::default()
            },
        )
        .expect("repl runs");
        (String::from_utf8(out).expect("utf8"), failures, sink.seen)
    }

    #[test]
    fn table_distinguishes_null_from_empty_text_zero_and_confidence() {
        let mut answer = FakeSink::ok(vec![json!({
            "actual": null,
            "empty_text": "",
            "zero": 0,
            "confidence": 0.5347
        })]);
        answer.columns = ["actual", "empty_text", "zero", "confidence"]
            .map(str::to_string)
            .to_vec();
        let (output, failures, _) = piped("SQL SELECT * FROM predictions;", vec![Ok(answer)]);
        assert_eq!(failures, 0);
        assert!(
            output.contains(" NULL              0    0.5347"),
            "{output}"
        );
    }

    #[test]
    fn json_preserves_null_and_empty_text() {
        let mut sink = FakeSink {
            seen: Vec::new(),
            answers: vec![Ok(FakeSink::ok(vec![json!({"id": "", "score": null})]))],
        };
        let mut out = Vec::new();
        run(
            &mut sink,
            "SQL SELECT * FROM predictions;".as_bytes(),
            &mut out,
            ReplOptions {
                interactive: false,
                format: Format::Json,
                ..Default::default()
            },
        )
        .expect("repl runs");
        let parsed: Value = serde_json::from_slice(&out).expect("valid json");
        assert!(parsed["rows"][0]["score"].is_null());
        assert_eq!(parsed["rows"][0]["id"], "");
    }

    #[test]
    fn splits_input_on_semicolons() {
        let (_, _, seen) = piped("COUNT a;\nCOUNT b;\n", Vec::new());
        assert_eq!(seen, vec!["COUNT a;", "COUNT b;"]);
    }

    #[test]
    fn joins_multi_line_statements() {
        let (_, _, seen) = piped("SEARCH products\n  NEAR [1,0,0]\n  LIMIT 5;\n", Vec::new());
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("NEAR [1,0,0]"));
    }

    #[test]
    fn keeps_transaction_block_as_one_terminal_statement() {
        let input = "TRANSACTION {\n  SQL INSERT INTO t VALUES ('a;b');\n  VECTOR UPSERT INTO c {id: 'a', vector: [1]};\n  GRAPH CONNECT c 'a' -> E -> 'a';\n};\n";
        let (_, _, seen) = piped(input, Vec::new());
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("TRANSACTION {"));
        assert!(seen[0].contains("GRAPH CONNECT"));
    }

    #[test]
    fn runs_a_trailing_statement_without_a_semicolon() {
        let (_, _, seen) = piped("COUNT a", Vec::new());
        assert_eq!(seen, vec!["COUNT a"]);
    }

    #[test]
    fn renders_a_table_and_a_footer() {
        let answer = FakeSink::ok(vec![json!({"id": "phone", "score": 0.9987})]);
        let (output, failures, _) = piped("SEARCH a NEAR [1];", vec![Ok(answer)]);

        assert_eq!(failures, 0);
        assert!(output.contains("id"), "{output}");
        assert!(output.contains("phone"), "{output}");
        assert!(output.contains("0.9987"), "{output}");
        assert!(output.contains("1 row"), "{output}");
        assert!(output.contains("1412 points scanned"), "{output}");
        assert!(output.contains("q_test"), "{output}");
    }

    #[test]
    fn footer_never_prints_an_ef_search_or_a_recall_measurement() {
        let answer = FakeSink::ok(vec![json!({"id": "a", "score": 1.0})]);
        let (output, _, _) = piped("SEARCH a NEAR [1];", vec![Ok(answer)]);
        assert!(!output.contains("ef_search"), "{output}");
        assert!(!output.to_lowercase().contains("recall≈"), "{output}");
    }

    #[test]
    fn a_requested_recall_target_is_labelled_as_requested() {
        let mut answer = FakeSink::ok(Vec::new());
        answer.stats.recall_target_requested = Some(0.99);
        let (output, _, _) = piped("SEARCH a NEAR [1] RECALL 0.99;", vec![Ok(answer)]);
        assert!(
            output.contains("recall target 0.99 (requested)"),
            "{output}"
        );
    }

    #[test]
    fn degraded_answers_say_so() {
        let mut answer = FakeSink::ok(Vec::new());
        answer.stats.degraded = Some(true);
        let (output, _, _) = piped("SEARCH a NEAR [1];", vec![Ok(answer)]);
        assert!(output.contains("DEGRADED"), "{output}");
    }

    #[test]
    fn errors_print_the_trace_and_a_caret_even_when_trace_is_off() {
        let mut trace = QueryTrace::new("q_err");
        trace.push_ok(stage::PARSE, 40, None);
        trace.push_failed(
            stage::COMPILE_FILTER,
            10,
            "chironql.no_or_across_fields",
            "no OR",
        );
        let error = ChironQlError {
            error: "ChironQL filters are conjunctions — there is no OR".to_string(),
            code: "chironql.no_or_across_fields".to_string(),
            hint: Some("Single-field disjunction is IN".to_string()),
            position: Some(7),
            affected_estimate: None,
            query_id: "q_err".to_string(),
            trace: Some(Box::new(trace)),
        };

        let (output, failures, _) = piped("COUNT a WHERE x = 1 OR y = 2;", vec![Err(error)]);

        assert_eq!(failures, 1);
        assert!(output.contains("✗"), "{output}");
        assert!(output.contains("at compile_filter"), "{output}");
        assert!(output.contains("hint:"), "{output}");
        assert!(output.contains('^'), "{output}");
        assert!(output.contains("trace  q_err"), "{output}");
        assert!(output.contains("FAIL"), "{output}");
    }

    #[test]
    fn json_format_emits_one_object_per_statement() {
        let answer = FakeSink::ok(vec![json!({"id": "a", "score": 1.0})]);
        let mut sink = FakeSink {
            seen: Vec::new(),
            answers: vec![Ok(answer)],
        };
        let mut out = Vec::new();
        run(
            &mut sink,
            "SEARCH a NEAR [1];".as_bytes(),
            &mut out,
            ReplOptions {
                interactive: false,
                format: Format::Json,
                ..Default::default()
            },
        )
        .expect("repl runs");

        let output = String::from_utf8(out).expect("utf8");
        let parsed: Value = serde_json::from_str(&output).expect("valid json");
        assert_eq!(parsed["query_id"], json!("q_test"));
    }

    #[test]
    fn meta_commands_expand_to_statements() {
        let (_, _, seen) = piped("\\l\n\\d products\n\\c products\n", Vec::new());
        assert_eq!(
            seen,
            vec!["SHOW COLLECTIONS;", "DESCRIBE products;", "USE products;"]
        );
    }

    /// Written like a statement, semicolon included, and in the backslash
    /// spelling every other meta-command here uses. Neither reaches the
    /// parser, which would answer "unknown statement".
    #[test]
    fn clear_is_a_meta_command_when_it_is_asked_for() {
        let (output, _, seen) = piped("clear;\nCLEAR;\n\\clear\n", Vec::new());
        assert!(seen.is_empty(), "clear never becomes a statement: {seen:?}");
        assert!(
            !output.contains("unknown command"),
            "every spelling is recognised: {output}"
        );
    }

    /// A writer that counts flushes, to pin the one thing a `Vec<u8>` cannot
    /// show: whether output that carries no newline actually left the buffer.
    #[derive(Default)]
    struct FlushSpy {
        written: Vec<u8>,
        flushes: usize,
    }

    impl Write for FlushSpy {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// The clear sequence has no newline and the console writes through a
    /// line-buffered stdout, so without an explicit flush it sits in the
    /// buffer until something else prints a line — and `\q` exits the process,
    /// so "until" can mean "never". This was the actual bug.
    #[test]
    fn clearing_flushes_what_it_wrote() {
        let mut sink = FakeSink {
            seen: Vec::new(),
            answers: Vec::new(),
        };
        let mut out = FlushSpy::default();
        let mut format = Format::Table;
        let (mut trace, mut timing) = (false, false);

        meta_command(
            &mut sink,
            "clear;",
            &mut format,
            &mut trace,
            &mut timing,
            &mut out,
        )
        .expect("clear runs");

        assert_eq!(out.flushes, 1, "the sequence is pushed out, not buffered");
    }

    #[test]
    fn params_meta_command_sets_typed_values_for_the_next_statement() {
        struct ParamSink(Vec<RelationalValue>);
        impl QuerySink for ParamSink {
            fn execute(
                &mut self,
                _query: &str,
                _options: ExecuteOptions,
            ) -> Result<ChironQlResponse, ChironQlError> {
                Ok(FakeSink::ok(Vec::new()))
            }
            fn set_parameters(
                &mut self,
                parameters: Vec<RelationalValue>,
            ) -> Result<(), ChironQlError> {
                self.0 = parameters;
                Ok(())
            }
        }

        let mut sink = ParamSink(Vec::new());
        let mut output = Vec::new();
        let mut format = Format::Table;
        let (mut trace, mut timing) = (false, false);
        meta_command(
            &mut sink,
            r#"\params [{"type":"text","value":"doc-1"},{"type":"integer","value":7}]"#,
            &mut format,
            &mut trace,
            &mut timing,
            &mut output,
        )
        .expect("parameters accepted");

        assert_eq!(
            sink.0,
            vec![
                RelationalValue::Text("doc-1".into()),
                RelationalValue::Integer(7)
            ]
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("next statement")
        );
    }

    /// The semicolon is the request. Without it the word is ordinary input,
    /// the screen is left alone, and the parser gets to say what it thinks of
    /// `clear` — which is the whole point of requiring it.
    #[test]
    fn a_bare_clear_does_not_clear() {
        let (output, _, _) = piped("clear\n", Vec::new());
        assert!(!output.contains('\x1b'), "nothing was cleared: {output:?}");
    }

    #[test]
    fn the_help_lists_clear() {
        let (output, _, _) = piped("\\h\n", Vec::new());
        assert!(output.contains("clear;"), "{output}");
    }

    #[test]
    fn quit_stops_the_loop() {
        let (_, _, seen) = piped("\\q\nCOUNT a;\n", Vec::new());
        assert!(seen.is_empty());
    }

    #[test]
    fn help_and_role_do_not_reach_the_sink() {
        let (output, _, seen) = piped("\\h\n\\role\n", Vec::new());
        assert!(seen.is_empty());
        assert!(output.contains("SEARCH"), "{output}");
        assert!(output.contains("read_only"), "{output}");
    }

    #[test]
    fn caret_lands_on_the_offending_line_of_a_multi_line_statement() {
        let statement = "SEARCH a\n  WHERE x = 1 OR y = 2;";
        let position = statement.find("OR").expect("OR present");
        let (_, column, text) = locate(statement, position).expect("located");
        assert_eq!(text, "  WHERE x = 1 OR y = 2;");
        assert_eq!(&text[column..column + 2], "OR");
    }
}
