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
}

/// In-process sink: no socket, no serialization, no auth round trip.
pub struct LocalSink {
    db: Db,
    session: Session,
    role: Role,
    tenant: TenantScope,
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
}

impl QuerySink for LocalSink {
    fn execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        let mut ctx = ExecContext {
            db: &self.db,
            session: &mut self.session,
            role: self.role,
            // The console is not collection-scoped: it is the operator's own
            // process. HTTP callers get their key's allowlist instead.
            allowed_collections: None,
            want_trace: options.trace,
            confirm: options.confirm,
            tenant: self.tenant.clone(),
        };
        chironql_exec::execute(&mut ctx, query)
    }

    fn role(&self) -> Option<Role> {
        Some(self.role)
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

        // Statements end at `;`. Anything else continues.
        if !buffer.trim_end().ends_with(';') {
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

        let statement = std::mem::take(&mut buffer);
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
        }

        if options.interactive {
            write!(out, "{PROMPT}")?;
            out.flush()?;
        }
    }

    // Trailing input without a `;` is still a statement worth running — a
    // piped heredoc that forgets the semicolon should not silently do nothing.
    if !buffer.trim().is_empty()
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

                if !buffer.trim_end().ends_with(';') {
                    if buffer.trim().is_empty() {
                        buffer.clear();
                    }
                    continue;
                }

                let statement = std::mem::take(&mut buffer);
                let _ = editor.add_history_entry(statement.trim());

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

    match outcome {
        Ok(response) => {
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
                Format::Table => render_error(&error, statement, out)?,
            }
            Ok(false)
        }
    }
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
    sink: &S,
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
 Introspect   SHOW COLLECTIONS · DESCRIBE · USE
 Write        UPSERT · UPDATE ... SET PAYLOAD · DELETE ... POINTS
              DELETE ... WHERE   (counts first, then asks)
 Admin        CREATE COLLECTION ... DIM <n> [METRIC …] [WITH {…}]
              DROP COLLECTION ... [IF EXISTS]   (counts first, then asks)

 Collection DDL needs a read_write role. Snapshots, restore and compaction stay
 in `chironctl`.

 \\h           this help
 clear;       clear the screen (also \\clear)
 \\l           list collections
 \\d [coll]    describe a collection
 \\c <coll>    use a collection for later statements
 \\trace       show the server's execution trace (always shown on failure)
 \\timing      show client-side elapsed time
 \\format      table | json
 \\role        the role this session runs as
 \\q           quit

 Statements end with `;` and may span lines. Full reference: docs/CHIRONQL.md
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
        Value::Null => String::new(),
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
                kind: ChironQlKind::Rows,
                columns: vec!["id".to_string(), "score".to_string()],
                rows,
                stats: ChironQlStats {
                    took_ms: 3.1,
                    searched: Some(1412),
                    degraded: Some(false),
                    ..Default::default()
                },
                next: None,
                query_id: "q_test".to_string(),
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
        let sink = FakeSink {
            seen: Vec::new(),
            answers: Vec::new(),
        };
        let mut out = FlushSpy::default();
        let mut format = Format::Table;
        let (mut trace, mut timing) = (false, false);

        meta_command(
            &sink,
            "clear;",
            &mut format,
            &mut trace,
            &mut timing,
            &mut out,
        )
        .expect("clear runs");

        assert_eq!(out.flushes, 1, "the sequence is pushed out, not buffered");
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
