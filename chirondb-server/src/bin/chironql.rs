//! `chironql` — the ChironQL terminal client.
//!
//! P3 of the ChironQL plan. Named after the language, following the convention
//! ArangoDB and Neo4j use (`arangosh` for AQL, `cypher-shell` for Cypher).
//!
//! This binary is thin on purpose: the REPL, the rendering and the grammar all
//! live in the server crate and are shared with `chirondb --console`. What is
//! here is the transport ([`HttpSink`]) and the flags.
//!
//! It is a **network client**. It never opens a data directory: two processes
//! opening the same one is how data gets corrupted. To query a database on the
//! machine you are sitting at, start that server with `--console`.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use chirondb::chironql_repl::{
    ExecuteOptions, Format, QuerySink, ReplOptions, run, run_interactive,
};
use chirondb_types::chironql::{ChironQlError, ChironQlRequest, ChironQlResponse};
use clap::{Parser, ValueEnum};

/// Exit codes, so a script can tell the three failures apart.
const EXIT_OK: u8 = 0;
const EXIT_QUERY_ERROR: u8 = 1;
const EXIT_CONNECTION_ERROR: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "chironql",
    version,
    about = "Interactive ChironQL client for ChironDB"
)]
struct Args {
    /// Server to talk to.
    #[arg(long, default_value = "http://127.0.0.1:7401")]
    url: String,
    /// API key. Falls back to CHIRONDB_API_KEY, then GAUSSDB_API_KEY.
    #[arg(long)]
    api_key: Option<String>,
    /// Session collection, as if `USE <name>` had been run.
    #[arg(long)]
    collection: Option<String>,
    /// Run one statement and exit. Reads nothing from stdin.
    #[arg(long)]
    exec: Option<String>,
    /// Output format. Defaults to table on a terminal and json when piped.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,
    /// Show the server's execution trace on success. Failures always show it.
    #[arg(long)]
    trace: bool,
    /// Where to keep history. Defaults to ~/.chironql_history.
    #[arg(long)]
    history: Option<PathBuf>,
    /// Answer yes to confirmation prompts. Required for destructive
    /// statements when the session is not interactive.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

impl From<OutputFormat> for Format {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Table => Format::Table,
            OutputFormat::Json => Format::Json,
        }
    }
}

/// Sends statements to a server over HTTP. The other implementation of
/// [`QuerySink`] is the in-process one the embedded console uses.
struct HttpSink {
    client: reqwest::blocking::Client,
    endpoint: String,
    api_key: Option<String>,
    collection: Option<String>,
    /// Set when the transport itself failed, so `main` can exit 2 rather than
    /// reporting a query error for a server that is not there.
    transport_failed: bool,
}

impl HttpSink {
    fn new(url: &str, api_key: Option<String>, collection: Option<String>) -> Self {
        let endpoint = format!("{}/v1/chironql", url.trim_end_matches('/'));
        Self {
            client: reqwest::blocking::Client::new(),
            endpoint,
            api_key,
            collection,
            transport_failed: false,
        }
    }

    fn transport_error(&mut self, message: String) -> ChironQlError {
        self.transport_failed = true;
        ChironQlError {
            error: message,
            code: "chironql.connection_failed".to_string(),
            hint: Some(format!(
                "Is a ChironDB server listening at {}?",
                self.endpoint.trim_end_matches("/v1/chironql")
            )),
            position: None,
            affected_estimate: None,
            query_id: String::new(),
            trace: None,
        }
    }
}

impl QuerySink for HttpSink {
    fn execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        let request = ChironQlRequest {
            query: query.to_string(),
            collection: self.collection.clone(),
            trace: options.trace,
            confirm: options.confirm,
        };

        let mut builder = self.client.post(&self.endpoint).json(&request);
        if let Some(key) = &self.api_key {
            builder = builder.bearer_auth(key);
        }

        let response = match builder.send() {
            Ok(response) => response,
            Err(error) => return Err(self.transport_error(error.to_string())),
        };

        let status = response.status();
        let body = match response.text() {
            Ok(body) => body,
            Err(error) => return Err(self.transport_error(error.to_string())),
        };

        if status.is_success() {
            // `USE` is a client-side session change over HTTP: the server has
            // no session to keep it in, so the client remembers it instead.
            if let Some(collection) = use_target(query) {
                self.collection = Some(collection);
            }
            return serde_json::from_str::<ChironQlResponse>(&body).map_err(|error| {
                self.transport_error(format!("could not read the server's reply: {error}"))
            });
        }

        match serde_json::from_str::<ChironQlError>(&body) {
            Ok(error) => Err(error),
            // A non-JSON body means something other than ChironDB answered —
            // a proxy, a 401 from a gateway, an HTML error page.
            Err(_) => Err(self.transport_error(format!("server returned {status}: {body}"))),
        }
    }
}

/// The collection named by a `USE` statement, if this is one.
fn use_target(query: &str) -> Option<String> {
    let trimmed = query.trim().trim_end_matches(';').trim();
    let mut parts = trimmed.split_whitespace();
    let keyword = parts.next()?;
    if !keyword.eq_ignore_ascii_case("use") {
        return None;
    }
    let name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(name.to_string())
}

fn default_history_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".chironql_history"))
}

fn main() -> ExitCode {
    let args = Args::parse();

    let api_key = args.api_key.clone().or_else(|| {
        std::env::var("CHIRONDB_API_KEY")
            .or_else(|_| std::env::var("GAUSSDB_API_KEY"))
            .ok()
    });

    let mut sink = HttpSink::new(&args.url, api_key, args.collection.clone());
    let interactive = std::io::stdin().is_terminal() && args.exec.is_none();
    let format = args
        .format
        .map(Format::from)
        // Table when a human is watching, JSON when piped: the convention
        // every well-behaved CLI follows.
        .unwrap_or(if std::io::stdout().is_terminal() {
            Format::Table
        } else {
            Format::Json
        });

    let options = ReplOptions {
        interactive,
        format,
        trace: args.trace,
        confirm: args.yes,
        banner: interactive.then(|| {
            chirondb::branding::banner(&format!(
                "chironql {} · ChironQL {} · {} · \\h for help",
                env!("CARGO_PKG_VERSION"),
                chirondb::chironql_parser::LANGUAGE_VERSION,
                args.url
            ))
        }),
    };

    let failures = if let Some(statement) = args.exec {
        let mut out = std::io::stdout();
        run(
            &mut sink,
            statement.as_bytes(),
            &mut out,
            ReplOptions {
                interactive: false,
                ..options
            },
        )
    } else if interactive {
        run_interactive(
            &mut sink,
            options,
            args.history.or_else(default_history_path),
        )
    } else {
        let mut input = String::new();
        if let Err(error) = std::io::stdin().read_to_string(&mut input) {
            eprintln!("chironql: could not read stdin: {error}");
            return ExitCode::from(EXIT_CONNECTION_ERROR);
        }
        let mut out = std::io::stdout();
        run(&mut sink, input.as_bytes(), &mut out, options)
    };

    match failures {
        Err(error) => {
            eprintln!("chironql: {error}");
            ExitCode::from(EXIT_CONNECTION_ERROR)
        }
        // A server that never answered is a different problem from a query the
        // server rejected, and a script needs to tell them apart.
        Ok(_) if sink.transport_failed => ExitCode::from(EXIT_CONNECTION_ERROR),
        Ok(0) => ExitCode::from(EXIT_OK),
        Ok(_) => ExitCode::from(EXIT_QUERY_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_statements_are_recognised_for_client_side_session_state() {
        assert_eq!(use_target("USE products;"), Some("products".to_string()));
        assert_eq!(
            use_target("  use   products  "),
            Some("products".to_string())
        );
        assert_eq!(use_target("SEARCH products NEAR [1];"), None);
        assert_eq!(use_target("USE products extra;"), None);
    }
}
