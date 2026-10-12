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
use std::time::Duration;

use chirondb::chironql_repl::{
    ExecuteOptions, Format, QuerySink, ReplOptions, run, run_interactive, run_one,
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
    /// Read the API key from a private file instead of a process argument.
    #[arg(long, conflicts_with = "api_key")]
    api_key_file: Option<PathBuf>,
    /// Additional trusted CA certificate (PEM). Hostname verification stays on.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Exclusive private destination for ISSUE/ROTATE API KEY.
    #[arg(long)]
    key_out: Option<PathBuf>,
    /// Session collection, as if `USE <name>` had been run.
    #[arg(long)]
    collection: Option<String>,
    /// Run one statement and exit. Reads nothing from stdin.
    #[arg(long)]
    exec: Option<String>,
    /// Typed positional parameters as a RelationalValue JSON array.
    #[arg(long, requires = "exec")]
    params_json: Option<String>,
    /// Stable idempotency key for a SQL mutation.
    #[arg(long, requires = "exec")]
    idempotency_key: Option<String>,
    /// Optional audit correlation for relational or atomic multi-model mutation.
    #[arg(long, requires = "exec")]
    retry_id: Option<String>,
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
    key_out: Option<PathBuf>,
    pending_confirmation: Option<(String, String)>,
    parameters: Vec<chirondb::RelationalValue>,
    idempotency_key: Option<String>,
    retry_id: Option<String>,
}

impl HttpSink {
    fn new(
        url: &str,
        api_key: Option<String>,
        collection: Option<String>,
        ca_cert: Option<&std::path::Path>,
        key_out: Option<PathBuf>,
        parameters: Vec<chirondb::RelationalValue>,
        retry_id: Option<String>,
    ) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(url).map_err(|_| "invalid server URL")?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.scheme(), "http" | "https")
        {
            return Err("invalid server URL".into());
        }
        let loopback = parsed.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        if api_key.is_some() && parsed.scheme() != "https" && !loopback {
            return Err("credential authentication requires HTTPS or a loopback IP address".into());
        }
        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(35));
        if let Some(path) = ca_cert {
            let pem = std::fs::read(path).map_err(|_| "cannot read CA certificate")?;
            let certificate =
                reqwest::Certificate::from_pem(&pem).map_err(|_| "invalid CA certificate")?;
            builder = builder.add_root_certificate(certificate);
        }
        let endpoint = format!("{}/v1/chironql", url.trim_end_matches('/'));
        Ok(Self {
            client: builder
                .build()
                .map_err(|_| "cannot initialize TLS client")?,
            endpoint,
            api_key,
            collection,
            transport_failed: false,
            key_out,
            pending_confirmation: None,
            parameters,
            idempotency_key: None,
            retry_id,
        })
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

impl HttpSink {
    fn send(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        let request = ChironQlRequest {
            query: query.to_string(),
            collection: self.collection.clone(),
            trace: options.trace,
            confirm: options.confirm,
            parameters: self.parameters.clone(),
            idempotency_key: self.idempotency_key.clone(),
            retry_id: self.retry_id.clone(),
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
            Err(_) => {
                let code = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|body| {
                        body.pointer("/error/code")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                if let Some(code) = code.filter(|code| code.starts_with("security.")) {
                    return Err(local_error(&code, "server rejected the request"));
                }
                Err(self.transport_error(format!("server returned {status}")))
            }
        }
    }
}

fn local_error(code: &str, message: &str) -> ChironQlError {
    ChironQlError {
        error: message.into(),
        code: code.into(),
        hint: None,
        position: None,
        affected_estimate: None,
        query_id: String::new(),
        trace: None,
    }
}

impl QuerySink for HttpSink {
    fn redact_query_input(&self) -> bool {
        self.api_key
            .as_ref()
            .is_some_and(|key| key.starts_with("chiron."))
    }
    fn set_parameters(
        &mut self,
        parameters: Vec<chirondb::RelationalValue>,
    ) -> Result<(), ChironQlError> {
        self.parameters = parameters;
        Ok(())
    }
    fn execute(
        &mut self,
        query: &str,
        options: ExecuteOptions,
    ) -> Result<ChironQlResponse, ChironQlError> {
        use chirondb::{
            chironql_credentials::{KeyDestination, with_revision},
            chironql_parser::{SecurityCommand, Statement},
        };
        let parsed = chirondb::chironql_parser::parse(query).ok();
        let security = match &parsed {
            Some(Statement::Security(statement)) => Some(statement),
            _ => None,
        };
        let mut destination = if security.is_some_and(|s| s.issues_key()) {
            let path = self.key_out.as_deref().ok_or_else(|| {
                local_error(
                    "chironql.key_output_required",
                    "ISSUE/ROTATE requires --key-out",
                )
            })?;
            Some(KeyDestination::create(path).map_err(|_| {
                local_error(
                    "chironql.key_output_unavailable",
                    "credential destination must be a new writable private file",
                )
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
            let revision = self
                .send(&revision_query, ExecuteOptions::default())?
                .rows
                .first()
                .and_then(|row| row.get("revision"))
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    local_error(
                        "chironql.invalid_reply",
                        "server did not return a security revision",
                    )
                })?;
            with_revision(query, revision)
        } else {
            query.into()
        };
        let result = self.send(&prepared, options);
        self.parameters.clear();
        self.idempotency_key = None;
        self.retry_id = None;
        if let Err(error) = &result {
            if error.code == "chironql.confirmation_required" {
                self.pending_confirmation = Some((query.into(), prepared));
            }
            return result;
        }
        let mut result = result?;
        if let Some(credential) = result.credential.take() {
            let destination = destination.as_mut().ok_or_else(|| {
                local_error(
                    "chironql.unexpected_credential",
                    "unexpected credential response was suppressed",
                )
            })?;
            destination.save(&credential.secret).map_err(|_| local_error("chironql.key_output_failed",
                &format!("credential {} was issued but could not be saved; revoke that credential ID before retrying", credential.id)))?;
            if matches!(security.map(|s| &s.command), Some(SecurityCommand::RotateKey { id })
                if self.api_key.as_ref().is_some_and(|key| key.starts_with(&format!("chiron.{id}."))))
            {
                self.api_key = Some(credential.secret);
            }
            result
                .rows
                .push(serde_json::json!({"credential_id":credential.id,"saved":true}));
            result
                .columns
                .extend(["credential_id".into(), "saved".into()]);
        } else if destination.is_some() {
            return Err(local_error(
                "chironql.invalid_reply",
                "credential response is missing; do not automatically retry issuance",
            ));
        }
        Ok(result)
    }
}

/// The collection named by a `USE` statement, if this is one.
fn use_target(query: &str) -> Option<String> {
    match chirondb::chironql_parser::parse(query).ok()? {
        chirondb::chironql_parser::Statement::Use { collection } => Some(collection),
        _ => None,
    }
}

fn default_history_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".chironql_history"))
}

fn main() -> ExitCode {
    let args = Args::parse();

    let parameters = match args.params_json.as_deref() {
        Some(value) => match serde_json::from_str::<Vec<chirondb::RelationalValue>>(value) {
            Ok(parameters) => parameters,
            Err(error) => {
                eprintln!("--params-json must be a tagged RelationalValue array: {error}");
                return ExitCode::from(EXIT_QUERY_ERROR);
            }
        },
        None => Vec::new(),
    };

    let api_key = if let Some(path) = &args.api_key_file {
        match chirondb::chironql_credentials::read_key(path) {
            Ok(key) => Some(key),
            Err(_) => {
                eprintln!("cannot read private API key file");
                return ExitCode::from(EXIT_CONNECTION_ERROR);
            }
        }
    } else {
        args.api_key.clone().or_else(|| {
            std::env::var("CHIRONDB_API_KEY")
                .or_else(|_| std::env::var("GAUSSDB_API_KEY"))
                .ok()
        })
    };

    let protected = api_key
        .as_ref()
        .is_some_and(|key| key.starts_with("chiron."));
    let mut sink = match HttpSink::new(
        &args.url,
        api_key,
        args.collection.clone(),
        args.ca_cert.as_deref(),
        args.key_out,
        parameters,
        args.retry_id.clone(),
    ) {
        Ok(sink) => sink,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(EXIT_CONNECTION_ERROR);
        }
    };
    sink.idempotency_key = args.idempotency_key.clone();
    let interactive = std::io::stdin().is_terminal() && args.exec.is_none();
    let connection_identity = if interactive {
        match sink.send("SHOW CURRENT USER;", ExecuteOptions::default()) {
            Ok(user) => {
                let name = user
                    .rows
                    .first()
                    .and_then(|row| row.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                match sink.send("SHOW CURRENT USER PRIVILEGES;", ExecuteOptions::default()) {
                    Ok(privileges) => {
                        let admin = privileges.rows.iter().any(|row| {
                            row.get("action").and_then(|a| a.as_str()) == Some("identity_manage")
                        });
                        format!(
                            " · authenticated as {name}{}",
                            if admin {
                                " (security administration)"
                            } else {
                                ""
                            }
                        )
                    }
                    Err(error) => {
                        eprintln!("{}: {}", error.code, error.error);
                        return ExitCode::from(EXIT_QUERY_ERROR);
                    }
                }
            }
            Err(error) if !protected && error.code == "chironql.permission_denied" => {
                " · legacy session".into()
            }
            Err(error) => {
                eprintln!("{}: {}", error.code, error.error);
                return ExitCode::from(if sink.transport_failed {
                    EXIT_CONNECTION_ERROR
                } else {
                    EXIT_QUERY_ERROR
                });
            }
        }
    } else {
        String::new()
    };
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
                "chironql {} · ChironQL {} · {}{} · \\h for help",
                env!("CARGO_PKG_VERSION"),
                chirondb::chironql_parser::LANGUAGE_VERSION,
                args.url,
                connection_identity
            ))
        }),
    };

    let failures = if let Some(statement) = args.exec {
        let mut out = std::io::stdout();
        run_one(
            &mut sink,
            &statement,
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
            if protected {
                None
            } else {
                args.history.or_else(default_history_path)
            },
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
        assert_eq!(use_target("-- comment\nUSE docs;"), Some("docs".into()));
        assert_eq!(
            use_target("  use   products  "),
            Some("products".to_string())
        );
        assert_eq!(use_target("SEARCH products NEAR [1];"), None);
        assert_eq!(use_target("USE products extra;"), None);
    }
}
