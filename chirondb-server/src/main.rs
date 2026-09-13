use std::{
    ffi::OsString,
    io::IsTerminal,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use chirondb::{
    Db,
    api::{self, ServerOptions},
    auth::AuthConfig,
    chironql_repl::{self, LocalSink, ReplOptions},
    cluster::{ClusterConfig, ClusterHandle, NodeRole},
    encryption::{Keyring, install_process_keyring},
    events::EventHub,
    grpc, observability,
    placement::ClusterNode,
    rbac::{RbacConfig, Role},
    security_paths::StoragePolicy,
    segment::ColdObjectStoreConfig,
    tenant::TenantEnforcement,
    tls, wire,
};
use clap::{Parser, ValueEnum};
use serde::Deserialize;

// M2-006: jemalloc as global allocator. Reduces fragmentation under the
// concurrent insert + compaction load typical of LS-Vec. SPEC Table II.
// Disabled on MSVC + on miri (jemalloc is incompatible).
#[cfg(all(feature = "jemalloc", not(target_env = "msvc"), not(miri),))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Tenant enforcement mode. Mirrors `tenant::TenantEnforcement`; kept separate
/// so the CLI surface does not expose the internal type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum TenantMode {
    #[default]
    Disabled,
    DryRun,
    Enforced,
}

impl From<TenantMode> for TenantEnforcement {
    fn from(mode: TenantMode) -> Self {
        match mode {
            TenantMode::Disabled => TenantEnforcement::Disabled,
            TenantMode::DryRun => TenantEnforcement::DryRun,
            TenantMode::Enforced => TenantEnforcement::Enforced,
        }
    }
}

/// Console permission level. Mirrors `rbac::Role`; kept separate so the CLI
/// surface does not expose the internal type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum ConsoleRole {
    // clap renders these kebab-case, but every doc, log line and error message
    // in the project spells the roles `read_only` / `read_write`. Both spellings
    // are accepted so a copied command works.
    #[value(alias = "read_only")]
    ReadOnly,
    #[default]
    #[value(alias = "read_write")]
    ReadWrite,
    Admin,
}

fn console_role_name(role: Role) -> &'static str {
    if role.allows_admin() {
        "admin"
    } else if role.allows_write() {
        "read_write"
    } else {
        "read_only"
    }
}

impl From<ConsoleRole> for Role {
    fn from(role: ConsoleRole) -> Self {
        match role {
            ConsoleRole::ReadOnly => Role::ReadOnly,
            ConsoleRole::ReadWrite => Role::ReadWrite,
            ConsoleRole::Admin => Role::Admin,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "ChironDB vector database server"
)]
struct Args {
    /// Attach an interactive ChironQL console to this process's stdin.
    ///
    /// Requires a TTY: without one the console stays off and the server runs
    /// normally, so systemd units, Kubernetes pods and `docker run` without
    /// `-it` are unaffected. Logs move to stderr while the console is on, so
    /// the prompt keeps stdout to itself.
    #[arg(long)]
    console: bool,
    /// Role the console runs as.
    ///
    /// Defaults to read_write: `--console` is already opt-in and refuses to
    /// start without a terminal, so the person typing is the person who
    /// started the process. `--console-role read_only` narrows it when a
    /// session is only meant to look.
    #[arg(long, value_enum, default_value_t = ConsoleRole::ReadWrite)]
    console_role: ConsoleRole,
    /// Pre-set the console's session collection, as if `USE <name>` had run.
    #[arg(long)]
    collection: Option<String>,
    /// Row-level tenant isolation: `disabled` (default), `dry-run`, or
    /// `enforced`.
    ///
    /// Switching straight to `enforced` on a database that predates it hides
    /// every point that has no `tenant_id`, because an unowned row is visible
    /// to nobody. Backfill first, confirm with `dry-run`, then enforce.
    #[arg(long, value_enum, default_value_t = TenantMode::Disabled)]
    tenant_enforcement: TenantMode,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    listen_http: Option<SocketAddr>,
    #[arg(long)]
    listen_grpc: Option<SocketAddr>,
    #[arg(long)]
    listen_wire: Option<SocketAddr>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long)]
    api_key_file: Option<PathBuf>,
    #[arg(long)]
    rbac_config_file: Option<PathBuf>,
    /// External versioned keyring used by application-level encryption.
    #[arg(long)]
    encryption_keyring_file: Option<PathBuf>,
    /// Only this local directory may be used by snapshot and restore requests.
    #[arg(long)]
    snapshot_root: Option<PathBuf>,
    /// Development-only escape hatch for plaintext/incomplete public profiles.
    #[arg(long)]
    allow_insecure_non_loopback: bool,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    tls_client_ca: Option<PathBuf>,
    #[arg(long)]
    rate_limit_per_second: Option<u32>,
    #[arg(long)]
    max_points_per_collection: Option<usize>,
    #[arg(long)]
    auto_compact_wal_bytes: Option<u64>,
    #[arg(long)]
    auto_compact_interval_secs: Option<u64>,
    /// P3 — interval (seconds) between recall-SLA drift sweeps. Default 1800
    /// (30 min). 0 disables monitoring even when collections have a
    /// `recall_sla` set.
    #[arg(long)]
    drift_monitor_interval_secs: Option<u64>,
    /// PA-2c — server-side default for `SearchRequest.with_payload` when a
    /// request leaves it unset. `false` skips the per-hit
    /// `serde_json::Value` clone — significant p99 win for id-only callers
    /// (VectorDBBench, ann-benchmarks, agentic re-rankers). Default = `true`
    /// (back-compat).
    #[arg(long)]
    default_with_payload: Option<bool>,
    /// P2C — opt-in flag to enable intra-query parallel beam scoring at
    /// layer 0. Default OFF to preserve the recall_golden floor and avoid
    /// the insert-phase hang the original P2C attempt hit. When ON, the
    /// HNSW layer-0 beam expansion dispatches unvisited-neighbor scoring
    /// to `rayon::par_iter` once the batch size hits the standard
    /// `HNSW_M=16` threshold. Cross-platform; behavior is identical on
    /// x86 and aarch64 because the dispatch is over a pure-read distance
    /// compute with no shared mutable state.
    #[arg(long)]
    intra_query_parallel: Option<bool>,
    #[arg(long)]
    wal_archive_retain_last: Option<usize>,
    #[arg(long)]
    wal_archive_max_bytes: Option<u64>,
    #[arg(long)]
    wal_archive_max_age_secs: Option<u64>,
    #[arg(long)]
    wal_external_archive_dir: Option<PathBuf>,
    #[arg(long)]
    wal_object_store_dir: Option<PathBuf>,
    #[arg(long)]
    wal_object_store_url: Option<String>,
    #[arg(long)]
    wal_archive_command: Option<String>,
    #[arg(long)]
    cold_object_store_dir: Option<PathBuf>,
    #[arg(long)]
    cold_object_store_url: Option<String>,
    #[arg(long)]
    cluster_node_id: Option<u64>,
    /// Peer list: "id1=host:raftport,id2=host:raftport,..."
    #[arg(long)]
    cluster_peers: Option<String>,
    #[arg(long)]
    cluster_listen_raft: Option<std::net::SocketAddr>,
    /// "all" | "ingress" | "coordinator" | "engine"
    #[arg(long)]
    cluster_node_role: Option<String>,
    /// Allowed CORS origin (repeatable; pass `*` for any). Disabled if unset.
    #[arg(long)]
    cors_origin: Vec<String>,
    /// Enable direct browser gRPC-Web support. Requires explicit CORS origins.
    #[arg(long)]
    enable_grpc_web: bool,
    /// WebSocket metrics push interval (ms). Default 5000.
    #[arg(long)]
    ws_metrics_interval: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    mcp: Option<chirondb::mcp::McpConfig>,
    listen_http: Option<SocketAddr>,
    listen_grpc: Option<SocketAddr>,
    listen_wire: Option<SocketAddr>,
    data_dir: Option<PathBuf>,
    api_key: Option<String>,
    api_key_file: Option<PathBuf>,
    rbac_config_file: Option<PathBuf>,
    encryption_keyring_file: Option<PathBuf>,
    snapshot_root: Option<PathBuf>,
    allow_insecure_non_loopback: bool,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    rate_limit_per_second: Option<u32>,
    max_points_per_collection: Option<usize>,
    auto_compact_wal_bytes: Option<u64>,
    auto_compact_interval_secs: Option<u64>,
    drift_monitor_interval_secs: Option<u64>,
    default_with_payload: Option<bool>,
    intra_query_parallel: Option<bool>,
    wal_archive_retain_last: Option<usize>,
    wal_archive_max_bytes: Option<u64>,
    wal_archive_max_age_secs: Option<u64>,
    wal_external_archive_dir: Option<PathBuf>,
    wal_object_store_dir: Option<PathBuf>,
    wal_object_store_url: Option<String>,
    wal_archive_command: Option<String>,
    cold_object_store_dir: Option<PathBuf>,
    cold_object_store_url: Option<String>,
    cluster_node_id: Option<u64>,
    cluster_peers: Option<String>,
    cluster_listen_raft: Option<std::net::SocketAddr>,
    cluster_node_role: Option<String>,
    #[serde(default)]
    cors_origin: Vec<String>,
    enable_grpc_web: bool,
    ws_metrics_interval: Option<u64>,
}

#[derive(Debug)]
struct EffectiveConfig {
    mcp: Option<chirondb::mcp::McpConfig>,
    listen_http: SocketAddr,
    listen_grpc: SocketAddr,
    listen_wire: SocketAddr,
    data_dir: PathBuf,
    api_key: Option<String>,
    api_key_file: Option<PathBuf>,
    rbac_config_file: Option<PathBuf>,
    encryption_keyring_file: Option<PathBuf>,
    snapshot_root: Option<PathBuf>,
    allow_insecure_non_loopback: bool,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    rate_limit_per_second: Option<u32>,
    max_points_per_collection: Option<usize>,
    auto_compact_wal_bytes: Option<u64>,
    auto_compact_interval_secs: u64,
    drift_monitor_interval_secs: u64,
    default_with_payload: bool,
    intra_query_parallel: bool,
    wal_archive_retain_last: Option<usize>,
    wal_archive_max_bytes: Option<u64>,
    wal_archive_max_age_secs: Option<u64>,
    wal_external_archive_dir: Option<PathBuf>,
    wal_object_store_dir: Option<PathBuf>,
    wal_object_store_url: Option<String>,
    wal_archive_command: Option<String>,
    cold_object_store_dir: Option<PathBuf>,
    cold_object_store_url: Option<String>,
    cluster: Option<ClusterConfig>,
    cors_origins: Vec<String>,
    enable_grpc_web: bool,
    ws_metrics_interval_ms: u64,
}

fn compatible_env(primary: &str, legacy: &str) -> Option<String> {
    prefer_primary(std::env::var(primary).ok(), std::env::var(legacy).ok())
}

fn compatible_env_os(primary: &str, legacy: &str) -> Option<OsString> {
    prefer_primary(std::env::var_os(primary), std::env::var_os(legacy))
}

fn prefer_primary<T>(primary: Option<T>, legacy: Option<T>) -> Option<T> {
    primary.or(legacy)
}

fn compatible_bool_env(primary: &str, legacy: &str) -> anyhow::Result<Option<bool>> {
    let Some(raw) = compatible_env(primary, legacy) else {
        return Ok(None);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => bail!("invalid boolean value for {primary}: {raw}"),
    }
}

fn validate_external_keyring_path(data_dir: &Path, keyring_file: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to prepare data dir {}", data_dir.display()))?;
    let canonical_data = std::fs::canonicalize(data_dir)
        .with_context(|| format!("failed to resolve data dir {}", data_dir.display()))?;
    let canonical_keyring = std::fs::canonicalize(keyring_file)
        .with_context(|| format!("failed to resolve keyring {}", keyring_file.display()))?;
    if canonical_keyring.starts_with(&canonical_data) {
        bail!(
            "encryption keyring must be mounted outside the data directory: {}",
            keyring_file.display()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_listener_security(
    config: &EffectiveConfig,
    public_listener: bool,
    secure_profile: bool,
    tls_configured: bool,
    auth_configured: bool,
    rbac_configured: bool,
    encryption_keyring_configured: bool,
) -> anyhow::Result<()> {
    if config
        .cluster
        .as_ref()
        .is_some_and(|cluster| !cluster.listen_raft.ip().is_loopback())
    {
        bail!("Raft may only bind to loopback until mTLS node identity is implemented");
    }
    if !public_listener || !secure_profile {
        return Ok(());
    }
    if !tls_configured {
        bail!("non-loopback listeners require --tls-cert and --tls-key");
    }
    if !auth_configured {
        bail!("non-loopback listeners require API credentials");
    }
    if !rbac_configured {
        bail!("non-loopback listeners require --rbac-config-file");
    }
    if !encryption_keyring_configured {
        bail!("non-loopback listeners require --encryption-keyring-file");
    }
    if config.cors_origins.iter().any(|origin| origin == "*") {
        bail!("secure mode does not allow wildcard CORS origins");
    }
    let configured_urls = [
        config.wal_object_store_url.clone().or_else(|| {
            compatible_env(
                "CHIRONDB_WAL_OBJECT_STORE_URL",
                "GAUSSDB_WAL_OBJECT_STORE_URL",
            )
        }),
        config.cold_object_store_url.clone().or_else(|| {
            compatible_env(
                "CHIRONDB_COLD_OBJECT_STORE_URL",
                "GAUSSDB_COLD_OBJECT_STORE_URL",
            )
        }),
    ];
    if configured_urls
        .iter()
        .flatten()
        .any(|url| url.trim_start().starts_with("http://"))
    {
        bail!("secure mode requires HTTPS object-store URLs");
    }
    Ok(())
}

/// M4-003: latency-tuned Tokio runtime. SPEC Section VIII.A — one worker
/// thread per *physical* core (not logical) to keep SIMD distance kernels
/// fed without HT contention. Override with `GAUSSDB_WORKER_THREADS=<n>`.
fn select_worker_threads(env_override: Option<&str>, physical_cores: usize) -> usize {
    if let Some(raw) = env_override
        && let Ok(n) = raw.parse::<usize>()
        && n >= 1
    {
        return n;
    }
    physical_cores.max(1)
}

fn main() -> anyhow::Result<()> {
    let env_raw = compatible_env("CHIRONDB_WORKER_THREADS", "GAUSSDB_WORKER_THREADS");
    let workers = select_worker_threads(env_raw.as_deref(), num_cpus::get_physical());

    // PD-3: cap the rayon global pool to half the Tokio worker count so rayon's
    // compute threads don't compete with Tokio's I/O threads at high concurrency.
    let rayon_threads = (workers / 2).max(2);
    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .build_global()
        .ok();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("chirondb-worker")
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("failed to build tokio runtime: {error}"))?;

    runtime.block_on(async_main())
}

#[cfg(test)]
mod worker_thread_selection {
    use super::select_worker_threads;

    #[test]
    fn defaults_to_physical_cores() {
        assert_eq!(select_worker_threads(None, 8), 8);
    }

    #[test]
    fn floors_at_one_when_physical_is_zero() {
        assert_eq!(select_worker_threads(None, 0), 1);
    }

    #[test]
    fn env_override_wins_when_valid() {
        assert_eq!(select_worker_threads(Some("12"), 4), 12);
        assert_eq!(select_worker_threads(Some("1"), 32), 1);
    }

    #[test]
    fn env_override_rejected_when_zero_or_garbage() {
        assert_eq!(select_worker_threads(Some("0"), 4), 4);
        assert_eq!(select_worker_threads(Some("nope"), 4), 4);
        assert_eq!(select_worker_threads(Some(""), 4), 4);
    }
}

async fn async_main() -> anyhow::Result<()> {
    // Args are parsed before tracing is initialised: `--console` decides
    // whether log lines go to stdout (default, unchanged) or stderr, and the
    // subscriber can only be installed once.
    let args = Args::parse();
    let console_requested = args.console;
    let console_role: Role = args.console_role.into();
    let console_collection = args.collection.clone();
    let tenant_enforcement: TenantEnforcement = args.tenant_enforcement.into();
    let log_target = if console_requested {
        observability::LogTarget::Stderr
    } else {
        observability::LogTarget::Stdout
    };
    let tracing_guard = observability::init_tracing_to(log_target)
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing: {error}"))?;
    let config = effective_config(args)?;
    let _ = observability::init_metrics();
    let rbac_config_path = config.rbac_config_file.clone().or_else(|| {
        compatible_env_os("CHIRONDB_RBAC_CONFIG_FILE", "GAUSSDB_RBAC_CONFIG_FILE")
            .map(PathBuf::from)
    });
    let rbac_config = rbac_config_path
        .as_deref()
        .map(RbacConfig::load_from_file)
        .transpose()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rbac_configured = rbac_config.is_some();
    let auth = AuthConfig::from_key_sources(
        config
            .api_key
            .clone()
            .or_else(|| compatible_env("CHIRONDB_API_KEY", "GAUSSDB_API_KEY")),
        config.api_key_file.clone().or_else(|| {
            compatible_env_os("CHIRONDB_API_KEY_FILE", "GAUSSDB_API_KEY_FILE").map(PathBuf::from)
        }),
    )
    .with_rate_limit(rate_limit_per_second(config.rate_limit_per_second)?);
    let require_stable_principal_ids = !config.listen_http.ip().is_loopback()
        || !config.listen_grpc.ip().is_loopback()
        || !config.listen_wire.ip().is_loopback();
    let auth = if let Some(rbac) = rbac_config {
        auth.with_validated_rbac(rbac, require_stable_principal_ids)
            .map_err(|error| anyhow::anyhow!(error))?
    } else {
        auth
    };
    let max_points_per_collection = max_points_per_collection(config.max_points_per_collection)?;
    let tls = tls_paths(&config)?;
    let tls_client_ca = tls_client_ca_path(&config)?;
    let public_listener = !config.listen_http.ip().is_loopback()
        || !config.listen_grpc.ip().is_loopback()
        || !config.listen_wire.ip().is_loopback();
    let secure_profile = public_listener && !config.allow_insecure_non_loopback;
    if let Some(keyring_file) = config.encryption_keyring_file.as_deref() {
        validate_external_keyring_path(&config.data_dir, keyring_file)?;
    }
    let encryption_keyring = config
        .encryption_keyring_file
        .as_deref()
        .map(Keyring::load)
        .transpose()
        .context("failed to load encryption keyring")?;
    validate_listener_security(
        &config,
        public_listener,
        secure_profile,
        tls.is_some(),
        auth.is_enabled(),
        rbac_configured,
        encryption_keyring.is_some(),
    )?;
    if public_listener && config.allow_insecure_non_loopback {
        tracing::error!(
            "INSECURE NON-LOOPBACK MODE ENABLED: traffic or persisted data may be unprotected"
        );
        metrics::gauge!("chirondb_insecure_non_loopback_enabled").set(1.0);
    }
    if tls.is_some() {
        tls::install_default_crypto_provider();
    }
    let reloadable_tls = match tls.clone() {
        Some((cert, key)) => Some(
            tls::ReloadingTlsConfig::load(cert, key, tls_client_ca.clone())
                .await
                .context("failed to load shared TLS certificate resolver")?,
        ),
        None => None,
    };
    if secure_profile && !chirondb::storage_layout::is_generation_layout(&config.data_dir) {
        chirondb::storage_layout::initialize_empty(&config.data_dir)
            .context("secure mode requires generation-based storage")?;
    }
    if secure_profile {
        chirondb::encryption::verify_tree(
            encryption_keyring
                .as_ref()
                .expect("secure profile validation requires a keyring"),
            &config.data_dir,
        )
        .context("secure startup refused plaintext or invalid encrypted persistence")?;
    }
    if let Some(keyring) = encryption_keyring {
        install_process_keyring(keyring, secure_profile)
            .context("failed to install encryption keyring")?;
    }
    let cold_object_store = cold_object_store_config(
        config.cold_object_store_dir.as_deref(),
        config.cold_object_store_url.as_deref(),
        &config.data_dir,
    )?;
    let db = Db::open_with_cold_object_store_config(&config.data_dir, cold_object_store.clone())
        .with_context(|| format!("failed to open data dir {}", config.data_dir.display()))?;
    let tls_reloader = reloadable_tls
        .as_ref()
        .map(|tls| tls.spawn_reloader(db.clone()));
    if secure_profile {
        chirondb::audit::verify_hash_chain(&config.data_dir)
            .context("secure startup refused an invalid audit chain")?;
    }
    db.set_max_points_per_collection(max_points_per_collection);
    db.set_default_with_payload(config.default_with_payload);
    db.set_intra_query_parallel(config.intra_query_parallel);
    db.set_tenant_enforcement(tenant_enforcement);
    if tenant_enforcement != TenantEnforcement::Disabled {
        // Worth a line in the log: it changes what every request can see.
        tracing::warn!(
            mode = ?tenant_enforcement,
            "row-level tenant isolation is active; requests use authenticated tenant \
             scopes and unscoped engine operations refuse under `enforced`"
        );
    }
    let wal_archive_retain_last = wal_archive_retain_last(config.wal_archive_retain_last)?;
    db.set_wal_archive_retain_last(wal_archive_retain_last);
    let wal_archive_max_bytes = wal_archive_max_bytes(config.wal_archive_max_bytes)?;
    db.set_wal_archive_max_bytes(wal_archive_max_bytes);
    let wal_archive_max_age = wal_archive_max_age(config.wal_archive_max_age_secs)?;
    db.set_wal_archive_max_age(wal_archive_max_age);
    let wal_external_archive_dir =
        wal_external_archive_dir(config.wal_external_archive_dir.as_deref(), &config.data_dir)?;
    db.set_wal_external_archive_dir(wal_external_archive_dir.clone());
    let wal_object_store = wal_object_store_config(
        config.wal_object_store_dir.as_deref(),
        config.wal_object_store_url.as_deref(),
        &config.data_dir,
    )?;
    let storage_policy = StoragePolicy::new(
        config.snapshot_root.clone(),
        match wal_object_store.as_ref() {
            Some(ColdObjectStoreConfig::Url(url)) => Some(url.as_str()),
            _ => None,
        },
        secure_profile,
    )
    .context("invalid snapshot/object-store security policy")?;
    if let Some(config) = wal_object_store.clone() {
        match config {
            ColdObjectStoreConfig::LocalDir(path) => db.set_wal_object_store_dir(Some(path)),
            ColdObjectStoreConfig::Url(url) => db.set_wal_object_store_url(Some(url)),
        }
    }
    let wal_archive_command = wal_archive_command(config.wal_archive_command.as_deref())?;
    db.set_wal_archive_command(wal_archive_command.clone());
    let auto_compact_wal_bytes = auto_compact_wal_bytes(config.auto_compact_wal_bytes)?;
    let auto_compact_interval = Duration::from_secs(config.auto_compact_interval_secs.max(1));
    let auto_compaction = auto_compact_wal_bytes.map(|threshold_bytes| {
        spawn_auto_compaction(db.clone(), threshold_bytes, auto_compact_interval)
    });
    let drift_monitor = (config.drift_monitor_interval_secs > 0).then(|| {
        spawn_drift_monitor(
            db.clone(),
            Duration::from_secs(config.drift_monitor_interval_secs),
        )
    });
    let cluster_handle = config.cluster.as_ref().map(|cluster_config| {
        tracing::info!(
            node_id = cluster_config.node_id,
            role = ?cluster_config.node_role,
            listen_raft = %cluster_config.listen_raft,
            peers = cluster_config.peers.len(),
            "cluster mode active"
        );
        ClusterHandle::new(cluster_config.clone())
    });
    let _ = cluster_handle; // available for future use by API/gRPC layers
    let flamegraph_capture = observability::spawn_flamegraph_capture_from_env()
        .context("failed to initialize flamegraph capture")?;
    tracing::info!(
        listen_http = %config.listen_http,
        listen_grpc = %config.listen_grpc,
        listen_wire = %config.listen_wire,
        data_dir = %config.data_dir.display(),
        auth_enabled = auth.is_enabled(),
        rate_limit_enabled = auth.rate_limit_enabled(),
        max_points_per_collection = max_points_per_collection
            .map(|max_points| max_points.to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        tls_enabled = tls.is_some(),
        mtls_enabled = tls_client_ca.is_some(),
        grpc_web_enabled = config.enable_grpc_web,
        auto_compact_wal_bytes = auto_compact_wal_bytes.unwrap_or_default(),
        auto_compact_interval_secs = config.auto_compact_interval_secs.max(1),
        wal_archive_retain_last = wal_archive_retain_last
            .map(|retain_last| retain_last.to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        wal_archive_max_bytes = wal_archive_max_bytes
            .map(|max_bytes| max_bytes.to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        wal_archive_max_age_secs = wal_archive_max_age
            .map(|max_age| max_age.as_secs().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        wal_external_archive_dir = wal_external_archive_dir
            .as_ref()
            .map(|archive_dir| archive_dir.display().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
        wal_object_store = wal_object_store
            .as_ref()
            .map(cold_object_store_display)
            .unwrap_or_else(|| "disabled".to_string()),
        wal_archive_command = wal_archive_command
            .as_ref()
            .map(|_| "configured")
            .unwrap_or("disabled"),
        cold_object_store = cold_object_store
            .as_ref()
            .map(cold_object_store_display)
            .unwrap_or_else(|| "disabled".to_string()),
        otel_enabled = tracing_guard.otel_enabled(),
        flamegraph_capture_enabled = flamegraph_capture.is_some(),
        "starting ChironDB"
    );
    let events = EventHub::default();
    let http_options = ServerOptions {
        mcp: config
            .mcp
            .clone()
            .map(|mcp| chirondb::mcp::McpServer::new(db.clone(), auth.clone(), mcp))
            .transpose()?,
        cors_origins: config.cors_origins.clone(),
        ws_metrics_interval: Duration::from_millis(config.ws_metrics_interval_ms.max(100)),
        events: events.clone(),
        storage_policy: storage_policy.clone(),
    };
    // Embedded ChironQL console. Off unless asked for, and off unless stdin is
    // a terminal — a daemon must never sit on a prompt or execute piped stdin.
    //
    // It runs on its own OS thread rather than `spawn_blocking`: the loop
    // blocks for the process's lifetime, and a tokio blocking-pool slot is
    // meant for transient work. The server keeps serving HTTP/gRPC/wire the
    // whole time the console waits at a prompt, and `\q` stops the server.
    if console_requested {
        if std::io::stdin().is_terminal() {
            let console_db = db.clone();
            let banner = chirondb::branding::banner(&format!(
                "ChironDB {} · ChironQL {} · console attached ({}) · logs → stderr\n\
                 \\h for help · \\q or Ctrl-D to stop the server",
                env!("CARGO_PKG_VERSION"),
                chirondb::chironql_parser::LANGUAGE_VERSION,
                console_role_name(console_role),
            ));
            tracing::info!(
                role = console_role_name(console_role),
                "chironql console attached to stdin"
            );
            std::thread::Builder::new()
                .name("chironql-console".to_string())
                .spawn(move || {
                    let mut sink = LocalSink::new(console_db, console_role)
                        .with_collection(console_collection);
                    let options = ReplOptions {
                        interactive: true,
                        banner: Some(banner),
                        ..Default::default()
                    };
                    // Separate history file from the `chironql` client, so a
                    // local operator session and a remote client session do not
                    // interleave each other's recall.
                    let history = std::env::var_os("HOME")
                        .map(|home| PathBuf::from(home).join(".chironql_console_history"));
                    let outcome = chironql_repl::run_interactive(&mut sink, options, history);
                    if let Err(error) = outcome {
                        tracing::warn!(%error, "chironql console ended");
                    }

                    // Leaving the console ends the process.
                    //
                    // `--console` means this terminal *is* the server: the
                    // process is in the foreground and the prompt is the only
                    // thing on it. Detaching the console but leaving the
                    // process running gave a terminal with no prompt, no
                    // output and no obvious way out — `\q` looked like a hang.
                    //
                    // This runs after `run_interactive` has returned, so
                    // rustyline's editor has already been dropped and the
                    // terminal is back in its normal mode. Exiting before that
                    // would skip the destructor and leave the user's shell in
                    // raw mode.
                    tracing::info!("chironql console closed; shutting down");
                    std::process::exit(0);
                })
                .context("failed to start the chironql console thread")?;
        } else {
            tracing::warn!(
                "--console needs a terminal on stdin; console not started, server                  continuing normally"
            );
        }
    }

    let http_db = db.clone();
    let grpc_db = db.clone();
    let wire_db = db;
    let http_auth = auth.clone();
    let grpc_auth = auth.clone();
    let wire_auth = auth;
    let http_tls = reloadable_tls.clone();
    let grpc_tls = reloadable_tls.clone();
    let wire_tls = reloadable_tls;
    let grpc_options = grpc::GrpcServerOptions {
        grpc_web_enabled: config.enable_grpc_web,
        cors_origins: config.cors_origins.clone(),
        storage_policy: storage_policy.clone(),
    };
    tokio::try_join!(
        async {
            match http_tls {
                Some(tls) => api::serve_tls_config_with_options(
                    http_db,
                    http_auth,
                    config.listen_http,
                    tls,
                    http_options,
                )
                .await
                .context("https server failed"),
                None => {
                    api::serve_with_options(http_db, http_auth, config.listen_http, http_options)
                        .await
                        .context("http server failed")
                }
            }
        },
        async {
            match grpc_tls {
                Some(tls) => grpc::serve_tls_config_with_options(
                    grpc_db,
                    grpc_auth,
                    config.listen_grpc,
                    tls,
                    grpc_options,
                )
                .await
                .map_err(|error| anyhow::anyhow!(error))
                .context("grpc tls server failed"),
                None => {
                    grpc::serve_with_options(grpc_db, grpc_auth, config.listen_grpc, grpc_options)
                        .await
                        .map_err(|error| anyhow::anyhow!(error))
                        .context("grpc server failed")
                }
            }
        },
        async {
            match wire_tls {
                Some(tls) => wire::serve_tls_config_with_auth_and_policy(
                    wire_db,
                    wire_auth,
                    config.listen_wire,
                    tls,
                    storage_policy,
                )
                .await
                .context("GaussWire TLS server failed"),
                None => wire::serve_with_auth_and_policy(
                    wire_db,
                    wire_auth,
                    config.listen_wire,
                    storage_policy,
                )
                .await
                .context("GaussWire server failed"),
            }
        }
    )?;
    if let Some(auto_compaction) = auto_compaction {
        auto_compaction.abort();
    }
    if let Some(drift_monitor) = drift_monitor {
        drift_monitor.abort();
    }
    if let Some(tls_reloader) = tls_reloader {
        tls_reloader.abort();
    }
    Ok(())
}

fn spawn_auto_compaction(
    db: Db,
    threshold_bytes: u64,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            // PA-5: defer compaction while search is in flight. Compaction
            // grabs per-collection write locks; running it alongside live
            // search creates p99 spikes (the search future blocks waiting
            // for the lock). Defer up to a small number of ticks; force a
            // run after that to keep WAL growth bounded.
            let inflight = db.search_inflight();
            if inflight > 0 {
                tracing::debug!(
                    inflight,
                    threshold_bytes,
                    "auto-compaction deferred: search in flight"
                );
                metrics::counter!("gaussdb_auto_compaction_deferred_total").increment(1);
                continue;
            }
            let db = db.clone();
            match tokio::task::spawn_blocking(move || {
                db.compact_collections_for_maintenance(threshold_bytes)
            })
            .await
            {
                Ok(Ok(compacted)) if compacted.is_empty() => {}
                Ok(Ok(compacted)) => {
                    tracing::info!(
                        collections = compacted.len(),
                        threshold_bytes,
                        "scheduled maintenance compaction completed"
                    );
                }
                Ok(Err(error)) => {
                    tracing::error!(%error, threshold_bytes, "auto-compaction failed");
                }
                Err(error) => {
                    tracing::error!(%error, threshold_bytes, "auto-compaction task panicked");
                }
            }
        }
    })
}

/// P3 — periodically run `Db::check_recall_drift_all` so collections with a
/// contracted `recall_sla` get a durable `recall_sla_breach` audit record when
/// the engine's active `ef_search` no longer reaches the SLA on the freshly
/// observed curve. Disabled when `drift_monitor_interval_secs = 0` or when no
/// collection sets `recall_sla`.
fn spawn_drift_monitor(db: Db, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        loop {
            interval.tick().await;
            let db = db.clone();
            match tokio::task::spawn_blocking(move || db.check_recall_drift_all()).await {
                Ok(breaches) if breaches.is_empty() => {}
                Ok(breaches) => {
                    for (collection, report) in &breaches {
                        tracing::warn!(
                            %collection,
                            sla = report.sla,
                            active_ef = report.active_ef,
                            observed_recall = report.observed_recall_at_active_ef,
                            ef_search_needed = ?report.ef_search_needed,
                            "recall SLA breach detected"
                        );
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "drift monitor task panicked");
                }
            }
        }
    })
}

fn effective_config(args: Args) -> anyhow::Result<EffectiveConfig> {
    let file = match args.config.as_deref() {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read config {}", path.display()))?;
            toml::from_str::<FileConfig>(&raw)
                .with_context(|| format!("failed to parse config {}", path.display()))?
        }
        None => FileConfig::default(),
    };
    Ok(EffectiveConfig {
        mcp: file.mcp,
        listen_http: args
            .listen_http
            .or(file.listen_http)
            .unwrap_or_else(|| "127.0.0.1:7401".parse().expect("default http addr")),
        listen_grpc: args
            .listen_grpc
            .or(file.listen_grpc)
            .unwrap_or_else(|| "127.0.0.1:7402".parse().expect("default grpc addr")),
        listen_wire: args
            .listen_wire
            .or(file.listen_wire)
            .unwrap_or_else(|| "127.0.0.1:7403".parse().expect("default wire addr")),
        data_dir: args
            .data_dir
            .or(file.data_dir)
            .or_else(|| {
                compatible_env_os("CHIRONDB_DATA_DIR", "GAUSSDB_DATA_DIR").map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from("./data")),
        api_key: args.api_key.or(file.api_key),
        api_key_file: args.api_key_file.or(file.api_key_file),
        rbac_config_file: args.rbac_config_file.or(file.rbac_config_file),
        encryption_keyring_file: args
            .encryption_keyring_file
            .or(file.encryption_keyring_file)
            .or_else(|| {
                compatible_env_os(
                    "CHIRONDB_ENCRYPTION_KEYRING_FILE",
                    "GAUSSDB_ENCRYPTION_KEYRING_FILE",
                )
                .map(PathBuf::from)
            }),
        snapshot_root: args.snapshot_root.or(file.snapshot_root).or_else(|| {
            compatible_env_os("CHIRONDB_SNAPSHOT_ROOT", "GAUSSDB_SNAPSHOT_ROOT").map(PathBuf::from)
        }),
        allow_insecure_non_loopback: args.allow_insecure_non_loopback
            || file.allow_insecure_non_loopback
            || compatible_bool_env(
                "CHIRONDB_ALLOW_INSECURE_NON_LOOPBACK",
                "GAUSSDB_ALLOW_INSECURE_NON_LOOPBACK",
            )?
            .unwrap_or(false),
        tls_cert: args.tls_cert.or(file.tls_cert),
        tls_key: args.tls_key.or(file.tls_key),
        tls_client_ca: args.tls_client_ca.or(file.tls_client_ca),
        rate_limit_per_second: args.rate_limit_per_second.or(file.rate_limit_per_second),
        max_points_per_collection: args
            .max_points_per_collection
            .or(file.max_points_per_collection),
        auto_compact_wal_bytes: args.auto_compact_wal_bytes.or(file.auto_compact_wal_bytes),
        auto_compact_interval_secs: args
            .auto_compact_interval_secs
            .or(file.auto_compact_interval_secs)
            .unwrap_or(5),
        drift_monitor_interval_secs: args
            .drift_monitor_interval_secs
            .or(file.drift_monitor_interval_secs)
            .unwrap_or(1800),
        default_with_payload: args
            .default_with_payload
            .or(file.default_with_payload)
            .unwrap_or(true),
        intra_query_parallel: args
            .intra_query_parallel
            .or(file.intra_query_parallel)
            .unwrap_or(false),
        wal_archive_retain_last: args
            .wal_archive_retain_last
            .or(file.wal_archive_retain_last),
        wal_archive_max_bytes: args.wal_archive_max_bytes.or(file.wal_archive_max_bytes),
        wal_archive_max_age_secs: args
            .wal_archive_max_age_secs
            .or(file.wal_archive_max_age_secs),
        wal_external_archive_dir: args
            .wal_external_archive_dir
            .or(file.wal_external_archive_dir),
        wal_object_store_dir: args.wal_object_store_dir.or(file.wal_object_store_dir),
        wal_object_store_url: args.wal_object_store_url.or(file.wal_object_store_url),
        wal_archive_command: args.wal_archive_command.or(file.wal_archive_command),
        cold_object_store_dir: args.cold_object_store_dir.or(file.cold_object_store_dir),
        cold_object_store_url: args.cold_object_store_url.or(file.cold_object_store_url),
        cluster: parse_cluster_config(
            args.cluster_node_id.or(file.cluster_node_id),
            args.cluster_peers.or(file.cluster_peers).as_deref(),
            args.cluster_listen_raft.or(file.cluster_listen_raft),
            args.cluster_node_role.or(file.cluster_node_role).as_deref(),
        )?,
        cors_origins: if !args.cors_origin.is_empty() {
            args.cors_origin
        } else {
            file.cors_origin
        },
        enable_grpc_web: args.enable_grpc_web || file.enable_grpc_web,
        ws_metrics_interval_ms: args
            .ws_metrics_interval
            .or(file.ws_metrics_interval)
            .unwrap_or(5000),
    })
}

fn tls_paths(config: &EffectiveConfig) -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    let cert = config
        .tls_cert
        .clone()
        .or_else(|| compatible_env_os("CHIRONDB_TLS_CERT", "GAUSSDB_TLS_CERT").map(PathBuf::from));
    let key = config
        .tls_key
        .clone()
        .or_else(|| compatible_env_os("CHIRONDB_TLS_KEY", "GAUSSDB_TLS_KEY").map(PathBuf::from));
    match (cert, key) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (None, None) => Ok(None),
        _ => bail!("--tls-cert and --tls-key must be provided together"),
    }
}

fn tls_client_ca_path(config: &EffectiveConfig) -> anyhow::Result<Option<PathBuf>> {
    let client_ca = config.tls_client_ca.clone().or_else(|| {
        compatible_env_os("CHIRONDB_TLS_CLIENT_CA", "GAUSSDB_TLS_CLIENT_CA").map(PathBuf::from)
    });
    let cert_configured = config.tls_cert.is_some()
        || compatible_env_os("CHIRONDB_TLS_CERT", "GAUSSDB_TLS_CERT").is_some();
    let key_configured = config.tls_key.is_some()
        || compatible_env_os("CHIRONDB_TLS_KEY", "GAUSSDB_TLS_KEY").is_some();
    if client_ca.is_some() && (!cert_configured || !key_configured) {
        bail!("--tls-client-ca requires --tls-cert and --tls-key");
    }
    Ok(client_ca)
}

fn rate_limit_per_second(flag: Option<u32>) -> anyhow::Result<Option<u32>> {
    if flag.is_some() {
        return Ok(flag);
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_RATE_LIMIT_PER_SECOND",
        "GAUSSDB_RATE_LIMIT_PER_SECOND",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    raw.parse::<u32>()
        .map(Some)
        .with_context(|| format!("invalid CHIRONDB_RATE_LIMIT_PER_SECOND value: {raw}"))
}

fn max_points_per_collection(flag: Option<usize>) -> anyhow::Result<Option<usize>> {
    if let Some(value) = flag {
        if value == 0 {
            bail!("--max-points-per-collection must be greater than zero");
        }
        return Ok(Some(value));
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_MAX_POINTS_PER_COLLECTION",
        "GAUSSDB_MAX_POINTS_PER_COLLECTION",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let value = raw
        .parse::<usize>()
        .with_context(|| format!("invalid CHIRONDB_MAX_POINTS_PER_COLLECTION value: {raw}"))?;
    if value == 0 {
        bail!("CHIRONDB_MAX_POINTS_PER_COLLECTION must be greater than zero");
    }
    Ok(Some(value))
}

fn auto_compact_wal_bytes(flag: Option<u64>) -> anyhow::Result<Option<u64>> {
    if let Some(value) = flag {
        if value == 0 {
            bail!("--auto-compact-wal-bytes must be greater than zero");
        }
        return Ok(Some(value));
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_AUTO_COMPACT_WAL_BYTES",
        "GAUSSDB_AUTO_COMPACT_WAL_BYTES",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("invalid CHIRONDB_AUTO_COMPACT_WAL_BYTES value: {raw}"))?;
    if value == 0 {
        bail!("CHIRONDB_AUTO_COMPACT_WAL_BYTES must be greater than zero");
    }
    Ok(Some(value))
}

fn wal_archive_retain_last(flag: Option<usize>) -> anyhow::Result<Option<usize>> {
    if flag.is_some() {
        return Ok(flag);
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_WAL_ARCHIVE_RETAIN_LAST",
        "GAUSSDB_WAL_ARCHIVE_RETAIN_LAST",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    raw.parse::<usize>()
        .map(Some)
        .with_context(|| format!("invalid CHIRONDB_WAL_ARCHIVE_RETAIN_LAST value: {raw}"))
}

fn wal_archive_max_bytes(flag: Option<u64>) -> anyhow::Result<Option<u64>> {
    if let Some(value) = flag {
        if value == 0 {
            bail!("--wal-archive-max-bytes must be greater than zero");
        }
        return Ok(Some(value));
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_WAL_ARCHIVE_MAX_BYTES",
        "GAUSSDB_WAL_ARCHIVE_MAX_BYTES",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("invalid CHIRONDB_WAL_ARCHIVE_MAX_BYTES value: {raw}"))?;
    if value == 0 {
        bail!("CHIRONDB_WAL_ARCHIVE_MAX_BYTES must be greater than zero");
    }
    Ok(Some(value))
}

fn wal_archive_max_age(flag: Option<u64>) -> anyhow::Result<Option<Duration>> {
    if let Some(value) = flag {
        if value == 0 {
            bail!("--wal-archive-max-age-secs must be greater than zero");
        }
        return Ok(Some(Duration::from_secs(value)));
    }
    let Some(raw) = compatible_env_os(
        "CHIRONDB_WAL_ARCHIVE_MAX_AGE_SECS",
        "GAUSSDB_WAL_ARCHIVE_MAX_AGE_SECS",
    ) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("invalid CHIRONDB_WAL_ARCHIVE_MAX_AGE_SECS value: {raw}"))?;
    if value == 0 {
        bail!("CHIRONDB_WAL_ARCHIVE_MAX_AGE_SECS must be greater than zero");
    }
    Ok(Some(Duration::from_secs(value)))
}

fn wal_external_archive_dir(
    flag: Option<&Path>,
    data_dir: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    let archive_dir = match flag {
        Some(path) => Some(path.to_path_buf()),
        None => compatible_env_os(
            "CHIRONDB_WAL_EXTERNAL_ARCHIVE_DIR",
            "GAUSSDB_WAL_EXTERNAL_ARCHIVE_DIR",
        )
        .map(PathBuf::from),
    };
    let Some(archive_dir) = archive_dir else {
        return Ok(None);
    };
    if archive_dir.as_os_str().is_empty() {
        bail!("WAL external archive dir must not be empty");
    }
    let archive_dir_abs = absolute_path(&archive_dir)?;
    let data_dir_abs = absolute_path(data_dir)?;
    if archive_dir_abs.starts_with(&data_dir_abs) {
        bail!(
            "WAL external archive dir must not be inside data dir: {}",
            archive_dir.display()
        );
    }
    Ok(Some(archive_dir))
}

fn wal_archive_command(flag: Option<&str>) -> anyhow::Result<Option<String>> {
    let command = match flag {
        Some(command) => Some(command.to_string()),
        None => compatible_env(
            "CHIRONDB_WAL_ARCHIVE_COMMAND",
            "GAUSSDB_WAL_ARCHIVE_COMMAND",
        ),
    };
    let Some(command) = command else {
        return Ok(None);
    };
    if command.trim().is_empty() {
        bail!("WAL archive command must not be empty");
    }
    Ok(Some(command))
}

fn wal_object_store_config(
    dir_flag: Option<&Path>,
    url_flag: Option<&str>,
    data_dir: &Path,
) -> anyhow::Result<Option<ColdObjectStoreConfig>> {
    let store_dir = wal_object_store_dir(dir_flag, data_dir)?;
    let store_url = match url_flag {
        Some(url) => Some(url.to_string()),
        None => compatible_env(
            "CHIRONDB_WAL_OBJECT_STORE_URL",
            "GAUSSDB_WAL_OBJECT_STORE_URL",
        ),
    };
    if store_dir.is_some() && store_url.is_some() {
        bail!("configure only one of WAL object store dir or URL");
    }
    if let Some(url) = store_url {
        if url.trim().is_empty() {
            bail!("WAL object store URL must not be empty");
        }
        return Ok(Some(ColdObjectStoreConfig::Url(url)));
    }
    Ok(store_dir.map(ColdObjectStoreConfig::LocalDir))
}

fn wal_object_store_dir(flag: Option<&Path>, data_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let store_dir = match flag {
        Some(path) => Some(path.to_path_buf()),
        None => compatible_env_os(
            "CHIRONDB_WAL_OBJECT_STORE_DIR",
            "GAUSSDB_WAL_OBJECT_STORE_DIR",
        )
        .map(PathBuf::from),
    };
    let Some(store_dir) = store_dir else {
        return Ok(None);
    };
    if store_dir.as_os_str().is_empty() {
        bail!("WAL object store dir must not be empty");
    }
    let store_dir_abs = absolute_path(&store_dir)?;
    let data_dir_abs = absolute_path(data_dir)?;
    if store_dir_abs.starts_with(&data_dir_abs) {
        bail!(
            "WAL object store dir must not be inside data dir: {}",
            store_dir.display()
        );
    }
    Ok(Some(store_dir))
}

fn cold_object_store_config(
    dir_flag: Option<&Path>,
    url_flag: Option<&str>,
    data_dir: &Path,
) -> anyhow::Result<Option<ColdObjectStoreConfig>> {
    let store_dir = cold_object_store_dir(dir_flag, data_dir)?;
    let store_url = match url_flag {
        Some(url) => Some(url.to_string()),
        None => compatible_env(
            "CHIRONDB_COLD_OBJECT_STORE_URL",
            "GAUSSDB_COLD_OBJECT_STORE_URL",
        ),
    };
    if store_dir.is_some() && store_url.is_some() {
        bail!("configure only one of cold object store dir or URL");
    }
    if let Some(url) = store_url {
        if url.trim().is_empty() {
            bail!("cold object store URL must not be empty");
        }
        return Ok(Some(ColdObjectStoreConfig::Url(url)));
    }
    Ok(store_dir.map(ColdObjectStoreConfig::LocalDir))
}

fn cold_object_store_dir(flag: Option<&Path>, data_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let store_dir = match flag {
        Some(path) => Some(path.to_path_buf()),
        None => compatible_env_os(
            "CHIRONDB_COLD_OBJECT_STORE_DIR",
            "GAUSSDB_COLD_OBJECT_STORE_DIR",
        )
        .map(PathBuf::from),
    };
    let Some(store_dir) = store_dir else {
        return Ok(None);
    };
    if store_dir.as_os_str().is_empty() {
        bail!("cold object store dir must not be empty");
    }
    let store_dir_abs = absolute_path(&store_dir)?;
    let data_dir_abs = absolute_path(data_dir)?;
    if store_dir_abs.starts_with(&data_dir_abs) {
        bail!(
            "cold object store dir must not be inside data dir: {}",
            store_dir.display()
        );
    }
    Ok(Some(store_dir))
}

fn cold_object_store_display(config: &ColdObjectStoreConfig) -> String {
    match config {
        ColdObjectStoreConfig::LocalDir(path) => path.display().to_string(),
        ColdObjectStoreConfig::Url(url) => url.clone(),
    }
}

fn parse_cluster_config(
    node_id: Option<u64>,
    peers_str: Option<&str>,
    listen_raft: Option<std::net::SocketAddr>,
    role_str: Option<&str>,
) -> anyhow::Result<Option<ClusterConfig>> {
    // Cluster mode requires at least a node_id
    let Some(node_id) = node_id else {
        return Ok(None);
    };
    let listen_raft =
        listen_raft.unwrap_or_else(|| "127.0.0.1:7410".parse().expect("default raft addr"));
    let node_role = match role_str.unwrap_or("all") {
        "all" => NodeRole::All,
        "ingress" => NodeRole::Ingress,
        "coordinator" => NodeRole::Coordinator,
        "engine" => NodeRole::Engine,
        other => anyhow::bail!("unknown cluster node role: {other}"),
    };
    let peers = parse_cluster_peers(peers_str)?;
    Ok(Some(ClusterConfig {
        node_id,
        node_role,
        listen_raft,
        peers,
    }))
}

/// Parse "1=host:7410,2=host:7411" into Vec<ClusterNode>.
fn parse_cluster_peers(peers_str: Option<&str>) -> anyhow::Result<Vec<ClusterNode>> {
    let Some(raw) = peers_str else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|entry| {
            let entry = entry.trim();
            let (id_str, addr) = entry.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("invalid peer entry (expected id=host:port): {entry}")
            })?;
            let id = id_str
                .trim()
                .parse::<u64>()
                .with_context(|| format!("invalid peer id: {id_str}"))?;
            Ok(ClusterNode {
                id,
                addr: addr.trim().to_string(),
                zone: None,
            })
        })
        .collect()
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Args, effective_config, prefer_primary, validate_external_keyring_path,
        validate_listener_security,
    };
    use clap::Parser;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn encryption_keyring_must_be_outside_data_dir() {
        let temp = TempDir::new().unwrap();
        let data = temp.path().join("data");
        let external = temp.path().join("keyring.json");
        std::fs::write(&external, "{}").unwrap();
        validate_external_keyring_path(&data, &external).unwrap();

        let nested = data.join("secrets/keyring.json");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, "{}").unwrap();
        let error = validate_external_keyring_path(&data, &nested).unwrap_err();
        assert!(error.to_string().contains("outside the data directory"));
    }

    #[test]
    fn public_listener_security_requirements_fail_closed() {
        let config = effective_config(Args::try_parse_from(["chirondb"]).unwrap()).unwrap();
        let cases = [
            ((false, false, false, false), "--tls-cert"),
            ((true, false, false, false), "API credentials"),
            ((true, true, false, false), "--rbac-config-file"),
            ((true, true, true, false), "--encryption-keyring-file"),
        ];
        for ((tls, auth, rbac, keyring), expected) in cases {
            let error = validate_listener_security(&config, true, true, tls, auth, rbac, keyring)
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
        validate_listener_security(&config, true, true, true, true, true, true).unwrap();
        validate_listener_security(&config, true, false, false, false, false, false).unwrap();
    }

    #[test]
    fn secure_profile_rejects_wildcard_cors() {
        let mut config = effective_config(Args::try_parse_from(["chirondb"]).unwrap()).unwrap();
        config.cors_origins = vec!["*".to_string()];
        let error =
            validate_listener_security(&config, true, true, true, true, true, true).unwrap_err();
        assert!(error.to_string().contains("wildcard CORS"));
    }

    /// Every doc and log line in the project spells these roles with an
    /// underscore; clap's own rendering is kebab-case. Both parse.
    #[test]
    fn console_role_takes_either_spelling() {
        for (typed, expected) in [
            ("read_only", super::ConsoleRole::ReadOnly),
            ("read-only", super::ConsoleRole::ReadOnly),
            ("read_write", super::ConsoleRole::ReadWrite),
            ("read-write", super::ConsoleRole::ReadWrite),
            ("admin", super::ConsoleRole::Admin),
        ] {
            let args = Args::try_parse_from(["chirondb", "--console-role", typed])
                .unwrap_or_else(|error| panic!("`--console-role {typed}` should parse: {error}"));
            assert_eq!(args.console_role, expected, "{typed}");
        }
    }

    #[test]
    fn chirondb_configuration_precedes_legacy_gaussdb_configuration() {
        assert_eq!(
            prefer_primary(Some("chiron"), Some("gauss")),
            Some("chiron")
        );
        assert_eq!(prefer_primary(None, Some("gauss")), Some("gauss"));
    }

    #[test]
    fn command_line_opts_into_grpc_web_with_explicit_origins() {
        let args = Args::try_parse_from([
            "gaussdb",
            "--enable-grpc-web",
            "--cors-origin",
            "http://127.0.0.1:3000",
        ])
        .unwrap();
        assert!(args.enable_grpc_web);
        assert_eq!(args.cors_origin, ["http://127.0.0.1:3000"]);
    }

    #[test]
    fn config_file_supplies_server_settings() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("gaussdb.toml");
        std::fs::write(
            &config_path,
            r#"
listen_http = "127.0.0.1:17401"
listen_grpc = "127.0.0.1:17402"
listen_wire = "127.0.0.1:17403"
data_dir = "/tmp/gaussdb-config-data"
api_key_file = "/run/secrets/gaussdb_api_keys"
max_points_per_collection = 1000
auto_compact_wal_bytes = 1024
auto_compact_interval_secs = 2
wal_archive_retain_last = 3
cold_object_store_url = "file:///tmp/gaussdb-cold"
enable_grpc_web = true
cors_origin = ["http://127.0.0.1:3000"]
"#,
        )
        .unwrap();

        let config = effective_config(Args {
            console: false,
            console_role: super::ConsoleRole::ReadWrite,
            tenant_enforcement: super::TenantMode::Disabled,
            collection: None,
            config: Some(config_path),
            listen_http: None,
            listen_grpc: None,
            listen_wire: None,
            data_dir: None,
            api_key: None,
            api_key_file: None,
            rbac_config_file: None,
            encryption_keyring_file: None,
            snapshot_root: None,
            allow_insecure_non_loopback: false,
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            rate_limit_per_second: None,
            max_points_per_collection: None,
            auto_compact_wal_bytes: None,
            auto_compact_interval_secs: None,
            drift_monitor_interval_secs: None,
            default_with_payload: None,
            intra_query_parallel: None,
            wal_archive_retain_last: None,
            wal_archive_max_bytes: None,
            wal_archive_max_age_secs: None,
            wal_external_archive_dir: None,
            wal_object_store_dir: None,
            wal_object_store_url: None,
            wal_archive_command: None,
            cold_object_store_dir: None,
            cold_object_store_url: None,
            cluster_node_id: None,
            cluster_peers: None,
            cluster_listen_raft: None,
            cluster_node_role: None,
            cors_origin: Vec::new(),
            enable_grpc_web: false,
            ws_metrics_interval: None,
        })
        .unwrap();

        assert_eq!(config.listen_http.to_string(), "127.0.0.1:17401");
        assert_eq!(config.listen_grpc.to_string(), "127.0.0.1:17402");
        assert_eq!(config.listen_wire.to_string(), "127.0.0.1:17403");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/gaussdb-config-data"));
        assert_eq!(
            config.api_key_file,
            Some(PathBuf::from("/run/secrets/gaussdb_api_keys"))
        );
        assert_eq!(config.auto_compact_wal_bytes, Some(1024));
        assert_eq!(config.max_points_per_collection, Some(1000));
        assert_eq!(config.auto_compact_interval_secs, 2);
        assert_eq!(config.wal_archive_retain_last, Some(3));
        assert!(config.enable_grpc_web);
        assert_eq!(config.cors_origins, ["http://127.0.0.1:3000"]);
        assert_eq!(
            config.cold_object_store_url,
            Some("file:///tmp/gaussdb-cold".to_string())
        );
    }

    #[test]
    fn command_line_overrides_config_file() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("gaussdb.toml");
        std::fs::write(
            &config_path,
            r#"
listen_http = "127.0.0.1:17401"
data_dir = "/tmp/from-config"
auto_compact_interval_secs = 2
"#,
        )
        .unwrap();

        let config = effective_config(Args {
            console: false,
            console_role: super::ConsoleRole::ReadWrite,
            tenant_enforcement: super::TenantMode::Disabled,
            collection: None,
            config: Some(config_path),
            listen_http: Some("127.0.0.1:27401".parse().unwrap()),
            listen_grpc: None,
            listen_wire: None,
            data_dir: Some(PathBuf::from("/tmp/from-cli")),
            api_key: None,
            api_key_file: None,
            rbac_config_file: None,
            encryption_keyring_file: None,
            snapshot_root: None,
            allow_insecure_non_loopback: false,
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            rate_limit_per_second: None,
            max_points_per_collection: Some(77),
            auto_compact_wal_bytes: None,
            auto_compact_interval_secs: Some(9),
            drift_monitor_interval_secs: None,
            default_with_payload: None,
            wal_archive_retain_last: None,
            wal_archive_max_bytes: None,
            wal_archive_max_age_secs: None,
            wal_external_archive_dir: None,
            wal_object_store_dir: None,
            wal_object_store_url: None,
            wal_archive_command: None,
            cold_object_store_dir: None,
            cold_object_store_url: None,
            cluster_node_id: None,
            cluster_peers: None,
            cluster_listen_raft: None,
            cluster_node_role: None,
            cors_origin: Vec::new(),
            enable_grpc_web: false,
            ws_metrics_interval: None,
            intra_query_parallel: None,
        })
        .unwrap();

        assert_eq!(config.listen_http.to_string(), "127.0.0.1:27401");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/from-cli"));
        assert_eq!(config.max_points_per_collection, Some(77));
        assert_eq!(config.auto_compact_interval_secs, 9);
    }
}
