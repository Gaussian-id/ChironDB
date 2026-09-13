use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chirondb::{
    CollectionConfig, Db, DistanceMetric, HybridFusion, HybridSearchRequest, MultiSearchRequest,
    PayloadType, Point, RecommendRequest, SearchRequest, SparseVector, audit, cli, encryption,
    storage_layout, tls,
};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "ChironDB HTTP administration client"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7401")]
    endpoint: String,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    client_cert: Option<PathBuf>,
    #[arg(long)]
    client_key: Option<PathBuf>,
    #[arg(long)]
    danger_accept_invalid_certs: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Health,
    ListCollections,
    CreateCollection {
        name: String,
        vector_dim: usize,
        #[arg(long, default_value = "cosine")]
        metric: DistanceMetricArg,
        #[arg(long = "payload-field")]
        payload_schema: Vec<String>,
    },
    UpdatePayloadSchema {
        collection: String,
        #[arg(long = "payload-field")]
        payload_schema: Vec<String>,
    },
    Insert {
        collection: String,
        id: String,
        vector: String,
        #[arg(long, default_value = "{}")]
        payload: String,
        #[arg(long)]
        sparse: Option<String>,
        #[arg(long = "named-vector")]
        named_vectors: Vec<String>,
    },
    Delete {
        collection: String,
        ids: Vec<String>,
    },
    Search {
        collection: String,
        vector: String,
        #[arg(short, long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long)]
        vector_name: Option<String>,
    },
    HybridSearch {
        collection: String,
        #[arg(long)]
        vector: Option<String>,
        #[arg(long)]
        vector_name: Option<String>,
        #[arg(long)]
        sparse: Option<String>,
        #[arg(short, long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long, default_value = "rrf")]
        fusion: HybridFusionArg,
        #[arg(long, default_value_t = 1.0)]
        dense_weight: f32,
        #[arg(long, default_value_t = 1.0)]
        sparse_weight: f32,
    },
    MultiSearch {
        collection: String,
        vectors: Vec<String>,
        #[arg(short, long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long)]
        vector_name: Option<String>,
        #[arg(long)]
        fusion: Option<HybridFusionArg>,
        #[arg(long)]
        fused_k: Option<usize>,
        #[arg(long, value_delimiter = ',')]
        weights: Vec<f32>,
    },
    Recommend {
        collection: String,
        #[arg(long, value_delimiter = ',')]
        positive: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        negative: Vec<String>,
        #[arg(short, long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long)]
        vector_name: Option<String>,
    },
    Count {
        collection: String,
        #[arg(long)]
        filter: Option<String>,
    },
    /// Report how many points still have no `tenant_id`, and optionally stamp
    /// them.
    ///
    /// The migration step that has to happen before tenant enforcement can be
    /// switched on: once it is on, a point with no tenant belongs to nobody
    /// and is therefore visible to nobody.
    TenantBackfill {
        collection: String,
        /// Tenant to stamp onto untenanted points. Without it this only
        /// reports, which is the safe thing to run first.
        #[arg(long)]
        tenant: Option<String>,
        /// Points to examine per page.
        #[arg(long, default_value_t = 500)]
        batch: u64,
    },
    Scroll {
        collection: String,
        /// ID-based continuation token from previous page (omit to start from beginning).
        #[arg(long)]
        offset: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        filter: Option<String>,
    },
    Compact {
        collection: String,
    },
    TierCold {
        collection: String,
    },
    PruneWalArchive {
        collection: String,
        #[arg(long)]
        retain_last: usize,
    },
    Snapshot {
        path: PathBuf,
    },
    Restore {
        path: PathBuf,
        #[arg(long = "target-wal-lsn")]
        target_wal_lsns: Vec<String>,
        #[arg(long = "target-wal-unix-ms")]
        target_wal_unix_ms: Vec<String>,
        #[arg(long = "wal-restore-archive-dir")]
        wal_restore_archive_dir: Option<PathBuf>,
        #[arg(long = "wal-restore-object-store-dir")]
        wal_restore_object_store_dir: Option<PathBuf>,
        #[arg(long = "wal-restore-object-store-url")]
        wal_restore_object_store_url: Option<String>,
    },
    ShardMove,
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SecurityCommand {
    Inspect {
        #[arg(long)]
        data_dir: PathBuf,
    },
    MigrateEncryption {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
    },
    VerifyEncryption {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
    },
    RotateKey {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        keyring: PathBuf,
    },
    VerifyAudit {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum DistanceMetricArg {
    L2,
    Cosine,
    Dot,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum HybridFusionArg {
    Rrf,
    Weighted,
}

impl From<DistanceMetricArg> for DistanceMetric {
    fn from(value: DistanceMetricArg) -> Self {
        match value {
            DistanceMetricArg::L2 => Self::L2,
            DistanceMetricArg::Cosine => Self::Cosine,
            DistanceMetricArg::Dot => Self::Dot,
        }
    }
}

impl From<HybridFusionArg> for HybridFusion {
    fn from(value: HybridFusionArg) -> Self {
        match value {
            HybridFusionArg::Rrf => Self::Rrf,
            HybridFusionArg::Weighted => Self::Weighted,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Command::Security { command } = &args.command {
        return run_security_command(command);
    }
    if args.endpoint.starts_with("https://")
        || args.ca_cert.is_some()
        || args.client_cert.is_some()
        || args.client_key.is_some()
        || args.danger_accept_invalid_certs
    {
        tls::install_default_crypto_provider();
    }
    if (args.client_cert.is_some() || args.client_key.is_some())
        && !args.endpoint.starts_with("https://")
    {
        anyhow::bail!("HTTP client certificate options require an https:// endpoint");
    }
    let client_identity =
        client_identity_paths(args.client_cert.as_deref(), args.client_key.as_deref())?;
    let client = build_client(
        args.ca_cert.as_deref(),
        client_identity,
        args.danger_accept_invalid_certs,
    )
    .await?;
    let base = args.endpoint.trim_end_matches('/');
    let api_key = args
        .api_key
        .or_else(|| std::env::var("CHIRONDB_API_KEY").ok())
        .or_else(|| std::env::var("GAUSSDB_API_KEY").ok());

    let response = match args.command {
        Command::Health => {
            apply_auth(client.get(format!("{base}/health")), api_key.as_deref())
                .send()
                .await?
        }
        Command::ListCollections => {
            apply_auth(
                client.get(format!("{base}/collections")),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::CreateCollection {
            name,
            vector_dim,
            metric,
            payload_schema,
        } => {
            apply_auth(
                client
                    .post(format!("{base}/collections"))
                    .json(&CollectionConfig {
                        name,
                        vector_dim,
                        metric: metric.into(),
                        shards: 1,
                        replicas: 1,
                        quantization: None,
                        payload_schema: parse_payload_schema(&payload_schema)?,
                        named_vector_dims: Default::default(),
                        hnsw_m: None,
                        hnsw_ef_construction: None,
                        hnsw_ef_search: None,
                        recall_sla: None,
                        index_kind: None,
                        streamer_max_bytes: 0,
                    }),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::UpdatePayloadSchema {
            collection,
            payload_schema,
        } => {
            apply_auth(
                client
                    .put(format!("{base}/collections/{collection}/payload_schema"))
                    .json(&json!({
                        "payload_schema": parse_payload_schema(&payload_schema)?,
                    })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Insert {
            collection,
            id,
            vector,
            payload,
            sparse,
            named_vectors,
        } => {
            let point = Point {
                id,
                vector: parse_vector(&vector)?,
                vectors: parse_named_vectors(&named_vectors)?,
                sparse_vector: sparse
                    .map(|raw| parse_sparse_vector(&raw))
                    .transpose()
                    .context("sparse vector must be JSON or index:value pairs")?,
                payload: serde_json::from_str(&payload).context("payload must be JSON")?,
            };
            apply_auth(
                client
                    .put(format!("{base}/collections/{collection}/points"))
                    .json(&json!({ "points": [point] })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Delete { collection, ids } => {
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/points/delete"))
                    .json(&json!({ "ids": ids })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Search {
            collection,
            vector,
            k,
            filter,
            budget_ms,
            vector_name,
        } => {
            let request = SearchRequest {
                graph: None,
                vector: parse_vector(&vector)?,
                vector_name,
                k,
                filter: filter
                    .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                    .transpose()?,
                budget_ms,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            };
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/search"))
                    .json(&request),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::HybridSearch {
            collection,
            vector,
            vector_name,
            sparse,
            k,
            filter,
            budget_ms,
            fusion,
            dense_weight,
            sparse_weight,
        } => {
            let request = HybridSearchRequest {
                graph: None,
                vector: vector.map(|raw| parse_vector(&raw)).transpose()?,
                vector_name,
                sparse_vector: sparse
                    .map(|raw| parse_sparse_vector(&raw))
                    .transpose()
                    .context("sparse vector must be JSON or index:value pairs")?,
                k,
                filter: filter
                    .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                    .transpose()?,
                budget_ms,
                fusion: fusion.into(),
                dense_weight,
                sparse_weight,
            };
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/hybrid_search"))
                    .json(&request),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::MultiSearch {
            collection,
            vectors,
            k,
            filter,
            budget_ms,
            vector_name,
            fusion,
            fused_k,
            weights,
        } => {
            let filter: Option<Value> = filter
                .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                .transpose()?;
            let searches = vectors
                .iter()
                .map(|vector| {
                    Ok(SearchRequest {
                        graph: None,
                        vector: parse_vector(vector)?,
                        vector_name: vector_name.clone(),
                        k,
                        filter: filter.clone().map(chirondb::Filter),
                        budget_ms,
                        consistency: None,
                        ef_search: None,
                        recall_target: None,
                        with_payload: None,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let request = MultiSearchRequest {
                searches,
                fusion: fusion.map(Into::into),
                fused_k,
                weights,
            };
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/multi_search"))
                    .json(&request),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Recommend {
            collection,
            positive,
            negative,
            k,
            filter,
            budget_ms,
            vector_name,
        } => {
            let request = RecommendRequest {
                positive,
                negative,
                vector_name,
                k,
                filter: filter
                    .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                    .transpose()?,
                budget_ms,
            };
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/recommend"))
                    .json(&request),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Count { collection, filter } => {
            let filter: Option<Value> = filter
                .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                .transpose()?;
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/count"))
                    .json(&json!({ "filter": filter })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::TenantBackfill {
            collection,
            tenant,
            batch,
        } => {
            // Walk the collection with SCROLL rather than loading it whole:
            // the point of this command is to run against a database too big
            // to hold in memory.
            let mut offset: Option<String> = None;
            let mut scanned = 0u64;
            let mut untenanted = 0u64;
            let mut stamped = 0u64;

            loop {
                let page: Value = apply_auth(
                    client
                        .post(format!("{base}/collections/{collection}/scroll"))
                        .json(&json!({"offset": offset, "limit": batch})),
                    api_key.as_deref(),
                )
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

                let points = page["points"].as_array().cloned().unwrap_or_default();
                if points.is_empty() {
                    break;
                }

                for point in &points {
                    scanned += 1;
                    if point["payload"].get("tenant_id").is_some() {
                        continue;
                    }
                    untenanted += 1;

                    let Some(tenant) = tenant.as_deref() else {
                        continue;
                    };
                    let Some(id) = point["id"].as_str() else {
                        continue;
                    };
                    // Merge, so the stamp is added without disturbing the rest
                    // of the payload.
                    apply_auth(
                        client
                            .post(format!("{base}/collections/{collection}/points/payload"))
                            .json(&json!({
                                "id": id,
                                "payload": {"tenant_id": tenant},
                                "merge": true
                            })),
                        api_key.as_deref(),
                    )
                    .send()
                    .await?
                    .error_for_status()?;
                    stamped += 1;
                }

                match page["next_offset"].as_str() {
                    Some(next) => offset = Some(next.to_string()),
                    None => break,
                }
            }

            let remaining = untenanted - stamped;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "collection": collection,
                    "scanned": scanned,
                    "untenanted": untenanted,
                    "stamped": stamped,
                    "remaining_untenanted": remaining,
                    "ready_for_enforcement": remaining == 0,
                }))?
            );
            return Ok(());
        }
        Command::Scroll {
            collection,
            offset,
            limit,
            filter,
        } => {
            let filter: Option<Value> = filter
                .map(|raw| serde_json::from_str(&raw).context("filter must be JSON"))
                .transpose()?;
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/scroll"))
                    .json(&json!({
                        "offset": offset,
                        "limit": limit,
                        "filter": filter
                    })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Compact { collection } => {
            apply_auth(
                client.post(format!("{base}/collections/{collection}/compact")),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::TierCold { collection } => {
            apply_auth(
                client.post(format!("{base}/collections/{collection}/cold/tier")),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::PruneWalArchive {
            collection,
            retain_last,
        } => {
            apply_auth(
                client
                    .post(format!("{base}/collections/{collection}/wal_archive/prune"))
                    .json(&json!({ "retain_last": retain_last })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Snapshot { path } => {
            apply_auth(
                client
                    .post(format!("{base}/admin/snapshot"))
                    .json(&json!({ "path": path })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Restore {
            path,
            target_wal_lsns,
            target_wal_unix_ms,
            wal_restore_archive_dir,
            wal_restore_object_store_dir,
            wal_restore_object_store_url,
        } => {
            let target_wal_lsns = parse_collection_u64_map(&target_wal_lsns, "target WAL LSN")?;
            let target_wal_unix_ms =
                parse_collection_u64_map(&target_wal_unix_ms, "target WAL Unix ms")?;
            apply_auth(
                client.post(format!("{base}/admin/restore")).json(&json!({
                    "path": path,
                    "target_wal_lsns": target_wal_lsns,
                    "target_wal_unix_ms": target_wal_unix_ms,
                    "wal_restore_archive_dir": wal_restore_archive_dir,
                    "wal_restore_object_store_dir": wal_restore_object_store_dir,
                    "wal_restore_object_store_url": wal_restore_object_store_url,
                })),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::ShardMove => {
            apply_auth(
                client.post(format!("{base}/admin/shard_move")),
                api_key.as_deref(),
            )
            .send()
            .await?
        }
        Command::Security { .. } => unreachable!("security commands return before HTTP setup"),
    };

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("request failed with {status}: {body}");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&body)?)?
    );
    Ok(())
}

fn run_security_command(command: &SecurityCommand) -> anyhow::Result<()> {
    match command {
        SecurityCommand::Inspect { data_dir } => {
            let _lock = storage_layout::acquire_exclusive(data_dir)?;
            let layout = storage_layout::resolve(data_dir)?;
            let report = encryption::inspect_tree(&layout.active_root)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "data_dir": data_dir,
                    "active_generation": layout.generation,
                    "active_root": layout.active_root,
                    "encryption": report,
                    "audit_chain_valid": audit::verify_hash_chain(data_dir).is_ok(),
                }))?
            );
        }
        SecurityCommand::MigrateEncryption { data_dir, keyring } => {
            let keyring = encryption::Keyring::load(keyring)?;
            if !storage_layout::is_generation_layout(data_dir) {
                storage_layout::migrate_legacy(data_dir)?;
            }
            let before = encryption::inspect_tree(data_dir)?;
            if before.plaintext_files == 0 {
                let report = encryption::verify_tree(&keyring, data_dir)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "already_encrypted",
                        "active_generation": storage_layout::resolve(data_dir)?.generation,
                        "verification": report,
                    }))?
                );
                return Ok(());
            }
            {
                let db = Db::open(data_dir)
                    .context("failed to open plaintext data for offline encryption preparation")?;
                db.prepare_encryption_migration()
                    .context("failed to prepare unified graph/vector state before encryption")?;
            }
            let migration = storage_layout::migrate_encryption(data_dir, &keyring)?;
            encryption::install_process_keyring(keyring, false)?;
            audit::verify_hash_chain(data_dir)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "migration": migration,
                    "external_authorities_rewrapped": false,
                    "external_key_retirement": "verify or migrate configured cold-object and WAL-archive mirrors independently",
                }))?
            );
        }
        SecurityCommand::VerifyEncryption { data_dir, keyring } => {
            let _lock = storage_layout::acquire_exclusive(data_dir)?;
            let keyring = encryption::Keyring::load(keyring)?;
            let report = encryption::verify_tree(&keyring, data_dir)?;
            encryption::install_process_keyring(keyring, false)?;
            audit::verify_hash_chain(data_dir)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        SecurityCommand::RotateKey { data_dir, keyring } => {
            let _lock = storage_layout::acquire_exclusive(data_dir)?;
            let keyring = encryption::Keyring::load(keyring)?;
            let rotated = encryption::rewrap_tree_resumable(&keyring, data_dir)?;
            let verified = encryption::verify_tree(&keyring, data_dir)?;
            let external_cold_object_files =
                chirondb_core::segment::external_cold_object_file_count(data_dir, &keyring)?;
            let active_key_id = keyring.active_key_id().to_string();
            encryption::install_process_keyring(keyring, false)?;
            audit::verify_hash_chain(data_dir)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "rotated_files": rotated,
                    "active_key_id": active_key_id,
                    "verified": verified,
                    "external_cold_object_files_preserved": external_cold_object_files,
                    "external_authorities_rewrapped": false,
                    "external_key_retirement": "verify or migrate configured cold-object and WAL-archive mirrors independently",
                }))?
            );
        }
        SecurityCommand::VerifyAudit { data_dir, keyring } => {
            let _lock = storage_layout::acquire_exclusive(data_dir)?;
            if let Some(keyring) = keyring {
                encryption::install_process_keyring(encryption::Keyring::load(keyring)?, false)?;
            }
            audit::verify_hash_chain(data_dir)?;
            println!("{}", json!({"status": "ok", "chain": "valid"}));
        }
    }
    Ok(())
}

fn apply_auth(request: reqwest::RequestBuilder, api_key: Option<&str>) -> reqwest::RequestBuilder {
    match api_key {
        Some(api_key) => request.bearer_auth(api_key),
        None => request,
    }
}

async fn build_client(
    ca_cert: Option<&Path>,
    client_identity: Option<(&Path, &Path)>,
    danger_accept_invalid_certs: bool,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(ca_cert) = ca_cert {
        let certificate = tokio::fs::read(ca_cert)
            .await
            .with_context(|| format!("failed to read CA certificate {}", ca_cert.display()))?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&certificate).context("CA certificate must be PEM")?,
        );
    }
    if danger_accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some((client_cert, client_key)) = client_identity {
        let mut identity = tokio::fs::read(client_cert).await.with_context(|| {
            format!(
                "failed to read client certificate {}",
                client_cert.display()
            )
        })?;
        identity.extend(tokio::fs::read(client_key).await.with_context(|| {
            format!("failed to read client private key {}", client_key.display())
        })?);
        builder = builder.identity(
            reqwest::Identity::from_pem(&identity)
                .context("client certificate and key must be PEM")?,
        );
    }
    builder.build().context("failed to build HTTP client")
}

fn client_identity_paths<'a>(
    client_cert: Option<&'a Path>,
    client_key: Option<&'a Path>,
) -> anyhow::Result<Option<(&'a Path, &'a Path)>> {
    match (client_cert, client_key) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (None, None) => Ok(None),
        _ => anyhow::bail!("--client-cert and --client-key must be provided together"),
    }
}

fn parse_vector(raw: &str) -> anyhow::Result<Vec<f32>> {
    if raw.trim_start().starts_with('[') {
        return serde_json::from_str(raw).context("vector must be a JSON array of numbers");
    }

    raw.split(',')
        .map(|part| {
            part.trim()
                .parse::<f32>()
                .with_context(|| format!("invalid vector component: {part}"))
        })
        .collect()
}

fn parse_named_vectors(raw: &[String]) -> anyhow::Result<HashMap<String, Vec<f32>>> {
    let mut vectors = HashMap::new();
    for item in raw {
        let (name, vector) = item
            .split_once('=')
            .with_context(|| format!("invalid named vector, expected name=values: {item}"))?;
        if name.is_empty() {
            anyhow::bail!("named vector name must not be empty");
        }
        vectors.insert(name.to_string(), parse_vector(vector)?);
    }
    Ok(vectors)
}

fn parse_payload_schema(raw: &[String]) -> anyhow::Result<HashMap<String, PayloadType>> {
    cli::parse_payload_schema(raw)
}

fn parse_collection_u64_map(raw: &[String], label: &str) -> anyhow::Result<HashMap<String, u64>> {
    let mut targets = HashMap::new();
    for value in raw {
        let (collection, target) = value
            .split_once('=')
            .with_context(|| format!("{label} must be collection=value: {value}"))?;
        targets.insert(
            collection.to_string(),
            target
                .parse::<u64>()
                .with_context(|| format!("invalid {label} for {collection}: {target}"))?,
        );
    }
    Ok(targets)
}

fn parse_sparse_vector(raw: &str) -> anyhow::Result<SparseVector> {
    if raw.trim_start().starts_with('{') {
        return serde_json::from_str(raw)
            .context("sparse vector must be {\"indices\":[...],\"values\":[...]}");
    }

    let mut indices = Vec::new();
    let mut values = Vec::new();
    for part in raw.split(',') {
        let (index, value) = part
            .split_once(':')
            .with_context(|| format!("invalid sparse component: {part}"))?;
        indices.push(
            index
                .trim()
                .parse::<u32>()
                .with_context(|| format!("invalid sparse index: {index}"))?,
        );
        values.push(
            value
                .trim()
                .parse::<f32>()
                .with_context(|| format!("invalid sparse value: {value}"))?,
        );
    }
    Ok(SparseVector { indices, values })
}
