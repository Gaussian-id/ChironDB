use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chirondb::grpc::chiron_pb::ChironQlRequest;
use chirondb::grpc::chiron_pb::chiron_db_client::ChironDbClient;
use chirondb::grpc::pb::{
    ColdTierRequest, CollectionConfig, CompactRequest, CountRequest, CreateCollectionRequest,
    DeleteRequest, DenseVector, HybridSearchRequest, ListCollectionsRequest, MultiSearchRequest,
    Point, PruneWalArchiveRequest, RecommendRequest, RestoreRequest, ScrollRequest, SearchQuery,
    SearchRequest, SearchResponse, ShardMoveRequest, SnapshotRequest, SparseVector,
    UpdatePayloadSchemaRequest, UpsertRequest,
};
use chirondb::tls;
use chirondb::{PayloadType, cli};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "ChironDB gRPC client"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7402")]
    endpoint: String,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    #[arg(long)]
    tls_domain: Option<String>,
    #[arg(long)]
    client_cert: Option<PathBuf>,
    #[arg(long)]
    client_key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Health,
    ReflectServices,
    ListCollections,
    CreateCollection {
        name: String,
        vector_dim: u64,
        #[arg(long, default_value = "cosine")]
        metric: String,
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
        k: u64,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long)]
        vector_name: Option<String>,
        #[arg(long)]
        recall_target: Option<f32>,
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
        k: u64,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long, default_value = "rrf")]
        fusion: String,
        #[arg(long, default_value_t = 1.0)]
        dense_weight: f32,
        #[arg(long, default_value_t = 1.0)]
        sparse_weight: f32,
    },
    MultiSearch {
        collection: String,
        vectors: Vec<String>,
        #[arg(short, long, default_value_t = 10)]
        k: u64,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        budget_ms: Option<u64>,
        #[arg(long)]
        vector_name: Option<String>,
        #[arg(long)]
        fusion: Option<String>,
        #[arg(long)]
        fused_k: Option<u64>,
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
        k: u64,
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
    /// Run one ChironQL statement. See docs/CHIRONQL.md for the language.
    Query {
        statement: String,
        /// Session collection, as `USE <name>` would set.
        #[arg(long)]
        collection: Option<String>,
        /// Ask for the server's stage-by-stage execution trace. Failures
        /// carry it either way.
        #[arg(long)]
        trace: bool,
        /// Proceed with a statement that stops and asks, such as a filtered
        /// delete.
        #[arg(long)]
        yes: bool,
    },
    Scroll {
        collection: String,
        #[arg(long)]
        offset: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u64,
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
        retain_last: u64,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let api_key = args
        .api_key
        .or_else(|| std::env::var("CHIRONDB_API_KEY").ok())
        .or_else(|| std::env::var("GAUSSDB_API_KEY").ok());
    if args.endpoint.starts_with("https://")
        || args.ca_cert.is_some()
        || args.tls_domain.is_some()
        || args.client_cert.is_some()
        || args.client_key.is_some()
    {
        tls::install_default_crypto_provider();
    }
    if (args.client_cert.is_some() || args.client_key.is_some())
        && !args.endpoint.starts_with("https://")
    {
        anyhow::bail!("gRPC client certificate options require an https:// endpoint");
    }
    if (args.client_cert.is_some() || args.client_key.is_some()) && args.ca_cert.is_none() {
        anyhow::bail!("gRPC client certificate options require --ca-cert");
    }
    let client_identity =
        client_identity_paths(args.client_cert.as_deref(), args.client_key.as_deref())?;
    let channel = connect_channel(
        args.endpoint,
        args.ca_cert.as_deref(),
        args.tls_domain.as_deref(),
        client_identity,
    )
    .await
    .context("failed to connect to gRPC endpoint")?;
    let mut client = ChironDbClient::new(channel.clone());

    let output = match args.command {
        Command::Health => {
            let response = client
                .health(with_auth(
                    chirondb::grpc::pb::HealthRequest {},
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "status": response.status,
                "data_dir": response.data_dir,
                "collections": response.collections,
                "version": response.version,
            })
        }
        Command::ReflectServices => json!(reflect_services(channel, api_key.as_deref()).await?),
        Command::ListCollections => {
            let response = client
                .list_collections(with_auth(ListCollectionsRequest {}, api_key.as_deref())?)
                .await?
                .into_inner();
            json!(
                response
                    .collections
                    .into_iter()
                    .map(collection_config_json)
                    .collect::<Vec<_>>()
            )
        }
        Command::CreateCollection {
            name,
            vector_dim,
            metric,
            payload_schema,
        } => {
            let response = client
                .create_collection(with_auth(
                    CreateCollectionRequest {
                        config: Some(CollectionConfig {
                            name,
                            vector_dim,
                            metric,
                            shards: 1,
                            replicas: 1,
                            quantization: String::new(),
                            payload_schema: parse_payload_schema(&payload_schema)?
                                .into_iter()
                                .map(|(field, value_type)| (field, value_type.to_string()))
                                .collect(),
                            hnsw_m: None,
                            hnsw_ef_construction: None,
                            hnsw_ef_search: None,
                            recall_sla: None,
                            streamer_max_bytes: 0,
                        }),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            collection_config_json(response)
        }
        Command::UpdatePayloadSchema {
            collection,
            payload_schema,
        } => {
            let response = client
                .update_payload_schema(with_auth(
                    UpdatePayloadSchemaRequest {
                        collection,
                        payload_schema: parse_payload_schema(&payload_schema)?
                            .into_iter()
                            .map(|(field, value_type)| (field, value_type.to_string()))
                            .collect(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            collection_config_json(response)
        }
        Command::Insert {
            collection,
            id,
            vector,
            payload,
            sparse,
            named_vectors,
        } => {
            let response = client
                .upsert(with_auth(
                    UpsertRequest {
                        collection,
                        points: vec![Point {
                            id,
                            vector: parse_vector(&vector)?,
                            payload_json: payload,
                            sparse_vector: sparse
                                .map(|raw| parse_sparse_vector(&raw))
                                .transpose()?,
                            vectors: parse_named_vectors(&named_vectors)?,
                        }],
                        no_wait: false,
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({ "total": response.total })
        }
        Command::Delete { collection, ids } => {
            let response = client
                .delete(with_auth(
                    DeleteRequest { collection, ids },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({ "deleted": response.deleted })
        }
        Command::Search {
            collection,
            vector,
            k,
            filter,
            budget_ms,
            vector_name,
            recall_target,
        } => {
            let response = client
                .search(with_auth(
                    SearchRequest {
                        collection,
                        query: Some(SearchQuery {
                            vector: parse_vector(&vector)?,
                            k,
                            filter_json: filter.unwrap_or_default(),
                            budget_ms,
                            vector_name: vector_name.unwrap_or_default(),
                            ef_search: None,
                            recall_target,
                            graph_json: None,
                        }),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            search_response_json(response)?
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
            let vector = vector.map(|raw| parse_vector(&raw)).transpose()?;
            let response = client
                .hybrid_search(with_auth(
                    HybridSearchRequest {
                        collection,
                        use_dense_vector: vector.is_some(),
                        vector: vector.unwrap_or_default(),
                        vector_name: vector_name.unwrap_or_default(),
                        sparse_vector: sparse.map(|raw| parse_sparse_vector(&raw)).transpose()?,
                        k,
                        filter_json: filter.unwrap_or_default(),
                        budget_ms,
                        fusion,
                        dense_weight,
                        sparse_weight,
                        graph_json: None,
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            search_response_json(response)?
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
            let searches = vectors
                .iter()
                .map(|vector| {
                    Ok(SearchQuery {
                        vector: parse_vector(vector)?,
                        k,
                        filter_json: filter.clone().unwrap_or_default(),
                        budget_ms,
                        vector_name: vector_name.clone().unwrap_or_default(),
                        ef_search: None,
                        recall_target: None,
                        graph_json: None,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let response = client
                .multi_search(with_auth(
                    MultiSearchRequest {
                        collection,
                        searches,
                        fusion: fusion.unwrap_or_default(),
                        fused_k: fused_k.unwrap_or_default(),
                        weights,
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "results": response.results.into_iter()
                    .map(search_response_json)
                    .collect::<anyhow::Result<Vec<_>>>()?,
                "fused": response.fused.map(search_response_json).transpose()?,
            })
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
            let response = client
                .recommend(with_auth(
                    RecommendRequest {
                        collection,
                        positive,
                        negative,
                        k,
                        filter_json: filter.unwrap_or_default(),
                        budget_ms,
                        vector_name: vector_name.unwrap_or_default(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            search_response_json(response)?
        }
        Command::Count { collection, filter } => {
            let response = client
                .count(with_auth(
                    CountRequest {
                        collection,
                        filter_json: filter.unwrap_or_default(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({ "count": response.count })
        }
        Command::Query {
            statement,
            collection,
            trace,
            yes,
        } => {
            let response = client
                .execute_query(with_auth(
                    ChironQlRequest {
                        query: statement,
                        collection,
                        trace,
                        confirm: yes,
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            // Rows, stats and the trace arrive as JSON strings; reassemble
            // them so the output is one JSON document rather than a document
            // with strings of JSON inside it.
            json!({
                "kind": response.kind,
                "columns": response.columns,
                "rows": response
                    .rows_json
                    .iter()
                    .map(|row| serde_json::from_str::<serde_json::Value>(row)
                        .unwrap_or(serde_json::Value::Null))
                    .collect::<Vec<_>>(),
                "stats": serde_json::from_str::<serde_json::Value>(&response.stats_json)
                    .unwrap_or(serde_json::Value::Null),
                "next": response.next,
                "query_id": response.query_id,
                "trace": response
                    .trace_json
                    .as_deref()
                    .and_then(|trace| serde_json::from_str::<serde_json::Value>(trace).ok()),
            })
        }
        Command::Scroll {
            collection,
            offset,
            limit,
            filter,
        } => {
            let response = client
                .scroll(with_auth(
                    ScrollRequest {
                        collection,
                        offset: offset.unwrap_or_default(),
                        limit,
                        filter_json: filter.unwrap_or_default(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "points": response.points.into_iter()
                    .map(point_json)
                    .collect::<anyhow::Result<Vec<_>>>()?,
                "next_offset": response.next_offset,
            })
        }
        Command::Compact { collection } => {
            let response = client
                .compact(with_auth(
                    CompactRequest { collection },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "collection": response.collection,
                "segment_id": response.segment_id,
                "points": response.points,
                "h2qg_cells": response.h2qg_cells,
                "named_h2qg_fields": response.named_h2qg_fields,
                "sparse_dimensions": response.sparse_dimensions,
                "sparse_postings": response.sparse_postings,
                "payload_fields": response.payload_fields,
                "payload_values": response.payload_values,
                "payload_postings": response.payload_postings,
                "tombstones": response.tombstones,
                "wal_archived_segments": response.wal_archived_segments,
                "wal_archived_bytes": response.wal_archived_bytes,
                "wal_external_archived_segments": response.wal_external_archived_segments,
                "wal_external_archived_bytes": response.wal_external_archived_bytes,
                "wal_object_archived_segments": response.wal_object_archived_segments,
                "wal_object_archived_bytes": response.wal_object_archived_bytes,
                "wal_archive_command_executed": response.wal_archive_command_executed,
                "wal_auto_retained_archives": response.wal_auto_retained_archives,
                "wal_auto_pruned_archives": response.wal_auto_pruned_archives,
                "wal_auto_pruned_bytes": response.wal_auto_pruned_bytes,
            })
        }
        Command::TierCold { collection } => {
            let response = client
                .tier_cold(with_auth(
                    ColdTierRequest { collection },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "collection": response.collection,
                "segments": response.segments,
                "files": response.files,
                "bytes": response.bytes,
                "points": response.points,
            })
        }
        Command::PruneWalArchive {
            collection,
            retain_last,
        } => {
            let response = client
                .prune_wal_archive(with_auth(
                    PruneWalArchiveRequest {
                        collection,
                        retain_last,
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({
                "collection": response.collection,
                "retained_archives": response.retained_archives,
                "pruned_archives": response.pruned_archives,
                "pruned_bytes": response.pruned_bytes,
            })
        }
        Command::Snapshot { path } => {
            let response = client
                .snapshot(with_auth(
                    SnapshotRequest {
                        path: path.display().to_string(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({ "status": response.status })
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
            let response = client
                .restore(with_auth(
                    RestoreRequest {
                        path: path.display().to_string(),
                        target_wal_lsns,
                        target_wal_unix_ms,
                        wal_restore_archive_dir: wal_restore_archive_dir
                            .map(|path| path.display().to_string())
                            .unwrap_or_default(),
                        wal_restore_object_store_dir: wal_restore_object_store_dir
                            .map(|path| path.display().to_string())
                            .unwrap_or_default(),
                        wal_restore_object_store_url: wal_restore_object_store_url
                            .unwrap_or_default(),
                    },
                    api_key.as_deref(),
                )?)
                .await?
                .into_inner();
            json!({ "status": response.status })
        }
        Command::ShardMove => {
            let response = client
                .shard_move(with_auth(ShardMoveRequest {}, api_key.as_deref())?)
                .await?
                .into_inner();
            json!({ "status": response.status })
        }
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn with_auth<T>(message: T, api_key: Option<&str>) -> anyhow::Result<Request<T>> {
    let mut request = Request::new(message);
    if let Some(api_key) = api_key {
        let value = format!("Bearer {api_key}")
            .parse()
            .context("api key must be valid gRPC metadata")?;
        request.metadata_mut().insert("authorization", value);
    }
    Ok(request)
}

async fn connect_channel(
    endpoint: String,
    ca_cert: Option<&Path>,
    tls_domain: Option<&str>,
    client_identity: Option<(&Path, &Path)>,
) -> anyhow::Result<Channel> {
    let tls_requested = endpoint.starts_with("https://")
        || ca_cert.is_some()
        || tls_domain.is_some()
        || client_identity.is_some();
    if tls_requested && !endpoint.starts_with("https://") {
        anyhow::bail!("gRPC TLS options require an https:// endpoint");
    }

    let mut endpoint = Endpoint::from_shared(endpoint)?;
    if tls_requested {
        let mut tls_config = ClientTlsConfig::new().with_enabled_roots();
        if let Some(ca_cert) = ca_cert {
            let certificate = tokio::fs::read(ca_cert)
                .await
                .with_context(|| format!("failed to read CA certificate {}", ca_cert.display()))?;
            tls_config = tls_config.ca_certificate(Certificate::from_pem(certificate));
        }
        if let Some(domain) = tls_domain {
            tls_config = tls_config.domain_name(domain);
        }
        if let Some((client_cert, client_key)) = client_identity {
            let cert = tokio::fs::read(client_cert).await.with_context(|| {
                format!(
                    "failed to read client certificate {}",
                    client_cert.display()
                )
            })?;
            let key = tokio::fs::read(client_key).await.with_context(|| {
                format!("failed to read client private key {}", client_key.display())
            })?;
            tls_config = tls_config.identity(Identity::from_pem(cert, key));
        }
        endpoint = endpoint.tls_config(tls_config)?;
    }

    endpoint
        .connect()
        .await
        .context("gRPC channel connect failed")
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

async fn reflect_services(channel: Channel, api_key: Option<&str>) -> anyhow::Result<Vec<String>> {
    let request = tonic_reflection::pb::v1::ServerReflectionRequest {
        host: String::new(),
        message_request: Some(
            tonic_reflection::pb::v1::server_reflection_request::MessageRequest::ListServices(
                String::new(),
            ),
        ),
    };
    let mut request = Request::new(tokio_stream::once(request));
    if let Some(api_key) = api_key {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {api_key}")
                .parse()
                .context("api key must be valid gRPC metadata")?,
        );
    }
    let mut client =
        tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient::new(channel);
    let response = client
        .server_reflection_info(request)
        .await?
        .into_inner()
        .message()
        .await?
        .context("reflection server closed without a response")?;
    let Some(
        tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            services,
        ),
    ) = response.message_response
    else {
        anyhow::bail!("reflection server returned an unexpected response");
    };
    Ok(services
        .service
        .into_iter()
        .map(|service| service.name)
        .collect())
}

fn collection_config_json(config: CollectionConfig) -> Value {
    json!({
        "name": config.name,
        "vector_dim": config.vector_dim,
        "metric": config.metric,
        "shards": config.shards,
        "replicas": config.replicas,
        "quantization": empty_string_to_null(config.quantization),
        "payload_schema": config.payload_schema,
    })
}

fn point_json(point: Point) -> anyhow::Result<Value> {
    Ok(json!({
        "id": point.id,
        "vector": point.vector,
        "vectors": point.vectors.into_iter()
            .map(|(name, vector)| (name, vector.values))
            .collect::<HashMap<_, _>>(),
        "sparse_vector": point.sparse_vector.map(|sparse| json!({
            "indices": sparse.indices,
            "values": sparse.values,
        })),
        "payload": serde_json::from_str::<Value>(&point.payload_json)
            .context("server returned invalid payload_json")?,
    }))
}

fn search_response_json(response: SearchResponse) -> anyhow::Result<Value> {
    Ok(json!({
        "hits": response.hits.into_iter().map(|hit| {
            Ok(json!({
                "id": hit.id,
                "score": hit.score,
                "payload": serde_json::from_str::<Value>(&hit.payload_json)
                    .context("server returned invalid payload_json")?,
            }))
        }).collect::<anyhow::Result<Vec<_>>>()?,
        "degraded": response.degraded,
        "searched": response.searched,
        "elapsed_ms": response.elapsed_ms,
    }))
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

fn parse_named_vectors(raw: &[String]) -> anyhow::Result<HashMap<String, DenseVector>> {
    let mut vectors = HashMap::new();
    for item in raw {
        let (name, vector) = item
            .split_once('=')
            .with_context(|| format!("invalid named vector, expected name=values: {item}"))?;
        if name.is_empty() {
            anyhow::bail!("named vector name must not be empty");
        }
        vectors.insert(
            name.to_string(),
            DenseVector {
                values: parse_vector(vector)?,
            },
        );
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
        let parsed: chirondb::SparseVector = serde_json::from_str(raw)
            .context("sparse vector must be {\"indices\":[...],\"values\":[...]}")?;
        return Ok(SparseVector {
            indices: parsed.indices,
            values: parsed.values,
        });
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

fn empty_string_to_null(value: String) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value)
    }
}
