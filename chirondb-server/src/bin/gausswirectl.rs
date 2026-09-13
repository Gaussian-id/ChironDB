use std::{collections::HashMap, path::PathBuf, time::SystemTime};

use anyhow::Context;
use chirondb::{
    cli,
    grpc::pb::{
        ColdTierRequest, CollectionConfig, CompactRequest, CountRequest, CreateCollectionRequest,
        DeleteRequest, DenseVector, HealthRequest, HybridSearchRequest, ListCollectionsRequest,
        MultiSearchRequest, Point, PruneWalArchiveRequest, RecommendRequest, RestoreRequest,
        ScrollRequest, SearchQuery, SearchRequest, SearchResponse, ShardMoveRequest,
        SnapshotRequest, SparseVector, UpdatePayloadSchemaRequest, UpsertRequest,
        WireChironQlRequest, WireRequest, wire_request, wire_response,
    },
    wire,
};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "ChironWire binary client for ChironDB"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7403")]
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
    /// Execute one ChironQL statement over the native ChironWire envelope.
    Query {
        statement: String,
        #[arg(long)]
        collection: Option<String>,
        #[arg(long)]
        trace: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        deferred_session_id: Option<String>,
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
    if (args.tls_domain.is_some() || args.client_cert.is_some() || args.client_key.is_some())
        && args.ca_cert.is_none()
    {
        anyhow::bail!("GaussWire TLS domain/client certificate options require --ca-cert");
    }
    let client_identity =
        client_identity_paths(args.client_cert.as_deref(), args.client_key.as_deref())?;
    let api_key = args
        .api_key
        .or_else(|| std::env::var("CHIRONDB_API_KEY").ok())
        .or_else(|| std::env::var("GAUSSDB_API_KEY").ok())
        .unwrap_or_default();
    let request = WireRequest {
        request_id: request_id(),
        api_key,
        operation: Some(match args.command {
            Command::Health => wire_request::Operation::Health(HealthRequest {}),
            Command::ListCollections => {
                wire_request::Operation::ListCollections(ListCollectionsRequest {})
            }
            Command::CreateCollection {
                name,
                vector_dim,
                metric,
                payload_schema,
            } => wire_request::Operation::CreateCollection(CreateCollectionRequest {
                config: Some(CollectionConfig {
                    name,
                    vector_dim,
                    metric,
                    shards: 1,
                    replicas: 1,
                    quantization: String::new(),
                    payload_schema: parse_payload_schema(&payload_schema)?,
                    hnsw_m: None,
                    hnsw_ef_construction: None,
                    hnsw_ef_search: None,
                    recall_sla: None,
                    streamer_max_bytes: 0,
                }),
            }),
            Command::UpdatePayloadSchema {
                collection,
                payload_schema,
            } => wire_request::Operation::UpdatePayloadSchema(UpdatePayloadSchemaRequest {
                collection,
                payload_schema: parse_payload_schema(&payload_schema)?,
            }),
            Command::Insert {
                collection,
                id,
                vector,
                payload,
                sparse,
                named_vectors,
            } => wire_request::Operation::Upsert(UpsertRequest {
                collection,
                points: vec![Point {
                    id,
                    vector: parse_vector(&vector)?,
                    payload_json: payload,
                    sparse_vector: sparse.map(|raw| parse_sparse_vector(&raw)).transpose()?,
                    vectors: parse_named_vectors(&named_vectors)?,
                }],
                no_wait: false,
            }),
            Command::Delete { collection, ids } => {
                wire_request::Operation::Delete(DeleteRequest { collection, ids })
            }
            Command::Search {
                collection,
                vector,
                k,
                filter,
                budget_ms,
                vector_name,
                recall_target,
            } => wire_request::Operation::Search(SearchRequest {
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
            }),
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
            } => wire_request::Operation::HybridSearch(HybridSearchRequest {
                collection,
                vector: vector
                    .as_deref()
                    .map(parse_vector)
                    .transpose()?
                    .unwrap_or_default(),
                sparse_vector: sparse.map(|raw| parse_sparse_vector(&raw)).transpose()?,
                k,
                filter_json: filter.unwrap_or_default(),
                budget_ms,
                fusion,
                dense_weight,
                sparse_weight,
                use_dense_vector: vector.is_some(),
                vector_name: vector_name.unwrap_or_default(),
                graph_json: None,
            }),
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
            } => wire_request::Operation::MultiSearch(MultiSearchRequest {
                collection,
                searches: vectors
                    .into_iter()
                    .map(|vector| {
                        Ok(SearchQuery {
                            vector: parse_vector(&vector)?,
                            k,
                            filter_json: filter.clone().unwrap_or_default(),
                            budget_ms,
                            vector_name: vector_name.clone().unwrap_or_default(),
                            ef_search: None,
                            recall_target: None,
                            graph_json: None,
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                fusion: fusion.unwrap_or_default(),
                fused_k: fused_k.unwrap_or_default(),
                weights,
            }),
            Command::Recommend {
                collection,
                positive,
                negative,
                k,
                filter,
                budget_ms,
                vector_name,
            } => wire_request::Operation::Recommend(RecommendRequest {
                collection,
                positive,
                negative,
                k,
                filter_json: filter.unwrap_or_default(),
                budget_ms,
                vector_name: vector_name.unwrap_or_default(),
            }),
            Command::Count { collection, filter } => wire_request::Operation::Count(CountRequest {
                collection,
                filter_json: filter.unwrap_or_default(),
            }),
            Command::Query {
                statement,
                collection,
                trace,
                yes,
                deferred_session_id,
            } => wire_request::Operation::Chironql(WireChironQlRequest {
                query: statement,
                collection,
                trace,
                confirm: yes,
                deferred_session_id,
            }),
            Command::Scroll {
                collection,
                offset,
                limit,
                filter,
            } => wire_request::Operation::Scroll(ScrollRequest {
                collection,
                offset: offset.unwrap_or_default(),
                limit,
                filter_json: filter.unwrap_or_default(),
            }),
            Command::Compact { collection } => {
                wire_request::Operation::Compact(CompactRequest { collection })
            }
            Command::TierCold { collection } => {
                wire_request::Operation::TierCold(ColdTierRequest { collection })
            }
            Command::PruneWalArchive {
                collection,
                retain_last,
            } => wire_request::Operation::PruneWalArchive(PruneWalArchiveRequest {
                collection,
                retain_last,
            }),
            Command::Snapshot { path } => wire_request::Operation::Snapshot(SnapshotRequest {
                path: path.display().to_string(),
            }),
            Command::Restore {
                path,
                target_wal_lsns,
                target_wal_unix_ms,
                wal_restore_archive_dir,
                wal_restore_object_store_dir,
                wal_restore_object_store_url,
            } => wire_request::Operation::Restore(RestoreRequest {
                path: path.display().to_string(),
                target_wal_lsns: parse_collection_u64_map(&target_wal_lsns, "target WAL LSN")?,
                target_wal_unix_ms: parse_collection_u64_map(
                    &target_wal_unix_ms,
                    "target WAL Unix ms",
                )?,
                wal_restore_archive_dir: wal_restore_archive_dir
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                wal_restore_object_store_dir: wal_restore_object_store_dir
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                wal_restore_object_store_url: wal_restore_object_store_url.unwrap_or_default(),
            }),
            Command::ShardMove => wire_request::Operation::ShardMove(ShardMoveRequest {}),
        }),
    };
    let response = if let Some(ca_cert) = args.ca_cert {
        wire::send_request_tls(
            &args.endpoint,
            args.tls_domain.as_deref().unwrap_or("localhost"),
            ca_cert,
            client_identity.map(|(cert, key)| (cert.to_path_buf(), key.to_path_buf())),
            request,
        )
        .await
    } else {
        wire::send_request(&args.endpoint, request).await
    }
    .map_err(|error| anyhow::anyhow!("GaussWire request failed: {error}"))?;
    if !response.error_code.is_empty() {
        anyhow::bail!(
            "{}: {}{}",
            response.error_code,
            response.error_message,
            response
                .error_details_json
                .as_deref()
                .map(|details| format!("\n{details}"))
                .unwrap_or_default()
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&response_json(response)?)?
    );
    Ok(())
}

fn client_identity_paths<'a>(
    client_cert: Option<&'a std::path::Path>,
    client_key: Option<&'a std::path::Path>,
) -> anyhow::Result<Option<(&'a std::path::Path, &'a std::path::Path)>> {
    match (client_cert, client_key) {
        (Some(cert), Some(key)) => Ok(Some((cert, key))),
        (None, None) => Ok(None),
        _ => anyhow::bail!("--client-cert and --client-key must be provided together"),
    }
}

fn response_json(response: chirondb::grpc::pb::WireResponse) -> anyhow::Result<Value> {
    let Some(payload) = response.payload else {
        return Ok(json!({}));
    };
    Ok(match payload {
        wire_response::Payload::Health(response) => json!({
            "status": response.status,
            "data_dir": response.data_dir,
            "collections": response.collections,
            "version": response.version,
        }),
        wire_response::Payload::Collection(config) => collection_config_json(config),
        wire_response::Payload::ListCollections(response) => {
            json!(
                response
                    .collections
                    .into_iter()
                    .map(collection_config_json)
                    .collect::<Vec<_>>()
            )
        }
        wire_response::Payload::Upsert(response) => json!({"total": response.total}),
        wire_response::Payload::Delete(response) => json!({"deleted": response.deleted}),
        wire_response::Payload::Search(response) => search_response_json(response)?,
        wire_response::Payload::Count(response) => json!({"count": response.count}),
        wire_response::Payload::MultiSearch(response) => json!({
            "results": response.results.into_iter()
                .map(search_response_json)
                .collect::<anyhow::Result<Vec<_>>>()?,
            "fused": response.fused.map(search_response_json).transpose()?,
        }),
        wire_response::Payload::Scroll(response) => json!({
            "points": response.points.into_iter()
                .map(point_json)
                .collect::<anyhow::Result<Vec<_>>>()?,
            "next_offset": response.next_offset,
        }),
        wire_response::Payload::Compact(response) => json!({
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
        }),
        wire_response::Payload::ColdTier(response) => json!({
            "collection": response.collection,
            "segments": response.segments,
            "files": response.files,
            "bytes": response.bytes,
            "points": response.points,
        }),
        wire_response::Payload::WalArchivePrune(response) => json!({
            "collection": response.collection,
            "retained_archives": response.retained_archives,
            "pruned_archives": response.pruned_archives,
            "pruned_bytes": response.pruned_bytes,
        }),
        wire_response::Payload::Status(response) => json!({"status": response.status}),
        wire_response::Payload::GetPoints(response) => json!({
            "points": response.points.into_iter()
                .map(point_json)
                .collect::<anyhow::Result<Vec<_>>>()?,
        }),
        wire_response::Payload::SetPayload(response) => json!({
            "point": response.point.map(point_json).transpose()?,
        }),
        wire_response::Payload::DeleteByFilter(response) => {
            json!({"deleted": response.deleted})
        }
        wire_response::Payload::Chironql(response) => json!({
            "kind": response.kind,
            "columns": response.columns,
            "rows": response.rows_json.iter()
                .map(|row| serde_json::from_str::<Value>(row).unwrap_or(Value::Null))
                .collect::<Vec<_>>(),
            "stats": serde_json::from_str::<Value>(&response.stats_json)
                .unwrap_or(Value::Null),
            "next": response.next,
            "query_id": response.query_id,
            "trace": response.trace_json.as_deref()
                .and_then(|trace| serde_json::from_str::<Value>(trace).ok()),
        }),
    })
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
        "graph": response.graph_json.as_deref()
            .and_then(|graph| serde_json::from_str::<Value>(graph).ok()),
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

fn parse_payload_schema(raw: &[String]) -> anyhow::Result<HashMap<String, String>> {
    cli::parse_payload_schema(raw).map(|schema| {
        schema
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    })
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

fn request_id() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
