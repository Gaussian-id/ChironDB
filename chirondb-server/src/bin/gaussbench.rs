use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest, encryption};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;

#[path = "../bench/ann_benchmarks.rs"]
mod ann_benchmarks;
#[path = "../bench/beir_benchmarks.rs"]
mod beir_benchmarks;
#[path = "../bench/stable_tail.rs"]
mod stable_tail;
#[path = "../bench/structural_nodes.rs"]
mod structural_nodes;

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Run deterministic ChironDB benchmarks"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Enable application-level persistence encryption for this benchmark.
    /// The same global option applies to synthetic and official workloads.
    #[arg(long, global = true)]
    encryption_keyring_file: Option<PathBuf>,
    // Back-compat flags for the legacy single-shot synthetic benchmark.
    // When no subcommand is given these fall through to `Command::Synthetic`.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "chironbench")]
    collection: String,
    #[arg(long, default_value_t = 1_000)]
    points: usize,
    #[arg(long, default_value_t = 128)]
    dim: usize,
    #[arg(long, default_value_t = 100)]
    batch_size: usize,
    #[arg(long, default_value_t = 1_000)]
    searches: usize,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long)]
    keep_data: bool,
    #[arg(long, default_value_t = 1_000_000_000)]
    scale_projection_points: u64,
    /// P2C — opt-in flag forwarded to the spawned server. When set, the
    /// server enables intra-query parallel beam scoring on the HNSW
    /// layer-0 expansion. Default OFF to preserve the recall_golden
    /// floor on small corpora; the bench is the only place that
    /// measures the lift, so this is its on-switch.
    #[arg(long)]
    intra_query_parallel: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Legacy deterministic synthetic benchmark. Default when no subcommand
    /// is given so existing scripts keep working.
    Synthetic(SyntheticArgs),
    /// P4/P5 — bounded-streamer lifecycle gate. Streams a deterministic
    /// corpus through automatic sealed segments and records peak process RSS.
    Lifecycle(LifecycleArgs),
    /// P4 + P6 — ann-benchmarks.com Pareto recall@k vs QPS sweep. Expects
    /// a `.gbench` binary dataset (convert upstream `.hdf5` files with
    /// `.github/tools/ann-benchmarks/h5_to_gbench.py`).
    AnnBenchmarks(AnnArgs),
    /// P2 + P6 — BEIR nDCG@10 sweep across dense/sparse/hybrid fusion modes.
    /// Expects a `.beirbench.json` dataset with pre-embedded corpus and queries.
    BeirBenchmarks(BeirArgs),
    /// P0/C19 — inject and profile identity-derived structural nodes.
    StructuralNodes(structural_nodes::Args),
    /// P4 + P6 — real engine-backed multi-shard stable-tail validation.
    StableTail(StableTailArgs),
    /// P4 + P6 — inspect a committed LS-VEC segment's reproducible component
    /// bytes and exact-vector encoding.
    SegmentMemory(SegmentMemoryArgs),
    /// P4 + P5 + P6 — compact, tier, restart, and prove explicit bounded
    /// DiskANN page I/O against an ann-benchmarks corpus.
    DiskAnnCold(DiskAnnColdArgs),
}

#[derive(Debug, clap::Args)]
struct SyntheticArgs {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "chironbench")]
    collection: String,
    #[arg(long, default_value_t = 1_000)]
    points: usize,
    #[arg(long, default_value_t = 128)]
    dim: usize,
    #[arg(long, default_value_t = 100)]
    batch_size: usize,
    #[arg(long, default_value_t = 1_000)]
    searches: usize,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long)]
    keep_data: bool,
    #[arg(long, default_value_t = 1_000_000_000)]
    scale_projection_points: u64,
    /// P2C — opt-in flag passed to the spawned server. When set, the
    /// server enables intra-query parallel beam scoring on the HNSW
    /// layer-0 expansion. Default OFF to preserve the recall_golden
    /// floor on small corpora; the bench is the only place that
    /// measures the lift, so this is its on-switch.
    #[arg(long)]
    intra_query_parallel: bool,
}

#[derive(Debug, clap::Args)]
struct LifecycleArgs {
    /// Durable database directory. The 1M x 960 gate needs roughly 5 GiB.
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value = "ls_vec_lifecycle")]
    collection: String,
    #[arg(long, default_value_t = 1_000_000)]
    points: usize,
    #[arg(long, default_value_t = 960)]
    dim: usize,
    #[arg(long, default_value_t = 1_000)]
    batch_size: usize,
    #[arg(long, default_value_t = 10)]
    searches: usize,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    streamer_max_bytes: usize,
    #[arg(long, default_value_t = 7_200)]
    seal_timeout_secs: u64,
    /// Persisted index family. LS-VEC is the sole supported value.
    #[arg(long, default_value = "lsvec", value_parser = ["lsvec"])]
    index_kind: String,
}

#[derive(Debug, clap::Args)]
struct AnnArgs {
    /// Path to a .gbench binary dataset. See the Obsidian benchmark notes for the file
    /// format and conversion instructions.
    #[arg(long)]
    dataset: PathBuf,
    /// Durable database directory. When it already contains the matching
    /// ann_benchmarks collection, reuse the built index and run only queries.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Comma-separated ef_search values to sweep, e.g. "32,64,128,256,512".
    #[arg(long, value_delimiter = ',', default_values_t = [32u32, 64, 128, 256, 512])]
    ef_grid: Vec<u32>,
    /// HNSW M (neighbours per node). None = engine default (16).
    #[arg(long)]
    hnsw_m: Option<u32>,
    /// HNSW ef_construction. None = engine default (200).
    #[arg(long)]
    hnsw_ef_construction: Option<u32>,
    /// Persisted index family. Omit for the LS-VEC default.
    #[arg(long, value_parser = ["lsvec"])]
    index_kind: Option<String>,
    /// Write the JSON report to this path. Default: stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Tag the report with this git SHA. Default: "unspecified".
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
    /// Sample only the first N test queries instead of the full test set.
    /// The corpus (train set + ground truth) is unaffected -- this only
    /// trims search-phase wall time on large datasets. None = full test set.
    #[arg(long)]
    max_queries: Option<usize>,
    /// Diagnostic: force the server-wide cascade flag before search.
    /// Omit to leave the engine default (ON).
    #[arg(long)]
    cascade: Option<bool>,
    /// Query for top-K and score recall@K instead of the dataset's native
    /// ground-truth width (e.g. ann-benchmarks sift-128 bakes k=100).
    /// Industry-standard ANN reports (ann-benchmarks.com, Chroma, Qdrant)
    /// compare recall@10 — use `--k 10` for an apples-to-apples number.
    /// None = dataset's native k.
    #[arg(long)]
    k: Option<usize>,
    /// Recall contract used to derive LS-VEC's internal exact-rerank pool.
    /// This is not a public rho knob. Default = 0.97.
    #[arg(long)]
    recall_target: Option<f32>,
    /// Diagnostic: compact a reused collection into one fully sealed LS-VEC
    /// segment before measuring. This isolates the sealed cascade from the
    /// live-streamer HNSW leg.
    #[arg(long)]
    compact_reused: bool,
    /// Benchmark-only fixture: copy every official train row into this named
    /// vector field and run the official query set against that field.
    #[arg(long)]
    named_vector_copy: Option<String>,
    /// Deterministic exact filtered-ground-truth sidecar. Reports using it are
    /// custom C0
    /// augmentations, never upstream ann-benchmarks results.
    #[arg(long)]
    filter_fixture: Option<PathBuf>,
    /// C19 custom augmentation: structural rows expected in a reused state.
    /// Non-zero values always label the report as modified evidence.
    #[arg(long, default_value_t = 0)]
    expected_structural_points: usize,
    /// Measure the sequential gate only and omit the saturated diagnostic.
    #[arg(long)]
    sequential_only: bool,
}

#[derive(Debug, clap::Args)]
struct BeirArgs {
    /// Path to a `.beirbench.json` dataset with pre-embedded corpus and queries.
    #[arg(long)]
    dataset: PathBuf,
    /// Write the JSON report to this path. Default: stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Tag the report with this git SHA. Default: "unspecified".
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
    /// C19 custom identity-derived structural-node ratio.
    #[arg(long, default_value_t = 0.0)]
    structural_ratio_percent: f64,
    /// C19 sensitivity control: replace identity-derived vectors with zero.
    #[arg(long)]
    structural_negative_control: bool,
}

#[derive(Debug, clap::Args)]
struct StableTailArgs {
    /// Official `.gbench` workload used for real shard vectors and queries.
    #[arg(long)]
    dataset: PathBuf,
    /// Durable root containing one independent local Db per shard.
    #[arg(long)]
    data_dir: PathBuf,
    /// Optional train-corpus prefix for smoke runs. Omit for the full official
    /// corpus.
    #[arg(long)]
    train_points: Option<usize>,
    /// Number of official test queries per shard-count/mode. Use >=1000 for
    /// a meaningful p99.9 sample.
    #[arg(long, default_value_t = 2_000)]
    queries: usize,
    /// Comma-separated fan-out widths. Every topology independently partitions
    /// the same indexed corpus across exactly this many physical shards.
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 2, 4, 8])]
    shard_grid: Vec<usize>,
    /// Benchmark-only in-sync execution replicas per logical shard. Values
    /// greater than one exercise delayed hedging and report request
    /// amplification; this does not change a collection schema.
    #[arg(long, default_value_t = 1)]
    replicas_per_shard: usize,
    /// Long-lived closed-loop coordinator workers.
    #[arg(long, default_value_t = 10)]
    workers: usize,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long, default_value_t = 64)]
    ef_search: u32,
    #[arg(long, default_value_t = 0.95)]
    recall_target: f32,
    /// Total coordinator budget applied to budgeted fan-out.
    #[arg(long, default_value_t = 100)]
    budget_ms: u64,
    /// Explicit timer/scheduler tolerance for the product p99.9 <=
    /// budget+tolerance gate. The report also records the literal budget gate.
    #[arg(long, default_value_t = 5.0)]
    budget_tolerance_ms: f64,
    /// Safety timeout for the unbudgeted comparison; must exceed budget.
    #[arg(long, default_value_t = 2_000)]
    unbudgeted_timeout_ms: u64,
    /// Minimum deterministic Pareto queue/network delay per shard.
    #[arg(long, default_value_t = 1.0)]
    delay_base_ms: f64,
    /// Pareto tail exponent (>1).
    #[arg(long, default_value_t = 1.5)]
    delay_alpha: f64,
    /// Upper bound on the injected queue/network delay.
    #[arg(long, default_value_t = 1_000.0)]
    delay_cap_ms: f64,
    #[arg(long, default_value_t = 42)]
    delay_seed: u64,
    /// Write the machine-readable JSON report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Tag the report with the exact measured source SHA.
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
}

#[derive(Debug, clap::Args)]
struct SegmentMemoryArgs {
    /// Committed hot `searchers/sg-*` or cold `cold/sg-*` directory containing `seal.gdx`.
    #[arg(long)]
    segment_dir: PathBuf,
    /// Write the machine-readable JSON report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Tag the report with the exact inspected source SHA.
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
}

#[derive(Debug, clap::Args)]
struct DiskAnnColdArgs {
    /// Official `.gbench` corpus and ground truth.
    #[arg(long)]
    dataset: PathBuf,
    /// Existing, fully ingested ann-benchmarks database.
    #[arg(long)]
    data_dir: PathBuf,
    /// Number of official test queries. Omit for the full query set.
    #[arg(long)]
    queries: Option<usize>,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long, default_value_t = 64)]
    ef_search: u32,
    #[arg(long, default_value_t = 0.99)]
    recall_target: f32,
    /// Fail unless the detected cgroup limit is below the cold segment bytes
    /// and the measured process peak remains below that limit.
    #[arg(long)]
    require_out_of_ram: bool,
    /// Reuse an already compacted and cold-tiered LS-VEC collection. This is
    /// the serving-only mode for constrained containers; it never rebuilds
    /// the index under the memory cap.
    #[arg(long)]
    prepared_cold: bool,
    /// Write the machine-readable JSON report to this path.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Tag the report with the exact measured source SHA.
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
}

#[derive(Debug, Serialize)]
struct BenchReport {
    encryption_enabled: bool,
    peak_rss_bytes: u64,
    final_rss_bytes: u64,
    collection: String,
    points: usize,
    dim: usize,
    batch_size: usize,
    searches: usize,
    k: usize,
    write_batches: usize,
    write_points_per_second: f64,
    search_queries_per_second: f64,
    write_latency_ms: LatencyReport,
    search_latency_ms: LatencyReport,
    storage: StorageReport,
    scale_projection: ScaleProjectionReport,
}

#[derive(Debug, Serialize)]
struct LatencyReport {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

#[derive(Debug, Serialize)]
struct StorageReport {
    wal_bytes_after_write: u64,
    bytes_after_compaction: u64,
    bytes_per_vector: f64,
    write_amplification: f64,
    compaction_amplification: f64,
}

#[derive(Debug, Serialize)]
struct ScaleProjectionReport {
    target_points: u64,
    projected_compacted_bytes: f64,
    projected_compacted_gib: f64,
}

#[derive(Debug, Serialize)]
struct LifecycleReport {
    collection: String,
    index_kind: String,
    points: usize,
    dim: usize,
    batch_size: usize,
    streamer_max_bytes: usize,
    write_points_per_second: f64,
    write_elapsed_seconds: f64,
    seal_wait_seconds: f64,
    searches: usize,
    search_queries_per_second: f64,
    live_points: usize,
    sealed_segments: usize,
    peak_rss_bytes: u64,
    final_rss_bytes: u64,
    data_bytes: u64,
}

#[derive(Debug, Serialize)]
struct SegmentMemoryReport {
    segment_dir: String,
    git_sha: String,
    marker_version: u32,
    points: usize,
    dim: usize,
    primary_vector_source: String,
    duplicate_primary_files_present: bool,
    exact_vector_format_version: u32,
    exact_vector_bytes_per_component: f64,
    exact_vector_file_bytes: u64,
    exact_vector_file_bytes_per_vector: f64,
    named_vectors: Vec<NamedVectorMemory>,
    total_segment_bytes: u64,
    total_segment_bytes_per_vector: f64,
    files: Vec<SegmentFileMemory>,
}

#[derive(Debug, Serialize)]
struct SegmentFileMemory {
    name: String,
    bytes: u64,
    bytes_per_vector: f64,
}

#[derive(Debug, Serialize)]
struct NamedVectorMemory {
    name: String,
    points: usize,
    dim: usize,
    search_vector_format_version: u32,
    search_vector_bytes_per_component: f64,
    search_vector_file_bytes: u64,
    search_vector_file_bytes_per_vector: f64,
    exact_original_preserved_in_payload: bool,
}

#[derive(Debug, Serialize)]
struct DiskAnnColdReport {
    dataset: String,
    git_sha: String,
    collection: String,
    n_train: usize,
    n_test: usize,
    dim: usize,
    k: usize,
    ef_search: u32,
    recall_target: f32,
    recall_at_k: f64,
    recall_floor: f64,
    recall_floor_met: bool,
    degraded_queries: usize,
    qps: f64,
    latency_ms: LatencyReport,
    cold_segment_bytes: u64,
    diskann_artifact_bytes: u64,
    logical_f32_corpus_bytes: u64,
    process_peak_rss_bytes: u64,
    process_final_rss_bytes: u64,
    cgroup_memory_limit_bytes: Option<u64>,
    out_of_ram_verified: bool,
    explicit_page_io_verified: bool,
    prepared_cold: bool,
    page_reads_per_query: f64,
    io: chirondb::index::diskann::DiskAnnIoStats,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(path) = cli.encryption_keyring_file.as_deref() {
        let keyring = encryption::Keyring::load(path)
            .with_context(|| format!("load benchmark encryption keyring {}", path.display()))?;
        encryption::install_process_keyring(keyring, true)
            .context("enable benchmark persistence encryption")?;
    }
    let command = match cli.command {
        Some(command) => command,
        None => Command::Synthetic(SyntheticArgs {
            data_dir: cli.data_dir,
            collection: cli.collection,
            points: cli.points,
            dim: cli.dim,
            batch_size: cli.batch_size,
            searches: cli.searches,
            k: cli.k,
            keep_data: cli.keep_data,
            scale_projection_points: cli.scale_projection_points,
            intra_query_parallel: cli.intra_query_parallel,
        }),
    };
    match command {
        Command::Synthetic(args) => run_synthetic(args),
        Command::Lifecycle(args) => run_lifecycle(args),
        Command::AnnBenchmarks(args) => run_ann_benchmarks(args),
        Command::BeirBenchmarks(args) => run_beir_benchmarks(args),
        Command::StructuralNodes(args) => structural_nodes::run(args),
        Command::StableTail(args) => run_stable_tail(args),
        Command::SegmentMemory(args) => run_segment_memory(args),
        Command::DiskAnnCold(args) => run_diskann_cold(args),
    }
}

fn run_ann_benchmarks(args: AnnArgs) -> Result<()> {
    let config = ann_benchmarks::RunConfig {
        dataset_path: args.dataset,
        data_dir: args.data_dir,
        ef_grid: args.ef_grid,
        hnsw_m: args.hnsw_m,
        hnsw_ef_construction: args.hnsw_ef_construction,
        index_kind: args.index_kind,
        output: args.output,
        git_sha: args.git_sha,
        max_queries: args.max_queries,
        cascade: args.cascade,
        k_override: args.k,
        recall_target: args.recall_target,
        compact_reused: args.compact_reused,
        named_vector_copy: args.named_vector_copy,
        filter_fixture: args.filter_fixture,
        expected_structural_points: args.expected_structural_points,
        sequential_only: args.sequential_only,
    };
    let _report = ann_benchmarks::run(&config)?;
    Ok(())
}

fn run_beir_benchmarks(args: BeirArgs) -> Result<()> {
    let config = beir_benchmarks::RunConfig {
        dataset_path: args.dataset,
        output: args.output,
        git_sha: args.git_sha,
        structural_ratio_percent: args.structural_ratio_percent,
        structural_negative_control: args.structural_negative_control,
    };
    let _report = beir_benchmarks::run(&config)?;
    Ok(())
}

fn run_stable_tail(args: StableTailArgs) -> Result<()> {
    let config = stable_tail::RunConfig {
        dataset_path: args.dataset,
        data_dir: args.data_dir,
        train_points: args.train_points,
        query_count: args.queries,
        shard_counts: args.shard_grid,
        replicas_per_shard: args.replicas_per_shard,
        workers: args.workers,
        k: args.k,
        ef_search: args.ef_search,
        recall_target: args.recall_target,
        budget_ms: args.budget_ms,
        budget_tolerance_ms: args.budget_tolerance_ms,
        unbudgeted_timeout_ms: args.unbudgeted_timeout_ms,
        delay_base_ms: args.delay_base_ms,
        delay_alpha: args.delay_alpha,
        delay_cap_ms: args.delay_cap_ms,
        delay_seed: args.delay_seed,
        output: args.output,
        git_sha: args.git_sha,
    };
    let _report = stable_tail::run(&config)?;
    Ok(())
}

fn run_segment_memory(args: SegmentMemoryArgs) -> Result<()> {
    let report = segment_memory_report(&args.segment_dir, args.git_sha)?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = args.output {
        fs::write(&output, format!("{json}\n"))
            .with_context(|| format!("write segment-memory report {}", output.display()))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

fn run_diskann_cold(args: DiskAnnColdArgs) -> Result<()> {
    const COLLECTION: &str = "ann_benchmarks";
    const RECALL_FLOOR: f64 = 0.95;

    anyhow::ensure!(
        (0.5..=1.0).contains(&args.recall_target) && !args.recall_target.is_nan(),
        "recall_target must be in 0.5..=1.0"
    );
    let mut dataset = ann_benchmarks::MmapDataset::open(&args.dataset)?;
    dataset.limit_queries(args.queries);
    let query_k = args.k.min(dataset.k);
    anyhow::ensure!(query_k > 0, "k must be greater than zero");
    let rss_sampler = RssSampler::start();

    // The gate owns the normal compaction/tiering lifecycle, then drops every
    // hot handle. Reopen is required: cold-specific page I/O is selected from
    // durable placement, never toggled in a live index.
    if !args.prepared_cold {
        let db = Db::open(&args.data_dir).context("open DiskANN preparation database")?;
        let collection = db
            .list_collections()
            .into_iter()
            .find(|collection| collection.name == COLLECTION)
            .context("ann_benchmarks collection is missing")?;
        anyhow::ensure!(
            collection.vector_dim == dataset.dim
                && collection.metric == dataset.metric.to_distance()
                && collection.index_kind.as_deref() == Some("lsvec"),
            "ann_benchmarks collection does not match the LS-VEC dataset"
        );
        anyhow::ensure!(
            db.count(COLLECTION, None)?.count == dataset.train_count,
            "ann_benchmarks collection point count does not match the dataset"
        );
        db.compact_collection(COLLECTION)
            .context("compact collection into the current segment format")?;
        db.tier_collection_to_cold(COLLECTION)
            .context("tier committed segment to cold storage")?;
    }

    let db = Db::open(&args.data_dir).context("reopen cold DiskANN database")?;
    let initial_io = db.diskann_io_stats(COLLECTION)?;
    anyhow::ensure!(
        initial_io.active_segments > 0,
        "no cold LS-VEC DiskANN segment became active after restart"
    );
    db.reset_diskann_io_stats(COLLECTION)?;

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(dataset.test_count);
    let mut recall_sum = 0.0_f64;
    let mut degraded_queries = 0usize;
    for query_index in 0..dataset.test_count {
        if query_index > 0 && query_index.is_multiple_of(1_000) {
            eprintln!(
                "DiskANN cold progress {query_index}/{} elapsed={:.1}s",
                dataset.test_count,
                started.elapsed().as_secs_f64()
            );
        }
        let query_started = Instant::now();
        let response = db.search(
            COLLECTION,
            SearchRequest {
                graph: None,
                vector: dataset.test_vector(query_index),
                vector_name: None,
                k: query_k,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: Some(args.ef_search),
                recall_target: Some(args.recall_target),
                with_payload: Some(false),
            },
        )?;
        latencies.push(query_started.elapsed());
        degraded_queries += usize::from(response.degraded);
        let hits = response
            .hits
            .iter()
            .filter_map(|hit| hit.id.parse::<u32>().ok())
            .take(query_k)
            .collect::<std::collections::HashSet<_>>();
        let truth = dataset
            .neighbors(query_index)
            .into_iter()
            .take(query_k)
            .collect::<std::collections::HashSet<_>>();
        recall_sum += hits.intersection(&truth).count() as f64 / query_k as f64;
    }
    let elapsed = started.elapsed();
    let io = db.diskann_io_stats(COLLECTION)?;
    let final_rss = rss_bytes();
    drop(db);
    let peak_rss = rss_sampler.finish();

    let cold_dir = args
        .data_dir
        .join("collections")
        .join(COLLECTION)
        .join("cold");
    let cold_segment_bytes = dir_size(&cold_dir)?;
    let diskann_artifact_bytes =
        named_file_bytes(&cold_dir, chirondb::index::diskann::DISKANN_FILE)?;
    let memory_limit = cgroup_memory_limit_bytes();
    let recall = recall_sum / dataset.test_count.max(1) as f64;
    let explicit_page_io_verified =
        io.active_segments > 0 && io.physical_page_reads > 0 && io.page_read_errors == 0;
    let out_of_ram_verified = memory_limit
        .is_some_and(|limit| cold_segment_bytes > limit && peak_rss > 0 && peak_rss < limit);
    let report = DiskAnnColdReport {
        dataset: args.dataset.display().to_string(),
        git_sha: args.git_sha,
        collection: COLLECTION.to_string(),
        n_train: dataset.train_count,
        n_test: dataset.test_count,
        dim: dataset.dim,
        k: query_k,
        ef_search: args.ef_search,
        recall_target: args.recall_target,
        recall_at_k: recall,
        recall_floor: RECALL_FLOOR,
        recall_floor_met: recall >= RECALL_FLOOR,
        degraded_queries,
        qps: dataset.test_count as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
        latency_ms: latency_report(&latencies),
        cold_segment_bytes,
        diskann_artifact_bytes,
        logical_f32_corpus_bytes: logical_vector_bytes(dataset.train_count, dataset.dim),
        process_peak_rss_bytes: peak_rss,
        process_final_rss_bytes: final_rss,
        cgroup_memory_limit_bytes: memory_limit,
        out_of_ram_verified,
        explicit_page_io_verified,
        prepared_cold: args.prepared_cold,
        page_reads_per_query: io.physical_page_reads as f64 / dataset.test_count.max(1) as f64,
        io,
    };
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = args.output {
        fs::write(&output, format!("{json}\n"))
            .with_context(|| format!("write DiskANN cold report {}", output.display()))?;
    } else {
        println!("{json}");
    }
    anyhow::ensure!(
        report.recall_floor_met,
        "cold DiskANN recall@{} {:.5} is below {:.2}",
        query_k,
        recall,
        RECALL_FLOOR
    );
    anyhow::ensure!(
        report.explicit_page_io_verified,
        "cold DiskANN did not produce clean explicit page-I/O evidence"
    );
    anyhow::ensure!(
        !args.require_out_of_ram || report.out_of_ram_verified,
        "cold segment did not exceed the cgroup memory limit with bounded process RSS"
    );
    Ok(())
}

fn segment_memory_report(segment_dir: &Path, git_sha: String) -> Result<SegmentMemoryReport> {
    let marker = chirondb::seal::read_marker(&segment_dir.join(chirondb::seal::SEAL_FILE))
        .with_context(|| format!("read segment marker {}", segment_dir.display()))?;
    anyhow::ensure!(
        marker.points > 0,
        "segment-memory requires a non-empty segment"
    );
    let store = chirondb::seal::V4Store::open(segment_dir)
        .with_context(|| format!("open segment store {}", segment_dir.display()))?;
    let mut files = fs::read_dir(segment_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            metadata.is_file().then(|| SegmentFileMemory {
                name: entry.file_name().to_string_lossy().into_owned(),
                bytes: metadata.len(),
                bytes_per_vector: metadata.len() as f64 / marker.points as f64,
            })
        })
        .collect::<Vec<_>>();
    files.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let total_segment_bytes = files.iter().map(|file| file.bytes).sum();
    let exact_vector_file_bytes = files
        .iter()
        .find(|file| file.name == chirondb::seal::VECTOR_FILE)
        .map_or(0, |file| file.bytes);
    let diskann_present = files
        .iter()
        .any(|file| file.name == chirondb::index::diskann::DISKANN_FILE);
    let vamana_present = files
        .iter()
        .any(|file| file.name == chirondb::index::vamana::VAMANA_SEGMENT_FILE);
    let named_vectors = chirondb::seal::inspect_named_vector_storage(segment_dir)?
        .into_iter()
        .map(|stats| NamedVectorMemory {
            name: stats.name,
            points: stats.points,
            dim: stats.dim,
            search_vector_format_version: stats.search_vector_format_version,
            search_vector_bytes_per_component: stats.search_vector_bytes_per_component,
            search_vector_file_bytes: stats.search_vector_file_bytes,
            search_vector_file_bytes_per_vector: stats.search_vector_file_bytes_per_vector,
            exact_original_preserved_in_payload: stats.exact_original_preserved_in_payload,
        })
        .collect();
    Ok(SegmentMemoryReport {
        segment_dir: segment_dir.display().to_string(),
        git_sha,
        marker_version: marker.version,
        points: marker.points,
        dim: marker.vector_dim,
        primary_vector_source: if matches!(marker.version, 7 | 9) {
            chirondb::index::diskann::DISKANN_FILE.to_string()
        } else {
            chirondb::seal::VECTOR_FILE.to_string()
        },
        duplicate_primary_files_present: diskann_present
            && (exact_vector_file_bytes > 0 || vamana_present),
        exact_vector_format_version: store.exact_vector_format_version(),
        exact_vector_bytes_per_component: store.exact_vector_bytes_per_component(),
        exact_vector_file_bytes,
        exact_vector_file_bytes_per_vector: exact_vector_file_bytes as f64 / marker.points as f64,
        named_vectors,
        total_segment_bytes,
        total_segment_bytes_per_vector: total_segment_bytes as f64 / marker.points as f64,
        files,
    })
}

fn run_lifecycle(args: LifecycleArgs) -> Result<()> {
    fs::create_dir_all(&args.data_dir).context("create lifecycle data directory")?;
    let rss_sampler = RssSampler::start();
    let db = Db::open(&args.data_dir).context("open lifecycle database")?;
    db.create_collection(CollectionConfig {
        name: args.collection.clone(),
        vector_dim: args.dim,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: Some(args.index_kind.clone()),
        streamer_max_bytes: args.streamer_max_bytes,
    })
    .context("create lifecycle collection")?;

    let batch_size = args.batch_size.max(1);
    let write_started = Instant::now();
    for batch_start in (0..args.points).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(args.points);
        loop {
            let points = (batch_start..batch_end)
                .map(|i| Point {
                    id: format!("p{i:08}"),
                    vector: deterministic_vector(i as u64, args.dim),
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({"bucket": i % 16}),
                })
                .collect();
            match db.upsert(&args.collection, points) {
                Ok(_) => break,
                Err(chirondb::GaussError::ResourceExhausted(_)) => {
                    anyhow::ensure!(
                        Instant::now()
                            < write_started + Duration::from_secs(args.seal_timeout_secs),
                        "lifecycle admission remained resource-exhausted for {} seconds",
                        args.seal_timeout_secs
                    );
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("upsert lifecycle batch ending at {batch_end}"));
                }
            }
        }
    }
    let write_elapsed = write_started.elapsed();

    let seal_started = Instant::now();
    let seal_deadline = seal_started + Duration::from_secs(args.seal_timeout_secs);
    while db
        .seal_in_progress(&args.collection)
        .context("read lifecycle seal status")?
    {
        anyhow::ensure!(
            Instant::now() < seal_deadline,
            "automatic segment seal exceeded {} seconds",
            args.seal_timeout_secs
        );
        thread::sleep(Duration::from_millis(100));
    }
    let seal_wait = seal_started.elapsed();

    let live_points = db
        .count(&args.collection, None)
        .context("count lifecycle collection")?
        .count;
    anyhow::ensure!(
        live_points == args.points,
        "lifecycle count mismatch: expected {}, got {live_points}",
        args.points
    );

    let search_started = Instant::now();
    for i in 0..args.searches {
        let response = db
            .search(
                &args.collection,
                SearchRequest {
                    graph: None,
                    vector: deterministic_vector(i as u64, args.dim),
                    vector_name: None,
                    k: args.k,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .context("search lifecycle collection")?;
        anyhow::ensure!(
            args.k == 0 || !response.hits.is_empty(),
            "lifecycle search returned no hits"
        );
    }
    let search_elapsed = search_started.elapsed();
    let peak_rss_bytes = rss_sampler.finish();
    let report = LifecycleReport {
        collection: args.collection.clone(),
        index_kind: args.index_kind,
        points: args.points,
        dim: args.dim,
        batch_size,
        streamer_max_bytes: args.streamer_max_bytes,
        write_points_per_second: args.points as f64 / write_elapsed.as_secs_f64().max(f64::EPSILON),
        write_elapsed_seconds: write_elapsed.as_secs_f64(),
        seal_wait_seconds: seal_wait.as_secs_f64(),
        searches: args.searches,
        search_queries_per_second: args.searches as f64
            / search_elapsed.as_secs_f64().max(f64::EPSILON),
        live_points,
        sealed_segments: count_sealed_segments(&args.data_dir)?,
        peak_rss_bytes,
        final_rss_bytes: rss_bytes(),
        data_bytes: dir_size(&args.data_dir)?,
    };
    anyhow::ensure!(
        report.sealed_segments > 0,
        "automatic lifecycle produced no sealed segment"
    );
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_synthetic(args: SyntheticArgs) -> Result<()> {
    let temp_dir = if args.data_dir.is_none() && !args.keep_data {
        Some(TempDir::new().context("create temporary benchmark data directory")?)
    } else {
        None
    };
    let data_dir = args
        .data_dir
        .as_deref()
        .or_else(|| temp_dir.as_ref().map(|dir| dir.path()))
        .context("benchmark data directory")?;

    let rss_sampler = RssSampler::start();
    let db = Db::open(data_dir).context("open benchmark database")?;
    let config = CollectionConfig {
        name: args.collection.clone(),
        vector_dim: args.dim,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    };
    db.create_collection(config)
        .context("create benchmark collection")?;

    let mut write_latencies = Vec::new();
    let write_started = Instant::now();
    for batch_start in (0..args.points).step_by(args.batch_size.max(1)) {
        let batch_end = (batch_start + args.batch_size.max(1)).min(args.points);
        let points = (batch_start..batch_end)
            .map(|i| Point {
                id: format!("p{i:08}"),
                vector: deterministic_vector(i as u64, args.dim),
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"bucket": i % 16}),
            })
            .collect();
        let started = Instant::now();
        db.upsert(&args.collection, points)
            .context("upsert benchmark batch")?;
        write_latencies.push(started.elapsed());
    }
    let write_elapsed = write_started.elapsed();
    let wal_bytes_after_write = dir_size(data_dir)?;

    let mut search_latencies = Vec::with_capacity(args.searches);
    let search_started = Instant::now();
    for i in 0..args.searches {
        let request = SearchRequest {
            graph: None,
            vector: deterministic_vector(i as u64, args.dim),
            vector_name: None,
            k: args.k,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        };
        let started = Instant::now();
        db.search(&args.collection, request)
            .context("search benchmark collection")?;
        search_latencies.push(started.elapsed());
    }
    let search_elapsed = search_started.elapsed();
    db.compact_collection(&args.collection)
        .context("compact benchmark collection for footprint metrics")?;
    let bytes_after_compaction = dir_size(data_dir)?;

    let bytes_per_vector = bytes_after_compaction as f64 / args.points.max(1) as f64;
    let final_rss_bytes = rss_bytes();
    let peak_rss_bytes = rss_sampler.finish();
    let report = BenchReport {
        encryption_enabled: encryption::encryption_enabled(),
        peak_rss_bytes,
        final_rss_bytes,
        collection: args.collection,
        points: args.points,
        dim: args.dim,
        batch_size: args.batch_size.max(1),
        searches: args.searches,
        k: args.k,
        write_batches: write_latencies.len(),
        write_points_per_second: args.points as f64 / write_elapsed.as_secs_f64().max(f64::EPSILON),
        search_queries_per_second: args.searches as f64
            / search_elapsed.as_secs_f64().max(f64::EPSILON),
        write_latency_ms: latency_report(&write_latencies),
        search_latency_ms: latency_report(&search_latencies),
        storage: StorageReport {
            wal_bytes_after_write,
            bytes_after_compaction,
            bytes_per_vector,
            write_amplification: wal_bytes_after_write as f64
                / logical_vector_bytes(args.points, args.dim).max(1) as f64,
            compaction_amplification: bytes_after_compaction as f64
                / wal_bytes_after_write.max(1) as f64,
        },
        scale_projection: ScaleProjectionReport {
            target_points: args.scale_projection_points,
            projected_compacted_bytes: projected_compacted_bytes(
                bytes_per_vector,
                args.scale_projection_points,
            ),
            projected_compacted_gib: projected_compacted_gib(
                bytes_per_vector,
                args.scale_projection_points,
            ),
        },
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn deterministic_vector(seed: u64, dim: usize) -> Vec<f32> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..dim)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let value = ((state >> 32) as u32) as f32 / u32::MAX as f32;
            value * 2.0 - 1.0
        })
        .collect()
}

struct RssSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RssSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(rss_bytes()));
        let thread_stop = Arc::clone(&stop);
        let thread_peak = Arc::clone(&peak);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                thread_peak.fetch_max(rss_bytes(), Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
            }
            thread_peak.fetch_max(rss_bytes(), Ordering::Relaxed);
        });
        Self {
            stop,
            peak,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.peak.load(Ordering::Relaxed)
    }
}

impl Drop for RssSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|contents| {
                contents
                    .split_whitespace()
                    .nth(1)
                    .and_then(|pages| pages.parse::<u64>().ok())
            })
            .unwrap_or(0)
            .saturating_mul(4096)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|rss| rss.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

fn count_sealed_segments(data_dir: &Path) -> Result<usize> {
    let collections = data_dir.join("collections");
    if !collections.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for collection in fs::read_dir(collections)? {
        let searchers = collection?.path().join("searchers");
        if !searchers.exists() {
            continue;
        }
        for segment in fs::read_dir(searchers)? {
            let segment = segment?;
            let name = segment.file_name();
            let name = name.to_string_lossy();
            if segment.file_type()?.is_dir()
                && (name.starts_with("sg-v4-")
                    || name.starts_with("sg-v5-")
                    || name.starts_with("sg-v6-"))
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn latency_report(values: &[Duration]) -> LatencyReport {
    LatencyReport {
        p50: percentile_ms(values, 0.50),
        p95: percentile_ms(values, 0.95),
        p99: percentile_ms(values, 0.99),
        max: values
            .iter()
            .copied()
            .max()
            .map(duration_ms)
            .unwrap_or_default(),
    }
}

fn percentile_ms(values: &[Duration], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    duration_ms(sorted[rank.min(sorted.len() - 1)])
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}

fn named_file_bytes(path: &Path, file_name: &str) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += named_file_bytes(&entry.path(), file_name)?;
        } else if entry.file_name() == std::ffi::OsStr::new(file_name) {
            total += metadata.len();
        }
    }
    Ok(total)
}

fn cgroup_memory_limit_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/sys/fs/cgroup/memory.max")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .or_else(|| {
                fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
                    .ok()
                    .and_then(|value| value.trim().parse::<u64>().ok())
            })
            .filter(|limit| *limit < u64::MAX / 2)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn logical_vector_bytes(points: usize, dim: usize) -> u64 {
    points as u64 * dim as u64 * std::mem::size_of::<f32>() as u64
}

fn projected_compacted_bytes(bytes_per_vector: f64, target_points: u64) -> f64 {
    bytes_per_vector * target_points as f64
}

fn projected_compacted_gib(bytes_per_vector: f64, target_points: u64) -> f64 {
    projected_compacted_bytes(bytes_per_vector, target_points) / 1024.0_f64.powi(3)
}

#[cfg(test)]
mod tests {
    use super::{
        DiskAnnColdArgs, deterministic_vector, logical_vector_bytes, percentile_ms,
        projected_compacted_bytes, projected_compacted_gib, run_diskann_cold,
        segment_memory_report,
    };
    use chirondb::{CollectionConfig, Db, DistanceMetric, Point, seal};
    use serde_json::json;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn deterministic_vectors_are_stable_and_dimensioned() {
        assert_eq!(deterministic_vector(7, 4), deterministic_vector(7, 4));
        assert_eq!(deterministic_vector(7, 4).len(), 4);
        assert_ne!(deterministic_vector(7, 4), deterministic_vector(8, 4));
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let values = [1_u64, 2, 3, 4, 5]
            .into_iter()
            .map(Duration::from_millis)
            .collect::<Vec<_>>();
        assert_eq!(percentile_ms(&values, 0.50), 3.0);
        assert_eq!(percentile_ms(&values, 0.95), 5.0);
        assert_eq!(percentile_ms(&values, 0.99), 5.0);
    }

    #[test]
    fn logical_vector_bytes_counts_f32_payload() {
        assert_eq!(logical_vector_bytes(10, 3), 120);
    }

    #[test]
    fn scale_projection_uses_measured_bytes_per_vector() {
        assert_eq!(projected_compacted_bytes(512.0, 1_000), 512_000.0);
        assert!((projected_compacted_gib(1024.0, 1024 * 1024) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn segment_memory_reports_actual_v6_component_bytes() {
        let temp = TempDir::new().unwrap();
        let segment_dir = temp.path().join("segment");
        let points = (0..8)
            .map(|ordinal| Point {
                id: ordinal.to_string(),
                vector: vec![ordinal as f32 / 7.0; 16],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({}),
            })
            .collect::<Vec<_>>();
        seal::build_segment(
            points.as_slice(),
            &segment_dir,
            seal::SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();

        let report = segment_memory_report(&segment_dir, "test-sha".to_string()).unwrap();
        assert_eq!(report.git_sha, "test-sha");
        assert_eq!(report.marker_version, 6);
        assert_eq!(report.primary_vector_source, seal::VECTOR_FILE);
        assert!(report.duplicate_primary_files_present);
        assert_eq!(report.exact_vector_format_version, 5);
        assert_eq!(report.exact_vector_bytes_per_component, 2.25);
        assert_eq!(report.points, 8);
        assert_eq!(report.dim, 16);
        assert!(
            report
                .files
                .iter()
                .any(|file| file.name == seal::VECTOR_FILE)
        );
        assert!(report.total_segment_bytes >= report.exact_vector_file_bytes);

        seal::thin_algorithm2_segment_for_cold(&segment_dir).unwrap();
        let cold_report = segment_memory_report(&segment_dir, "test-sha".to_string()).unwrap();
        assert_eq!(cold_report.marker_version, 7);
        assert_eq!(
            cold_report.primary_vector_source,
            chirondb::index::diskann::DISKANN_FILE
        );
        assert!(!cold_report.duplicate_primary_files_present);
        assert_eq!(cold_report.exact_vector_file_bytes, 0);
    }

    #[test]
    fn segment_memory_reports_v8_named_rows_and_cold_v9_continuity() {
        let temp = TempDir::new().unwrap();
        let segment_dir = temp.path().join("named-segment");
        let points = (0..8)
            .map(|ordinal| {
                let mut point = Point {
                    id: ordinal.to_string(),
                    vector: vec![ordinal as f32 / 7.0; 16],
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: json!({}),
                };
                point
                    .vectors
                    .insert("image".to_string(), vec![ordinal as f32; 16]);
                point
            })
            .collect::<Vec<_>>();
        seal::build_segment(
            points.as_slice(),
            &segment_dir,
            seal::SealConfig {
                vector_dim: 16,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: seal::SealIndexKind::Algorithm2,
                base_lsn: 0,
                end_lsn: 1,
            },
        )
        .unwrap();

        let report = segment_memory_report(&segment_dir, "test-sha".to_string()).unwrap();
        assert_eq!(report.marker_version, 8);
        assert_eq!(report.named_vectors.len(), 1);
        let named = &report.named_vectors[0];
        assert_eq!(named.name, "image");
        assert_eq!(named.points, 8);
        assert_eq!(named.dim, 16);
        assert_eq!(named.search_vector_format_version, 5);
        assert_eq!(named.search_vector_bytes_per_component, 2.25);
        assert_eq!(named.search_vector_file_bytes, 24 + 8 * (4 + 16 * 2));
        assert!(named.exact_original_preserved_in_payload);

        seal::thin_algorithm2_segment_for_cold(&segment_dir).unwrap();
        let cold_report = segment_memory_report(&segment_dir, "test-sha".to_string()).unwrap();
        assert_eq!(cold_report.marker_version, 9);
        assert_eq!(cold_report.named_vectors.len(), 1);
        assert_eq!(
            cold_report.named_vectors[0].search_vector_file_bytes,
            named.search_vector_file_bytes
        );
        assert!(!cold_report.duplicate_primary_files_present);
    }

    #[test]
    fn diskann_cold_command_smoke_proves_restart_io_and_recall() {
        let temp = TempDir::new().unwrap();
        let dataset_path = temp.path().join("tiny.gbench");
        let data_dir = temp.path().join("db");
        let output = temp.path().join("report.json");
        let train = (0..64)
            .map(|ordinal| vec![ordinal as f32, (ordinal % 7) as f32])
            .collect::<Vec<_>>();
        let test = (0..10)
            .map(|ordinal| train[ordinal].clone())
            .collect::<Vec<_>>();
        let neighbors = test
            .iter()
            .map(|query| {
                let mut ranked = train
                    .iter()
                    .enumerate()
                    .map(|(ordinal, vector)| {
                        (
                            vector
                                .iter()
                                .zip(query)
                                .map(|(left, right)| (left - right).powi(2))
                                .sum::<f32>(),
                            ordinal as u32,
                        )
                    })
                    .collect::<Vec<_>>();
                ranked.sort_unstable_by(|left, right| {
                    left.0
                        .total_cmp(&right.0)
                        .then_with(|| left.1.cmp(&right.1))
                });
                ranked.into_iter().take(10).map(|(_, id)| id).collect()
            })
            .collect::<Vec<Vec<u32>>>();
        super::ann_benchmarks::write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            2,
            10,
            super::ann_benchmarks::BenchMetric::L2,
        )
        .unwrap();

        let db = Db::open(&data_dir).unwrap();
        db.create_collection(CollectionConfig {
            name: "ann_benchmarks".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::L2,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: Default::default(),
            named_vector_dims: Default::default(),
            hnsw_m: Some(16),
            hnsw_ef_construction: Some(200),
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: Some("lsvec".to_string()),
            streamer_max_bytes: 1024 * 1024,
        })
        .unwrap();
        db.upsert(
            "ann_benchmarks",
            train
                .into_iter()
                .enumerate()
                .map(|(ordinal, vector)| Point {
                    id: ordinal.to_string(),
                    vector,
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::Value::Null,
                })
                .collect(),
        )
        .unwrap();
        drop(db);

        run_diskann_cold(DiskAnnColdArgs {
            dataset: dataset_path,
            data_dir: data_dir.clone(),
            queries: None,
            k: 10,
            ef_search: 64,
            recall_target: 0.99,
            require_out_of_ram: false,
            prepared_cold: false,
            output: Some(output.clone()),
            git_sha: "smoke-sha".to_string(),
        })
        .unwrap();

        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(report["git_sha"], "smoke-sha");
        assert_eq!(report["recall_floor_met"], true);
        assert_eq!(report["explicit_page_io_verified"], true);
        assert!(report["io"]["physical_page_reads"].as_u64().unwrap() > 0);
        assert_eq!(report["io"]["page_read_errors"], 0);

        let prepared_output = temp.path().join("prepared-report.json");
        run_diskann_cold(DiskAnnColdArgs {
            dataset: temp.path().join("tiny.gbench"),
            data_dir,
            queries: Some(2),
            k: 10,
            ef_search: 64,
            recall_target: 0.99,
            require_out_of_ram: false,
            prepared_cold: true,
            output: Some(prepared_output.clone()),
            git_sha: "prepared-sha".to_string(),
        })
        .unwrap();
        let prepared: serde_json::Value =
            serde_json::from_slice(&std::fs::read(prepared_output).unwrap()).unwrap();
        assert_eq!(prepared["prepared_cold"], true);
        assert_eq!(prepared["explicit_page_io_verified"], true);
    }
}
