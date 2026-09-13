//! P4 + P6 — real engine-backed multi-shard stable-tail benchmark.
//!
//! Uses independent local `Db` instances as shard holders, official
//! `.gbench` vectors as the workload, bounded closed-loop coordinators, and a
//! deterministic Pareto delay model for the queue/network component. The
//! benchmark compares unbudgeted fan-out with the production coordinator's
//! budget/cancellation path across increasing shard counts.

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chirondb::{
    CollectionConfig, Db, GaussError, Point, SearchRequest, SearchResponse,
    cluster::{ShardClient, fan_out_search, fan_out_search_replicated},
};
use serde::Serialize;

use super::ann_benchmarks::{BenchMetric, MmapDataset};

const COLLECTION: &str = "stable_tail";
const STABLE_TAIL_RATIO_LIMIT: f64 = 2.0;
const BLOCKING_QUIESCE_TIMEOUT: Duration = Duration::from_secs(1);
const REPLICA_HEDGE_BUDGET_DIVISOR: u64 = 10;

#[derive(Debug)]
pub struct RunConfig {
    pub dataset_path: PathBuf,
    pub data_dir: PathBuf,
    pub train_points: Option<usize>,
    pub query_count: usize,
    pub shard_counts: Vec<usize>,
    pub replicas_per_shard: usize,
    pub workers: usize,
    pub k: usize,
    pub ef_search: u32,
    pub recall_target: f32,
    pub budget_ms: u64,
    pub budget_tolerance_ms: f64,
    pub unbudgeted_timeout_ms: u64,
    pub delay_base_ms: f64,
    pub delay_alpha: f64,
    pub delay_cap_ms: f64,
    pub delay_seed: u64,
    pub output: Option<PathBuf>,
    pub git_sha: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailMode {
    Unbudgeted,
    Budgeted,
}

#[derive(Debug, Serialize)]
pub struct StableTailReport {
    pub schema_version: u32,
    pub dataset: String,
    pub git_sha: String,
    pub source_train_points: usize,
    pub indexed_train_points: usize,
    pub source_test_queries: usize,
    pub measured_queries: usize,
    pub dim: usize,
    pub k: usize,
    pub metric: BenchMetric,
    pub max_shards: usize,
    pub replicas_per_shard: usize,
    pub replica_policy: String,
    pub replica_fixture: String,
    pub total_topology_shards: usize,
    pub reused_topology_shards: usize,
    pub workers: usize,
    pub runtime_threads: usize,
    pub ef_search: u32,
    pub request_recall_target: f32,
    pub load_model: String,
    pub corpus_policy: String,
    pub budget_ms: u64,
    pub budget_tolerance_ms: f64,
    pub unbudgeted_timeout_ms: u64,
    pub delay_model: DelayModel,
    pub hardware: String,
    pub stable_tail_ratio_limit: f64,
    pub stable_tail_ratio_gate_passed: bool,
    pub literal_budget_gate_passed: bool,
    pub budget_gate_passed: bool,
    pub blocking_quiescence_timeout_ms: u64,
    pub blocking_quiescence_gate_passed: bool,
    pub unbudgeted_p999_growth_ratio: f64,
    pub points: Vec<TailPoint>,
}

#[derive(Debug, Serialize)]
pub struct DelayModel {
    pub distribution: String,
    pub base_ms: f64,
    pub alpha: f64,
    pub cap_ms: f64,
    pub seed: u64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct TailPoint {
    pub shards: usize,
    pub indexed_train_points: usize,
    pub mode: TailMode,
    pub coordinator_timeout_ms: u64,
    pub hedge_delay_ms: Option<u64>,
    pub qps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
    pub p99_to_p50_ratio: f64,
    pub degraded_query_rate: f64,
    pub over_budget_rate: f64,
    pub over_budget_with_tolerance_rate: f64,
    pub literal_budget_compliant: Option<bool>,
    pub budget_compliant: Option<bool>,
    pub baseline_shard_requests: usize,
    pub shard_requests_started: usize,
    pub hedged_replica_requests_started: usize,
    pub replica_request_amplification: f64,
    pub queries_with_blocking_searches_after_response: usize,
    pub max_blocking_searches_after_response: usize,
    pub blocking_searches_active_at_mode_end: usize,
    pub blocking_search_quiesce_ms: f64,
    pub blocking_searches_active_after_quiesce: usize,
}

#[derive(Clone)]
struct EngineShard {
    db: Arc<Db>,
}

struct EngineShardClient {
    shard: EngineShard,
    delay: Duration,
    shard_requests_started: Arc<AtomicUsize>,
    active_blocking_searches: Arc<AtomicUsize>,
    query_active_blocking_searches: Arc<AtomicUsize>,
}

struct CancelBlockingSearchOnDrop(Arc<AtomicBool>);

impl Drop for CancelBlockingSearchOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct ActiveBlockingSearch {
    all_queries: Arc<AtomicUsize>,
    query: Arc<AtomicUsize>,
}

impl ActiveBlockingSearch {
    fn new(all_queries: Arc<AtomicUsize>, query: Arc<AtomicUsize>) -> Self {
        all_queries.fetch_add(1, Ordering::AcqRel);
        query.fetch_add(1, Ordering::AcqRel);
        Self { all_queries, query }
    }
}

impl Drop for ActiveBlockingSearch {
    fn drop(&mut self) {
        self.all_queries.fetch_sub(1, Ordering::AcqRel);
        self.query.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ShardClient for EngineShardClient {
    async fn search(self, request: SearchRequest) -> chirondb::error::Result<SearchResponse> {
        self.shard_requests_started.fetch_add(1, Ordering::AcqRel);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let db = Arc::clone(&self.shard.db);
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelBlockingSearchOnDrop(Arc::clone(&cancelled));
        let active_search = ActiveBlockingSearch::new(
            self.active_blocking_searches,
            self.query_active_blocking_searches,
        );
        tokio::task::spawn_blocking(move || {
            let _active_search = active_search;
            db.search_with_cancellation(COLLECTION, request, &cancelled)
        })
        .await
        .map_err(|error| {
            GaussError::InvalidRequest(format!("stable-tail shard task failed: {error}"))
        })?
    }
}

#[derive(Clone, Copy)]
struct QuerySample {
    elapsed: Duration,
    degraded: bool,
    active_blocking_searches_at_response: usize,
}

struct LoadOutcome {
    samples: Vec<QuerySample>,
    response_window_elapsed: Duration,
    active_after_responses: usize,
    quiesce_elapsed: Duration,
    active_after_quiesce: usize,
    shard_requests_started: usize,
}

struct SummaryContext {
    budget_ms: u64,
    tolerance_ms: f64,
    indexed_train_points: usize,
    replicas_per_shard: usize,
    coordinator_timeout_ms: u64,
}

pub fn run(config: &RunConfig) -> Result<StableTailReport> {
    let mut shard_counts = config.shard_counts.clone();
    shard_counts.sort_unstable();
    shard_counts.dedup();
    anyhow::ensure!(!shard_counts.is_empty(), "shard grid must not be empty");
    anyhow::ensure!(
        shard_counts.iter().all(|&count| count > 0),
        "shard counts must be positive"
    );
    anyhow::ensure!(config.workers > 0, "workers must be positive");
    anyhow::ensure!(
        config.replicas_per_shard > 0,
        "replicas per shard must be positive"
    );
    anyhow::ensure!(config.query_count > 0, "query count must be positive");
    anyhow::ensure!(
        config.train_points.is_none_or(|points| points > 0),
        "train points must be positive when provided"
    );
    anyhow::ensure!(config.k > 0, "top-k must be positive");
    anyhow::ensure!(
        config.recall_target.is_finite() && (0.5..=1.0).contains(&config.recall_target),
        "recall target must be finite and within 0.5..=1.0"
    );
    anyhow::ensure!(config.budget_ms > 0, "budget must be positive");
    anyhow::ensure!(
        config.budget_tolerance_ms.is_finite() && config.budget_tolerance_ms >= 0.0,
        "budget tolerance must be finite and non-negative"
    );
    anyhow::ensure!(
        config.unbudgeted_timeout_ms > config.budget_ms,
        "unbudgeted timeout must exceed the budget"
    );
    anyhow::ensure!(
        config.delay_base_ms.is_finite() && config.delay_base_ms >= 0.0,
        "delay base must be finite and non-negative"
    );
    anyhow::ensure!(
        config.delay_alpha.is_finite() && config.delay_alpha > 1.0,
        "Pareto alpha must be finite and greater than one"
    );
    anyhow::ensure!(
        config.delay_cap_ms.is_finite() && config.delay_cap_ms >= config.delay_base_ms,
        "delay cap must be finite and at least the base"
    );

    let mut dataset = MmapDataset::open(&config.dataset_path)?;
    let source_train_points = dataset.train_count;
    let source_test_queries = dataset.test_count;
    if let Some(train_points) = config.train_points {
        dataset.train_count = dataset.train_count.min(train_points);
    }
    dataset.limit_queries(Some(config.query_count));
    anyhow::ensure!(
        config.k <= dataset.k,
        "top-k {} exceeds dataset ground-truth width {}",
        config.k,
        dataset.k
    );
    let max_shards = *shard_counts.last().expect("non-empty shard grid");
    anyhow::ensure!(
        dataset.train_count >= max_shards,
        "indexed train points must be at least max shard count"
    );

    fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("create stable-tail data dir {}", config.data_dir.display()))?;
    let dataset = Arc::new(dataset);
    // Shard CPU runs on Tokio's blocking pool. The async runtime only drives
    // the fixed coordinator workers, timers, and completion queues, so scaling
    // reactor threads by shard count creates scheduler contention and can
    // delay the very budget timer this harness is measuring.
    let logical_cpus = std::thread::available_parallelism().map_or(1, usize::from);
    let runtime_threads = config.workers.min(logical_cpus).max(2);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .worker_threads(runtime_threads)
        .thread_name("gaussbench-tail")
        .build()
        .context("build stable-tail runtime")?;

    let mut points = Vec::with_capacity(shard_counts.len() * 2);
    let mut reused_topology_shards = 0;
    for &shard_count in &shard_counts {
        let topology_dir = config.data_dir.join(format!("topology-{shard_count:02}"));
        let (shards, reused_shards) = build_or_open_shards(&dataset, &topology_dir, shard_count)?;
        reused_topology_shards += reused_shards;
        for mode in [TailMode::Unbudgeted, TailMode::Budgeted] {
            let budget_ms = match mode {
                TailMode::Unbudgeted => config.unbudgeted_timeout_ms,
                TailMode::Budgeted => config.budget_ms,
            };
            let outcome = runtime.block_on(run_load(
                Arc::clone(&dataset),
                shards[..shard_count].to_vec(),
                config,
                shard_count,
                mode,
                budget_ms,
            ))?;
            let qps = outcome.samples.len() as f64
                / outcome
                    .response_window_elapsed
                    .as_secs_f64()
                    .max(f64::EPSILON);
            points.push(summarize(
                outcome,
                shard_count,
                mode,
                qps,
                SummaryContext {
                    budget_ms: config.budget_ms,
                    tolerance_ms: config.budget_tolerance_ms,
                    indexed_train_points: dataset.train_count,
                    replicas_per_shard: config.replicas_per_shard,
                    coordinator_timeout_ms: budget_ms,
                },
            ));
            let point = points.last().expect("point was pushed");
            eprintln!(
                "shards={shard_count:>2} mode={mode:?} qps={:.1} p99={:.3}ms \
                 p99.9={:.3}ms degraded={:.3}% detached_queries={} blocking_end={}/{}",
                point.qps,
                point.p99_ms,
                point.p999_ms,
                point.degraded_query_rate * 100.0,
                point.queries_with_blocking_searches_after_response,
                point.blocking_searches_active_at_mode_end,
                point.blocking_searches_active_after_quiesce
            );
        }
    }

    let stable_tail_ratio_gate_passed = points.iter().all(|point| {
        !matches!(point.mode, TailMode::Budgeted)
            || point.p99_to_p50_ratio <= STABLE_TAIL_RATIO_LIMIT
    });
    let literal_budget_gate_passed = points.iter().all(|point| {
        !matches!(point.mode, TailMode::Budgeted) || point.literal_budget_compliant == Some(true)
    });
    let budget_gate_passed = points.iter().all(|point| {
        !matches!(point.mode, TailMode::Budgeted) || point.budget_compliant == Some(true)
    });
    let blocking_quiescence_gate_passed = points
        .iter()
        .all(|point| point.blocking_searches_active_after_quiesce == 0);
    let unbudgeted = points
        .iter()
        .filter(|point| matches!(point.mode, TailMode::Unbudgeted))
        .collect::<Vec<_>>();
    let unbudgeted_p999_growth_ratio = unbudgeted
        .last()
        .zip(unbudgeted.first())
        .map_or(1.0, |(last, first)| {
            last.p999_ms / first.p999_ms.max(f64::EPSILON)
        });
    let dataset_name = config
        .dataset_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();
    let report = StableTailReport {
        schema_version: 5,
        dataset: dataset_name,
        git_sha: config.git_sha.clone(),
        source_train_points,
        indexed_train_points: dataset.train_count,
        source_test_queries,
        measured_queries: dataset.test_count,
        dim: dataset.dim,
        k: config.k,
        metric: dataset.metric,
        max_shards,
        replicas_per_shard: config.replicas_per_shard,
        replica_policy: if config.replicas_per_shard == 1 {
            "single replica; no hedge".to_string()
        } else {
            "primary immediately; one follower after 10% of the coordinator timeout; additional followers only on error; first successful response wins; unfinished replicas cancelled".to_string()
        },
        replica_fixture: "same immutable local Db shard searched through independent clients with independently seeded deterministic queue/network delay; this is not physical or remote replica evidence".to_string(),
        total_topology_shards: shard_counts.iter().sum(),
        reused_topology_shards,
        workers: config.workers,
        runtime_threads,
        ef_search: config.ef_search,
        request_recall_target: config.recall_target,
        load_model: "bounded closed-loop coordinators".to_string(),
        corpus_policy: "full indexed train corpus repeated at every shard topology".to_string(),
        budget_ms: config.budget_ms,
        budget_tolerance_ms: config.budget_tolerance_ms,
        unbudgeted_timeout_ms: config.unbudgeted_timeout_ms,
        delay_model: DelayModel {
            distribution: "deterministic Pareto".to_string(),
            base_ms: config.delay_base_ms,
            alpha: config.delay_alpha,
            cap_ms: config.delay_cap_ms,
            seed: config.delay_seed,
            scope: "queue/network delay before a real local LS-VEC shard search".to_string(),
        },
        hardware: format!(
            "{}-{}; logical_cpus={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            logical_cpus
        ),
        stable_tail_ratio_limit: STABLE_TAIL_RATIO_LIMIT,
        stable_tail_ratio_gate_passed,
        literal_budget_gate_passed,
        budget_gate_passed,
        blocking_quiescence_timeout_ms: BLOCKING_QUIESCE_TIMEOUT.as_millis() as u64,
        blocking_quiescence_gate_passed,
        unbudgeted_p999_growth_ratio,
        points,
    };
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output) = &config.output {
        fs::write(output, format!("{json}\n"))
            .with_context(|| format!("write stable-tail report {}", output.display()))?;
    } else {
        println!("{json}");
    }
    Ok(report)
}

fn build_or_open_shards(
    dataset: &MmapDataset,
    data_dir: &std::path::Path,
    max_shards: usize,
) -> Result<(Vec<EngineShard>, usize)> {
    let mut shards = Vec::with_capacity(max_shards);
    let mut reused_shards = 0;
    for shard_index in 0..max_shards {
        let shard_dir = data_dir.join(format!("shard-{shard_index:02}"));
        fs::create_dir_all(&shard_dir)
            .with_context(|| format!("create shard dir {}", shard_dir.display()))?;
        let db = Db::open(&shard_dir)
            .with_context(|| format!("open shard database {}", shard_dir.display()))?;
        let expected_points = dataset
            .train_count
            .saturating_add(max_shards - 1 - shard_index)
            / max_shards;
        let existing = db
            .list_collections()
            .into_iter()
            .find(|collection| collection.name == COLLECTION);
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing.vector_dim == dataset.dim
                    && existing.metric == dataset.metric.to_distance(),
                "reused shard {shard_index} collection schema does not match dataset"
            );
            anyhow::ensure!(
                db.count(COLLECTION, None)?.count == expected_points,
                "reused shard {shard_index} point count does not match expected partition"
            );
            reused_shards += 1;
        } else {
            db.create_collection(CollectionConfig {
                name: COLLECTION.to_string(),
                vector_dim: dataset.dim,
                metric: dataset.metric.to_distance(),
                shards: 1,
                replicas: 1,
                quantization: None,
                payload_schema: Default::default(),
                named_vector_dims: Default::default(),
                hnsw_m: None,
                hnsw_ef_construction: None,
                hnsw_ef_search: None,
                recall_sla: Some(0.95),
                index_kind: Some("lsvec".to_string()),
                streamer_max_bytes: 1024 * 1024 * 1024,
            })?;
            let partition = (shard_index..dataset.train_count)
                .step_by(max_shards)
                .collect::<Vec<_>>();
            for (batch_index, chunk) in partition.chunks(1_000).enumerate() {
                let points = chunk
                    .iter()
                    .map(|&index| Point {
                        id: index.to_string(),
                        vector: dataset.train_vector(index),
                        vectors: Default::default(),
                        sparse_vector: None,
                        payload: serde_json::Value::Null,
                    })
                    .collect();
                db.upsert(COLLECTION, points)
                    .with_context(|| format!("upsert shard {shard_index} batch {batch_index}"))?;
            }
            db.compact_collection(COLLECTION)
                .with_context(|| format!("compact shard {shard_index}"))?;
        }
        let status = db.index_status(COLLECTION)?;
        anyhow::ensure!(
            !status.build_in_flight && status.indexed_points == expected_points,
            "shard {shard_index} is not fully query-ready: indexed={}/{} build_in_flight={}",
            status.indexed_points,
            expected_points,
            status.build_in_flight
        );
        eprintln!("stable-tail shard {shard_index}/{max_shards} ready points={expected_points}");
        shards.push(EngineShard { db: Arc::new(db) });
    }
    Ok((shards, reused_shards))
}

async fn run_load(
    dataset: Arc<MmapDataset>,
    shards: Vec<EngineShard>,
    config: &RunConfig,
    shard_count: usize,
    mode: TailMode,
    budget_ms: u64,
) -> Result<LoadOutcome> {
    let response_window_started = Instant::now();
    let completed = Arc::new(AtomicUsize::new(0));
    let shard_requests_started = Arc::new(AtomicUsize::new(0));
    let active_blocking_searches = Arc::new(AtomicUsize::new(0));
    let mut workers = tokio::task::JoinSet::new();
    let worker_count = config.workers.min(dataset.test_count);
    for worker in 0..worker_count {
        let dataset = Arc::clone(&dataset);
        let shards = shards.clone();
        let completed = Arc::clone(&completed);
        let shard_requests_started = Arc::clone(&shard_requests_started);
        let active_blocking_searches = Arc::clone(&active_blocking_searches);
        let replicas_per_shard = config.replicas_per_shard;
        let ef_search = config.ef_search;
        let recall_target = config.recall_target;
        let k = config.k;
        let delay_base_ms = config.delay_base_ms;
        let delay_alpha = config.delay_alpha;
        let delay_cap_ms = config.delay_cap_ms;
        let delay_seed = config.delay_seed;
        workers.spawn(async move {
            let mut samples = Vec::with_capacity(dataset.test_count.div_ceil(worker_count));
            for query_index in (worker..dataset.test_count).step_by(worker_count) {
                let query_active_blocking_searches = Arc::new(AtomicUsize::new(0));
                let request = SearchRequest {
                    graph: None,
                    vector: dataset.test_vector(query_index),
                    vector_name: None,
                    k,
                    filter: None,
                    budget_ms: Some(budget_ms),
                    consistency: None,
                    ef_search: Some(ef_search),
                    recall_target: Some(recall_target),
                    with_payload: Some(false),
                };
                let started = Instant::now();
                let response = if replicas_per_shard == 1 {
                    let clients = shards
                        .iter()
                        .enumerate()
                        .map(|(shard_index, shard)| EngineShardClient {
                            shard: shard.clone(),
                            active_blocking_searches: Arc::clone(&active_blocking_searches),
                            query_active_blocking_searches: Arc::clone(
                                &query_active_blocking_searches,
                            ),
                            shard_requests_started: Arc::clone(&shard_requests_started),
                            delay: pareto_delay(
                                query_index,
                                shard_index,
                                delay_base_ms,
                                delay_alpha,
                                delay_cap_ms,
                                delay_seed,
                            ),
                        })
                        .collect();
                    fan_out_search(clients, request, budget_ms).await
                } else {
                    let replica_sets = shards
                        .iter()
                        .enumerate()
                        .map(|(shard_index, shard)| {
                            (0..replicas_per_shard)
                                .map(|replica_index| EngineShardClient {
                                    shard: shard.clone(),
                                    active_blocking_searches: Arc::clone(&active_blocking_searches),
                                    query_active_blocking_searches: Arc::clone(
                                        &query_active_blocking_searches,
                                    ),
                                    shard_requests_started: Arc::clone(&shard_requests_started),
                                    delay: pareto_replica_delay(
                                        query_index,
                                        shard_index,
                                        replica_index,
                                        delay_base_ms,
                                        delay_alpha,
                                        delay_cap_ms,
                                        delay_seed,
                                    ),
                                })
                                .collect()
                        })
                        .collect();
                    fan_out_search_replicated(replica_sets, request, budget_ms).await
                };
                samples.push(QuerySample {
                    elapsed: started.elapsed(),
                    degraded: response.degraded,
                    active_blocking_searches_at_response: query_active_blocking_searches
                        .load(Ordering::Acquire),
                });
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done.is_multiple_of(1_000) {
                    eprintln!(
                        "stable-tail shards={shard_count} mode={mode:?} progress \
                         {done}/{}",
                        dataset.test_count
                    );
                }
            }
            samples
        });
    }

    let mut samples = Vec::with_capacity(dataset.test_count);
    while let Some(result) = workers.join_next().await {
        samples.extend(result.context("stable-tail worker task")?);
    }
    let response_window_elapsed = response_window_started.elapsed();
    let active_after_responses = active_blocking_searches.load(Ordering::Acquire);
    let quiesce_started = Instant::now();
    while active_blocking_searches.load(Ordering::Acquire) > 0
        && quiesce_started.elapsed() < BLOCKING_QUIESCE_TIMEOUT
    {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(LoadOutcome {
        samples,
        response_window_elapsed,
        active_after_responses,
        quiesce_elapsed: quiesce_started.elapsed(),
        active_after_quiesce: active_blocking_searches.load(Ordering::Acquire),
        shard_requests_started: shard_requests_started.load(Ordering::Acquire),
    })
}

fn summarize(
    outcome: LoadOutcome,
    shards: usize,
    mode: TailMode,
    qps: f64,
    context: SummaryContext,
) -> TailPoint {
    let mut latencies = outcome
        .samples
        .iter()
        .map(|sample| sample.elapsed)
        .collect::<Vec<_>>();
    let query_count = outcome.samples.len().max(1) as f64;
    let budget_with_tolerance_ms = context.budget_ms as f64 + context.tolerance_ms;
    let degraded = outcome
        .samples
        .iter()
        .filter(|sample| sample.degraded)
        .count() as f64
        / query_count;
    let queries_with_blocking_searches_after_response = outcome
        .samples
        .iter()
        .filter(|sample| sample.active_blocking_searches_at_response > 0)
        .count();
    let max_blocking_searches_after_response = outcome
        .samples
        .iter()
        .map(|sample| sample.active_blocking_searches_at_response)
        .max()
        .unwrap_or(0);
    let over_budget = outcome
        .samples
        .iter()
        .filter(|sample| sample.elapsed.as_secs_f64() * 1_000.0 > context.budget_ms as f64)
        .count() as f64
        / query_count;
    let over_budget_with_tolerance = outcome
        .samples
        .iter()
        .filter(|sample| sample.elapsed.as_secs_f64() * 1_000.0 > budget_with_tolerance_ms)
        .count() as f64
        / query_count;
    let p50_ms = percentile_ms(&mut latencies.clone(), 0.50);
    let p99_ms = percentile_ms(&mut latencies.clone(), 0.99);
    let p999_ms = percentile_ms(&mut latencies.clone(), 0.999);
    let baseline_shard_requests = outcome.samples.len() * shards;
    let hedged_replica_requests_started = outcome
        .shard_requests_started
        .saturating_sub(baseline_shard_requests);
    TailPoint {
        shards,
        indexed_train_points: context.indexed_train_points,
        mode,
        coordinator_timeout_ms: context.coordinator_timeout_ms,
        hedge_delay_ms: (context.replicas_per_shard > 1).then_some(
            reported_replica_hedge_delay_ms(context.coordinator_timeout_ms),
        ),
        qps,
        p50_ms,
        p95_ms: percentile_ms(&mut latencies.clone(), 0.95),
        p99_ms,
        p999_ms,
        max_ms: percentile_ms(&mut latencies, 1.0),
        p99_to_p50_ratio: p99_ms / p50_ms.max(f64::EPSILON),
        degraded_query_rate: degraded,
        over_budget_rate: over_budget,
        over_budget_with_tolerance_rate: over_budget_with_tolerance,
        literal_budget_compliant: matches!(mode, TailMode::Budgeted)
            .then_some(p999_ms <= context.budget_ms as f64),
        budget_compliant: matches!(mode, TailMode::Budgeted)
            .then_some(p999_ms <= budget_with_tolerance_ms),
        baseline_shard_requests,
        shard_requests_started: outcome.shard_requests_started,
        hedged_replica_requests_started,
        replica_request_amplification: outcome.shard_requests_started as f64
            / baseline_shard_requests.max(1) as f64,
        queries_with_blocking_searches_after_response,
        max_blocking_searches_after_response,
        blocking_searches_active_at_mode_end: outcome.active_after_responses,
        blocking_search_quiesce_ms: outcome.quiesce_elapsed.as_secs_f64() * 1_000.0,
        blocking_searches_active_after_quiesce: outcome.active_after_quiesce,
    }
}

fn reported_replica_hedge_delay_ms(budget_ms: u64) -> u64 {
    budget_ms.div_ceil(REPLICA_HEDGE_BUDGET_DIVISOR).max(1)
}

fn percentile_ms(samples: &mut [Duration], quantile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_unstable();
    let index = ((samples.len() - 1) as f64 * quantile)
        .round()
        .clamp(0.0, (samples.len() - 1) as f64) as usize;
    samples[index].as_secs_f64() * 1_000.0
}

fn pareto_delay(
    query_index: usize,
    shard_index: usize,
    base_ms: f64,
    alpha: f64,
    cap_ms: f64,
    seed: u64,
) -> Duration {
    pareto_replica_delay(query_index, shard_index, 0, base_ms, alpha, cap_ms, seed)
}

fn pareto_replica_delay(
    query_index: usize,
    shard_index: usize,
    replica_index: usize,
    base_ms: f64,
    alpha: f64,
    cap_ms: f64,
    seed: u64,
) -> Duration {
    if base_ms == 0.0 {
        return Duration::ZERO;
    }
    let mixed = splitmix64(
        seed ^ (query_index as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93)
            ^ (shard_index as u64).wrapping_mul(0xA5A3_56F5_0993_7A5D)
            ^ (replica_index as u64).wrapping_mul(0x8D58_AC26_AEFD_DA4D),
    );
    let unit = (((mixed >> 11) as f64) + 0.5) / ((1u64 << 53) as f64);
    let delay_ms = (base_ms / (1.0 - unit).powf(1.0 / alpha)).min(cap_ms);
    Duration::from_secs_f64(delay_ms / 1_000.0)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::ann_benchmarks::write_gbench;

    #[test]
    fn pareto_delay_is_deterministic_and_capped() {
        let a = pareto_delay(7, 3, 1.0, 1.5, 25.0, 42);
        let b = pareto_delay(7, 3, 1.0, 1.5, 25.0, 42);
        assert_eq!(a, b);
        assert!(a >= Duration::from_millis(1));
        assert!(a <= Duration::from_millis(25));
    }

    #[test]
    fn summary_distinguishes_literal_and_tolerated_budget_gates() {
        let samples = vec![
            QuerySample {
                elapsed: Duration::from_millis(101),
                degraded: true,
                active_blocking_searches_at_response: 2,
            },
            QuerySample {
                elapsed: Duration::from_millis(102),
                degraded: true,
                active_blocking_searches_at_response: 0,
            },
        ];

        let point = summarize(
            LoadOutcome {
                samples,
                response_window_elapsed: Duration::from_millis(200),
                active_after_responses: 2,
                quiesce_elapsed: Duration::from_millis(3),
                active_after_quiesce: 0,
                shard_requests_started: 3,
            },
            1,
            TailMode::Budgeted,
            10.0,
            SummaryContext {
                budget_ms: 100,
                tolerance_ms: 5.0,
                indexed_train_points: 100,
                replicas_per_shard: 2,
                coordinator_timeout_ms: 100,
            },
        );

        assert_eq!(point.over_budget_rate, 1.0);
        assert_eq!(point.over_budget_with_tolerance_rate, 0.0);
        assert_eq!(point.literal_budget_compliant, Some(false));
        assert_eq!(point.budget_compliant, Some(true));
        assert_eq!(point.p99_to_p50_ratio, 1.0);
        assert_eq!(point.hedge_delay_ms, Some(10));
        assert_eq!(point.baseline_shard_requests, 2);
        assert_eq!(point.hedged_replica_requests_started, 1);
        assert_eq!(point.replica_request_amplification, 1.5);
        assert_eq!(point.queries_with_blocking_searches_after_response, 1);
        assert_eq!(point.max_blocking_searches_after_response, 2);
        assert_eq!(point.blocking_searches_active_at_mode_end, 2);
        assert_eq!(point.blocking_searches_active_after_quiesce, 0);
    }

    #[test]
    fn real_shard_smoke_emits_both_modes() {
        let temp = tempdir().unwrap();
        let dataset_path = temp.path().join("tiny.gbench");
        let train = (0..400)
            .map(|index| {
                (0..16)
                    .map(|dim| ((index * 17 + dim * 13) % 101) as f32 / 101.0)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let test = train[..20].to_vec();
        let neighbors = (0..20)
            .map(|index| {
                (0..10)
                    .map(|offset| ((index + offset) % train.len()) as u32)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            16,
            10,
            BenchMetric::L2,
        )
        .unwrap();
        let output = temp.path().join("report.json");

        let report = run(&RunConfig {
            dataset_path,
            data_dir: temp.path().join("data"),
            train_points: Some(400),
            query_count: 20,
            shard_counts: vec![1, 2],
            replicas_per_shard: 2,
            workers: 2,
            k: 10,
            ef_search: 32,
            recall_target: 0.95,
            budget_ms: 20,
            budget_tolerance_ms: 10.0,
            unbudgeted_timeout_ms: 100,
            delay_base_ms: 0.1,
            delay_alpha: 1.5,
            delay_cap_ms: 2.0,
            delay_seed: 42,
            output: Some(output.clone()),
            git_sha: "test".to_string(),
        })
        .unwrap();

        assert_eq!(report.points.len(), 4);
        assert_eq!(report.measured_queries, 20);
        assert_eq!(report.total_topology_shards, 3);
        assert_eq!(report.reused_topology_shards, 0);
        assert_eq!(report.schema_version, 5);
        assert_eq!(report.replicas_per_shard, 2);
        assert_eq!(report.stable_tail_ratio_limit, 2.0);
        assert_eq!(report.runtime_threads, 2);
        assert_eq!(report.ef_search, 32);
        assert_eq!(report.request_recall_target, 0.95);
        assert!(
            report
                .points
                .iter()
                .all(|point| point.indexed_train_points == 400)
        );
        assert!(report.points.iter().all(|point| {
            point.shard_requests_started >= point.baseline_shard_requests
                && point.replica_request_amplification >= 1.0
        }));
        assert!(report.budget_gate_passed);
        assert!(report.blocking_quiescence_gate_passed);
        assert!(
            report
                .points
                .iter()
                .all(|point| point.blocking_searches_active_after_quiesce == 0)
        );
        assert!(output.is_file());
    }
}
