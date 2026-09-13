use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use chirondb::{
    CollectionConfig, Db, DistanceMetric, Point, SearchRequest, SparseVector, encryption, wal::Wal,
};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::TempDir;

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Run a deterministic ChironDB backup, restore, and PITR drill"
)]
struct Args {
    /// External CHIRENC1 keyring used to open encrypted persistence.
    #[arg(long)]
    encryption_keyring_file: Option<PathBuf>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    snapshot_dir: Option<PathBuf>,
    #[arg(long, default_value = "gaussdrill")]
    collection: String,
    /// Total points stored in the full snapshot/recovery profile.
    #[arg(long, default_value_t = 2)]
    points: usize,
    /// Dense-vector dimension used by the deterministic recovery profile.
    #[arg(long, default_value_t = 2)]
    vector_dim: usize,
    /// Fail the drill when the full WAL recovery profile exceeds this bound.
    #[arg(long)]
    max_recovery_seconds: Option<f64>,
    /// Fail when peak recovery RSS exceeds post-recovery steady RSS by this bound.
    #[arg(long)]
    max_rss_delta_mib: Option<u64>,
    /// Profile only the recovery of an existing database. This leaves the
    /// database unchanged and requires `--data-dir`.
    #[arg(long)]
    existing_recovery_profile: bool,
    /// Expected point count for `--collection` in existing-recovery mode.
    #[arg(long, requires = "existing_recovery_profile")]
    expected_points: Option<usize>,
    #[arg(long)]
    keep_data: bool,
    /// Run the fixed G7 recovery tier instead of the snapshot/PITR drill.
    #[arg(long, value_enum)]
    recovery_tier: Option<RecoveryTier>,
    /// Machine-readable output for a fixed recovery tier.
    #[arg(long, requires = "recovery_tier")]
    tier_output: Option<PathBuf>,
    /// Passed 1M and 10M evidence used for the mandatory 100M resource preflight.
    #[arg(long, requires = "recovery_tier")]
    prior_tier_evidence: Vec<PathBuf>,
    /// Exact source revision represented by fixed-tier evidence.
    #[arg(long, requires = "recovery_tier")]
    tested_sha: Option<String>,
    /// Exact `chirondb-core` Git tree represented by fixed-tier evidence.
    #[arg(long, requires = "recovery_tier")]
    core_tree_hash: Option<String>,
    /// Exact `chirondb-server` Git tree represented by fixed-tier evidence.
    #[arg(long, requires = "recovery_tier")]
    server_tree_hash: Option<String>,
    /// Linux gate mode: evict the host page cache before every reopen sample.
    /// Requires root and is intended only for isolated benchmark runners.
    #[arg(long, requires = "recovery_tier")]
    drop_linux_page_cache: bool,
    #[arg(long, hide = true)]
    tier_reopen_child: bool,
    #[arg(long, hide = true)]
    tier_expected_points: Option<usize>,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum RecoveryTier {
    #[value(name = "1m")]
    One,
    #[value(name = "10m")]
    Ten,
    #[value(name = "100m")]
    Hundred,
}

impl RecoveryTier {
    fn label(self) -> &'static str {
        match self {
            Self::One => "1m",
            Self::Ten => "10m",
            Self::Hundred => "100m",
        }
    }

    fn points(self) -> usize {
        match self {
            Self::One => 1_000_000,
            Self::Ten => 10_000_000,
            Self::Hundred => 100_000_000,
        }
    }
}

#[derive(Debug, Serialize)]
struct TierPreflight {
    limit_fraction: f64,
    projected_peak_rss_bytes: Option<u64>,
    projected_data_bytes: Option<u64>,
    available_memory_bytes: Option<u64>,
    available_disk_bytes: Option<u64>,
    passed: bool,
    blocker: Option<String>,
}

#[derive(Debug, Serialize)]
struct TierRecoveryReport {
    schema_version: u32,
    status: &'static str,
    verdict: &'static str,
    tier: &'static str,
    tested_sha: String,
    core_tree_hash: String,
    server_tree_hash: String,
    actions_run_id: Option<String>,
    seed: u64,
    requested_points: usize,
    actual_points: usize,
    vector_dim: usize,
    payload: &'static str,
    ingest_seconds: f64,
    compact_seconds: f64,
    data_bytes: u64,
    peak_rss_bytes: u64,
    final_rss_bytes: u64,
    cold_reopen_samples_ms: Vec<u128>,
    reopen_isolation: &'static str,
    cold_reopen_valid: bool,
    recovered_counts: Vec<usize>,
    ann_rebuilt_on_reopen: bool,
    query_validated: bool,
    preflight: TierPreflight,
}

#[derive(Debug, Serialize)]
struct TierBlockedReport {
    schema_version: u32,
    status: &'static str,
    verdict: &'static str,
    tier: &'static str,
    tested_sha: String,
    core_tree_hash: String,
    server_tree_hash: String,
    actions_run_id: Option<String>,
    requested_points: usize,
    actual_points: usize,
    preflight: TierPreflight,
}

#[derive(Debug, Deserialize, Serialize)]
struct TierReopenSample {
    reopen_ms: u128,
    recovered_points: usize,
    indexed_points: usize,
    total_points: usize,
    build_in_flight: bool,
    query_hits: usize,
    peak_rss_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct PriorTierEvidence {
    verdict: String,
    requested_points: usize,
    actual_points: usize,
    data_bytes: u64,
    peak_rss_bytes: u64,
}

#[derive(Debug, Serialize)]
struct DrillReport {
    status: &'static str,
    encryption_enabled: bool,
    collection: String,
    snapshot_restore_ms: u128,
    lsn_restore_ms: u128,
    pitr_restore_ms: u128,
    crash_recovery_ms: u128,
    full_restore_points: usize,
    lsn_restore_points: usize,
    pitr_restore_points: usize,
    crash_recovered_points: usize,
    pitr_target_lsn: u64,
    pitr_target_unix_ms: u64,
    points_requested: usize,
    vector_dim: usize,
    profile_recovery_ms: u128,
    profile_recovery_points: usize,
    profile_recovery_points_per_second: f64,
    profile_wal_bytes: u64,
    profile_recovery_mib_per_second: f64,
    recovery_start_rss_bytes: u64,
    recovery_peak_rss_bytes: u64,
    recovery_steady_rss_bytes: u64,
    recovery_rss_delta_bytes: u64,
    recovery_rss_supported: bool,
    durability_profile: &'static str,
    recovery_scenarios_exercised: [&'static str; 4],
    reopen_mode: &'static str,
    max_recovery_seconds: Option<f64>,
    max_rss_delta_mib: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ExistingRecoveryReport {
    status: &'static str,
    encryption_enabled: bool,
    collection: String,
    durability_profile: &'static str,
    recovery_ms: u128,
    recovered_points: usize,
    recovery_points_per_second: f64,
    recovery_start_rss_bytes: u64,
    recovery_peak_rss_bytes: u64,
    recovery_steady_rss_bytes: u64,
    recovery_rss_delta_bytes: u64,
    recovery_rss_supported: bool,
    max_recovery_seconds: Option<f64>,
    max_rss_delta_mib: Option<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(path) = args.encryption_keyring_file.as_deref() {
        let keyring = encryption::Keyring::load(path)
            .with_context(|| format!("load drill encryption keyring {}", path.display()))?;
        encryption::install_process_keyring(keyring, true)
            .context("enable drill persistence encryption")?;
    }
    validate_recovery_limits(&args)?;
    if args.tier_reopen_child {
        return run_tier_reopen_child(&args);
    }
    if let Some(tier) = args.recovery_tier {
        return run_recovery_tier(&args, tier);
    }
    if args.existing_recovery_profile {
        return run_existing_recovery_profile(&args);
    }
    if args.points < 2 {
        anyhow::bail!("--points must be at least 2 so the LSN/PITR boundary can be verified");
    }
    if args.vector_dim == 0 {
        anyhow::bail!("--vector-dim must be greater than zero");
    }
    let data_temp = if args.data_dir.is_none() && !args.keep_data {
        Some(TempDir::new().context("create drill data directory")?)
    } else {
        None
    };
    let snapshot_temp = if args.snapshot_dir.is_none() && !args.keep_data {
        Some(TempDir::new().context("create drill snapshot directory")?)
    } else {
        None
    };
    let data_dir = args
        .data_dir
        .as_deref()
        .or_else(|| data_temp.as_ref().map(|dir| dir.path()))
        .context("drill data directory")?;
    let snapshot_dir = args
        .snapshot_dir
        .as_deref()
        .or_else(|| snapshot_temp.as_ref().map(|dir| dir.path()))
        .context("drill snapshot directory")?;

    let db = Db::open(data_dir).context("open drill database")?;
    db.create_collection(CollectionConfig {
        name: args.collection.clone(),
        vector_dim: args.vector_dim,
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
    })
    .context("create drill collection")?;

    upsert_point(&db, &args.collection, "kept", query_vector(args.vector_dim))?;
    let first_lsn = fs_len(&wal_dir(data_dir, &args.collection).join("000000.gdwal"))?;
    let first_record = Wal::load(&wal_dir(data_dir, &args.collection))?
        .into_iter()
        .next()
        .context("read first WAL record")?;
    wait_for_next_unix_millisecond(first_record.unix_ms)?;
    const PROFILE_BATCH_POINTS: usize = 1_000;
    for start in (1..args.points).step_by(PROFILE_BATCH_POINTS) {
        let end = (start + PROFILE_BATCH_POINTS).min(args.points);
        let points = (start..end)
            .map(|index| profile_point(index, args.vector_dim))
            .collect();
        db.upsert(&args.collection, points)
            .context("upsert drill profile points")?;
    }
    db.snapshot(snapshot_dir).context("create drill snapshot")?;
    let profile_wal_bytes = wal_bytes(&wal_dir(data_dir, &args.collection))?;

    let mut deleted_points = 0;
    for start in (0..args.points).step_by(PROFILE_BATCH_POINTS) {
        let end = (start + PROFILE_BATCH_POINTS).min(args.points);
        let ids = (start..end)
            .map(|index| {
                if index == 0 {
                    "kept".to_string()
                } else {
                    profile_id(index)
                }
            })
            .collect::<Vec<_>>();
        deleted_points += db
            .delete(&args.collection, &ids)
            .context("delete points before restore")?;
    }
    if deleted_points != args.points {
        anyhow::bail!(
            "delete before restore expected {} points, got {deleted_points}",
            args.points
        );
    }

    let snapshot_started = Instant::now();
    db.restore(snapshot_dir).context("restore drill snapshot")?;
    let snapshot_restore_ms = snapshot_started.elapsed().as_millis();
    let full_restore_points = db
        .count(&args.collection, None)
        .context("count after full restore")?
        .count;
    if full_restore_points != args.points {
        anyhow::bail!(
            "full snapshot restore expected {} points, got {full_restore_points}",
            args.points
        );
    }
    assert_searches(
        &db,
        &args.collection,
        args.vector_dim,
        &["kept", "excluded"],
    )?;

    let mut lsn_targets = HashMap::new();
    lsn_targets.insert(args.collection.clone(), first_lsn);
    let lsn_started = Instant::now();
    db.restore_to_wal_lsns(snapshot_dir, &lsn_targets)
        .context("restore drill LSN target")?;
    let lsn_restore_ms = lsn_started.elapsed().as_millis();
    let lsn_restore_points = db
        .count(&args.collection, None)
        .context("count after LSN restore")?
        .count;
    assert_searches(&db, &args.collection, args.vector_dim, &["kept"])?;
    if lsn_restore_points != 1 {
        anyhow::bail!("LSN restore expected 1 point, got {lsn_restore_points}");
    }

    let mut targets = HashMap::new();
    targets.insert(args.collection.clone(), first_record.unix_ms);
    let pitr_started = Instant::now();
    db.restore_to_wal_targets(snapshot_dir, &HashMap::new(), &targets)
        .context("restore drill PITR target")?;
    let pitr_restore_ms = pitr_started.elapsed().as_millis();
    let pitr_restore_points = db
        .count(&args.collection, None)
        .context("count after PITR restore")?
        .count;
    assert_searches(&db, &args.collection, args.vector_dim, &["kept"])?;
    if pitr_restore_points != 1 {
        anyhow::bail!("PITR restore expected 1 point, got {pitr_restore_points}");
    }

    drop(db);
    let crash_started = Instant::now();
    let recovered = Db::open(data_dir).context("reopen database after simulated crash")?;
    let crash_recovery_ms = crash_started.elapsed().as_millis();
    let crash_recovered_points = recovered
        .count(&args.collection, None)
        .context("count after crash recovery reopen")?
        .count;
    if crash_recovered_points != pitr_restore_points {
        anyhow::bail!(
            "crash recovery expected {pitr_restore_points} points, got {crash_recovered_points}"
        );
    }
    assert_searches(&recovered, &args.collection, args.vector_dim, &["kept"])?;

    // Keep the legacy one-point crash-recovery fields above stable, then run
    // an additive full-snapshot profile for capacity/recovery gates.
    recovered
        .restore(snapshot_dir)
        .context("restore full snapshot for recovery profile")?;
    drop(recovered);

    let recovery_start_rss_bytes = rss_bytes();
    let rss_sampler = RssSampler::start();
    let profile_started = Instant::now();
    let profile_recovered = Db::open(data_dir).context("open full recovery profile")?;
    let profile_elapsed = profile_started.elapsed();
    let sampled_recovery_peak_rss_bytes = rss_sampler.finish();
    let profile_recovery_points = profile_recovered
        .count(&args.collection, None)
        .context("count full recovery profile")?
        .count;
    if profile_recovery_points != args.points {
        anyhow::bail!(
            "full recovery profile expected {} points, got {profile_recovery_points}",
            args.points
        );
    }
    assert_searches(
        &profile_recovered,
        &args.collection,
        args.vector_dim,
        &["kept", "excluded"],
    )?;
    let recovery_steady_rss_bytes = rss_bytes();
    let recovery_peak_rss_bytes = sampled_recovery_peak_rss_bytes.max(recovery_steady_rss_bytes);
    let recovery_rss_delta_bytes =
        recovery_peak_rss_bytes.saturating_sub(recovery_steady_rss_bytes);
    let recovery_rss_supported = recovery_start_rss_bytes != 0
        || recovery_peak_rss_bytes != 0
        || recovery_steady_rss_bytes != 0;
    enforce_recovery_limits(
        &args,
        profile_elapsed,
        recovery_rss_delta_bytes,
        recovery_rss_supported,
    )?;
    let profile_recovery_points_per_second =
        profile_recovery_points as f64 / profile_elapsed.as_secs_f64().max(f64::EPSILON);
    let profile_recovery_mib_per_second = profile_wal_bytes as f64
        / (1024.0 * 1024.0)
        / profile_elapsed.as_secs_f64().max(f64::EPSILON);

    println!(
        "{}",
        serde_json::to_string_pretty(&DrillReport {
            status: "ok",
            encryption_enabled: encryption::encryption_enabled(),
            collection: args.collection,
            snapshot_restore_ms,
            lsn_restore_ms,
            pitr_restore_ms,
            crash_recovery_ms,
            full_restore_points,
            lsn_restore_points,
            pitr_restore_points,
            crash_recovered_points,
            pitr_target_lsn: first_lsn,
            pitr_target_unix_ms: first_record.unix_ms,
            points_requested: args.points,
            vector_dim: args.vector_dim,
            profile_recovery_ms: profile_elapsed.as_millis(),
            profile_recovery_points,
            profile_recovery_points_per_second,
            profile_wal_bytes,
            profile_recovery_mib_per_second,
            recovery_start_rss_bytes,
            recovery_peak_rss_bytes,
            recovery_steady_rss_bytes,
            recovery_rss_delta_bytes,
            recovery_rss_supported,
            durability_profile: "single_node_snapshot_pitr_reopen",
            recovery_scenarios_exercised: [
                "snapshot_restore",
                "lsn_restore",
                "timestamp_pitr_restore",
                "graceful_reopen_recovery",
            ],
            reopen_mode: "graceful_drop_reopen",
            max_recovery_seconds: args.max_recovery_seconds,
            max_rss_delta_mib: args.max_rss_delta_mib,
        })?
    );
    Ok(())
}

fn run_existing_recovery_profile(args: &Args) -> Result<()> {
    let data_dir = args
        .data_dir
        .as_deref()
        .context("--existing-recovery-profile requires --data-dir")?;
    let recovery_start_rss_bytes = rss_bytes();
    let rss_sampler = RssSampler::start();
    let recovery_started = Instant::now();
    let db = Db::open(data_dir).context("open existing recovery profile database")?;
    let recovery_elapsed = recovery_started.elapsed();
    let sampled_recovery_peak_rss_bytes = rss_sampler.finish();
    let recovered_points = db
        .count(&args.collection, None)
        .context("count existing recovery profile collection")?
        .count;
    if let Some(expected_points) = args.expected_points
        && recovered_points != expected_points
    {
        anyhow::bail!(
            "existing recovery profile expected {expected_points} points, got {recovered_points}"
        );
    }
    let recovery_steady_rss_bytes = rss_bytes();
    let recovery_peak_rss_bytes = sampled_recovery_peak_rss_bytes.max(recovery_steady_rss_bytes);
    let recovery_rss_delta_bytes =
        recovery_peak_rss_bytes.saturating_sub(recovery_steady_rss_bytes);
    let recovery_rss_supported = recovery_start_rss_bytes != 0
        || recovery_peak_rss_bytes != 0
        || recovery_steady_rss_bytes != 0;
    enforce_recovery_limits(
        args,
        recovery_elapsed,
        recovery_rss_delta_bytes,
        recovery_rss_supported,
    )?;
    let recovery_points_per_second =
        recovered_points as f64 / recovery_elapsed.as_secs_f64().max(f64::EPSILON);

    println!(
        "{}",
        serde_json::to_string_pretty(&ExistingRecoveryReport {
            status: "ok",
            encryption_enabled: encryption::encryption_enabled(),
            collection: args.collection.clone(),
            durability_profile: "existing_database_reopen",
            recovery_ms: recovery_elapsed.as_millis(),
            recovered_points,
            recovery_points_per_second,
            recovery_start_rss_bytes,
            recovery_peak_rss_bytes,
            recovery_steady_rss_bytes,
            recovery_rss_delta_bytes,
            recovery_rss_supported,
            max_recovery_seconds: args.max_recovery_seconds,
            max_rss_delta_mib: args.max_rss_delta_mib,
        })?
    );
    Ok(())
}

const RECOVERY_TIER_SEED: u64 = 0x4348_4952_4f4e_4737;
const RECOVERY_TIER_DIM: usize = 8;
const RECOVERY_TIER_BATCH: usize = 10_000;
const RECOVERY_TIER_SAMPLES: usize = 5;

fn run_recovery_tier(args: &Args, tier: RecoveryTier) -> Result<()> {
    let data_dir = args
        .data_dir
        .as_deref()
        .context("--recovery-tier requires --data-dir")?;
    let tested_sha = args
        .tested_sha
        .clone()
        .context("--recovery-tier requires --tested-sha")?;
    let core_tree_hash = args
        .core_tree_hash
        .clone()
        .context("--recovery-tier requires --core-tree-hash")?;
    let server_tree_hash = args
        .server_tree_hash
        .clone()
        .context("--recovery-tier requires --server-tree-hash")?;
    let actions_run_id = std::env::var("GITHUB_RUN_ID").ok();
    let preflight = recovery_tier_preflight(tier, data_dir, &args.prior_tier_evidence)?;
    if !preflight.passed {
        return emit_tier_report(
            args.tier_output.as_deref(),
            &TierBlockedReport {
                schema_version: 1,
                status: "resource-blocked",
                verdict: "resource-blocked",
                tier: tier.label(),
                tested_sha,
                core_tree_hash,
                server_tree_hash,
                actions_run_id,
                requested_points: tier.points(),
                actual_points: 0,
                preflight,
            },
        );
    }

    prepare_fresh_tier_directory(data_dir)?;
    let rss_sampler = RssSampler::start();
    let db = Db::open(data_dir).context("open fixed-tier database")?;
    db.create_collection(CollectionConfig {
        name: args.collection.clone(),
        vector_dim: RECOVERY_TIER_DIM,
        metric: DistanceMetric::L2,
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
    })
    .context("create fixed-tier collection")?;

    let ingest_started = Instant::now();
    for batch_start in (0..tier.points()).step_by(RECOVERY_TIER_BATCH) {
        let batch_end = (batch_start + RECOVERY_TIER_BATCH).min(tier.points());
        let points = (batch_start..batch_end).map(tier_point).collect::<Vec<_>>();
        db.upsert(&args.collection, points)
            .with_context(|| format!("ingest fixed tier at point {batch_start}"))?;
    }
    let ingest_seconds = ingest_started.elapsed().as_secs_f64();
    let actual_points = db
        .count(&args.collection, None)
        .context("count fixed-tier collection after ingest")?
        .count;
    if actual_points != tier.points() {
        anyhow::bail!(
            "fixed tier requested {} points but ingested {actual_points}",
            tier.points()
        );
    }

    let compact_started = Instant::now();
    db.compact_collection(&args.collection)
        .context("compact fixed-tier collection")?;
    let compact_seconds = compact_started.elapsed().as_secs_f64();
    let compacted_status = db
        .index_status(&args.collection)
        .context("read fixed-tier index status after compaction")?;
    if compacted_status.build_in_flight
        || compacted_status.indexed_points != compacted_status.total_points
    {
        anyhow::bail!(
            "compaction did not publish a complete ANN index: indexed={}, total={}, build_in_flight={}",
            compacted_status.indexed_points,
            compacted_status.total_points,
            compacted_status.build_in_flight
        );
    }
    drop(db);

    let mut samples = Vec::with_capacity(RECOVERY_TIER_SAMPLES);
    for _ in 0..RECOVERY_TIER_SAMPLES {
        if args.drop_linux_page_cache {
            drop_linux_page_cache()?;
        }
        samples.push(run_tier_reopen_process(
            data_dir,
            &args.collection,
            actual_points,
        )?);
    }
    let peak_rss_bytes = samples
        .iter()
        .map(|sample| sample.peak_rss_bytes)
        .fold(rss_sampler.finish(), u64::max);
    let final_rss_bytes = rss_bytes();
    let ann_rebuilt_on_reopen = samples
        .iter()
        .any(|sample| sample.build_in_flight || sample.indexed_points != sample.total_points);
    let query_validated = samples.iter().all(|sample| sample.query_hits > 0);
    let recovered_counts = samples
        .iter()
        .map(|sample| sample.recovered_points)
        .collect::<Vec<_>>();
    if recovered_counts.iter().any(|count| *count != actual_points) {
        anyhow::bail!("a process-cold reopen returned an unexpected point count");
    }
    if ann_rebuilt_on_reopen {
        anyhow::bail!("a process-cold reopen attempted to rebuild the ANN index");
    }
    if !query_validated {
        anyhow::bail!("a process-cold reopen failed its deterministic query");
    }
    let data_bytes = recursive_directory_size(data_dir)?;
    emit_tier_report(
        args.tier_output.as_deref(),
        &TierRecoveryReport {
            schema_version: 1,
            status: if args.drop_linux_page_cache {
                "passed"
            } else {
                "diagnostic"
            },
            verdict: if args.drop_linux_page_cache {
                "passed"
            } else {
                "diagnostic"
            },
            tier: tier.label(),
            tested_sha,
            core_tree_hash,
            server_tree_hash,
            actions_run_id,
            seed: RECOVERY_TIER_SEED,
            requested_points: tier.points(),
            actual_points,
            vector_dim: RECOVERY_TIER_DIM,
            payload: "empty",
            ingest_seconds,
            compact_seconds,
            data_bytes,
            peak_rss_bytes,
            final_rss_bytes,
            cold_reopen_samples_ms: samples.iter().map(|sample| sample.reopen_ms).collect(),
            reopen_isolation: if args.drop_linux_page_cache {
                "fresh_process_and_linux_page_cache_drop"
            } else {
                "fresh_process_only"
            },
            cold_reopen_valid: args.drop_linux_page_cache,
            recovered_counts,
            ann_rebuilt_on_reopen,
            query_validated,
            preflight,
        },
    )
}

fn run_tier_reopen_child(args: &Args) -> Result<()> {
    let data_dir = args
        .data_dir
        .as_deref()
        .context("--tier-reopen-child requires --data-dir")?;
    let expected = args
        .tier_expected_points
        .context("--tier-reopen-child requires --tier-expected-points")?;
    let sampler = RssSampler::start();
    let started = Instant::now();
    let db = Db::open(data_dir).context("open process-cold fixed tier")?;
    let recovered_points = db
        .count(&args.collection, None)
        .context("count process-cold fixed tier")?
        .count;
    if recovered_points != expected {
        anyhow::bail!("expected {expected} points after reopen, got {recovered_points}");
    }
    let status = db
        .index_status(&args.collection)
        .context("read process-cold index status")?;
    let query_hits = db
        .search(
            &args.collection,
            SearchRequest {
                graph: None,
                vector: tier_query(),
                vector_name: None,
                k: 10,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(false),
            },
        )
        .context("query process-cold fixed tier")?
        .hits
        .len();
    let sample = TierReopenSample {
        reopen_ms: started.elapsed().as_millis(),
        recovered_points,
        indexed_points: status.indexed_points,
        total_points: status.total_points,
        build_in_flight: status.build_in_flight,
        query_hits,
        peak_rss_bytes: sampler.finish(),
    };
    println!("{}", serde_json::to_string(&sample)?);
    Ok(())
}

fn run_tier_reopen_process(
    data_dir: &Path,
    collection: &str,
    expected_points: usize,
) -> Result<TierReopenSample> {
    let executable = std::env::current_exe().context("resolve chirondrill executable")?;
    let output = std::process::Command::new(executable)
        .arg("--tier-reopen-child")
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--collection")
        .arg(collection)
        .arg("--tier-expected-points")
        .arg(expected_points.to_string())
        .output()
        .context("start process-cold fixed-tier reopen")?;
    if !output.status.success() {
        anyhow::bail!(
            "process-cold reopen failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("decode process-cold reopen evidence")
}

fn recovery_tier_preflight(
    tier: RecoveryTier,
    data_dir: &Path,
    prior_paths: &[PathBuf],
) -> Result<TierPreflight> {
    let available_memory_bytes = available_memory_bytes();
    let available_disk_bytes = available_disk_bytes(data_dir);
    if !matches!(tier, RecoveryTier::Hundred) {
        return Ok(TierPreflight {
            limit_fraction: 0.70,
            projected_peak_rss_bytes: None,
            projected_data_bytes: None,
            available_memory_bytes,
            available_disk_bytes,
            passed: true,
            blocker: None,
        });
    }
    if prior_paths.len() != 2 {
        anyhow::bail!("100M preflight requires exactly the passed 1M and 10M evidence files");
    }
    let mut priors = prior_paths
        .iter()
        .map(|path| {
            let bytes = fs::read(path)
                .with_context(|| format!("read prior tier evidence {}", path.display()))?;
            serde_json::from_slice::<PriorTierEvidence>(&bytes)
                .with_context(|| format!("decode prior tier evidence {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    priors.sort_by_key(|prior| prior.requested_points);
    if priors
        .iter()
        .map(|prior| prior.requested_points)
        .collect::<Vec<_>>()
        != [1_000_000, 10_000_000]
        || priors
            .iter()
            .any(|prior| prior.verdict != "passed" || prior.actual_points != prior.requested_points)
    {
        anyhow::bail!("100M preflight accepts only passed, actual 1M and 10M evidence");
    }
    let target = tier.points() as u128;
    let projected_peak_rss_bytes = priors
        .iter()
        .map(|prior| ceil_ratio(prior.peak_rss_bytes, target, prior.actual_points))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max();
    let projected_data_bytes = priors
        .iter()
        .map(|prior| ceil_ratio(prior.data_bytes, target, prior.actual_points))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max();
    let mut blockers = Vec::new();
    match (projected_peak_rss_bytes, available_memory_bytes) {
        (Some(projected), Some(available)) if projected > available.saturating_mul(7) / 10 => {
            blockers.push(format!(
                "projected peak RSS {projected} exceeds 70% of available memory {available}"
            ));
        }
        (None, _) | (_, None) => blockers.push("available-memory preflight is unavailable".into()),
        _ => {}
    }
    match (projected_data_bytes, available_disk_bytes) {
        (Some(projected), Some(available)) if projected > available.saturating_mul(7) / 10 => {
            blockers.push(format!(
                "projected data size {projected} exceeds 70% of available disk {available}"
            ));
        }
        (None, _) | (_, None) => blockers.push("available-disk preflight is unavailable".into()),
        _ => {}
    }
    Ok(TierPreflight {
        limit_fraction: 0.70,
        projected_peak_rss_bytes,
        projected_data_bytes,
        available_memory_bytes,
        available_disk_bytes,
        passed: blockers.is_empty(),
        blocker: (!blockers.is_empty()).then(|| blockers.join("; ")),
    })
}

fn ceil_ratio(bytes: u64, target: u128, points: usize) -> Result<u64> {
    let divisor = points as u128;
    let projected = (u128::from(bytes)
        .checked_mul(target)
        .context("tier projection overflow")?
        .checked_add(divisor - 1)
        .context("tier projection overflow")?)
        / divisor;
    u64::try_from(projected).context("tier projection exceeds u64")
}

fn prepare_fresh_tier_directory(path: &Path) -> Result<()> {
    if path.exists()
        && fs::read_dir(path)
            .with_context(|| format!("read tier directory {}", path.display()))?
            .next()
            .is_some()
    {
        anyhow::bail!(
            "fixed recovery tier requires an empty data directory: {}",
            path.display()
        );
    }
    fs::create_dir_all(path).with_context(|| format!("create tier directory {}", path.display()))
}

fn tier_point(index: usize) -> Point {
    let mut state = RECOVERY_TIER_SEED ^ index as u64;
    let mut vector = Vec::with_capacity(RECOVERY_TIER_DIM);
    for _ in 0..RECOVERY_TIER_DIM {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        vector.push(((state >> 40) as f32 / (1_u32 << 24) as f32) * 2.0 - 1.0);
    }
    Point {
        id: format!("tier-{index:09}"),
        vector,
        vectors: Default::default(),
        sparse_vector: None,
        payload: serde_json::Value::Null,
    }
}

fn tier_query() -> Vec<f32> {
    tier_point(0).vector
}

fn recursive_directory_size(path: &Path) -> Result<u64> {
    fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .try_fold(0_u64, |total, entry| -> Result<u64> {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let bytes = if metadata.is_dir() {
                recursive_directory_size(&entry.path())?
            } else {
                metadata.len()
            };
            Ok(total.saturating_add(bytes))
        })
}

fn available_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    let value = line.strip_prefix("MemAvailable:")?;
                    value.split_whitespace().next()?.parse::<u64>().ok()
                })
            })
            .map(|kib| kib.saturating_mul(1024))
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("vm_stat").output().ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let page_size = text
            .lines()
            .next()?
            .split_whitespace()
            .find_map(|word| word.trim_end_matches('.').parse::<u64>().ok())?;
        let pages = text
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                matches!(
                    name,
                    "Pages free" | "Pages inactive" | "Pages speculative" | "Pages purgeable"
                )
                .then(|| value.trim().trim_end_matches('.').parse::<u64>().ok())
                .flatten()
            })
            .sum::<u64>();
        pages.checked_mul(page_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn available_disk_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let probe = path
            .ancestors()
            .find(|candidate| candidate.exists())
            .unwrap_or(Path::new("/"));
        let output = std::process::Command::new("df")
            .args(["-Pk"])
            .arg(probe)
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        text.lines()
            .last()?
            .split_whitespace()
            .nth(3)?
            .parse::<u64>()
            .ok()
            .map(|kib| kib.saturating_mul(1024))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn drop_linux_page_cache() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("sync")
            .status()
            .context("run sync before page-cache eviction")?;
        if !status.success() {
            anyhow::bail!("sync failed before page-cache eviction: {status}");
        }
        fs::write("/proc/sys/vm/drop_caches", b"3\n")
            .context("drop Linux page cache; fixed-tier gate must run as root")?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("--drop-linux-page-cache is supported only on Linux")
    }
}

fn emit_tier_report(path: Option<&Path>, report: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create evidence directory {}", parent.display()))?;
        }
        fs::write(path, &bytes)
            .with_context(|| format!("write tier evidence {}", path.display()))?;
    }
    println!(
        "{}",
        String::from_utf8(bytes).context("serialize tier evidence as UTF-8")?
    );
    Ok(())
}
fn validate_recovery_limits(args: &Args) -> Result<()> {
    if args
        .max_recovery_seconds
        .is_some_and(|seconds| !seconds.is_finite() || seconds <= 0.0)
    {
        anyhow::bail!("--max-recovery-seconds must be finite and greater than zero");
    }
    if args.max_rss_delta_mib == Some(0) {
        anyhow::bail!("--max-rss-delta-mib must be greater than zero");
    }
    Ok(())
}

fn enforce_recovery_limits(
    args: &Args,
    recovery_elapsed: Duration,
    recovery_rss_delta_bytes: u64,
    recovery_rss_supported: bool,
) -> Result<()> {
    if let Some(max_seconds) = args.max_recovery_seconds
        && recovery_elapsed.as_secs_f64() > max_seconds
    {
        anyhow::bail!(
            "full recovery took {:.3}s, exceeding the {:.3}s gate",
            recovery_elapsed.as_secs_f64(),
            max_seconds
        );
    }
    if args.max_rss_delta_mib.is_some() && !recovery_rss_supported {
        anyhow::bail!("--max-rss-delta-mib requires RSS measurement support on the current host");
    }
    if let Some(max_mib) = args.max_rss_delta_mib
        && recovery_rss_delta_bytes > max_mib.saturating_mul(1024 * 1024)
    {
        anyhow::bail!(
            "full recovery peak RSS exceeded steady state by {:.2} MiB, exceeding the {max_mib} MiB gate",
            recovery_rss_delta_bytes as f64 / (1024.0 * 1024.0)
        );
    }
    Ok(())
}

fn upsert_point(db: &Db, collection: &str, id: &str, vector: Vec<f32>) -> Result<()> {
    db.upsert(
        collection,
        vec![Point {
            id: id.to_string(),
            vector,
            vectors: Default::default(),
            sparse_vector: Some(SparseVector {
                indices: vec![7],
                values: vec![1.0],
            }),
            payload: json!({"kind": id}),
        }],
    )?;
    Ok(())
}

fn assert_searches(db: &Db, collection: &str, vector_dim: usize, expected: &[&str]) -> Result<()> {
    let response = db.search(
        collection,
        SearchRequest {
            graph: None,
            vector: query_vector(vector_dim),
            vector_name: None,
            k: 10,
            filter: None,
            budget_ms: None,
            consistency: None,
            ef_search: None,
            recall_target: None,
            with_payload: None,
        },
    )?;
    let ids = response
        .hits
        .iter()
        .map(|hit| hit.id.as_str())
        .collect::<Vec<_>>();
    for expected_id in expected {
        if !ids.contains(expected_id) {
            anyhow::bail!("missing expected restored point: {expected_id}");
        }
    }
    Ok(())
}

fn profile_id(index: usize) -> String {
    if index == 1 {
        "excluded".to_string()
    } else {
        format!("profile-{index:08}")
    }
}

fn profile_point(index: usize, vector_dim: usize) -> Point {
    let mut vector = vec![0.0; vector_dim];
    if index == 1 {
        if vector_dim == 1 {
            vector[0] = 0.5;
        } else {
            vector[1] = 1.0;
        }
    } else {
        // Filler vectors are deterministic and remain below the two boundary
        // points for the drill query, even when the collection crosses the ANN
        // threshold. This keeps correctness checks stable at large scales.
        vector[0] = -1.0;
        for (dimension, value) in vector.iter_mut().enumerate().skip(1) {
            let mixed = (index as u64)
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add((dimension as u64).wrapping_mul(1_442_695_040_888_963_407));
            *value = ((mixed >> 40) as f32 / (1_u32 << 24) as f32) * 0.25;
        }
    }
    Point {
        id: profile_id(index),
        vector,
        vectors: Default::default(),
        sparse_vector: Some(SparseVector {
            indices: vec![(index % 1024) as u32],
            values: vec![1.0],
        }),
        payload: json!({"kind": profile_id(index), "ordinal": index}),
    }
}

fn query_vector(vector_dim: usize) -> Vec<f32> {
    let mut vector = vec![0.0; vector_dim];
    vector[0] = 1.0;
    vector
}

fn wait_for_next_unix_millisecond(after: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis() as u64;
        if now > after {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(1) {
            anyhow::bail!("system clock did not advance while preparing PITR boundary");
        }
        thread::sleep(Duration::from_millis(1));
    }
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
                thread::sleep(Duration::from_millis(10));
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
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    let value = line.strip_prefix("VmRSS:")?;
                    value.split_whitespace().next()?.parse::<u64>().ok()
                })
            })
            .unwrap_or(0)
            .saturating_mul(1024)
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

fn wal_dir(data_dir: &Path, collection: &str) -> PathBuf {
    data_dir.join("collections").join(collection).join("wal")
}

fn fs_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("read metadata for {}", path.display()))?
        .len())
}

fn wal_bytes(path: &Path) -> Result<u64> {
    std::fs::read_dir(path)
        .with_context(|| format!("read WAL directory {}", path.display()))?
        .try_fold(0_u64, |total, entry| -> std::io::Result<u64> {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry.path().extension().is_some_and(|ext| ext == "gdwal")
            {
                Ok(total.saturating_add(entry.metadata()?.len()))
            } else {
                Ok(total)
            }
        })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_tier_point_is_deterministic_and_payload_free() {
        let first = tier_point(42);
        let second = tier_point(42);
        assert_eq!(first.id, "tier-000000042");
        assert_eq!(first.vector, second.vector);
        assert_eq!(first.vector.len(), RECOVERY_TIER_DIM);
        assert!(first.vector.iter().all(|value| value.is_finite()));
        assert!(first.sparse_vector.is_none());
        assert_eq!(first.payload, serde_json::Value::Null);
    }

    #[test]
    fn tier_projection_rounds_up_without_overflow() {
        assert_eq!(ceil_ratio(3, 10, 4).unwrap(), 8);
        assert!(ceil_ratio(u64::MAX, u128::MAX, 1).is_err());
    }

    #[test]
    fn hundred_million_preflight_rejects_non_actual_prior_evidence() {
        let temp = TempDir::new().unwrap();
        let one_million = temp.path().join("1m.json");
        let ten_million = temp.path().join("10m.json");
        fs::write(
            &one_million,
            br#"{"verdict":"passed","requested_points":1000000,"actual_points":999999,"data_bytes":1,"peak_rss_bytes":1}"#,
        )
        .unwrap();
        fs::write(
            &ten_million,
            br#"{"verdict":"passed","requested_points":10000000,"actual_points":10000000,"data_bytes":1,"peak_rss_bytes":1}"#,
        )
        .unwrap();
        let error = recovery_tier_preflight(
            RecoveryTier::Hundred,
            temp.path(),
            &[one_million, ten_million],
        )
        .unwrap_err();
        assert!(error.to_string().contains("actual 1M and 10M"));
    }
}
