//! P0/C19 structural-node contamination harness.
//!
//! This is a custom augmentation over hash-bound industry corpora. It never
//! labels its output as an unmodified ann-benchmarks result.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use chirondb::{
    Db, Point, TenantScope,
    index::{ivf::IvfArtifact, vamana::VamanaArtifact},
    seal::V4Store,
};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ann_benchmarks::MmapDataset;

const COLLECTION: &str = "ann_benchmarks";
const MARKER_FILE: &str = "c19-structural-nodes.json";
const MARKER_SCHEMA: &str = "chirondb-c19-structural-marker-v2";
const STRUCTURAL_SEED: u64 = 13_969_199_075_232_164_731;
const SCALE_SAMPLE_ROWS: usize = 4096;
const BATCH_SIZE: usize = 1000;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: StructuralCommand,
}

#[derive(Debug, Subcommand)]
enum StructuralCommand {
    /// Add a cumulative structural-node ratio to an existing official state.
    Inject(InjectArgs),
    /// Compare sealed baseline/candidate centroid and Vamana connectivity.
    Profile(ProfileArgs),
}

#[derive(Debug, clap::Args)]
struct InjectArgs {
    #[arg(long)]
    dataset: PathBuf,
    #[arg(long)]
    data_dir: PathBuf,
    /// Exact structural-free parent used for sealed topology comparison.
    #[arg(long)]
    baseline_data: Option<PathBuf>,
    #[arg(long)]
    ratio_percent: f64,
    #[arg(long)]
    compact: bool,
    #[arg(long)]
    negative_control: bool,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
}

#[derive(Debug, clap::Args)]
struct ProfileArgs {
    #[arg(long)]
    dataset: PathBuf,
    #[arg(long)]
    baseline_data: PathBuf,
    #[arg(long)]
    candidate_data: PathBuf,
    #[arg(long)]
    ratio_percent: f64,
    #[arg(long, default_value_t = 10_000)]
    neighbor_sample: usize,
    #[arg(long)]
    negative_control: bool,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, default_value = "unspecified")]
    git_sha: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StructuralMarker {
    schema: String,
    dataset_sha256: String,
    semantic_points: usize,
    structural_points: usize,
    ratio_percent: f64,
    seed: u64,
    negative_control: bool,
    fixture: String,
    topology_parent_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct InjectionReport {
    schema: &'static str,
    git_sha: String,
    dataset: String,
    dataset_sha256: String,
    data_dir: String,
    semantic_points: usize,
    structural_points_before: usize,
    structural_points_after: usize,
    injected_points: usize,
    ratio_percent: f64,
    negative_control: bool,
    topology_parent_sha256: Option<String>,
    vectors_nonzero: bool,
    vectors_unique: bool,
    compacted: bool,
    elapsed_seconds: f64,
    total_points: usize,
    sealed_segments: usize,
}

#[derive(Debug, Serialize)]
struct ProfileReport {
    schema: &'static str,
    git_sha: String,
    dataset: String,
    dataset_sha256: String,
    baseline_data: String,
    candidate_data: String,
    semantic_points: usize,
    structural_points: usize,
    ratio_percent: f64,
    negative_control: bool,
    topology_parent_sha256: String,
    normalized_centroid_drift: f64,
    normalized_centroid_drift_limit: f64,
    mean_original_neighbor_loss: f64,
    mean_original_neighbor_loss_limit: f64,
    p95_original_neighbor_loss: f64,
    p95_original_neighbor_loss_limit: f64,
    baseline_weak_components: usize,
    candidate_weak_components: usize,
    weak_component_increase: isize,
    original_nodes_without_original_neighbors: usize,
    sampled_original_nodes: usize,
    passed: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        StructuralCommand::Inject(args) => inject(args),
        StructuralCommand::Profile(args) => profile(args),
    }
}

fn inject(args: InjectArgs) -> Result<()> {
    validate_ratio(args.ratio_percent)?;
    let started = Instant::now();
    let dataset = MmapDataset::open(&args.dataset)?;
    let dataset_sha256 = sha256_file(&args.dataset)?;
    let target = structural_count(dataset.train_count, args.ratio_percent)?;
    let topology_parent_sha256 =
        validate_topology_parent(&args.data_dir, args.baseline_data.as_deref(), args.compact)?;
    let db = Db::open(&args.data_dir).context("open C19 candidate state")?;
    let config = db
        .list_collections()
        .into_iter()
        .find(|config| config.name == COLLECTION)
        .context("C19 candidate state has no ann_benchmarks collection")?;
    anyhow::ensure!(
        config.vector_dim == dataset.dim && config.metric == dataset.metric.to_distance(),
        "candidate collection does not match the C19 dataset"
    );
    let total_before = db.count(COLLECTION, None)?.count;
    anyhow::ensure!(
        total_before >= dataset.train_count,
        "candidate state has fewer points than the semantic corpus"
    );
    let structural_before = total_before - dataset.train_count;
    anyhow::ensure!(
        structural_before <= target,
        "candidate already has {structural_before} structural points, above target {target}"
    );
    anyhow::ensure!(
        !args.compact || structural_before == 0,
        "sealed C19 candidate must be cloned from the measured structural-free baseline"
    );
    validate_existing_marker(
        &args.data_dir,
        &dataset_sha256,
        dataset.train_count,
        structural_before,
        args.negative_control,
    )?;

    let scales = sampled_nonzero_scales(&dataset);
    let (vectors_nonzero, vectors_unique) =
        validate_fixture_vectors(&dataset, &scales, target, args.negative_control)?;
    anyhow::ensure!(
        args.negative_control || vectors_nonzero,
        "identity-derived fixture produced an all-zero vector"
    );
    anyhow::ensure!(
        args.negative_control || vectors_unique,
        "structural fixture vectors are not unique"
    );

    let dataset_name = dataset_name(&args.dataset);
    let scope = TenantScope::system();
    for chunk_start in (structural_before..target).step_by(BATCH_SIZE) {
        let chunk_end = (chunk_start + BATCH_SIZE).min(target);
        let points = (chunk_start..chunk_end)
            .map(|ordinal| Point {
                id: structural_id(&dataset_name, ordinal),
                vector: structural_vector(&dataset, &scales, ordinal, args.negative_control),
                vectors: HashMap::new(),
                sparse_vector: None,
                payload: serde_json::json!({
                    "c19_structural": true,
                    "identity": structural_id(&dataset_name, ordinal),
                }),
            })
            .collect::<Vec<_>>();
        let unsafe_reason = args
            .negative_control
            .then_some("C19 shared-zero negative control; benchmark-only unsafe fixture");
        db.upsert_structural_scoped(COLLECTION, points, true, &scope, unsafe_reason)
            .with_context(|| format!("inject structural rows {chunk_start}..{chunk_end}"))?;
        if chunk_start % 100_000 == 0 {
            eprintln!(
                "C19 inject progress {chunk_end}/{target} elapsed={:.1}s",
                started.elapsed().as_secs_f64()
            );
        }
    }
    if args.compact {
        #[cfg(feature = "benchmark-internals")]
        db.compact_collection_full_for_benchmark(COLLECTION)
            .context("major-compact C19 structural candidate")?;
        #[cfg(not(feature = "benchmark-internals"))]
        anyhow::bail!("sealed C19 topology compaction requires --features benchmark-internals");
    }
    let total_after = db.count(COLLECTION, None)?.count;
    anyhow::ensure!(
        total_after == dataset.train_count + target,
        "C19 candidate count mismatch after injection"
    );
    let marker = StructuralMarker {
        schema: MARKER_SCHEMA.to_string(),
        dataset_sha256: dataset_sha256.clone(),
        semantic_points: dataset.train_count,
        structural_points: target,
        ratio_percent: args.ratio_percent,
        seed: STRUCTURAL_SEED,
        negative_control: args.negative_control,
        fixture: fixture_name(args.negative_control).to_string(),
        topology_parent_sha256: topology_parent_sha256.clone(),
    };
    write_marker(&args.data_dir, &marker)?;
    let report = InjectionReport {
        schema: "chirondb-c19-injection-v1",
        git_sha: args.git_sha,
        dataset: dataset_name,
        dataset_sha256,
        data_dir: args.data_dir.display().to_string(),
        semantic_points: dataset.train_count,
        structural_points_before: structural_before,
        structural_points_after: target,
        injected_points: target - structural_before,
        ratio_percent: args.ratio_percent,
        negative_control: args.negative_control,
        topology_parent_sha256,
        vectors_nonzero,
        vectors_unique,
        compacted: args.compact,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        total_points: total_after,
        sealed_segments: sealed_segment_count(&args.data_dir)?,
    };
    write_report(args.output.as_deref(), &report)
}

fn profile(args: ProfileArgs) -> Result<()> {
    validate_ratio(args.ratio_percent)?;
    anyhow::ensure!(args.neighbor_sample > 0, "neighbor sample must be positive");
    let dataset = MmapDataset::open(&args.dataset)?;
    let dataset_sha256 = sha256_file(&args.dataset)?;
    let target = structural_count(dataset.train_count, args.ratio_percent)?;
    let marker = read_marker(&args.candidate_data)?;
    anyhow::ensure!(
        marker.schema == MARKER_SCHEMA
            && marker.dataset_sha256 == dataset_sha256
            && marker.semantic_points == dataset.train_count
            && marker.structural_points == target
            && (marker.ratio_percent - args.ratio_percent).abs() < f64::EPSILON
            && marker.seed == STRUCTURAL_SEED
            && marker.negative_control == args.negative_control
            && marker.fixture == fixture_name(args.negative_control),
        "candidate C19 marker does not match this profile"
    );
    let topology_parent_sha256 = marker
        .topology_parent_sha256
        .as_deref()
        .context("sealed C19 marker has no measured-baseline parent fingerprint")?;
    let measured_baseline_sha256 = sealed_topology_fingerprint(&args.baseline_data)?;
    anyhow::ensure!(
        topology_parent_sha256 == measured_baseline_sha256,
        "candidate was not derived from the measured baseline topology"
    );

    let baseline_dir = sole_segment_dir(&args.baseline_data)?;
    let candidate_dir = sole_segment_dir(&args.candidate_data)?;
    let baseline_store = V4Store::open(&baseline_dir).context("open baseline vector store")?;
    let candidate_store = V4Store::open(&candidate_dir).context("open candidate vector store")?;
    anyhow::ensure!(
        baseline_store.len() == dataset.train_count,
        "baseline sealed point count does not match semantic corpus"
    );
    anyhow::ensure!(
        candidate_store.len() == dataset.train_count + target,
        "candidate sealed point count does not match semantic + structural corpus"
    );
    anyhow::ensure!(
        candidate_store.ids()[..dataset.train_count]
            .iter()
            .all(|id| id.bytes().all(|byte| byte.is_ascii_digit())),
        "candidate semantic points are not the sealed ordinal prefix"
    );
    anyhow::ensure!(
        candidate_store.ids()[dataset.train_count..]
            .iter()
            .all(|id| id.starts_with("structural::")),
        "candidate structural points are not the sealed ordinal suffix"
    );

    let baseline_ivf = IvfArtifact::open(&baseline_dir.join("ivf.gdx"))?;
    let candidate_ivf = IvfArtifact::open(&candidate_dir.join("ivf.gdx"))?;
    let baseline_vamana = VamanaArtifact::open(&baseline_dir.join("vamana.gdx"), &baseline_ivf)?;
    let candidate_vamana = VamanaArtifact::open(&candidate_dir.join("vamana.gdx"), &candidate_ivf)?;
    let baseline_connectivity =
        baseline_vamana.connectivity_profile_with_ivf(&baseline_ivf, dataset.train_count)?;
    let candidate_connectivity =
        candidate_vamana.connectivity_profile_with_ivf(&candidate_ivf, dataset.train_count)?;
    let baseline_ordinal_to_key = baseline_vamana.ordinal_to_key(&baseline_ivf)?;
    let candidate_ordinal_to_key = candidate_vamana.ordinal_to_key(&candidate_ivf)?;

    let sample = args.neighbor_sample.min(dataset.train_count);
    let sample_ordinals = (0..sample)
        .map(|index| index.saturating_mul(dataset.train_count) / sample)
        .collect::<Vec<_>>();
    let mut candidate_sample_ordinals = HashMap::with_capacity(sample);
    for &baseline_ordinal in &sample_ordinals {
        let id = baseline_store
            .id(baseline_ordinal)
            .context("baseline sample ordinal has no id")?;
        let candidate_ordinal = candidate_store
            .ordinal(id)
            .context("candidate is missing a baseline sample id")?;
        candidate_sample_ordinals.insert(baseline_ordinal, candidate_ordinal);
    }
    let mut losses = Vec::with_capacity(sample);
    for (&baseline_ordinal, &candidate_ordinal) in &candidate_sample_ordinals {
        let baseline_neighbors = baseline_vamana
            .ordinal_neighbors(&baseline_ivf, &baseline_ordinal_to_key, baseline_ordinal)?
            .into_iter()
            .filter_map(|ordinal| baseline_store.id(ordinal as usize))
            .collect::<HashSet<_>>();
        anyhow::ensure!(
            !baseline_neighbors.is_empty(),
            "baseline sample has zero degree"
        );
        let retained = candidate_vamana
            .ordinal_neighbors(&candidate_ivf, &candidate_ordinal_to_key, candidate_ordinal)?
            .into_iter()
            .filter_map(|ordinal| candidate_store.id(ordinal as usize))
            .filter(|id| id.bytes().all(|byte| byte.is_ascii_digit()))
            .filter(|id| baseline_neighbors.contains(id))
            .count();
        losses.push(1.0 - retained as f64 / baseline_neighbors.len() as f64);
    }
    losses.sort_by(f64::total_cmp);
    let mean_loss = losses.iter().sum::<f64>() / losses.len() as f64;
    let p95_loss = percentile(&losses, 0.95);

    let scales = sampled_nonzero_scales(&dataset);
    let normalized_centroid_drift =
        normalized_centroid_drift(&dataset, &scales, target, args.negative_control)?;
    let ratio_fraction = args.ratio_percent / 100.0;
    let centroid_limit = 0.0025_f64.max(ratio_fraction / 4.0);
    let mean_loss_limit = ratio_fraction + 0.005;
    let p95_loss_limit = 0.25;
    let weak_component_increase = candidate_connectivity.weak_components as isize
        - baseline_connectivity.weak_components as isize;
    let passed = normalized_centroid_drift <= centroid_limit
        && mean_loss <= mean_loss_limit
        && p95_loss <= p95_loss_limit
        && weak_component_increase <= 0
        && candidate_connectivity.original_nodes_without_original_neighbors == 0;
    let report = ProfileReport {
        schema: "chirondb-c19-profile-v1",
        git_sha: args.git_sha,
        dataset: dataset_name(&args.dataset),
        dataset_sha256,
        baseline_data: args.baseline_data.display().to_string(),
        candidate_data: args.candidate_data.display().to_string(),
        semantic_points: dataset.train_count,
        structural_points: target,
        ratio_percent: args.ratio_percent,
        negative_control: args.negative_control,
        topology_parent_sha256: measured_baseline_sha256,
        normalized_centroid_drift,
        normalized_centroid_drift_limit: centroid_limit,
        mean_original_neighbor_loss: mean_loss,
        mean_original_neighbor_loss_limit: mean_loss_limit,
        p95_original_neighbor_loss: p95_loss,
        p95_original_neighbor_loss_limit: p95_loss_limit,
        baseline_weak_components: baseline_connectivity.weak_components,
        candidate_weak_components: candidate_connectivity.weak_components,
        weak_component_increase,
        original_nodes_without_original_neighbors: candidate_connectivity
            .original_nodes_without_original_neighbors,
        sampled_original_nodes: sample,
        passed,
    };
    write_report(args.output.as_deref(), &report)
}

fn validate_ratio(ratio_percent: f64) -> Result<()> {
    anyhow::ensure!(
        [0.1, 1.0, 5.0]
            .iter()
            .any(|allowed| (ratio_percent - allowed).abs() < f64::EPSILON),
        "C19 ratio must be one of the preregistered 0.1, 1.0, or 5.0 percent values"
    );
    Ok(())
}

fn structural_count(semantic_points: usize, ratio_percent: f64) -> Result<usize> {
    let count = (semantic_points as f64 * ratio_percent / 100.0).ceil();
    anyhow::ensure!(
        count.is_finite() && count <= usize::MAX as f64,
        "ratio overflow"
    );
    Ok(count as usize)
}

fn sampled_nonzero_scales(dataset: &MmapDataset) -> Vec<f32> {
    let rows = SCALE_SAMPLE_ROWS.min(dataset.train_count);
    let mut sums = vec![0.0_f64; dataset.dim];
    let mut counts = vec![0usize; dataset.dim];
    for sample in 0..rows {
        let index = sample.saturating_mul(dataset.train_count) / rows;
        for (dim, value) in dataset.train_vector(index).into_iter().enumerate() {
            if value != 0.0 {
                sums[dim] += f64::from(value).powi(2);
                counts[dim] += 1;
            }
        }
    }
    sums.into_iter()
        .zip(counts)
        .map(|(sum, count)| {
            if count == 0 {
                1.0
            } else {
                (sum / count as f64).sqrt() as f32
            }
        })
        .collect()
}

fn structural_vector(
    dataset: &MmapDataset,
    scales: &[f32],
    ordinal: usize,
    negative_control: bool,
) -> Vec<f32> {
    if negative_control {
        return vec![0.0; dataset.dim];
    }
    let identity_seed = splitmix64(STRUCTURAL_SEED ^ ordinal as u64);
    let source = (identity_seed % dataset.train_count as u64) as usize;
    let mut vector = dataset.train_vector(source);
    perturb_identity_vector(&mut vector, scales, identity_seed);
    vector
}

fn perturb_identity_vector(vector: &mut [f32], scales: &[f32], identity_seed: u64) {
    for (dim, value) in vector.iter_mut().enumerate() {
        let sign = if splitmix64(identity_seed ^ dim as u64) & 1 == 0 {
            -1.0
        } else {
            1.0
        };
        *value += sign * scales[dim] * 0.01;
    }
}

fn validate_fixture_vectors(
    dataset: &MmapDataset,
    scales: &[f32],
    structural_points: usize,
    negative_control: bool,
) -> Result<(bool, bool)> {
    if negative_control {
        return Ok((false, structural_points <= 1));
    }
    let mut digests = HashSet::<[u8; 32]>::with_capacity(structural_points);
    let mut all_nonzero = true;
    for ordinal in 0..structural_points {
        let vector = structural_vector(dataset, scales, ordinal, false);
        all_nonzero &= vector.iter().any(|value| *value != 0.0);
        let mut digest = Sha256::new();
        for value in vector {
            digest.update(value.to_bits().to_le_bytes());
        }
        if !digests.insert(digest.finalize().into()) {
            return Ok((all_nonzero, false));
        }
    }
    Ok((all_nonzero, true))
}

fn normalized_centroid_drift(
    dataset: &MmapDataset,
    scales: &[f32],
    structural_points: usize,
    negative_control: bool,
) -> Result<f64> {
    let mut semantic_sum = vec![0.0_f64; dataset.dim];
    let mut semantic_norm_sq = 0.0_f64;
    for ordinal in 0..dataset.train_count {
        for (dim, value) in dataset.train_vector(ordinal).into_iter().enumerate() {
            let value = f64::from(value);
            semantic_sum[dim] += value;
            semantic_norm_sq += value * value;
        }
    }
    let mut candidate_sum = semantic_sum.clone();
    for ordinal in 0..structural_points {
        for (sum, value) in candidate_sum.iter_mut().zip(structural_vector(
            dataset,
            scales,
            ordinal,
            negative_control,
        )) {
            *sum += f64::from(value);
        }
    }
    let baseline_mean = semantic_sum
        .iter()
        .map(|sum| sum / dataset.train_count as f64)
        .collect::<Vec<_>>();
    let candidate_count = dataset.train_count + structural_points;
    let drift = baseline_mean
        .iter()
        .zip(candidate_sum)
        .map(|(baseline, sum)| {
            let delta = sum / candidate_count as f64 - baseline;
            delta * delta
        })
        .sum::<f64>()
        .sqrt();
    let mean_norm_sq = baseline_mean.iter().map(|value| value * value).sum::<f64>();
    let rms_radius_sq = semantic_norm_sq / dataset.train_count as f64 - mean_norm_sq;
    anyhow::ensure!(rms_radius_sq > 0.0, "baseline RMS radius is not positive");
    Ok(drift / rms_radius_sq.sqrt())
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    let rank = ((sorted.len() as f64 * quantile).ceil() as usize).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn structural_id(dataset: &str, ordinal: usize) -> String {
    format!("structural::{dataset}::{ordinal:08}")
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn fixture_name(negative_control: bool) -> &'static str {
    if negative_control {
        "shared-zero-negative-control"
    } else {
        "identity-source-row-plus-one-percent-signed-scale-native-metric-scale-v2"
    }
}

fn validate_topology_parent(
    candidate_data: &Path,
    baseline_data: Option<&Path>,
    compact: bool,
) -> Result<Option<String>> {
    if !compact {
        anyhow::ensure!(
            baseline_data.is_none(),
            "--baseline-data is reserved for sealed C19 topology injections"
        );
        return Ok(None);
    }
    let baseline_data = baseline_data.context(
        "sealed C19 injection requires --baseline-data so topology provenance is checkable",
    )?;
    anyhow::ensure!(
        std::fs::canonicalize(candidate_data)? != std::fs::canonicalize(baseline_data)?,
        "C19 baseline and candidate data directories must be distinct"
    );
    let baseline_sha256 = sealed_topology_fingerprint(baseline_data)?;
    let candidate_sha256 = sealed_topology_fingerprint(candidate_data)?;
    anyhow::ensure!(
        baseline_sha256 == candidate_sha256,
        "sealed C19 candidate topology does not match its measured baseline before injection"
    );
    Ok(Some(baseline_sha256))
}

fn sealed_topology_fingerprint(data_dir: &Path) -> Result<String> {
    let segment = sole_segment_dir(data_dir)?;
    let mut digest = Sha256::new();
    for name in ["vec.gdx", "ids.gdx", "ivf.gdx", "vamana.gdx", "seal.gdx"] {
        let path = segment.join(name);
        let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update(file.metadata()?.len().to_le_bytes());
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
    }
    Ok(lower_hex(&digest.finalize()))
}

fn dataset_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("collections")
        .join(COLLECTION)
        .join(MARKER_FILE)
}

fn validate_existing_marker(
    data_dir: &Path,
    dataset_sha256: &str,
    semantic_points: usize,
    structural_points: usize,
    negative_control: bool,
) -> Result<()> {
    let path = marker_path(data_dir);
    if structural_points == 0 && !path.exists() {
        return Ok(());
    }
    let marker = read_marker(data_dir)?;
    anyhow::ensure!(
        marker.schema == MARKER_SCHEMA
            && marker.dataset_sha256 == dataset_sha256
            && marker.semantic_points == semantic_points
            && marker.structural_points == structural_points
            && marker.seed == STRUCTURAL_SEED
            && marker.negative_control == negative_control
            && marker.fixture == fixture_name(negative_control),
        "existing C19 structural marker does not match the candidate state"
    );
    Ok(())
}

fn read_marker(data_dir: &Path) -> Result<StructuralMarker> {
    let path = marker_path(data_dir);
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_marker(data_dir: &Path, marker: &StructuralMarker) -> Result<()> {
    let path = marker_path(data_dir);
    std::fs::write(&path, serde_json::to_vec_pretty(marker)?)
        .with_context(|| format!("write {}", path.display()))
}

fn sole_segment_dir(data_dir: &Path) -> Result<PathBuf> {
    let mut dirs = sealed_segment_dirs(data_dir)?;
    anyhow::ensure!(
        dirs.len() == 1,
        "C19 topology profile requires exactly one sealed segment, found {}",
        dirs.len()
    );
    Ok(dirs.pop().expect("one segment"))
}

fn sealed_segment_count(data_dir: &Path) -> Result<usize> {
    Ok(sealed_segment_dirs(data_dir)?.len())
}

fn sealed_segment_dirs(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let root = data_dir.join("collections").join(COLLECTION);
    let mut dirs = Vec::new();
    for tier in ["searchers", "cold"] {
        let tier_dir = root.join(tier);
        if !tier_dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&tier_dir)? {
            let path = entry?.path();
            if path.is_dir() && path.join("seal.gdx").exists() {
                dirs.push(path);
            }
        }
    }
    Ok(dirs)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(lower_hex(&digest.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_report<T: Serialize>(output: Option<&Path>, report: &T) -> Result<()> {
    let serialized = serde_json::to_string_pretty(report)?;
    if let Some(path) = output {
        std::fs::write(path, &serialized)
            .with_context(|| format!("write report {}", path.display()))?;
    } else {
        println!("{serialized}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_and_structural_ids_are_stable() {
        assert_eq!(splitmix64(STRUCTURAL_SEED), 8_408_036_428_420_403_309);
        assert_eq!(
            structural_id("sift-128-euclidean", 7),
            "structural::sift-128-euclidean::00000007"
        );
    }

    #[test]
    fn ratio_counts_round_up() {
        assert_eq!(structural_count(5183, 0.1).unwrap(), 6);
        assert_eq!(structural_count(5183, 1.0).unwrap(), 52);
        assert_eq!(structural_count(5183, 5.0).unwrap(), 260);
    }

    #[test]
    fn only_preregistered_ratios_are_accepted() {
        for ratio in [0.1, 1.0, 5.0] {
            validate_ratio(ratio).unwrap();
        }
        assert!(validate_ratio(10.0).is_err());
    }

    #[test]
    fn identity_perturbation_preserves_native_vector_scale() {
        let mut vector = vec![3.0, 4.0];
        perturb_identity_vector(&mut vector, &[1.0, 1.0], 42);
        let norm = vector
            .iter()
            .map(|value| f64::from(*value).powi(2))
            .sum::<f64>()
            .sqrt();
        assert!((4.98..=5.02).contains(&norm));
    }

    #[test]
    fn topology_parent_fingerprint_is_content_bound() {
        let root = tempfile::tempdir().unwrap();
        let segment = root
            .path()
            .join("collections")
            .join(COLLECTION)
            .join("searchers")
            .join("segment-1");
        std::fs::create_dir_all(&segment).unwrap();
        std::fs::write(segment.join("vec.gdx"), b"vectors").unwrap();
        std::fs::write(segment.join("seal.gdx"), b"sealed").unwrap();
        std::fs::write(segment.join("ids.gdx"), b"ids").unwrap();
        std::fs::write(segment.join("ivf.gdx"), b"ivf").unwrap();
        std::fs::write(segment.join("vamana.gdx"), b"vamana").unwrap();

        let first = sealed_topology_fingerprint(root.path()).unwrap();
        let second = sealed_topology_fingerprint(root.path()).unwrap();
        assert_eq!(first, second);

        std::fs::write(segment.join("vamana.gdx"), b"different").unwrap();
        assert_ne!(first, sealed_topology_fingerprint(root.path()).unwrap());
    }
}
