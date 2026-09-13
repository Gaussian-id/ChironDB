//! P4 + P6 — ann-benchmarks harness for the `gaussbench` binary.
//!
//! Loads the standard ann-benchmarks datasets (sift-128-euclidean,
//! glove-100-angular, deep-image-96-angular, gist-960-euclidean, …) in a
//! dependency-free `.gbench` binary format (see schema below), upserts them
//! into a temp-dir `Db`, then runs a Pareto recall@k vs QPS sweep across a
//! configurable `ef_search` grid. Emits one JSON record per `ef_search` step
//! suitable for comparing recall and throughput on a consistent dataset.
//!
//! ## `.gbench` binary format (v1)
//!
//! Eight-byte ASCII magic `GBENCHv1`, then a fixed 40-byte little-endian
//! header, then three flat f32 / u32 arrays. The format is intentionally
//! trivial so we avoid the libhdf5 C dependency on macOS aarch64 / Windows
//! — convert the upstream ann-benchmarks `.hdf5` files with
//! `.github/tools/ann-benchmarks/h5_to_gbench.py`.
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "GBENCHv1"
//! 8       8     train_count : u64 LE
//! 16      8     test_count  : u64 LE
//! 24      4     dim         : u32 LE
//! 28      4     k           : u32 LE  (neighbors per test query)
//! 32      1     metric      : u8      (0=L2, 1=Cosine, 2=Dot)
//! 33      15    reserved (zeroed)
//! 48      4*train_count*dim  train[train_count][dim]  : f32 LE
//! ...     4*test_count*dim   test [test_count ][dim]  : f32 LE
//! ...     4*test_count*k     neighbors[test_count][k] : u32 LE
//! ```

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::io::{BufWriter, Write};

use anyhow::{Context, Result, bail};
use chirondb::index::ivf;
use chirondb::{CollectionConfig, Db, DistanceMetric, Filter, Point, SearchRequest};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const MAGIC: &[u8; 8] = b"GBENCHv1";
const FILTER_FIXTURE_SCHEMA: &str = "chirondb-filtered-ann-v1";
const FILTERED_COLLECTION: &str = "ann_filtered_c0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchMetric {
    L2,
    Cosine,
    Dot,
}

impl BenchMetric {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::L2),
            1 => Ok(Self::Cosine),
            2 => Ok(Self::Dot),
            other => bail!("unknown metric byte {other}"),
        }
    }

    pub(crate) fn to_distance(self) -> DistanceMetric {
        match self {
            Self::L2 => DistanceMetric::L2,
            Self::Cosine => DistanceMetric::Cosine,
            Self::Dot => DistanceMetric::Dot,
        }
    }
}

#[derive(Debug)]
pub(crate) struct MmapDataset {
    mmap: memmap2::Mmap,
    pub(crate) train_count: usize,
    pub(crate) test_count: usize,
    pub(crate) dim: usize,
    pub(crate) k: usize,
    pub(crate) metric: BenchMetric,
    train_offset: usize,
    test_offset: usize,
    neighbors_offset: usize,
}

impl MmapDataset {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("open mmap dataset {}", path.display()))?;
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("mmap dataset {}", path.display()))?;
        anyhow::ensure!(
            mmap.len() >= 48 && &mmap[..8] == MAGIC,
            "not a .gbench file (bad or truncated header): {}",
            path.display()
        );
        let train_count = usize::try_from(mmap_u64(&mmap, 8, "train_count")?)
            .context("gbench train_count exceeds this platform's usize")?;
        let test_count = usize::try_from(mmap_u64(&mmap, 16, "test_count")?)
            .context("gbench test_count exceeds this platform's usize")?;
        let dim = mmap_u32(&mmap, 24, "dim")? as usize;
        let k = mmap_u32(&mmap, 28, "k")? as usize;
        let metric = BenchMetric::from_byte(mmap[32])?;
        anyhow::ensure!(
            train_count > 0 && test_count > 0 && dim > 0 && k > 0,
            "gbench counts, dimension, and k must be non-zero"
        );
        let train_bytes = train_count
            .checked_mul(dim)
            .and_then(|values| values.checked_mul(4))
            .context("gbench train byte length overflow")?;
        let test_bytes = test_count
            .checked_mul(dim)
            .and_then(|values| values.checked_mul(4))
            .context("gbench test byte length overflow")?;
        let neighbors_bytes = test_count
            .checked_mul(k)
            .and_then(|values| values.checked_mul(4))
            .context("gbench neighbors byte length overflow")?;
        let train_offset = 48usize;
        let test_offset = train_offset
            .checked_add(train_bytes)
            .context("gbench test offset overflow")?;
        let neighbors_offset = test_offset
            .checked_add(test_bytes)
            .context("gbench neighbors offset overflow")?;
        let expected_len = neighbors_offset
            .checked_add(neighbors_bytes)
            .context("gbench file length overflow")?;
        anyhow::ensure!(
            mmap.len() == expected_len,
            "gbench length mismatch: expected {expected_len}, got {}",
            mmap.len()
        );
        Ok(Self {
            mmap,
            train_count,
            test_count,
            dim,
            k,
            metric,
            train_offset,
            test_offset,
            neighbors_offset,
        })
    }

    pub(crate) fn limit_queries(&mut self, max_queries: Option<usize>) {
        if let Some(max_queries) = max_queries {
            self.test_count = self.test_count.min(max_queries);
        }
    }

    pub(crate) fn train_vector(&self, index: usize) -> Vec<f32> {
        mmap_f32_row(&self.mmap, self.train_offset, index, self.dim)
    }

    pub(crate) fn test_vector(&self, index: usize) -> Vec<f32> {
        mmap_f32_row(&self.mmap, self.test_offset, index, self.dim)
    }

    pub(crate) fn neighbors(&self, index: usize) -> Vec<u32> {
        mmap_u32_row(&self.mmap, self.neighbors_offset, index, self.k)
    }
}

#[derive(Debug, Deserialize)]
struct FilterFixtureFile {
    schema: String,
    dataset: String,
    dataset_sha256: String,
    generator_sha256: String,
    assignment: String,
    payload_field: String,
    seed: u64,
    bucket_count: u32,
    query_count: usize,
    k: usize,
    query_buckets: Vec<u32>,
    neighbors: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FilterAugmentationReport {
    pub schema: String,
    pub fixture: String,
    pub fixture_sha256: String,
    pub dataset: String,
    pub dataset_sha256: String,
    pub generator_sha256: String,
    pub assignment: String,
    pub payload_field: String,
    pub seed: u64,
    pub bucket_count: u32,
    pub query_count: usize,
    pub k: usize,
}

#[derive(Debug)]
struct FilterFixture {
    report: FilterAugmentationReport,
    query_buckets: Vec<u32>,
    neighbors: Vec<Vec<u32>>,
}

impl FilterFixture {
    fn open(path: &Path, dataset_path: &Path, dataset: &MmapDataset) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read filtered ANN fixture {}", path.display()))?;
        let fixture: FilterFixtureFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse filtered ANN fixture {}", path.display()))?;
        anyhow::ensure!(
            fixture.schema == FILTER_FIXTURE_SCHEMA,
            "unsupported filtered ANN fixture schema {:?}",
            fixture.schema
        );
        anyhow::ensure!(
            fixture.payload_field == "c0_bucket",
            "filtered ANN fixture payload_field must be c0_bucket"
        );
        anyhow::ensure!(
            fixture.assignment == "splitmix64(point_ordinal XOR seed) mod bucket_count",
            "unsupported filtered ANN assignment"
        );
        anyhow::ensure!(
            fixture.bucket_count > 1,
            "filtered ANN bucket_count must exceed one"
        );
        anyhow::ensure!(
            fixture.query_count > 0 && fixture.query_count <= dataset.test_count,
            "filtered ANN query_count is outside the dataset"
        );
        anyhow::ensure!(
            fixture.k > 0 && fixture.k <= dataset.k,
            "filtered ANN k is outside the dataset ground-truth width"
        );
        anyhow::ensure!(
            fixture.query_buckets.len() == fixture.query_count
                && fixture.neighbors.len() == fixture.query_count,
            "filtered ANN query arrays disagree with query_count"
        );
        anyhow::ensure!(
            fixture.dataset_sha256.len() == 64 && fixture.generator_sha256.len() == 64,
            "filtered ANN hashes must be lowercase SHA-256 hex"
        );
        anyhow::ensure!(
            fixture
                .dataset_sha256
                .bytes()
                .chain(fixture.generator_sha256.bytes())
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "filtered ANN hashes must be lowercase SHA-256 hex"
        );
        let dataset_sha256 = sha256_file(dataset_path)?;
        anyhow::ensure!(
            fixture.dataset_sha256 == dataset_sha256,
            "filtered ANN fixture dataset hash does not match {}",
            dataset_path.display()
        );
        for (query_index, (&bucket, neighbors)) in fixture
            .query_buckets
            .iter()
            .zip(&fixture.neighbors)
            .enumerate()
        {
            anyhow::ensure!(
                bucket < fixture.bucket_count,
                "filtered ANN query {query_index} bucket is out of range"
            );
            anyhow::ensure!(
                neighbors.len() == fixture.k,
                "filtered ANN query {query_index} ground truth width mismatch"
            );
            for &point_id in neighbors {
                anyhow::ensure!(
                    (point_id as usize) < dataset.train_count,
                    "filtered ANN query {query_index} neighbor is out of range"
                );
                anyhow::ensure!(
                    stable_bucket(point_id as u64, fixture.seed, fixture.bucket_count) == bucket,
                    "filtered ANN query {query_index} neighbor violates its filter"
                );
            }
        }
        Ok(Self {
            report: FilterAugmentationReport {
                schema: fixture.schema,
                fixture: path.display().to_string(),
                fixture_sha256: sha256_bytes(&bytes),
                dataset: fixture.dataset,
                dataset_sha256,
                generator_sha256: fixture.generator_sha256,
                assignment: fixture.assignment,
                payload_field: fixture.payload_field,
                seed: fixture.seed,
                bucket_count: fixture.bucket_count,
                query_count: fixture.query_count,
                k: fixture.k,
            },
            query_buckets: fixture.query_buckets,
            neighbors: fixture.neighbors,
        })
    }

    fn bucket(&self, query_index: usize) -> u32 {
        self.query_buckets[query_index]
    }

    fn neighbors(&self, query_index: usize) -> &[u32] {
        &self.neighbors[query_index]
    }

    fn payload(&self, point_ordinal: u64) -> serde_json::Value {
        json!({
            "c0_bucket": stable_bucket(
                point_ordinal,
                self.report.seed,
                self.report.bucket_count,
            )
        })
    }

    fn filter(&self, query_index: usize) -> Filter {
        Filter(json!({"c0_bucket": self.bucket(query_index)}))
    }
}

fn stable_bucket(point_ordinal: u64, seed: u64, bucket_count: u32) -> u32 {
    let mut value = (point_ordinal ^ seed).wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    (value % u64::from(bucket_count)) as u32
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
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

fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
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

fn mmap_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("truncated gbench {field}"))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four bytes")))
}

fn mmap_u64(bytes: &[u8], offset: usize, field: &str) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .with_context(|| format!("truncated gbench {field}"))?;
    Ok(u64::from_le_bytes(raw.try_into().expect("eight bytes")))
}

fn mmap_f32_row(bytes: &[u8], base_offset: usize, index: usize, width: usize) -> Vec<f32> {
    let start = base_offset + index * width * 4;
    bytes[start..start + width * 4]
        .chunks_exact(4)
        .map(|raw| f32::from_le_bytes(raw.try_into().expect("four-byte chunk")))
        .collect()
}

fn mmap_u32_row(bytes: &[u8], base_offset: usize, index: usize, width: usize) -> Vec<u32> {
    let start = base_offset + index * width * 4;
    bytes[start..start + width * 4]
        .chunks_exact(4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("four-byte chunk")))
        .collect()
}

/// Test writer for the `.gbench` schema documented at the top of this module.
#[cfg(test)]
pub fn write_gbench(
    path: &Path,
    train: &[Vec<f32>],
    test: &[Vec<f32>],
    neighbors: &[Vec<u32>],
    dim: usize,
    k: usize,
    metric: BenchMetric,
) -> Result<()> {
    let mut writer = BufWriter::new(
        File::create(path).with_context(|| format!("create dataset {}", path.display()))?,
    );
    writer.write_all(MAGIC)?;
    writer.write_all(&(train.len() as u64).to_le_bytes())?;
    writer.write_all(&(test.len() as u64).to_le_bytes())?;
    writer.write_all(&(dim as u32).to_le_bytes())?;
    writer.write_all(&(k as u32).to_le_bytes())?;
    writer.write_all(&[metric as u8])?;
    writer.write_all(&[0u8; 15])?;
    for v in train {
        for &x in v {
            writer.write_all(&x.to_le_bytes())?;
        }
    }
    for v in test {
        for &x in v {
            writer.write_all(&x.to_le_bytes())?;
        }
    }
    for ids in neighbors {
        for &id in ids {
            writer.write_all(&id.to_le_bytes())?;
        }
    }
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AnnBenchmarkReport {
    pub dataset: String,
    pub git_sha: String,
    /// Present only for the separately labelled C0 custom workload. A report
    /// with this field is not an upstream ann-benchmarks result.
    pub filter_augmentation: Option<FilterAugmentationReport>,
    pub structural_augmentation: Option<StructuralAugmentationReport>,
    pub encryption_enabled: bool,
    /// Peak process RSS across dataset load, ingest/compaction, reopen, and query.
    pub peak_rss_bytes: u64,
    /// RSS sampled immediately before emitting the report.
    pub final_rss_bytes: u64,
    pub n_train: usize,
    pub n_test: usize,
    pub dim: usize,
    pub k: usize,
    pub metric: BenchMetric,
    pub hnsw_m: u32,
    pub hnsw_ef_construction: u32,
    pub index_kind: String,
    pub vector_name: Option<String>,
    pub streamer_max_bytes: usize,
    pub segment_count: usize,
    pub ivf_cells: usize,
    pub nprobe_policy: String,
    pub recall_target: f32,
    pub rescore_inflation: Option<usize>,
    pub hardware: String,
    pub saturated_threads: usize,
    pub load: LoadReport,
    pub pareto: Vec<ParetoPoint>,
}

#[derive(Debug, Serialize)]
pub struct LoadReport {
    pub reused: bool,
    pub insert_s: f64,
    /// Time after ingest spent waiting for automatic segment publication to
    /// quiesce before any explicit residual compaction starts.
    pub post_ingest_seal_wait_s: f64,
    /// Wall time spent inside explicit compaction calls made by this run.
    pub compaction_s: f64,
    pub optimize_s: f64,
}

#[derive(Debug, Serialize)]
pub struct ParetoPoint {
    pub ef_search: u32,
    pub recall: f64,
    pub recall_at_1: f64,
    pub recall_at_5: Option<f64>,
    pub recall_at_10: Option<f64>,
    pub qps: f64,
    pub saturated_measured: bool,
    pub saturated_qps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub saturated_p50_ms: f64,
    pub saturated_p95_ms: f64,
    pub saturated_p99_ms: f64,
    pub saturated_p999_ms: f64,
    pub degraded_query_rate: f64,
    pub saturated_degraded_query_rate: f64,
    pub persistent_cache: chirondb::encryption::PersistentCacheStats,
}

#[derive(Debug)]
pub struct RunConfig {
    pub dataset_path: PathBuf,
    pub data_dir: Option<PathBuf>,
    pub ef_grid: Vec<u32>,
    pub hnsw_m: Option<u32>,
    pub hnsw_ef_construction: Option<u32>,
    /// Index backend discriminator (`None` or `lsvec` → persisted Algorithm 2).
    pub index_kind: Option<String>,
    pub output: Option<PathBuf>,
    pub git_sha: String,
    /// Sample only the first N test queries instead of the full test set.
    /// Trims search-phase wall time on large datasets without touching the
    /// corpus or ground truth. `None` = full test set.
    pub max_queries: Option<usize>,
    /// Diagnostic override: force the server-wide cascade flag to this value
    /// before the search phase. `None` leaves the engine default (ON).
    pub cascade: Option<bool>,
    /// Query top-K and score recall@K instead of the dataset's native
    /// ground-truth width. `None` = dataset's native `k`. Must be `<=`
    /// dataset's native k (ground truth columns are pre-sorted by distance,
    /// so truncating to the first K is a valid top-K ground truth).
    pub k_override: Option<usize>,
    /// Effective recall contract for LS-VEC's engine-owned rerank inflation.
    /// `None` uses the product default (0.97).
    pub recall_target: Option<f32>,
    /// Compact a reused collection into one fully sealed Algorithm 2 segment
    /// before measuring, isolating the sealed cascade from the live streamer.
    pub compact_reused: bool,
    /// Benchmark-only named-vector storage/recall fixture. When set, copy
    /// each official train row into this named field and run the official
    /// queries against that field. This is not a product search knob.
    pub named_vector_copy: Option<String>,
    /// Separately labelled deterministic filtered ground truth. When present,
    /// ingest adds the fixture's deterministic payload label and every query
    /// is filtered/scored against its exact sidecar truth.
    pub filter_fixture: Option<PathBuf>,
    pub expected_structural_points: usize,
    /// C19's preregistered gate uses sequential QPS only. Avoid spending the
    /// full matrix on the separately reported saturated diagnostic.
    pub sequential_only: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct StructuralAugmentationReport {
    pub schema: &'static str,
    pub structural_points: usize,
    pub semantic_points: usize,
    pub ratio_percent: f64,
    pub classification: &'static str,
}

pub fn run(config: &RunConfig) -> Result<AnnBenchmarkReport> {
    let rss_sampler = RssSampler::start();
    let mut dataset = MmapDataset::open(&config.dataset_path)?;
    let filter_fixture = config
        .filter_fixture
        .as_deref()
        .map(|path| FilterFixture::open(path, &config.dataset_path, &dataset))
        .transpose()?;
    if let Some(fixture) = filter_fixture.as_ref() {
        let query_limit = config
            .max_queries
            .unwrap_or(fixture.report.query_count)
            .min(fixture.report.query_count);
        anyhow::ensure!(query_limit > 0, "filtered ANN query limit must be positive");
        dataset.limit_queries(Some(query_limit));
    } else {
        dataset.limit_queries(config.max_queries);
    }
    let recall_target = config
        .recall_target
        .unwrap_or(chirondb::h2qg::DEFAULT_RECALL_TARGET);
    anyhow::ensure!(
        (0.5..=1.0).contains(&recall_target) && !recall_target.is_nan(),
        "recall_target must be in 0.5..=1.0"
    );
    eprintln!(
        "loaded {} ({} train / {} test / dim {} / k {} / metric {:?})",
        config.dataset_path.display(),
        dataset.train_count,
        dataset.test_count,
        dataset.dim,
        dataset.k,
        dataset.metric
    );

    let temp = if config.data_dir.is_none() {
        Some(TempDir::new().context("create temp data dir")?)
    } else {
        None
    };
    let data_dir = config
        .data_dir
        .as_deref()
        .or_else(|| temp.as_ref().map(TempDir::path))
        .context("benchmark data directory")?;
    std::fs::create_dir_all(data_dir).context("create benchmark data directory")?;
    let db = Db::open(data_dir).context("open db")?;
    let collection = if filter_fixture.is_some() {
        FILTERED_COLLECTION
    } else {
        "ann_benchmarks"
    };
    let hnsw_m = config.hnsw_m.unwrap_or(16);
    let hnsw_ef_construction = config.hnsw_ef_construction.unwrap_or(200);
    let algorithm2 = config
        .index_kind
        .as_deref()
        .is_none_or(|kind| kind.eq_ignore_ascii_case("lsvec"));
    // The product default is 1 GiB. The acceptance harness deliberately
    // lowers only its collection cap so a 512 MiB SIFT1M corpus exercises
    // at least two sealed searchers plus a live streamer, as required by the
    // LS-VEC PRD's hot+cold fuse gate.
    let streamer_max_bytes = if algorithm2 {
        dataset
            .train_count
            .saturating_mul(dataset.dim)
            .saturating_mul(std::mem::size_of::<f32>())
            .saturating_mul(40)
            .saturating_div(100)
            .max(1)
    } else {
        0
    };
    let cfg = CollectionConfig {
        name: collection.into(),
        vector_dim: dataset.dim,
        metric: dataset.metric.to_distance(),
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: config
            .named_vector_copy
            .as_ref()
            .map(|name| std::collections::HashMap::from([(name.clone(), dataset.dim)]))
            .unwrap_or_default(),
        hnsw_m: Some(hnsw_m),
        hnsw_ef_construction: Some(hnsw_ef_construction),
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: config.index_kind.clone(),
        streamer_max_bytes,
    }
    .normalize();
    let existing = db
        .list_collections()
        .into_iter()
        .find(|existing| existing.name == collection);
    let reused = existing.is_some();
    anyhow::ensure!(
        reused || config.expected_structural_points == 0,
        "C19 structural augmentation requires an existing injected state"
    );
    let (insert_s, optimize_s, post_ingest_seal_wait_s, compaction_s) = if let Some(existing) =
        existing
    {
        anyhow::ensure!(
            existing.vector_dim == cfg.vector_dim
                && existing.metric == cfg.metric
                && existing.hnsw_m == cfg.hnsw_m
                && existing.hnsw_ef_construction == cfg.hnsw_ef_construction
                && existing.index_kind == cfg.index_kind
                && existing.named_vector_dims == cfg.named_vector_dims
                && existing.streamer_max_bytes == cfg.streamer_max_bytes,
            "reusable benchmark collection configuration does not match this run"
        );
        anyhow::ensure!(
            db.count(collection, None)?.count
                == dataset
                    .train_count
                    .checked_add(config.expected_structural_points)
                    .context("expected C19 point count overflow")?,
            "reusable benchmark collection point count does not match the dataset"
        );
        if let Some(fixture) = filter_fixture.as_ref() {
            let marker = filter_fixture_marker(data_dir, collection);
            let installed = std::fs::read_to_string(&marker).with_context(|| {
                format!(
                    "read filtered fixture marker for reusable collection {}",
                    marker.display()
                )
            })?;
            anyhow::ensure!(
                installed.trim() == fixture.report.fixture_sha256,
                "reusable collection was built with a different filtered fixture"
            );
        }
        if config.compact_reused {
            let optimize_started = Instant::now();
            let compaction_started = Instant::now();
            db.compact_collection(collection)
                .context("compact reused LS-VEC collection")?;
            let compaction_s = compaction_started.elapsed().as_secs_f64();
            (
                0.0,
                optimize_started.elapsed().as_secs_f64(),
                0.0,
                compaction_s,
            )
        } else {
            (0.0, 0.0, 0.0, 0.0)
        }
    } else {
        db.create_collection(cfg).context("create collection")?;

        let insert_started = Instant::now();
        let batch_size: usize = 1000;
        for chunk_start in (0..dataset.train_count).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(dataset.train_count);
            if chunk_start % 100_000 == 0 {
                eprintln!(
                    "ingest progress {chunk_start}/{} elapsed={:.1}s",
                    dataset.train_count,
                    insert_started.elapsed().as_secs_f64()
                );
            }
            let points: Vec<Point> = (chunk_start..chunk_end)
                .map(|i| {
                    let vector = dataset.train_vector(i);
                    let vectors = config
                        .named_vector_copy
                        .as_ref()
                        .map(|name| {
                            std::collections::HashMap::from([(name.clone(), vector.clone())])
                        })
                        .unwrap_or_default();
                    Point {
                        id: format!("{i}"),
                        vector,
                        vectors,
                        sparse_vector: None,
                        payload: filter_fixture
                            .as_ref()
                            .map_or(serde_json::Value::Null, |fixture| fixture.payload(i as u64)),
                    }
                })
                .collect();
            db.upsert(collection, points).context("upsert chunk")?;
        }
        eprintln!(
            "ingest complete {}/{} elapsed={:.1}s",
            dataset.train_count,
            dataset.train_count,
            insert_started.elapsed().as_secs_f64()
        );
        let insert_s = insert_started.elapsed().as_secs_f64();

        let optimize_started = Instant::now();
        let mut post_ingest_seal_wait_s = 0.0;
        let mut compaction_s = 0.0;
        if algorithm2 {
            let deadline = Instant::now() + Duration::from_secs(7_200);
            let mut next_status_log = Instant::now();
            let mut finalized_residual = false;
            let searchers_dir = data_dir
                .join("collections")
                .join(collection)
                .join("searchers");
            loop {
                let installed = std::fs::read_dir(&searchers_dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(std::result::Result::ok)
                    .any(|entry| {
                        let path = entry.path();
                        path.join(ivf::IVF_FILE).exists()
                            && path.join(chirondb::seal::SEAL_FILE).exists()
                    });
                let seal_in_progress = db.seal_in_progress(collection)?;
                anyhow::ensure!(
                    installed || seal_in_progress,
                    "Algorithm 2 seal failed before installing a committed segment"
                );
                let status = db.index_status(collection)?;
                let streamer_ready = steady_state_index_ready(
                    status.build_in_flight,
                    status.indexed_points,
                    status.total_points,
                );
                if Instant::now() >= next_status_log {
                    eprintln!(
                        "steady-state wait installed={installed} seal_in_progress={seal_in_progress} \
                         indexed_points={}/{} elapsed={:.1}s",
                        status.indexed_points,
                        status.total_points,
                        optimize_started.elapsed().as_secs_f64()
                    );
                    next_status_log = Instant::now() + Duration::from_secs(10);
                }
                if installed && !seal_in_progress && streamer_ready {
                    if !finalized_residual {
                        post_ingest_seal_wait_s = optimize_started.elapsed().as_secs_f64();
                    }
                    break;
                }
                if installed && !seal_in_progress && !finalized_residual {
                    post_ingest_seal_wait_s = optimize_started.elapsed().as_secs_f64();
                    eprintln!(
                        "finalizing residual streamer {}/{} with standard compaction",
                        status.total_points.saturating_sub(status.indexed_points),
                        status.total_points
                    );
                    let compaction_started = Instant::now();
                    db.compact_collection(collection)
                        .context("compact residual streamer")?;
                    compaction_s += compaction_started.elapsed().as_secs_f64();
                    finalized_residual = true;
                    continue;
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "Algorithm 2 seal did not install within 7200 seconds"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        } else {
            let compaction_started = Instant::now();
            db.compact_collection(collection).context("compact")?;
            compaction_s = compaction_started.elapsed().as_secs_f64();
        }
        if let Some(fixture) = filter_fixture.as_ref() {
            let marker = filter_fixture_marker(data_dir, collection);
            std::fs::write(&marker, format!("{}\n", fixture.report.fixture_sha256))
                .with_context(|| format!("write filtered fixture marker {}", marker.display()))?;
        }
        (
            insert_s,
            optimize_started.elapsed().as_secs_f64(),
            post_ingest_seal_wait_s,
            compaction_s,
        )
    };

    if let Some(cascade) = config.cascade {
        db.set_cascade(cascade);
        eprintln!("cascade forced to {cascade}");
    }

    let ground_truth_k = filter_fixture
        .as_ref()
        .map_or(dataset.k, |fixture| fixture.report.k);
    let query_k = config
        .k_override
        .unwrap_or(ground_truth_k)
        .min(ground_truth_k);
    let saturated_threads = rayon::current_num_threads();
    let saturated_pool = (!config.sequential_only)
        .then(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(saturated_threads)
                .stack_size(8 * 1024 * 1024)
                .thread_name(|index| format!("gaussbench-saturated-{index}"))
                .build()
        })
        .transpose()
        .context("build saturated benchmark pool")?;
    let ready_started = Instant::now();
    let ready_deadline = Instant::now() + Duration::from_secs(7_200);
    let mut next_ready_status_log = Instant::now();
    loop {
        let status = db.index_status(collection)?;
        let ready = steady_state_index_ready(
            status.build_in_flight,
            status.indexed_points,
            status.total_points,
        );
        if !ready && Instant::now() >= next_ready_status_log {
            eprintln!(
                "benchmark readiness wait build_in_flight={} indexed_points={}/{} elapsed={:.1}s",
                status.build_in_flight,
                status.indexed_points,
                status.total_points,
                ready_started.elapsed().as_secs_f64()
            );
            next_ready_status_log = Instant::now() + Duration::from_secs(10);
        }
        if ready {
            break;
        }
        anyhow::ensure!(
            status.build_in_flight,
            "benchmark collection has an ANN-sized unindexed streamer with no rebuild in flight"
        );
        anyhow::ensure!(
            Instant::now() < ready_deadline,
            "recovered streamer index did not rebuild within 7200 seconds"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut pareto = Vec::with_capacity(config.ef_grid.len());
    for &ef in &config.ef_grid {
        chirondb::encryption::reset_persistent_cache_stats();
        let sequential_started = Instant::now();
        let mut latencies = Vec::with_capacity(dataset.test_count);
        let mut total_recall = 0.0_f64;
        let mut total_recall_at_1 = 0.0_f64;
        let mut total_recall_at_5 = 0.0_f64;
        let mut total_recall_at_10 = 0.0_f64;
        let mut degraded_queries = 0usize;
        let mut slow_queries = 0usize;
        for q_idx in 0..dataset.test_count {
            if q_idx > 0 && q_idx % 1_000 == 0 {
                eprintln!(
                    "ef={ef:>5}  sequential progress {q_idx}/{} elapsed={:.1}s",
                    dataset.test_count,
                    sequential_started.elapsed().as_secs_f64()
                );
            }
            let query = dataset.test_vector(q_idx);
            let ground_truth = filter_fixture.as_ref().map_or_else(
                || dataset.neighbors(q_idx),
                |fixture| fixture.neighbors(q_idx).to_vec(),
            );
            let query_filter = filter_fixture.as_ref().map(|fixture| fixture.filter(q_idx));
            // PA-2 + PE-1c: bench harness never reads `payload`, so explicitly
            // skip the serde_json::Value clone per hit. `with_payload = false`
            // is the production-correct setting for any caller (ann-benchmarks,
            // VectorDBBench, internal recall calibration) that consumes hits
            // by id alone — closes the p99 gap to Qdrant on payload-heavy
            // schemas.
            let req = SearchRequest {
                graph: None,
                vector: query,
                vector_name: config.named_vector_copy.clone(),
                k: query_k,
                filter: query_filter,
                budget_ms: None,
                consistency: None,
                ef_search: Some(ef),
                recall_target: Some(recall_target),
                with_payload: Some(false),
            };
            let t0 = Instant::now();
            let resp = db.search(collection, req).context("search")?;
            let latency = t0.elapsed();
            degraded_queries += usize::from(resp.degraded);
            if latency >= Duration::from_millis(100) {
                slow_queries += 1;
                if slow_queries <= 5 {
                    eprintln!(
                        "ef={ef:>5}  slow query index={q_idx} latency_ms={:.3}",
                        latency.as_secs_f64() * 1_000.0
                    );
                }
            }
            latencies.push(latency);
            let hit_ids: std::collections::HashSet<u32> = resp
                .hits
                .iter()
                .filter_map(|h| h.id.parse::<u32>().ok())
                .collect();
            let gt_ids: std::collections::HashSet<u32> =
                ground_truth.iter().take(query_k).copied().collect();
            let inter = hit_ids.intersection(&gt_ids).count();
            total_recall += inter as f64 / query_k.max(1) as f64;
            let ordered_hits = resp
                .hits
                .iter()
                .filter_map(|hit| hit.id.parse::<u32>().ok())
                .collect::<Vec<_>>();
            if let Some(fixture) = filter_fixture.as_ref() {
                let expected_bucket = fixture.bucket(q_idx);
                anyhow::ensure!(
                    ordered_hits.iter().all(|&point_id| stable_bucket(
                        point_id as u64,
                        fixture.report.seed,
                        fixture.report.bucket_count,
                    ) == expected_bucket),
                    "filtered ANN query {q_idx} returned a point outside its bucket"
                );
            }
            total_recall_at_1 += recall_at(&ordered_hits, &ground_truth, 1);
            if query_k >= 5 {
                total_recall_at_5 += recall_at(&ordered_hits, &ground_truth, 5);
            }
            if query_k >= 10 {
                total_recall_at_10 += recall_at(&ordered_hits, &ground_truth, 10);
            }
        }
        if slow_queries > 0 {
            eprintln!(
                "ef={ef:>5}  slow query summary count={slow_queries}/{} threshold_ms=100 \
                 (first {} shown)",
                dataset.test_count,
                slow_queries.min(5)
            );
        }
        let total: Duration = latencies.iter().copied().sum();
        let qps = dataset.test_count as f64 / total.as_secs_f64().max(f64::EPSILON);
        let recall = total_recall / dataset.test_count.max(1) as f64;
        let query_count = dataset.test_count.max(1) as f64;
        let saturated_started = Instant::now();
        // Use exactly one long-lived loop per worker. Submitting all queries
        // as one Rayon parallel iterator allows nested engine Rayon work to
        // execute other queued benchmark queries while a search is waiting,
        // which makes a single query's measured duration include unrelated
        // queries and produces impossible multi-second percentiles alongside
        // four-digit QPS. Bounded workers model real closed-loop clients:
        // each worker issues its next query only after the previous response.
        let worker_samples = if let Some(saturated_pool) = saturated_pool.as_ref() {
            let saturated_completed = AtomicUsize::new(0);
            saturated_pool.install(|| {
                (0..saturated_threads)
                    .into_par_iter()
                    .map(|worker| {
                        let mut samples =
                            Vec::with_capacity(dataset.test_count.div_ceil(saturated_threads));
                        for query_index in (worker..dataset.test_count).step_by(saturated_threads) {
                            let query = dataset.test_vector(query_index);
                            let query_started = Instant::now();
                            let response = db.search(
                                collection,
                                SearchRequest {
                                    graph: None,
                                    vector: query,
                                    vector_name: config.named_vector_copy.clone(),
                                    k: query_k,
                                    filter: filter_fixture
                                        .as_ref()
                                        .map(|fixture| fixture.filter(query_index)),
                                    budget_ms: None,
                                    consistency: None,
                                    ef_search: Some(ef),
                                    recall_target: Some(recall_target),
                                    with_payload: Some(false),
                                },
                            )?;
                            samples.push((query_started.elapsed(), response.degraded));
                            let completed = saturated_completed.fetch_add(1, Ordering::Relaxed) + 1;
                            if completed.is_multiple_of(1_000) {
                                eprintln!(
                                    "ef={ef:>5}  saturated progress {completed}/{} elapsed={:.1}s",
                                    dataset.test_count,
                                    saturated_started.elapsed().as_secs_f64()
                                );
                            }
                        }
                        Ok::<_, chirondb::GaussError>(samples)
                    })
                    .collect::<Vec<_>>()
            })
        } else {
            Vec::new()
        };
        let mut saturated_latencies = Vec::with_capacity(dataset.test_count);
        let mut saturated_degraded_queries = 0usize;
        for samples in worker_samples {
            for (latency, degraded) in samples.context("saturated search")? {
                saturated_latencies.push(latency);
                saturated_degraded_queries += usize::from(degraded);
            }
        }
        let saturated_qps = if config.sequential_only {
            0.0
        } else {
            dataset.test_count as f64 / saturated_started.elapsed().as_secs_f64().max(f64::EPSILON)
        };
        pareto.push(ParetoPoint {
            ef_search: ef,
            recall,
            recall_at_1: total_recall_at_1 / query_count,
            recall_at_5: (query_k >= 5).then_some(total_recall_at_5 / query_count),
            recall_at_10: (query_k >= 10).then_some(total_recall_at_10 / query_count),
            qps,
            saturated_measured: !config.sequential_only,
            saturated_qps,
            p50_ms: percentile_ms(&mut latencies.clone(), 0.50),
            p95_ms: percentile_ms(&mut latencies.clone(), 0.95),
            p99_ms: percentile_ms(&mut latencies.clone(), 0.99),
            p999_ms: percentile_ms(&mut latencies.clone(), 0.999),
            saturated_p50_ms: percentile_ms(&mut saturated_latencies.clone(), 0.50),
            saturated_p95_ms: percentile_ms(&mut saturated_latencies.clone(), 0.95),
            saturated_p99_ms: percentile_ms(&mut saturated_latencies.clone(), 0.99),
            saturated_p999_ms: percentile_ms(&mut saturated_latencies.clone(), 0.999),
            degraded_query_rate: degraded_queries as f64 / query_count,
            saturated_degraded_query_rate: saturated_degraded_queries as f64 / query_count,
            persistent_cache: chirondb::encryption::persistent_cache_stats(),
        });
        let cache = chirondb::encryption::persistent_cache_stats();
        eprintln!(
            "ef={ef:>5}  recall@{query_k}={recall:.4}  qps={qps:>8.1}  saturated={saturated_qps:>8.1}  cache={}/{} decrypted={:.1}MiB",
            cache.hits,
            cache.hits.saturating_add(cache.misses),
            cache.decrypted_bytes as f64 / (1024.0 * 1024.0),
        );
    }

    let dataset_name = config
        .dataset_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let (segment_count, ivf_cells) = lsvec_layout_for_collection(data_dir, collection);
    let final_rss_bytes = rss_bytes();
    let peak_rss_bytes = rss_sampler.finish();
    let report = AnnBenchmarkReport {
        dataset: dataset_name,
        git_sha: config.git_sha.clone(),
        filter_augmentation: filter_fixture
            .as_ref()
            .map(|fixture| fixture.report.clone()),
        structural_augmentation: (config.expected_structural_points > 0).then_some(
            StructuralAugmentationReport {
                schema: "chirondb-c19-ann-augmentation-v1",
                structural_points: config.expected_structural_points,
                semantic_points: dataset.train_count,
                ratio_percent: config.expected_structural_points as f64 * 100.0
                    / dataset.train_count as f64,
                classification: "custom C19 augmentation; not an unmodified ann-benchmarks result",
            },
        ),
        encryption_enabled: chirondb::encryption::encryption_enabled(),
        peak_rss_bytes,
        final_rss_bytes,
        n_train: dataset.train_count,
        n_test: dataset.test_count,
        dim: dataset.dim,
        k: query_k,
        metric: dataset.metric,
        hnsw_m,
        hnsw_ef_construction,
        index_kind: "lsvec".to_string(),
        vector_name: config.named_vector_copy.clone(),
        streamer_max_bytes,
        segment_count,
        ivf_cells,
        nprobe_policy: "auto: >=sqrt(nlist), until postings >= 8*ef".to_string(),
        recall_target,
        rescore_inflation: chirondb::index::ivf_segment::rescore_inflation_for_recall_target(
            query_k,
            recall_target,
        ),
        hardware: format!(
            "{}-{}; logical_cpus={saturated_threads}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
        saturated_threads,
        load: LoadReport {
            reused,
            insert_s,
            post_ingest_seal_wait_s,
            compaction_s,
            optimize_s,
        },
        pareto,
    };

    let serialized = serde_json::to_string_pretty(&report)?;
    if let Some(path) = config.output.as_ref() {
        std::fs::write(path, &serialized)
            .with_context(|| format!("write report to {}", path.display()))?;
    } else {
        println!("{serialized}");
    }
    Ok(report)
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
        std::fs::read_to_string("/proc/self/statm")
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

fn filter_fixture_marker(data_dir: &Path, collection: &str) -> PathBuf {
    data_dir
        .join("collections")
        .join(collection)
        .join("filtered-fixture.sha256")
}

#[cfg(test)]
fn lsvec_layout(data_dir: &Path) -> (usize, usize) {
    lsvec_layout_for_collection(data_dir, "ann_benchmarks")
}

fn lsvec_layout_for_collection(data_dir: &Path, collection: &str) -> (usize, usize) {
    let mut segment_count = 0usize;
    let mut ivf_cells = 0usize;
    for tier in ["searchers", "cold"] {
        let segments = data_dir.join("collections").join(collection).join(tier);
        for path in std::fs::read_dir(segments)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
        {
            if !path.join(chirondb::seal::SEAL_FILE).exists() {
                continue;
            }
            let ivf_path = path.join(ivf::IVF_FILE);
            let Ok(artifact) = ivf::IvfArtifact::open(&ivf_path) else {
                continue;
            };
            segment_count += 1;
            ivf_cells += artifact.cells();
        }
    }
    (segment_count, ivf_cells)
}

fn recall_at(hits: &[u32], ground_truth: &[u32], k: usize) -> f64 {
    let k = k.min(hits.len()).min(ground_truth.len());
    if k == 0 {
        return 0.0;
    }
    let hits = hits
        .iter()
        .take(k)
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let truth = ground_truth
        .iter()
        .take(k)
        .copied()
        .collect::<std::collections::HashSet<_>>();
    hits.intersection(&truth).count() as f64 / k as f64
}

fn steady_state_index_ready(build_in_flight: bool, indexed: usize, total: usize) -> bool {
    let unindexed = total.saturating_sub(indexed);
    !build_in_flight && (unindexed == 0 || unindexed < chirondb::h2qg::HNSW_THRESHOLD)
}

fn percentile_ms(values: &mut [Duration], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable();
    let rank = ((values.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    let dur = values[rank.min(values.len() - 1)];
    dur.as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn recall_helper_matches_tiny_oracle() {
        let ground_truth = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(recall_at(&[1], &ground_truth, 1), 1.0);
        assert_eq!(recall_at(&[2, 1, 3, 99, 98], &ground_truth, 5), 0.6);
        assert_eq!(
            recall_at(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 99], &ground_truth, 10),
            0.9
        );
    }

    #[test]
    fn steady_state_gate_waits_for_an_ann_sized_streamer_suffix() {
        let threshold = chirondb::h2qg::HNSW_THRESHOLD;
        assert!(!steady_state_index_ready(false, 950_000, 1_000_000));
        assert!(!steady_state_index_ready(true, 1_000_000, 1_000_000));
        assert!(steady_state_index_ready(false, 1_000_000, 1_000_000));
        assert!(steady_state_index_ready(
            false,
            1_000_000 - (threshold - 1),
            1_000_000
        ));
    }

    fn synthesize(n_train: usize, n_test: usize, dim: usize) -> (Vec<Vec<f32>>, Vec<Vec<f32>>) {
        let mut train = Vec::with_capacity(n_train);
        for i in 0..n_train {
            let mut v = vec![0.0_f32; dim];
            for (j, slot) in v.iter_mut().enumerate() {
                *slot = ((i * 31 + j * 17) % 997) as f32 / 997.0;
            }
            train.push(v);
        }
        let mut test = Vec::with_capacity(n_test);
        for i in 0..n_test {
            // Pick a query that is a small perturbation of an existing train vector.
            let base = &train[i % n_train];
            let mut v = base.clone();
            v[0] += 1e-6;
            test.push(v);
        }
        (train, test)
    }

    fn exact_top_k(train: &[Vec<f32>], q: &[f32], k: usize, metric: BenchMetric) -> Vec<u32> {
        let dist_metric = metric.to_distance();
        let mut scored: Vec<(u32, f32)> = train
            .iter()
            .enumerate()
            .filter_map(|(i, v)| dist_metric.score(q, v).ok().map(|s| (i as u32, s)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        scored.into_iter().take(k).map(|(id, _)| id).collect()
    }

    struct FilterFixtureTestSpec {
        metric: BenchMetric,
        seed: u64,
        bucket_count: u32,
        k: usize,
    }

    fn write_filter_fixture(
        path: &Path,
        dataset_path: &Path,
        train: &[Vec<f32>],
        test: &[Vec<f32>],
        upstream_neighbors: &[Vec<u32>],
        spec: FilterFixtureTestSpec,
    ) {
        let query_buckets = upstream_neighbors
            .iter()
            .map(|neighbors| stable_bucket(u64::from(neighbors[0]), spec.seed, spec.bucket_count))
            .collect::<Vec<_>>();
        let neighbors = test
            .iter()
            .zip(&query_buckets)
            .map(|(query, &bucket)| {
                let mut scored = train
                    .iter()
                    .enumerate()
                    .filter(|(point_id, _)| {
                        stable_bucket(*point_id as u64, spec.seed, spec.bucket_count) == bucket
                    })
                    .map(|(point_id, vector)| {
                        (
                            point_id as u32,
                            spec.metric.to_distance().score(query, vector).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                scored
                    .into_iter()
                    .take(spec.k)
                    .map(|(point_id, _)| point_id)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let fixture = json!({
            "schema": FILTER_FIXTURE_SCHEMA,
            "dataset": dataset_path.file_name().unwrap().to_string_lossy(),
            "dataset_sha256": sha256_file(dataset_path).unwrap(),
            "generator_sha256": "0".repeat(64),
            "assignment": "splitmix64(point_ordinal XOR seed) mod bucket_count",
            "payload_field": "c0_bucket",
            "seed": spec.seed,
            "bucket_count": spec.bucket_count,
            "query_count": test.len(),
            "k": spec.k,
            "query_buckets": query_buckets,
            "neighbors": neighbors,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }

    #[test]
    fn run_against_synth_dataset_emits_pareto_with_high_recall_at_large_ef() {
        let dir = tempdir().unwrap();
        let dataset_path = dir.path().join("synth.gbench");
        let (train, test) = synthesize(256, 8, 16);
        let neighbors: Vec<Vec<u32>> = test
            .iter()
            .map(|q| exact_top_k(&train, q, 5, BenchMetric::Cosine))
            .collect();
        write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            16,
            5,
            BenchMetric::Cosine,
        )
        .unwrap();

        let output = dir.path().join("report.json");
        let config = RunConfig {
            dataset_path,
            data_dir: Some(dir.path().join("db")),
            ef_grid: vec![16, 64, 256],
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: None,
            output: Some(output.clone()),
            git_sha: "test".into(),
            max_queries: None,
            cascade: None,
            k_override: None,
            recall_target: None,
            compact_reused: false,
            named_vector_copy: None,
            filter_fixture: None,
            expected_structural_points: 0,
            sequential_only: false,
        };
        let report = run(&config).unwrap();
        assert_eq!(report.pareto.len(), 3);
        // At ef=256 on 256-point train and a small perturbation query, recall
        // should be ~1.0 in flat mode (below HNSW_THRESHOLD = 10_000).
        let high = report
            .pareto
            .iter()
            .find(|p| p.ef_search == 256)
            .expect("ef=256 row");
        assert!(high.recall >= 0.95, "high-ef recall too low: {high:?}");
        assert!(high.recall_at_1 >= 0.95);
        assert!(high.recall_at_5.is_some());
        assert!(high.saturated_measured);
        assert!(high.saturated_qps > 0.0);
        assert!(high.qps > 0.0);
        assert!(high.p999_ms >= high.p99_ms);
        assert!(high.saturated_p50_ms > 0.0);
        assert!(high.saturated_p95_ms >= high.saturated_p50_ms);
        assert!(high.saturated_p99_ms >= high.saturated_p95_ms);
        assert!(high.saturated_p999_ms >= high.saturated_p99_ms);
        assert_eq!(high.degraded_query_rate, 0.0);
        assert_eq!(high.saturated_degraded_query_rate, 0.0);
        assert!(output.exists(), "report json should be written");
        assert!(!report.load.reused);
        let reopened = run(&config).unwrap();
        assert!(reopened.load.reused);
        assert_eq!(reopened.load.insert_s, 0.0);
        assert_eq!(reopened.load.post_ingest_seal_wait_s, 0.0);
        assert_eq!(reopened.load.compaction_s, 0.0);
        assert_eq!(reopened.load.optimize_s, 0.0);
        let data_dir = config.data_dir.clone().unwrap();
        let compacted = run(&RunConfig {
            compact_reused: true,
            ..config
        })
        .unwrap();
        assert!(compacted.load.reused);
        assert!(compacted.load.optimize_s > 0.0);
        assert_eq!(compacted.load.post_ingest_seal_wait_s, 0.0);
        assert!(compacted.load.compaction_s > 0.0);
        assert!(compacted.load.optimize_s >= compacted.load.compaction_s);
        assert_eq!(compacted.segment_count, 1);
        let db = Db::open(&data_dir).unwrap();
        db.tier_collection_to_cold("ann_benchmarks").unwrap();
        drop(db);
        assert_eq!(
            lsvec_layout(&data_dir),
            (compacted.segment_count, compacted.ivf_cells)
        );
    }

    #[test]
    fn filtered_fixture_is_exact_labelled_and_reuse_safe() {
        let dir = tempdir().unwrap();
        let dataset_path = dir.path().join("filtered-synth.gbench");
        let (train, test) = synthesize(512, 12, 16);
        let neighbors = test
            .iter()
            .map(|query| exact_top_k(&train, query, 10, BenchMetric::Cosine))
            .collect::<Vec<_>>();
        write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            16,
            10,
            BenchMetric::Cosine,
        )
        .unwrap();
        let fixture_path = dir.path().join("filtered.json");
        write_filter_fixture(
            &fixture_path,
            &dataset_path,
            &train,
            &test,
            &neighbors,
            FilterFixtureTestSpec {
                metric: BenchMetric::Cosine,
                seed: 41,
                bucket_count: 8,
                k: 5,
            },
        );
        let config = RunConfig {
            dataset_path,
            data_dir: Some(dir.path().join("db")),
            ef_grid: vec![256],
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: None,
            output: None,
            git_sha: "filtered-test".into(),
            max_queries: None,
            cascade: None,
            k_override: None,
            recall_target: Some(0.99),
            compact_reused: false,
            named_vector_copy: None,
            filter_fixture: Some(fixture_path),
            expected_structural_points: 0,
            sequential_only: true,
        };
        let report = run(&config).unwrap();
        let augmentation = report.filter_augmentation.as_ref().unwrap();
        assert_eq!(augmentation.query_count, 12);
        assert_eq!(augmentation.bucket_count, 8);
        assert_eq!(report.k, 5);
        assert_eq!(report.pareto[0].recall, 1.0);
        assert_eq!(report.pareto[0].degraded_query_rate, 0.0);
        assert!(!report.pareto[0].saturated_measured);
        assert_eq!(report.pareto[0].saturated_qps, 0.0);
        let reused = run(&config).unwrap();
        assert!(reused.load.reused);
        assert_eq!(reused.pareto[0].recall, 1.0);
    }

    #[test]
    fn run_lsvec_uses_persisted_algorithm2_segment() {
        let dir = tempdir().unwrap();
        let dataset_path = dir.path().join("lsvec-synth.gbench");
        let (train, test) = synthesize(256, 8, 16);
        let neighbors = test
            .iter()
            .map(|query| exact_top_k(&train, query, 5, BenchMetric::Cosine))
            .collect::<Vec<_>>();
        write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            16,
            5,
            BenchMetric::Cosine,
        )
        .unwrap();

        let report = run(&RunConfig {
            dataset_path: dataset_path.clone(),
            data_dir: None,
            ef_grid: vec![256],
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: Some("lsvec".to_string()),
            output: Some(dir.path().join("lsvec-report.json")),
            git_sha: "test".into(),
            max_queries: None,
            cascade: None,
            k_override: None,
            recall_target: Some(0.99),
            compact_reused: false,
            named_vector_copy: None,
            filter_fixture: None,
            expected_structural_points: 0,
            sequential_only: false,
        })
        .unwrap();
        assert_eq!(report.recall_target, 0.99);
        assert_eq!(report.rescore_inflation, Some(5));
        assert!(
            report.pareto[0].recall >= 0.95,
            "Algorithm 2 high-ef recall too low: {:?}",
            report.pareto[0]
        );

        let named_data_dir = dir.path().join("named-db");
        let named_report = run(&RunConfig {
            dataset_path,
            data_dir: Some(named_data_dir.clone()),
            ef_grid: vec![256],
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: Some("lsvec".to_string()),
            output: Some(dir.path().join("lsvec-named-report.json")),
            git_sha: "test".into(),
            max_queries: None,
            cascade: None,
            k_override: None,
            recall_target: Some(0.99),
            compact_reused: false,
            named_vector_copy: Some("image".to_string()),
            filter_fixture: None,
            expected_structural_points: 0,
            sequential_only: false,
        })
        .unwrap();
        assert_eq!(named_report.vector_name.as_deref(), Some("image"));
        assert!(
            named_report.pareto[0].recall >= 0.95,
            "named Algorithm 2 high-ef recall too low: {:?}",
            named_report.pareto[0]
        );
        let marker_versions =
            std::fs::read_dir(named_data_dir.join("collections/ann_benchmarks/searchers"))
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter_map(|entry| {
                    chirondb::seal::read_marker(&entry.path().join(chirondb::seal::SEAL_FILE))
                        .ok()
                        .map(|marker| marker.version)
                })
                .collect::<Vec<_>>();
        assert!(!marker_versions.is_empty());
        assert!(marker_versions.iter().all(|version| *version == 8));
    }

    /// Synthetic Pareto baseline runner for B8 of `.SPEC/gaussdb-vector_cleaned.md`. Runs
    /// the ann-benchmarks harness against a moderately-sized synthetic dataset
    /// (1000 train / 100 test / dim 128) on the four canonical metrics and
    /// writes a JSON report to `benchmark_results/`. Gated on the env var
    /// `GAUSSDB_WRITE_BASELINE=1` so normal `cargo test` runs stay fast.
    ///
    /// Real sift-128-euclidean / glove-100-angular runs (B8 acceptance per
    /// `.SPEC/gaussdb-vector_cleaned.md`) reuse the same harness via
    /// `.github/tools/ann-benchmarks/h5_to_gbench.py` — they take a long
    /// time and a network fetch, so they are not gated here. See
    /// the Obsidian benchmark notes for the procedure.
    #[test]
    fn write_synthetic_pareto_baseline() {
        if std::env::var("GAUSSDB_WRITE_BASELINE").as_deref() != Ok("1") {
            return;
        }
        let dir = tempdir().unwrap();
        let dataset_path = dir.path().join("synth.gbench");
        let (train, test) = synthesize(1000, 100, 128);
        let neighbors: Vec<Vec<u32>> = test
            .iter()
            .map(|q| exact_top_k(&train, q, 10, BenchMetric::Cosine))
            .collect();
        write_gbench(
            &dataset_path,
            &train,
            &test,
            &neighbors,
            128,
            10,
            BenchMetric::Cosine,
        )
        .unwrap();
        let output = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("benchmark_results")
            .join("synthetic-128d-1k.json");
        let config = RunConfig {
            dataset_path,
            data_dir: None,
            ef_grid: vec![16, 32, 64, 128, 256],
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: None,
            output: Some(output.clone()),
            git_sha: std::env::var("GAUSSDB_GIT_SHA").unwrap_or_else(|_| "untagged".into()),
            max_queries: None,
            cascade: None,
            k_override: None,
            recall_target: None,
            compact_reused: false,
            named_vector_copy: None,
            filter_fixture: None,
            expected_structural_points: 0,
            sequential_only: false,
        };
        let report = run(&config).unwrap();
        assert_eq!(report.pareto.len(), 5);
        assert!(output.exists());
    }

    #[test]
    fn gbench_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("toy.gbench");
        let (train, test) = synthesize(8, 3, 4);
        let neighbors: Vec<Vec<u32>> = test
            .iter()
            .map(|q| exact_top_k(&train, q, 2, BenchMetric::Cosine))
            .collect();
        write_gbench(&path, &train, &test, &neighbors, 4, 2, BenchMetric::Cosine).unwrap();
        let mut mmap = MmapDataset::open(&path).unwrap();
        assert_eq!(mmap.train_count, train.len());
        assert_eq!(mmap.test_count, test.len());
        assert_eq!(mmap.dim, 4);
        assert_eq!(mmap.k, 2);
        assert_eq!(mmap.metric, BenchMetric::Cosine);
        assert_eq!(mmap.train_vector(3), train[3]);
        assert_eq!(mmap.test_vector(2), test[2]);
        assert_eq!(mmap.neighbors(1), neighbors[1]);
        mmap.limit_queries(Some(1));
        assert_eq!(mmap.test_count, 1);
    }
}
