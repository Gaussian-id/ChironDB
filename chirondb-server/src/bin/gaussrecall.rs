use std::time::Instant;

use anyhow::{Context, Result};
use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;

/// Vector distribution used to generate the dataset.
#[derive(Clone, Debug, Default, ValueEnum)]
enum Distribution {
    /// Uniformly random vectors in [-1, 1]^dim (PRNG-deterministic).
    #[default]
    Uniform,
    /// Clustered Gaussian vectors: sqrt(N) centroids, points drawn near each
    /// centroid.  More representative of real-world embedding distributions.
    Clustered,
}

#[derive(Debug, Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Run a deterministic ChironDB recall@k validation"
)]
struct Args {
    #[arg(long, default_value_t = 1_000)]
    points: usize,
    #[arg(long, default_value_t = 128)]
    dim: usize,
    #[arg(long, default_value_t = 100)]
    queries: usize,
    #[arg(long, default_value_t = 10)]
    k: usize,
    #[arg(long, default_value_t = 0.95)]
    min_recall: f64,
    /// Distribution of generated vectors.
    #[arg(long, default_value = "uniform")]
    distribution: Distribution,
    /// Run two passes: one below the HNSW threshold (flat index) and one at
    /// `--hnsw-scale` points (HNSW index).  Reports the combined worst recall.
    #[arg(long)]
    hnsw: bool,
    /// Number of points for the HNSW-scale pass when `--hnsw` is set.
    #[arg(long, default_value_t = 12_000)]
    hnsw_scale: usize,
    /// Override per-query `ef_search` instead of using the engine default.
    /// Diagnostic knob for isolating whether a recall gap is an ef-tuning
    /// shortfall (recall recovers as ef grows) or a structural bug (it
    /// doesn't).
    #[arg(long)]
    ef_search: Option<u32>,
    /// Override HNSW `M` (max out-degree per node) instead of the engine default.
    #[arg(long)]
    hnsw_m: Option<u32>,
    /// Override HNSW `ef_construction` instead of the engine default.
    #[arg(long)]
    hnsw_ef_construction: Option<u32>,
}

#[derive(Debug, Serialize)]
struct RecallReport {
    status: &'static str,
    distribution: String,
    points: usize,
    dim: usize,
    queries: usize,
    k: usize,
    min_required_recall_at_k: f64,
    mean_recall_at_k: f64,
    min_recall_at_k: f64,
    hnsw_mean_recall_at_k: Option<f64>,
    hnsw_min_recall_at_k: Option<f64>,
    elapsed_ms: u128,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let started = Instant::now();

    let dist_name = format!("{:?}", args.distribution).to_lowercase();

    let (mean_recall, min_recall) = run_recall_pass(
        args.points,
        args.dim,
        args.queries,
        args.k,
        &args.distribution,
        args.ef_search,
        args.hnsw_m,
        args.hnsw_ef_construction,
    )?;

    let (hnsw_mean, hnsw_min) = if args.hnsw {
        let (m, mn) = run_recall_pass(
            args.hnsw_scale,
            args.dim,
            args.queries,
            args.k,
            &args.distribution,
            args.ef_search,
            args.hnsw_m,
            args.hnsw_ef_construction,
        )?;
        (Some(m), Some(mn))
    } else {
        (None, None)
    };

    let overall_min = hnsw_min.unwrap_or(1.0).min(min_recall);
    let status = if overall_min >= args.min_recall {
        "ok"
    } else {
        "failed"
    };
    let report = RecallReport {
        status,
        distribution: dist_name,
        points: args.points,
        dim: args.dim,
        queries: args.queries,
        k: args.k,
        min_required_recall_at_k: args.min_recall,
        mean_recall_at_k: mean_recall,
        min_recall_at_k: min_recall,
        hnsw_mean_recall_at_k: hnsw_mean,
        hnsw_min_recall_at_k: hnsw_min,
        elapsed_ms: started.elapsed().as_millis(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if status == "ok" {
        Ok(())
    } else {
        anyhow::bail!(
            "min recall@{} {:.6} below required {:.6}",
            args.k,
            overall_min,
            args.min_recall
        )
    }
}

// CLI diagnostic tool, not library API -- each param is an independent sweep
// knob (dim/ef/M/ef_construction), a struct would just move the noise.
#[allow(clippy::too_many_arguments)]
fn run_recall_pass(
    n_points: usize,
    dim: usize,
    n_queries: usize,
    k: usize,
    distribution: &Distribution,
    ef_search: Option<u32>,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
) -> Result<(f64, f64)> {
    let temp = TempDir::new().context("create recall validation data directory")?;
    let db = Db::open(temp.path()).context("open recall validation database")?;
    let collection = "recall";
    db.create_collection(CollectionConfig {
        name: collection.to_string(),
        vector_dim: dim,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema: Default::default(),
        named_vector_dims: Default::default(),
        hnsw_m,
        hnsw_ef_construction,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .context("create recall validation collection")?;

    let centroids: Vec<Vec<f32>> = match distribution {
        Distribution::Uniform => Vec::new(),
        Distribution::Clustered => {
            let n_clusters = (n_points as f64).sqrt().ceil() as usize;
            (0..n_clusters)
                .map(|i| deterministic_vector(i as u64 ^ 0xDEAD_BEEF, dim))
                .collect()
        }
    };

    let points = (0..n_points)
        .map(|index| Point {
            id: format!("p{index:08}"),
            vector: match distribution {
                Distribution::Uniform => deterministic_vector(index as u64, dim),
                Distribution::Clustered => {
                    let cluster = index % centroids.len().max(1);
                    clustered_vector(&centroids[cluster], index as u64, dim, 0.15)
                }
            },
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": index % 16}),
        })
        .collect::<Vec<_>>();
    db.upsert(collection, points.clone())
        .context("upsert recall validation points")?;
    db.compact_collection(collection)
        .context("compact recall validation collection")?;

    let mut recalls = Vec::with_capacity(n_queries);
    for query_index in 0..n_queries {
        let query = match distribution {
            Distribution::Uniform => deterministic_vector((n_points + query_index) as u64, dim),
            Distribution::Clustered => {
                let cluster = query_index % centroids.len().max(1);
                clustered_vector(
                    &centroids[cluster],
                    (n_points + query_index) as u64,
                    dim,
                    0.1,
                )
            }
        };
        let expected = exact_top_k(&points, &query, k)?;
        let actual = db
            .search(
                collection,
                SearchRequest {
                    graph: None,
                    vector: query,
                    vector_name: None,
                    k,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .context("search recall validation collection")?
            .hits
            .into_iter()
            .map(|hit| hit.id)
            .collect::<Vec<_>>();
        let r = recall_at_k(&expected, &actual, k);
        if r < 0.5 && std::env::var("GAUSSRECALL_DEBUG").is_ok() {
            eprintln!(
                "query {query_index}: recall={r:.2} expected={expected:?} actual={actual:?} actual_len={}",
                actual.len()
            );
        }
        recalls.push(r);
    }

    let min = recalls.iter().copied().fold(1.0, f64::min);
    let mean = recalls.iter().sum::<f64>() / recalls.len().max(1) as f64;
    Ok((mean, min))
}

fn exact_top_k(points: &[Point], query: &[f32], k: usize) -> Result<Vec<String>> {
    let mut scored = points
        .iter()
        .map(|point| {
            Ok((
                point.id.clone(),
                DistanceMetric::Cosine.score(query, &point.vector)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.truncate(k);
    Ok(scored.into_iter().map(|(id, _)| id).collect())
}

fn recall_at_k(expected: &[String], actual: &[String], k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let actual = actual
        .iter()
        .take(k)
        .collect::<std::collections::HashSet<_>>();
    let hits = expected
        .iter()
        .take(k)
        .filter(|id| actual.contains(id))
        .count();
    hits as f64 / k as f64
}

fn deterministic_vector(seed: u64, dim: usize) -> Vec<f32> {
    let mut state = seed ^ 0x517c_c1b7_2722_0a95;
    (0..dim)
        .map(|_| {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let value = ((state >> 32) as u32) as f32 / u32::MAX as f32;
            value * 2.0 - 1.0
        })
        .collect()
}

/// Generate a vector near `centroid` with deterministic Gaussian-like noise of
/// magnitude `noise_scale`.  Uses Box–Muller approximation via the LCG PRNG.
fn clustered_vector(centroid: &[f32], seed: u64, dim: usize, noise_scale: f32) -> Vec<f32> {
    let noise = deterministic_vector(seed ^ 0xFEED_CAFE_DEAD_BEEF, dim);
    let mut v: Vec<f32> = centroid
        .iter()
        .zip(&noise)
        .map(|(c, n)| c + n * noise_scale)
        .collect();
    // L2-normalise so cosine metric is meaningful.
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    v.iter_mut().for_each(|x| *x /= norm);
    v
}

#[cfg(test)]
mod tests {
    use super::{deterministic_vector, recall_at_k};

    #[test]
    fn deterministic_vectors_are_stable() {
        assert_eq!(deterministic_vector(3, 4), deterministic_vector(3, 4));
        assert_ne!(deterministic_vector(3, 4), deterministic_vector(4, 4));
    }

    #[test]
    fn recall_at_k_counts_intersection() {
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let actual = vec!["c".to_string(), "x".to_string(), "a".to_string()];
        assert_eq!(recall_at_k(&expected, &actual, 3), 2.0 / 3.0);
        assert_eq!(recall_at_k(&expected, &actual, 0), 1.0);
    }
}
