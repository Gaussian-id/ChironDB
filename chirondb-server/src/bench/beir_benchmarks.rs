//! P2 + P6 — BEIR nDCG@10 harness for the `gaussbench` binary.
//!
//! Closes the same "no published industry-standard numbers" gap for the
//! hybrid retrieval engine (P2) that `ann_benchmarks.rs` closed for the pure
//! dense-ANN engine (P4). Loads a `.beirbench.json` dataset with a BEIR corpus
//! and pre-embedded queries (this repo has no embedding model of its own),
//! upserts the corpus with dense and BM25 sparse vectors, then measures nDCG@10
//! across dense-only, sparse-only, and the two hybrid fusion modes
//! (`HybridFusion::Rrf` / `Weighted`).
//!
//! MS MARCO / NQ (the literal Q3 acceptance-gate datasets per
//! `.SPEC/gaussdb-vector_cleaned.md`) have multi-million-document corpora — infeasible to
//! embed in a CPU-only sandbox. This harness runs against BEIR's smaller
//! tasks (scifact, nfcorpus, ...) as a first rung; MS MARCO/NQ stay tracked
//! as the still-open formal gate.
//!
//! ## `.beirbench.json` schema
//!
//! ```json
//! {
//!   "dim": 384,
//!   "corpus": [{"id": "4983", "text": "...", "vector": [0.1, ...]}, ...],
//!   "queries": [{"id": "0", "text": "...", "vector": [0.2, ...]}, ...],
//!   "qrels": {"query_id": {"doc_id": relevance_int, ...}, ...}
//! }
//! ```

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chirondb::sparse_index::{build_bm25_corpus, encode_bm25};
use chirondb::{
    CollectionConfig, Db, DistanceMetric, HybridFusion, HybridSearchRequest, Point, SearchRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct BeirCorpusDoc {
    id: String,
    text: String,
    vector: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct BeirQuery {
    id: String,
    text: String,
    vector: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct BeirDataset {
    dim: usize,
    corpus: Vec<BeirCorpusDoc>,
    queries: Vec<BeirQuery>,
    qrels: HashMap<String, HashMap<String, u32>>,
}

fn load_beirbench(path: &Path) -> Result<BeirDataset> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read dataset {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse dataset {}", path.display()))
}

/// Standard nDCG@k: `DCG = sum(rel_i / log2(i+2))` over the ranked list,
/// `IDCG` from sorting the same relevance values descending, `nDCG = DCG /
/// IDCG` (0.0 when IDCG is 0, i.e. the query has no positive relevance
/// judgments in the qrel).
pub fn ndcg_at_k(ranked_ids: &[String], qrel: &HashMap<String, u32>, k: usize) -> f64 {
    let dcg: f64 = ranked_ids
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, id)| {
            let rel = qrel.get(id).copied().unwrap_or(0) as f64;
            rel / (i as f64 + 2.0).log2()
        })
        .sum();

    let mut ideal: Vec<u32> = qrel.values().copied().collect();
    ideal.sort_unstable_by(|a, b| b.cmp(a));
    let idcg: f64 = ideal
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, &rel)| rel as f64 / (i as f64 + 2.0).log2())
        .sum();

    if idcg <= 0.0 { 0.0 } else { dcg / idcg }
}

#[derive(Debug, Serialize)]
pub struct ModeReport {
    pub mode: String,
    pub mean_ndcg_at_10: f64,
    pub qps: f64,
    pub ranking_sha256: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct BeirBenchmarkReport {
    pub dataset: String,
    pub dataset_sha256: String,
    pub git_sha: String,
    pub n_corpus: usize,
    pub n_queries: usize,
    pub dim: usize,
    pub structural_augmentation: Option<StructuralAugmentationReport>,
    pub load: LoadReport,
    pub modes: Vec<ModeReport>,
}

#[derive(Debug, Serialize)]
pub struct LoadReport {
    pub insert_s: f64,
    pub optimize_s: f64,
}

#[derive(Debug, Serialize)]
pub struct StructuralAugmentationReport {
    pub schema: &'static str,
    pub structural_points: usize,
    pub semantic_points: usize,
    pub ratio_percent: f64,
    pub negative_control: bool,
    pub classification: &'static str,
}

#[derive(Debug)]
pub struct RunConfig {
    pub dataset_path: PathBuf,
    pub output: Option<PathBuf>,
    pub git_sha: String,
    pub structural_ratio_percent: f64,
    pub structural_negative_control: bool,
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

pub fn run(config: &RunConfig) -> Result<BeirBenchmarkReport> {
    let dataset = load_beirbench(&config.dataset_path)?;
    let dataset_sha256 = sha256_file(&config.dataset_path)?;
    anyhow::ensure!(
        config.structural_ratio_percent == 0.0
            || [0.1, 1.0, 5.0].contains(&config.structural_ratio_percent),
        "C19 BEIR ratio must be 0, 0.1, 1.0, or 5.0 percent"
    );
    anyhow::ensure!(
        !config.structural_negative_control || config.structural_ratio_percent > 0.0,
        "C19 BEIR negative control requires a structural ratio"
    );
    let structural_points =
        (dataset.corpus.len() as f64 * config.structural_ratio_percent / 100.0).ceil() as usize;
    let structural_docs = beir_structural_docs(
        &dataset.corpus,
        structural_points,
        config.structural_negative_control,
    );
    validate_structural_docs(
        &structural_docs,
        dataset.dim,
        config.structural_negative_control,
    )?;
    anyhow::ensure!(
        structural_docs.is_empty()
            || dataset
                .queries
                .iter()
                .all(|query| !query.text.to_ascii_lowercase().contains("c19sid")),
        "C19 structural identifier token occurs in the frozen query set"
    );
    eprintln!(
        "loaded {} ({} corpus / {} queries / dim {})",
        config.dataset_path.display(),
        dataset.corpus.len(),
        dataset.queries.len(),
        dataset.dim
    );

    let temp = tempfile::TempDir::new().context("create temp data dir")?;
    let db = Db::open(temp.path()).context("open db")?;
    let collection = "beir_benchmarks";
    db.create_collection(CollectionConfig {
        name: collection.into(),
        vector_dim: dataset.dim,
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
    .context("create collection")?;

    // Corpus-stats pass: build a text-only Point map first so the BM25 IDF
    // is computed against the whole corpus, then encode each doc's own
    // sparse vector against those stats (avoids the O(n^2) cost of calling
    // bm25_encode_text per doc, which rebuilds corpus stats every call).
    let text_points: HashMap<String, Point> = dataset
        .corpus
        .iter()
        .map(|d| {
            (
                d.id.clone(),
                Point {
                    id: d.id.clone(),
                    vector: Vec::new(),
                    vectors: Default::default(),
                    sparse_vector: None,
                    payload: serde_json::json!({ "text": d.text }),
                },
            )
        })
        .collect();
    let bm25_corpus = build_bm25_corpus(&text_points, &[]);

    let insert_started = Instant::now();
    let batch_size = 256;
    for chunk in dataset.corpus.chunks(batch_size) {
        let points: Vec<Point> = chunk
            .iter()
            .map(|d| Point {
                id: d.id.clone(),
                vector: d.vector.clone(),
                vectors: Default::default(),
                sparse_vector: Some(encode_bm25(&bm25_corpus, &d.text)),
                payload: serde_json::json!({ "text": d.text }),
            })
            .collect();
        db.upsert(collection, points).context("upsert chunk")?;
    }
    let scope = chirondb::TenantScope::system();
    for chunk in structural_docs.chunks(batch_size) {
        let points = chunk
            .iter()
            .map(|doc| Point {
                id: doc.id.clone(),
                vector: doc.vector.clone(),
                vectors: Default::default(),
                // Structural nodes are dense identity anchors, not semantic
                // documents. Excluding them from both BM25 corpus statistics
                // and postings makes the preregistered sparse arm exactly
                // identical to the baseline.
                sparse_vector: None,
                payload: serde_json::json!({"text": doc.text, "c19_structural": true}),
            })
            .collect();
        let reason = config
            .structural_negative_control
            .then_some("C19 shared-zero negative control; benchmark-only unsafe fixture");
        db.upsert_structural_scoped(collection, points, true, &scope, reason)
            .context("upsert C19 BEIR structural chunk")?;
    }
    let insert_s = insert_started.elapsed().as_secs_f64();

    let optimize_started = Instant::now();
    db.compact_collection(collection).context("compact")?;
    let optimize_s = optimize_started.elapsed().as_secs_f64();

    // Only score queries that have a qrel entry (no qrel => no nDCG signal).
    let scored_queries: Vec<&BeirQuery> = dataset
        .queries
        .iter()
        .filter(|q| dataset.qrels.contains_key(&q.id))
        .collect();

    let mut modes = Vec::new();
    for mode in ["dense_only", "sparse_only", "hybrid_rrf", "hybrid_weighted"] {
        let mode_started = Instant::now();
        let mut ranking_digest = Sha256::new();
        let mut latencies = Vec::with_capacity(scored_queries.len());
        let mut total_ndcg = 0.0_f64;
        for q in &scored_queries {
            let qrel = &dataset.qrels[&q.id];
            let t0 = Instant::now();
            let hit_ids: Vec<String> = match mode {
                "dense_only" => {
                    let resp = db
                        .search(
                            collection,
                            SearchRequest {
                                graph: None,
                                vector: q.vector.clone(),
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
                        .context("dense search")?;
                    resp.hits.into_iter().map(|h| h.id).collect()
                }
                "sparse_only" => {
                    let resp = db
                        .hybrid_search(
                            collection,
                            HybridSearchRequest {
                                graph: None,
                                vector: None,
                                vector_name: None,
                                sparse_vector: Some(encode_bm25(&bm25_corpus, &q.text)),
                                k: 10,
                                filter: None,
                                budget_ms: None,
                                fusion: HybridFusion::Weighted,
                                dense_weight: 0.0,
                                sparse_weight: 1.0,
                            },
                        )
                        .context("sparse-only search")?;
                    resp.hits.into_iter().map(|h| h.id).collect()
                }
                "hybrid_rrf" | "hybrid_weighted" => {
                    let fusion = if mode == "hybrid_rrf" {
                        HybridFusion::Rrf
                    } else {
                        HybridFusion::Weighted
                    };
                    let resp = db
                        .hybrid_search(
                            collection,
                            HybridSearchRequest {
                                graph: None,
                                vector: Some(q.vector.clone()),
                                vector_name: None,
                                sparse_vector: Some(encode_bm25(&bm25_corpus, &q.text)),
                                k: 10,
                                filter: None,
                                budget_ms: None,
                                fusion,
                                dense_weight: 1.0,
                                sparse_weight: 1.0,
                            },
                        )
                        .context("hybrid search")?;
                    resp.hits.into_iter().map(|h| h.id).collect()
                }
                _ => unreachable!(),
            };
            update_ranking_digest(&mut ranking_digest, &q.id, &hit_ids);
            latencies.push(t0.elapsed());
            total_ndcg += ndcg_at_k(&hit_ids, qrel, 10);
        }
        let mean_ndcg = total_ndcg / scored_queries.len().max(1) as f64;
        let qps =
            scored_queries.len() as f64 / mode_started.elapsed().as_secs_f64().max(f64::EPSILON);
        modes.push(ModeReport {
            mode: mode.to_string(),
            mean_ndcg_at_10: mean_ndcg,
            qps,
            ranking_sha256: lower_hex(&ranking_digest.finalize()),
            p50_ms: percentile_ms(&mut latencies.clone(), 0.50),
            p95_ms: percentile_ms(&mut latencies.clone(), 0.95),
            p99_ms: percentile_ms(&mut latencies.clone(), 0.99),
        });
        eprintln!("mode={mode:>16}  nDCG@10={mean_ndcg:.4}");
    }

    let dataset_name = config
        .dataset_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let report = BeirBenchmarkReport {
        dataset: dataset_name,
        dataset_sha256,
        git_sha: config.git_sha.clone(),
        n_corpus: dataset.corpus.len(),
        n_queries: scored_queries.len(),
        dim: dataset.dim,
        structural_augmentation: (structural_points > 0).then_some(
            StructuralAugmentationReport {
                schema: "chirondb-c19-beir-augmentation-v1",
                structural_points,
                semantic_points: dataset.corpus.len(),
                ratio_percent: config.structural_ratio_percent,
                negative_control: config.structural_negative_control,
                classification: "custom C19 augmentation; measured once for BEIR SciFact and its MTEB retrieval identity",
            },
        ),
        load: LoadReport {
            insert_s,
            optimize_s,
        },
        modes,
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

fn beir_structural_docs(
    corpus: &[BeirCorpusDoc],
    count: usize,
    negative_control: bool,
) -> Vec<BeirCorpusDoc> {
    if count == 0 {
        return Vec::new();
    }
    let dim = corpus[0].vector.len();
    let mut scales = vec![0.0_f64; dim];
    let mut nonzero = vec![0usize; dim];
    for doc in corpus.iter().take(4096) {
        for (index, value) in doc.vector.iter().enumerate() {
            if *value != 0.0 {
                scales[index] += f64::from(*value).powi(2);
                nonzero[index] += 1;
            }
        }
    }
    let scales = scales
        .into_iter()
        .zip(nonzero)
        .map(|(sum, n)| {
            if n == 0 {
                1.0
            } else {
                (sum / n as f64).sqrt() as f32
            }
        })
        .collect::<Vec<_>>();
    (0..count)
        .map(|ordinal| {
            let identity_seed = splitmix64(13_969_199_075_232_164_731 ^ ordinal as u64);
            let mut vector = if negative_control {
                vec![0.0; dim]
            } else {
                let source = (identity_seed % corpus.len() as u64) as usize;
                let mut vector = corpus[source].vector.clone();
                for (index, value) in vector.iter_mut().enumerate() {
                    let sign = if splitmix64(identity_seed ^ index as u64) & 1 == 0 {
                        -1.0
                    } else {
                        1.0
                    };
                    *value += sign * scales[index] * 0.01;
                }
                vector
            };
            let norm = vector
                .iter()
                .map(|value| f64::from(*value).powi(2))
                .sum::<f64>()
                .sqrt();
            if norm > 0.0 {
                for value in &mut vector {
                    *value = (f64::from(*value) / norm) as f32;
                }
            }
            BeirCorpusDoc {
                id: format!("structural::scifact::{ordinal:08}"),
                text: format!("c19sid{ordinal:08}"),
                vector,
            }
        })
        .collect()
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn validate_structural_docs(
    docs: &[BeirCorpusDoc],
    expected_dim: usize,
    negative_control: bool,
) -> Result<()> {
    if negative_control {
        anyhow::ensure!(
            docs.iter().all(|doc| {
                doc.vector.len() == expected_dim && doc.vector.iter().all(|value| *value == 0.0)
            }),
            "C19 BEIR negative control is not the shared-zero fixture"
        );
        return Ok(());
    }
    let unique = docs
        .iter()
        .map(|doc| {
            anyhow::ensure!(
                doc.vector.len() == expected_dim
                    && doc.vector.iter().all(|value| value.is_finite())
                    && doc.vector.iter().any(|value| *value != 0.0),
                "C19 BEIR structural vector is invalid"
            );
            Ok(doc
                .vector
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>())
        })
        .collect::<Result<HashSet<_>>>()?;
    anyhow::ensure!(
        unique.len() == docs.len(),
        "C19 BEIR structural vectors are not unique"
    );
    Ok(())
}

fn update_ranking_digest(digest: &mut Sha256, query_id: &str, hit_ids: &[String]) {
    digest.update((query_id.len() as u64).to_le_bytes());
    digest.update(query_id.as_bytes());
    digest.update((hit_ids.len() as u64).to_le_bytes());
    for hit_id in hit_ids {
        digest.update((hit_id.len() as u64).to_le_bytes());
        digest.update(hit_id.as_bytes());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndcg_perfect_ranking_is_one() {
        let qrel = HashMap::from([("a".to_string(), 3), ("b".to_string(), 1)]);
        let ranked = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let score = ndcg_at_k(&ranked, &qrel, 10);
        assert!((score - 1.0).abs() < 1e-9, "expected 1.0, got {score}");
    }

    #[test]
    fn ndcg_empty_qrel_is_zero() {
        let qrel = HashMap::new();
        let ranked = vec!["a".to_string(), "b".to_string()];
        assert_eq!(ndcg_at_k(&ranked, &qrel, 10), 0.0);
    }

    #[test]
    fn ndcg_reversed_ranking_is_lower_than_perfect() {
        let qrel = HashMap::from([("a".to_string(), 3), ("b".to_string(), 1)]);
        let perfect = vec!["a".to_string(), "b".to_string()];
        let reversed = vec!["b".to_string(), "a".to_string()];
        let perfect_score = ndcg_at_k(&perfect, &qrel, 10);
        let reversed_score = ndcg_at_k(&reversed, &qrel, 10);
        assert!(reversed_score < perfect_score);
        assert!((perfect_score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ndcg_irrelevant_hits_only_is_zero() {
        let qrel = HashMap::from([("a".to_string(), 2)]);
        let ranked = vec!["x".to_string(), "y".to_string()];
        assert_eq!(ndcg_at_k(&ranked, &qrel, 10), 0.0);
    }

    #[test]
    fn c19_beir_vectors_are_nonzero_unique_and_dimensioned() {
        let corpus = vec![
            BeirCorpusDoc {
                id: "a".to_string(),
                text: "alpha".to_string(),
                vector: vec![1.0, 0.0, 0.0],
            },
            BeirCorpusDoc {
                id: "b".to_string(),
                text: "beta".to_string(),
                vector: vec![0.0, 1.0, 0.0],
            },
        ];
        let docs = beir_structural_docs(&corpus, 2, false);
        validate_structural_docs(&docs, 3, false).unwrap();
        assert!(docs.iter().all(|doc| doc.text.starts_with("c19sid")));
    }

    #[test]
    fn c19_beir_negative_control_is_shared_zero() {
        let corpus = vec![BeirCorpusDoc {
            id: "a".to_string(),
            text: "alpha".to_string(),
            vector: vec![1.0, 0.0],
        }];
        let docs = beir_structural_docs(&corpus, 3, true);
        validate_structural_docs(&docs, 2, true).unwrap();
        assert!(docs.iter().all(|doc| doc.vector == vec![0.0_f32, 0.0_f32]));
    }
}
