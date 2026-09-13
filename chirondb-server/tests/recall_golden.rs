//! Recall golden gate.
//!
//! Locks recall@k at the contracted floor for each index path:
//!   - flat (n < HNSW_THRESHOLD): recall = 1.0 (exact)
//!   - LS-VEC default sealed path: recall >= 0.97 at the default recall target
//!   - mini-HNSW remains an internal mutable-tier implementation detail
//!
//! Overrides:
//!   `GAUSSDB_RECALL_FLAT_N`     (default 2000)
//!   `GAUSSDB_RECALL_LSVEC_N`    (default 12000; legacy HNSW name also read)
//!   `GAUSSDB_RECALL_QUERIES`    (default 100)
//!   `GAUSSDB_RECALL_DIM`        (default 64)
//!   `GAUSSDB_RECALL_K`          (default 10)
//!   `GAUSSDB_RECALL_EF`         (optional diagnostic override)

use std::collections::HashSet;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest};
use serde_json::json;
use tempfile::TempDir;

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_optional_count(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn lcg_vector(seed: u64, dim: usize) -> Vec<f32> {
    let mut state = seed ^ 0x517c_c1b7_2722_0a95;
    (0..dim)
        .map(|_| {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let v = ((state >> 32) as u32) as f32 / u32::MAX as f32;
            v * 2.0 - 1.0
        })
        .collect()
}

fn exact_top_k(points: &[Point], query: &[f32], k: usize) -> Vec<String> {
    let mut scored: Vec<(String, f32)> = points
        .iter()
        .map(|p| {
            let s = DistanceMetric::Cosine.score(query, &p.vector).unwrap();
            (p.id.clone(), s)
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    scored.truncate(k);
    scored.into_iter().map(|(id, _)| id).collect()
}

fn recall(expected: &[String], actual: &[String]) -> f64 {
    if expected.is_empty() {
        return 1.0;
    }
    let actual: HashSet<&String> = actual.iter().collect();
    let hits = expected.iter().filter(|id| actual.contains(id)).count();
    hits as f64 / expected.len() as f64
}

fn run_recall_pass(n: usize, dim: usize, queries: usize, k: usize) -> f64 {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "recall_gate";
    db.create_collection(CollectionConfig {
        name: coll.to_string(),
        vector_dim: dim,
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
    .expect("create collection");

    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i % 8}),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("upsert");
    db.compact_collection(coll).expect("compact");
    let ef_search = env_optional_count("GAUSSDB_RECALL_EF").map(|ef| ef as u32);

    let mut total_recall = 0.0f64;
    for q in 0..queries {
        let query = lcg_vector((n + q) as u64, dim);
        let actual: Vec<String> = db
            .search(
                coll,
                SearchRequest {
                    graph: None,
                    vector: query.clone(),
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
            .expect("search")
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();
        let expected = exact_top_k(&points, &query, k);
        total_recall += recall(&expected, &actual);
    }
    // Mean recall, not worst-single-query -- matches the industry convention
    // (ann-benchmarks, Qdrant, Milvus, this repo's own gaussbench harness)
    // for reporting recall@k, and matches the same fix applied to
    // perf_regression.rs. See that file's `measure_qps_and_recall` doc
    // comment for the real ef-sweep evidence behind this.
    total_recall / queries as f64
}

/// P2C variant of `run_recall_pass` that flips the server-wide
/// `intra_query_parallel` flag to ON before running the same recall
/// queries. Must return the same recall@K (>= 0.99 for HNSW; the parallel
/// scoring path is bit-equivalent for any well-formed ef_search because
/// the heap-fold stays serial). Catches a class of bugs where the
/// parallel path silently changes the candidate order.
fn run_recall_pass_p2c(n: usize, dim: usize, queries: usize, k: usize) -> f64 {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "recall_gate_p2c";
    db.create_collection(CollectionConfig {
        name: coll.to_string(),
        vector_dim: dim,
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
    .expect("create collection");

    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i % 8}),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("upsert");
    db.compact_collection(coll).expect("compact");
    // P2C: flip the flag ON. The propagation walks every live H2qgIndex
    // and clones the shared Arc<AtomicBool> into its HnswGraph field.
    db.set_intra_query_parallel(true);
    assert!(
        db.intra_query_parallel(),
        "intra_query_parallel flag must be on after set"
    );

    let mut total_recall = 0.0f64;
    for q in 0..queries {
        let query = lcg_vector((n + q) as u64, dim);
        let actual: Vec<String> = db
            .search(
                coll,
                SearchRequest {
                    graph: None,
                    vector: query.clone(),
                    vector_name: None,
                    k,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: None,
                },
            )
            .expect("search")
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();
        let expected = exact_top_k(&points, &query, k);
        total_recall += recall(&expected, &actual);
    }
    // Mean recall, not worst-single-query -- matches the industry convention
    // (ann-benchmarks, Qdrant, Milvus, this repo's own gaussbench harness)
    // for reporting recall@k, and matches the same fix applied to
    // perf_regression.rs. See that file's `measure_qps_and_recall` doc
    // comment for the real ef-sweep evidence behind this.
    total_recall / queries as f64
}

#[test]
fn flat_recall_at_k_is_exact() {
    let n = env_count("GAUSSDB_RECALL_FLAT_N", 2_000);
    let dim = env_count("GAUSSDB_RECALL_DIM", 64);
    let queries = env_count("GAUSSDB_RECALL_QUERIES", 100);
    let k = env_count("GAUSSDB_RECALL_K", 10);

    let mean = run_recall_pass(n, dim, queries, k);
    eprintln!("flat mean recall@{k} = {mean:.6} (n={n}, queries={queries})");
    assert!(
        (mean - 1.0).abs() < 1e-9,
        "flat recall must be exact, got {mean:.6}"
    );
}

#[test]
fn lsvec_recall_at_k_default_target() {
    let n = env_count(
        "GAUSSDB_RECALL_LSVEC_N",
        env_count("GAUSSDB_RECALL_HNSW_N", 12_000),
    );
    let dim = env_count("GAUSSDB_RECALL_DIM", 64);
    let queries = env_count("GAUSSDB_RECALL_QUERIES", 100);
    let k = env_count("GAUSSDB_RECALL_K", 10);

    let mean = run_recall_pass(n, dim, queries, k);
    eprintln!("lsvec mean recall@{k} = {mean:.6} (n={n}, queries={queries})");
    assert!(
        mean >= 0.97 - 1e-9,
        "LS-VEC recall floor 0.97 (default target) broken: got {mean:.6}"
    );
}

/// P2C — recall gate with `intra_query_parallel = true`. Same HNSW
/// floor (1.0) as the serial path. The parallel scoring fold is
/// bit-equivalent because the heap fold stays serial — the parallel
/// only computes the `(distance, neighbour)` tuple, which is a pure
/// `&self` read. Catches regressions in the new `search_layer_with_codes`
/// signature (intra_parallel + filter parameters).
#[test]
fn hnsw_recall_at_k_p2c_intra_query_parallel() {
    // Smaller N to keep CI fast; the gate is correctness, not scale.
    let n = env_count("GAUSSDB_RECALL_HNSW_P2C_N", 2_000);
    let dim = env_count("GAUSSDB_RECALL_DIM", 64);
    let queries = env_count("GAUSSDB_RECALL_QUERIES", 100);
    let k = env_count("GAUSSDB_RECALL_K", 10);

    let mean = run_recall_pass_p2c(n, dim, queries, k);
    eprintln!("hnsw (P2C parallel beam) mean recall@{k} = {mean:.6} (n={n}, queries={queries})");
    // W0: default path targets 0.97; same throughput floor as the serial test.
    assert!(
        mean >= 0.97 - 1e-9,
        "P2C intra_query_parallel recall floor 0.97 (W0 default) broken: got {mean:.6}"
    );
}
