//! Phase 3b: cardinality-aware filtered search (ACORN-lite).
//!
//! Verifies the pre-filter exact path:
//!   - Restrictive filter (≤5% selectivity) skips HNSW and exact-scans the
//!     matching set. Recall = 1.0 by construction.
//!   - Wide filter (≥5% selectivity) takes the HNSW + effective_k inflation
//!     path. Recall ≥ 1.0 within ef_search budget.
//!
//! Reference: Patel et al., "ACORN: Performant and Predicate-Agnostic Search
//! Over Vector Embeddings", arXiv:2403.04871, 2024.

use std::collections::HashSet;

use chirondb::{CollectionConfig, Db, DistanceMetric, Filter, Point, SearchRequest};
use serde_json::json;
use tempfile::TempDir;

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

fn make_db_with_buckets(
    n: usize,
    dim: usize,
    n_buckets: u64,
) -> (TempDir, Db, &'static str, Vec<Point>) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "acorn_gate";

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
            payload: json!({"bucket": (i as u64) % n_buckets}),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("upsert");
    (dir, db, coll, points)
}

fn exact_top_k_with_filter(points: &[Point], query: &[f32], k: usize, bucket: u64) -> Vec<String> {
    let mut scored: Vec<(String, f32)> = points
        .iter()
        .filter(|p| p.payload.get("bucket").and_then(|v| v.as_u64()) == Some(bucket))
        .map(|p| {
            let s = DistanceMetric::Cosine.score(query, &p.vector).unwrap();
            (p.id.clone(), s)
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    scored.truncate(k);
    scored.into_iter().map(|(id, _)| id).collect()
}

#[test]
fn restrictive_filter_returns_exact_top_k() {
    // 12k points, 256 buckets ≈ 47 points each → ~0.4% selectivity.
    // Triggers the prefilter-exact path (≤5% cap, ≤5000 cap).
    let (_dir, db, coll, points) = make_db_with_buckets(12_000, 64, 256);

    let query = lcg_vector(99_999, 64);
    let bucket: u64 = 7;
    let filter = Filter(json!({"bucket": bucket}));

    let actual: Vec<String> = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query.clone(),
                vector_name: None,
                k: 10,
                filter: Some(filter),
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

    let expected = exact_top_k_with_filter(&points, &query, 10, bucket);
    assert_eq!(
        actual, expected,
        "restrictive filter (~0.4% selectivity) must return exact top-k"
    );
}

#[test]
fn wide_filter_uses_hnsw_path_recall_1_0() {
    // 12k points, 4 buckets ≈ 3000 per bucket → 25% selectivity.
    // Above the 5% cap → goes through HNSW + effective_k inflation path.
    let (_dir, db, coll, points) = make_db_with_buckets(12_000, 64, 4);

    let bucket: u64 = 2;
    let filter = Filter(json!({"bucket": bucket}));

    for q in 0..20 {
        let query = lcg_vector(50_000 + q, 64);
        let actual: Vec<String> = db
            .search(
                coll,
                SearchRequest {
                    graph: None,
                    vector: query.clone(),
                    vector_name: None,
                    k: 10,
                    filter: Some(filter.clone()),
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

        let expected = exact_top_k_with_filter(&points, &query, 10, bucket);

        let actual_set: HashSet<&String> = actual.iter().collect();
        let hits = expected.iter().filter(|id| actual_set.contains(id)).count();
        let r = if expected.is_empty() {
            1.0
        } else {
            hits as f64 / expected.len() as f64
        };
        assert!(
            r >= 1.0 - 1e-9,
            "wide filter q={q}: recall {r:.6} < 1.0; expected={:?} actual={:?}",
            expected,
            actual,
        );
    }
}

#[test]
fn no_filter_search_unchanged() {
    let (_dir, db, coll, points) = make_db_with_buckets(2_000, 64, 8);

    let query = lcg_vector(12_345, 64);
    let actual: Vec<String> = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query.clone(),
                vector_name: None,
                k: 10,
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

    let mut all: Vec<(String, f32)> = points
        .iter()
        .map(|p| {
            let s = DistanceMetric::Cosine.score(&query, &p.vector).unwrap();
            (p.id.clone(), s)
        })
        .collect();
    all.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let expected: Vec<String> = all.into_iter().take(10).map(|(id, _)| id).collect();
    assert_eq!(actual, expected);
}

/// P2F — wide filter (HNSW path) holds recall = 1.0 against ground truth,
/// same as the ACORN-lite test, but with enough points to exercise the
/// filter-aware HNSW beam under realistic `ef_search` width. The wide-filter
/// case is the one the inline filter was added for: 25% selectivity is
/// above the 5% prefilter-exact threshold, so the search takes the
/// HNSW + post-filter path; with the inline filter, the beam now skips
/// filtered-out neighbours during expansion (saving ~75% of the
/// candidate distance work for this dataset).
#[test]
fn p2f_filter_aware_hnsw_wide_filter_recall_1_0() {
    // 20k points × 4 buckets → 25% selectivity (above the 5% prefilter-exact
    // cap) and above the HNSW_THRESHOLD so the engine builds an HNSW index.
    let (_dir, db, coll, points) = make_db_with_buckets(20_000, 64, 4);

    let bucket: u64 = 1;
    let filter = Filter(json!({"bucket": bucket}));

    let mut total_recall = 0.0_f64;
    let mut queries = 0;
    for q in 0..10 {
        let query = lcg_vector(70_000 + q, 64);
        let actual: Vec<String> = db
            .search(
                coll,
                SearchRequest {
                    graph: None,
                    vector: query.clone(),
                    vector_name: None,
                    k: 10,
                    filter: Some(filter.clone()),
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
        let expected = exact_top_k_with_filter(&points, &query, 10, bucket);
        let actual_set: std::collections::HashSet<&String> = actual.iter().collect();
        let hits = expected.iter().filter(|id| actual_set.contains(id)).count();
        let r = if expected.is_empty() {
            1.0
        } else {
            hits as f64 / expected.len() as f64
        };
        total_recall += r;
        queries += 1;
    }
    let avg_recall = total_recall / queries as f64;
    assert!(
        (avg_recall - 1.0).abs() < 1e-9,
        "P2F filter-aware HNSW wide-filter avg recall {avg_recall:.6} < 1.0"
    );
}
