//! M4-002: data-parallel candidate scoring via rayon.
//!
//! Locks in:
//!   - Result set is identical between the serial (small candidate set) and
//!     parallel (large candidate set) code paths.
//!   - Parallel path does not introduce non-determinism in the final top-k
//!     ordering — ties are broken deterministically by id ascending.
//!   - Recall against a brute-force reference stays at 1.0.
//!
//! The threshold (`PARALLEL_RESCORE_THRESHOLD = 256`) is private to db.rs;
//! we exercise it indirectly by tuning ef_search so the candidate count
//! crosses the threshold.

use std::collections::HashSet;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest};
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

fn build(n: usize, dim: usize) -> (TempDir, Db, &'static str, Vec<Point>) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "rayon_gate";

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
    (dir, db, coll, points)
}

#[test]
fn parallel_path_matches_brute_force_top_k() {
    // n = 12000 crosses HNSW threshold; ef_search=512 ensures candidate
    // count exceeds the 256 parallel threshold.
    let dim = 64;
    let (_dir, db, coll, points) = build(12_000, dim);

    let mut failures = 0;
    for q in 0..30 {
        let query = lcg_vector(50_000 + q, dim);
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
                    ef_search: Some(512),
                    recall_target: None,
                    with_payload: None,
                },
            )
            .expect("search")
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();

        let expected = exact_top_k(&points, &query, 10);
        let actual_set: HashSet<&String> = actual.iter().collect();
        let hits = expected.iter().filter(|id| actual_set.contains(id)).count();
        let r = hits as f64 / expected.len() as f64;
        if r < 1.0 - 1e-9 {
            failures += 1;
            eprintln!(
                "q={q}: recall {r:.6} expected={:?} actual={:?}",
                expected, actual
            );
        }
    }
    assert_eq!(
        failures, 0,
        "parallel scoring path must match brute-force recall on every query"
    );
}

#[test]
fn parallel_path_is_deterministic_across_runs() {
    // Same query, same data, same db → identical top-k across repeated runs.
    // Catches any accidental non-determinism in the parallel merge (rayon
    // work-stealing ordering does not affect the final sort because we
    // total_cmp on score then id ascending).
    let dim = 64;
    let (_dir, db, coll, _) = build(12_000, dim);

    let query = lcg_vector(99_999, dim);
    let req = || SearchRequest {
        graph: None,
        vector: query.clone(),
        vector_name: None,
        k: 10,
        filter: None,
        budget_ms: None,
        consistency: None,
        ef_search: Some(512),
        recall_target: None,
        with_payload: None,
    };

    let first: Vec<String> = db
        .search(coll, req())
        .unwrap()
        .hits
        .into_iter()
        .map(|h| h.id)
        .collect();

    for run in 0..10 {
        let again: Vec<String> = db
            .search(coll, req())
            .unwrap()
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(first, again, "run {run}: top-k must be deterministic");
    }
}

#[test]
fn serial_path_still_works_below_threshold() {
    // Small collection → candidate count well below 256 → serial path.
    let dim = 32;
    let n = 200;
    let (_dir, db, coll, points) = build(n, dim);

    let query = lcg_vector(7777, dim);
    let actual: Vec<String> = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query.clone(),
                vector_name: None,
                k: 5,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
        )
        .unwrap()
        .hits
        .into_iter()
        .map(|h| h.id)
        .collect();
    let expected = exact_top_k(&points, &query, 5);
    assert_eq!(actual, expected);
}

#[test]
fn parallel_path_respects_filter() {
    // Wide filter (≥5% selectivity) → goes through the HNSW path. With
    // ef_search=512 the candidate count exceeds 256 → parallel scoring
    // runs the filter check. Verifies the rayon code path honours filters.
    let dim = 64;
    let (_dir, db, coll, _) = build(12_000, dim);

    let bucket: u64 = 3;
    let filter = chirondb::Filter(json!({"bucket": bucket}));

    let query = lcg_vector(11_111, dim);
    let hits = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query,
                vector_name: None,
                k: 20,
                filter: Some(filter),
                budget_ms: None,
                consistency: None,
                ef_search: Some(512),
                recall_target: None,
                with_payload: None,
            },
        )
        .unwrap()
        .hits;

    for h in &hits {
        let b = h.payload.get("bucket").and_then(|v| v.as_u64()).unwrap();
        assert_eq!(
            b, bucket,
            "filter violated: hit {:?} payload {:?}",
            h.id, h.payload
        );
    }
}
