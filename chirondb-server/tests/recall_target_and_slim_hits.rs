//! PA-1 + PA-2 (Phase A perf push).
//!
//! Locks in:
//!   - `recall_target` drives a lower `ef_search` than the default when the
//!     target is below 1.0, but recall on the recall_golden gate workload
//!     stays at the target floor.
//!   - `with_payload = Some(false)` returns `Value::Null` in every hit and
//!     skips the payload clone (we verify the null shape, not the alloc count).
//!   - `with_payload = None` or `Some(true)` preserves the prior contract.

use std::collections::HashSet;

use chirondb::{CollectionConfig, Db, DistanceMetric, GaussError, Point, SearchRequest};
use serde_json::{Value, json};
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
    let coll = "phase_a_gate";

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
            payload: json!({
                "bucket": i % 8,
                "name": format!("doc_{i:06}"),
                "lipsum": "lorem ipsum dolor sit amet consectetur adipiscing",
            }),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("upsert");
    (dir, db, coll, points)
}

fn recall(expected: &[String], actual: &[String]) -> f64 {
    if expected.is_empty() {
        return 1.0;
    }
    let actual: HashSet<&String> = actual.iter().collect();
    let hits = expected.iter().filter(|id| actual.contains(id)).count();
    hits as f64 / expected.len() as f64
}

#[test]
fn recall_target_095_floor_holds_on_hnsw_workload() {
    let dim = 64;
    let k = 10;
    let (_dir, db, coll, points) = build(12_000, dim);

    let mut total = 0.0_f64;
    let mut min = 1.0_f64;
    let queries = 30;
    for q in 0..queries {
        let query = lcg_vector(70_000 + q, dim);
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
                    recall_target: Some(0.95),
                    with_payload: None,
                },
            )
            .expect("search")
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();
        let expected = exact_top_k(&points, &query, k);
        let r = recall(&expected, &actual);
        total += r;
        if r < min {
            min = r;
        }
    }
    let mean = total / queries as f64;
    assert!(
        mean >= 0.95,
        "recall_target=0.95 mean recall {mean:.4} below target floor 0.95"
    );
    assert!(
        min >= 0.85,
        "recall_target=0.95 min recall {min:.4} below soft floor 0.85"
    );
}

#[test]
fn recall_target_099_remains_close_to_perfect() {
    let dim = 64;
    let k = 10;
    let (_dir, db, coll, points) = build(12_000, dim);

    let queries = 20;
    let mut total = 0.0_f64;
    for q in 0..queries {
        let query = lcg_vector(80_000 + q, dim);
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
                    recall_target: Some(0.99),
                    with_payload: None,
                },
            )
            .expect("search")
            .hits
            .into_iter()
            .map(|h| h.id)
            .collect();
        let expected = exact_top_k(&points, &query, k);
        total += recall(&expected, &actual);
    }
    let mean = total / queries as f64;
    assert!(
        mean >= 0.99,
        "recall_target=0.99 mean recall {mean:.4} below target floor 0.99"
    );
}

#[test]
fn invalid_recall_targets_reject_before_search() {
    let dim = 64;
    let (_dir, db, coll, _) = build(2_000, dim);

    for recall_target in [0.49, 1.01, f32::NAN, f32::INFINITY] {
        let result = db.search(
            coll,
            SearchRequest {
                graph: None,
                vector: lcg_vector(90_000, dim),
                vector_name: None,
                k: 10,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: Some(recall_target),
                with_payload: None,
            },
        );
        assert!(
            matches!(
                result,
                Err(GaussError::InvalidRequest(ref message))
                    if message.contains("recall_target must be finite and in [0.5, 1.0]")
            ),
            "unexpected result for recall_target={recall_target:?}: {result:?}"
        );
    }
}

#[test]
fn with_payload_false_returns_null_payloads() {
    let dim = 64;
    let (_dir, db, coll, _) = build(2_000, dim);

    let query = lcg_vector(12_345, dim);
    let hits = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query,
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
        .unwrap()
        .hits;
    assert!(!hits.is_empty(), "search must return hits");
    for h in &hits {
        assert_eq!(
            h.payload,
            Value::Null,
            "hit {:?} payload must be null",
            h.id
        );
        assert!(!h.id.is_empty(), "id still populated");
        assert!(h.score.is_finite(), "score still populated");
    }
}

#[test]
fn with_payload_default_and_true_preserve_payload() {
    let dim = 64;
    let (_dir, db, coll, _) = build(2_000, dim);

    let query = lcg_vector(54_321, dim);

    let default_hits = db
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
        .hits;

    let explicit_hits = db
        .search(
            coll,
            SearchRequest {
                graph: None,
                vector: query,
                vector_name: None,
                k: 5,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: Some(true),
            },
        )
        .unwrap()
        .hits;

    for h in default_hits.iter().chain(explicit_hits.iter()) {
        assert_ne!(
            h.payload,
            Value::Null,
            "hit {:?} payload must not be null when with_payload is None/Some(true)",
            h.id
        );
        assert!(h.payload.get("bucket").is_some(), "payload shape preserved");
    }
}
