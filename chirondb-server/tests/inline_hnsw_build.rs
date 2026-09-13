//! Phase 3a: inline HNSW build during upsert.
//!
//! Locks the contract: once a collection crosses `HNSW_THRESHOLD`, an HNSW
//! graph exists and is queried — *without* requiring an explicit compaction.
//! Before Phase 3a, the index lived only after `compact_collection()`; points
//! upserted in between fell through to flat scan.

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

fn recall(expected: &[String], actual: &[String]) -> f64 {
    if expected.is_empty() {
        return 1.0;
    }
    let actual: HashSet<&String> = actual.iter().collect();
    let hits = expected.iter().filter(|id| actual.contains(id)).count();
    hits as f64 / expected.len() as f64
}

#[test]
fn upsert_crossing_threshold_triggers_inline_hnsw_build() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "inline_hnsw";
    let dim = 64;
    let k = 10;

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

    // Cross HNSW_THRESHOLD (10_000) in a single upsert batch.
    let n = 12_000usize;
    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i % 8}),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("bulk upsert");

    // No compaction here. Search must work and recall must stay at 1.0 — proves
    // the HNSW graph was built inline during the threshold-crossing upsert.
    let queries = 50;
    let mut min_recall = 1.0f64;
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
        let r = recall(&expected, &actual);
        if r < min_recall {
            min_recall = r;
        }
    }

    assert!(
        min_recall >= 1.0 - 1e-9,
        "inline-built HNSW recall must be 1.0 (got {min_recall:.6}) — pre-Phase-3a fell through to flat scan, post-Phase-3a must hit the graph"
    );
}

#[test]
fn upsert_below_threshold_does_not_build_hnsw() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "below_threshold";
    let dim = 32;

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

    let n = 500usize;
    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        })
        .collect();

    db.upsert(coll, points.clone()).expect("upsert");

    // Below threshold = flat path = exact = recall 1.0.
    let query = lcg_vector(9999, dim);
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
        .expect("search")
        .hits
        .into_iter()
        .map(|h| h.id)
        .collect();
    let expected = exact_top_k(&points, &query, 5);
    assert_eq!(actual, expected);
}

#[test]
fn incremental_inserts_past_threshold_are_searchable_without_compact() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "incremental_post";
    let dim = 64;

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

    let initial = 10_500usize;
    let bulk: Vec<Point> = (0..initial)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        })
        .collect();
    db.upsert(coll, bulk.clone()).expect("seed");

    // 100 more incremental inserts, one at a time — must end up in the HNSW
    // graph (Phase 3a contract) so subsequent searches can find them.
    let mut all_points = bulk;
    for i in initial..(initial + 100) {
        let p = Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"churn": true}),
        };
        all_points.push(p.clone());
        db.upsert(coll, vec![p]).expect("incremental");
    }

    let query = lcg_vector((initial + 99) as u64, dim);
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
    let expected = exact_top_k(&all_points, &query, 10);

    let actual_set: HashSet<&String> = actual.iter().collect();
    let hits = expected.iter().filter(|id| actual_set.contains(id)).count();
    let r = hits as f64 / expected.len() as f64;
    assert!(
        r >= 1.0 - 1e-9,
        "post-threshold incremental inserts must be searchable; recall {r:.6}"
    );
}
