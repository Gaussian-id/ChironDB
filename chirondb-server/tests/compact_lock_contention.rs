//! PB-1: compact_collection lock contention.
//!
//! Locks in:
//!   - A concurrent search issued *during* compact_collection eventually
//!     returns and matches a baseline search after compaction.
//!   - The post-PB-1 split holds the per-collection write lock only across
//!     the in-memory swap; we do not assert wall-clock parallelism (CI is
//!     not stable enough for that), only correctness: searches still see
//!     consistent results across the compaction boundary.

use std::{sync::Arc, thread, time::Duration};

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

fn req(query: Vec<f32>, k: usize) -> SearchRequest {
    SearchRequest {
        graph: None,
        vector: query,
        vector_name: None,
        k,
        filter: None,
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: None,
        with_payload: None,
    }
}

fn build(n: usize, dim: usize) -> (TempDir, Db, &'static str) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "pb1_compact";

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
    db.upsert(coll, points).expect("upsert");
    (dir, db, coll)
}

#[test]
fn concurrent_search_during_compaction_succeeds() {
    let dim = 32;
    let (_dir, db, coll) = build(3_000, dim);
    let db = Arc::new(db);
    let coll = coll.to_string();

    let baseline = db.search(&coll, req(lcg_vector(99, dim), 5)).unwrap();
    let baseline_ids: Vec<String> = baseline.hits.into_iter().map(|h| h.id).collect();

    let db_compact = db.clone();
    let coll_compact = coll.clone();
    let compact_handle = thread::spawn(move || {
        // Sleep briefly so the search thread fires while compact is in flight.
        thread::sleep(Duration::from_millis(20));
        db_compact.compact_collection(&coll_compact)
    });

    let db_search = db.clone();
    let coll_search = coll.clone();
    let search_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        db_search.search(&coll_search, req(lcg_vector(99, dim), 5))
    });

    let compact_res = compact_handle.join().expect("compact thread joined");
    let search_res = search_handle.join().expect("search thread joined");
    compact_res.expect("compaction succeeded");
    let hits = search_res.expect("concurrent search succeeded");
    let post_ids: Vec<String> = hits.hits.into_iter().map(|h| h.id).collect();

    // Across the compact boundary, the same query must return the same top-k.
    // (Same data, no new upserts in between — the collection is invariant.)
    assert_eq!(
        baseline_ids, post_ids,
        "concurrent search must return identical top-k across the compact boundary"
    );
}

#[test]
fn search_after_compaction_is_consistent() {
    // Smoke: a single compact + search round-trip survives the PB-1 lock split.
    let dim = 32;
    let (_dir, db, coll) = build(2_000, dim);

    let before = db.search(coll, req(lcg_vector(42, dim), 10)).unwrap();
    let before_ids: Vec<String> = before.hits.into_iter().map(|h| h.id).collect();

    db.compact_collection(coll).unwrap();

    let after = db.search(coll, req(lcg_vector(42, dim), 10)).unwrap();
    let after_ids: Vec<String> = after.hits.into_iter().map(|h| h.id).collect();
    assert_eq!(before_ids, after_ids);
}
