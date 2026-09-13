//! Qdrant-semantics clamp: an explicit per-query `ef_search` below `k` must
//! not under-fill the HNSW beam — the engine clamps the resolved ef to at
//! least `k`, so the response always carries `k` hits (given ≥ k points).

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

#[test]
fn ef_search_below_k_still_returns_k_hits() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "ef_clamp";
    let dim = 32;
    let k = 10;

    db.create_collection(CollectionConfig {
        name: coll.to_string(),
        vector_dim: dim,
        metric: DistanceMetric::L2,
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

    // Cross HNSW_THRESHOLD (10_000) so the query hits the graph, not flat scan.
    let n = 12_000usize;
    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        })
        .collect();
    db.upsert(coll, points).expect("bulk upsert");
    // Force a full index build so the backfill safety net in
    // `search_point_candidates` (which only fires while the index lags the
    // collection) cannot mask an under-filled beam.
    db.compact_collection(coll).expect("compact");

    // ef_search well below k (and the 0 edge) must still fill k hits.
    for ef in [0u32, 2, 8] {
        let hits = db
            .search(
                coll,
                SearchRequest {
                    graph: None,
                    vector: lcg_vector(999_983, dim),
                    vector_name: None,
                    k,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: Some(ef),
                    recall_target: None,
                    with_payload: Some(false),
                },
            )
            .expect("search")
            .hits;
        assert_eq!(
            hits.len(),
            k,
            "ef_search={ef} must be clamped to k={k} and return k hits, got {}",
            hits.len()
        );
    }
}
