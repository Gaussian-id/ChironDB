//! P-A acceptance: standalone RaBitQ is no longer user-selectable; an omitted
//! index kind uses LS-VEC with mini-HNSW only as its internal mutable tier.

use std::collections::HashMap;

use chirondb::{CollectionConfig, Db, DistanceMetric, GaussError, Point, SearchRequest};
use tempfile::TempDir;

fn lcg_vector(seed: u64, dim: usize) -> Vec<f32> {
    let mut state = seed ^ 0x517c_c1b7_2722_0a95;
    (0..dim)
        .map(|_| {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            let v = ((state >> 32) as u32) as f32 / u32::MAX as f32;
            v * 2.0 - 1.0
        })
        .collect()
}

fn make_cfg(name: &str, dim: usize, index_kind: Option<&str>) -> CollectionConfig {
    CollectionConfig {
        name: name.to_string(),
        vector_dim: dim,
        metric: DistanceMetric::L2,
        shards: 1,
        replicas: 1,
        quantization: Some("none".to_string()),
        payload_schema: HashMap::new(),
        named_vector_dims: HashMap::new(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: index_kind.map(str::to_string),
        streamer_max_bytes: 0,
    }
}

#[test]
fn rabitq_index_kind_is_rejected() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let error = db
        .create_collection(make_cfg("rb", 64, Some("rabitq")))
        .unwrap_err();
    assert!(matches!(error, GaussError::InvalidRequest(message)
        if message.contains("LS-VEC is the sole index")));
}

#[test]
fn unspecified_index_kind_uses_lsvec_mutable_tier() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let dim = 32;
    let n = 11_000;

    db.create_collection(make_cfg("hn", dim, None)).unwrap();

    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i}"),
            vector: lcg_vector(i as u64, dim),
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        })
        .collect();
    db.upsert("hn", points).unwrap();

    // The live streamer may use mini-HNSW internally; the collection's
    // user-visible persisted family is normalized to LS-VEC.
    assert_eq!(
        db.list_collections()[0].index_kind.as_deref(),
        Some("lsvec")
    );
    let mut hits = 0;
    let queries = 50;
    for i in 0..queries {
        let q = lcg_vector(i as u64, dim);
        let resp = db
            .search(
                "hn",
                SearchRequest {
                    graph: None,
                    vector: q,
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
            .unwrap();
        if resp.hits.iter().any(|h| h.id == format!("p{i}")) {
            hits += 1;
        }
    }
    let recall = hits as f32 / queries as f32;
    assert!(
        recall >= 0.95,
        "LS-VEC mutable-tier recall@10 = {recall:.4} below 0.95 (hits={hits}/{queries})"
    );
}
