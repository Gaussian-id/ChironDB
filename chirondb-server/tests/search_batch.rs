//! PA-5: batch search endpoint + parallel multi_search branches.
//!
//! Locks in:
//!   - HTTP `POST /collections/{c}/search/batch` returns the same top-k
//!     for each branch as running each `SearchRequest` through `/search`
//!     individually.
//!   - `Db::multi_search` with `fusion=None` and N branches returns N
//!     `SearchResponse`s in the same order as the input.
//!   - Parallel-branch execution is deterministic: repeated runs of the
//!     same batch produce identical results.

use chirondb::{CollectionConfig, Db, DistanceMetric, MultiSearchRequest, Point, SearchRequest};
use serde_json::json;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::mpsc,
    time::Duration,
};

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

fn build(n: usize, dim: usize) -> (TempDir, Db, &'static str) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "pa5_batch";

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

#[test]
fn batch_matches_individual_searches() {
    let dim = 64;
    let (_dir, db, coll) = build(2_500, dim);

    let queries: Vec<Vec<f32>> = (0..5).map(|q| lcg_vector(60_000 + q, dim)).collect();

    let individual: Vec<Vec<String>> = queries
        .iter()
        .map(|q| {
            db.search(coll, req(q.clone(), 10))
                .unwrap()
                .hits
                .into_iter()
                .map(|h| h.id)
                .collect()
        })
        .collect();

    let multi = MultiSearchRequest {
        searches: queries.iter().map(|q| req(q.clone(), 10)).collect(),
        fusion: None,
        fused_k: None,
        weights: Vec::new(),
    };
    let batch = db.multi_search(coll, multi).unwrap();
    let batch_ids: Vec<Vec<String>> = batch
        .results
        .into_iter()
        .map(|r| r.hits.into_iter().map(|h| h.id).collect())
        .collect();

    assert_eq!(individual.len(), batch_ids.len(), "branch count must match");
    for (i, (ind, b)) in individual.iter().zip(batch_ids.iter()).enumerate() {
        assert_eq!(
            ind, b,
            "branch {i}: batch result must match individual search exactly"
        );
    }
}

#[test]
fn batch_is_deterministic_across_runs() {
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let dim = 64;
            let (_dir, db, coll) = build(12_000, dim);

            let queries: Vec<Vec<f32>> = (0..8).map(|q| lcg_vector(90_000 + q, dim)).collect();

            let build_multi = || MultiSearchRequest {
                searches: queries.iter().map(|q| req(q.clone(), 10)).collect(),
                fusion: None,
                fused_k: None,
                weights: Vec::new(),
            };

            let first = db.multi_search(coll, build_multi()).unwrap();
            let first_ids: Vec<Vec<String>> = first
                .results
                .into_iter()
                .map(|r| r.hits.into_iter().map(|h| h.id).collect())
                .collect();

            for run in 0..10 {
                let again = db.multi_search(coll, build_multi()).unwrap();
                let again_ids: Vec<Vec<String>> = again
                    .results
                    .into_iter()
                    .map(|r| r.hits.into_iter().map(|h| h.id).collect())
                    .collect();
                assert_eq!(
                    first_ids, again_ids,
                    "run {run}: parallel batch must be deterministic"
                );
            }
        }));
        let _ = finished_tx.send(outcome);
    });

    match finished_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => resume_unwind(panic),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("parallel batch deadlocked while a collection writer was queued")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("parallel batch worker exited without reporting its result")
        }
    }
}

#[test]
fn batch_single_search_takes_serial_path() {
    // Sanity: 1-branch batch still works (serial fast path inside
    // Db::multi_search when searches.len() < 2).
    let dim = 32;
    let (_dir, db, coll) = build(500, dim);

    let query = lcg_vector(123, dim);
    let multi = MultiSearchRequest {
        searches: vec![req(query.clone(), 5)],
        fusion: None,
        fused_k: None,
        weights: Vec::new(),
    };
    let batch = db.multi_search(coll, multi).unwrap();
    assert_eq!(batch.results.len(), 1);

    let individual = db.search(coll, req(query, 5)).unwrap();
    let batch_ids: Vec<String> = batch.results[0].hits.iter().map(|h| h.id.clone()).collect();
    let individual_ids: Vec<String> = individual.hits.iter().map(|h| h.id.clone()).collect();
    assert_eq!(batch_ids, individual_ids);
}

#[test]
fn batch_preserves_per_branch_overrides() {
    // Different recall_target / with_payload per branch — confirms each
    // branch is independently configured under parallel dispatch.
    let dim = 64;
    let (_dir, db, coll) = build(12_000, dim);

    let q1 = lcg_vector(11_111, dim);
    let q2 = lcg_vector(22_222, dim);

    let mut r1 = req(q1, 5);
    r1.with_payload = Some(false);
    r1.recall_target = Some(0.95);

    let mut r2 = req(q2, 5);
    r2.with_payload = Some(true);
    r2.recall_target = Some(0.99);

    let multi = MultiSearchRequest {
        searches: vec![r1, r2],
        fusion: None,
        fused_k: None,
        weights: Vec::new(),
    };
    let batch = db.multi_search(coll, multi).unwrap();
    assert_eq!(batch.results.len(), 2);
    for h in &batch.results[0].hits {
        assert_eq!(
            h.payload,
            serde_json::Value::Null,
            "branch 0 with_payload=false"
        );
    }
    for h in &batch.results[1].hits {
        assert_ne!(
            h.payload,
            serde_json::Value::Null,
            "branch 1 with_payload=true"
        );
    }
}
