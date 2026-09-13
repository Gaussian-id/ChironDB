//! PA-5 — `Db::search_inflight()` counts concurrent search calls accurately.
//! The auto-compaction driver in `main.rs::spawn_auto_compaction` reads this
//! counter to defer compaction while search latency would be impacted; this
//! test pins the counter contract.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest};
use tempfile::TempDir;

fn make_db(points: usize, dim: usize) -> (Db, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.create_collection(CollectionConfig {
        name: "inflight".to_string(),
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
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .unwrap();
    let batch: Vec<Point> = (0..points)
        .map(|i| Point {
            id: format!("p{i}"),
            vector: (0..dim).map(|j| ((i + j) as f32).sin()).collect(),
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        })
        .collect();
    db.upsert("inflight", batch).unwrap();
    (db, dir)
}

#[test]
fn inflight_counter_returns_to_zero_after_search() {
    let (db, _g) = make_db(2_000, 8);
    assert_eq!(db.search_inflight(), 0);

    for _ in 0..3 {
        let _ = db
            .search(
                "inflight",
                SearchRequest {
                    graph: None,
                    vector: vec![0.0; 8],
                    vector_name: None,
                    k: 5,
                    filter: None,
                    budget_ms: None,
                    consistency: None,
                    ef_search: None,
                    recall_target: None,
                    with_payload: Some(false),
                },
            )
            .unwrap();
        assert_eq!(db.search_inflight(), 0);
    }
}

#[test]
fn inflight_counter_reflects_concurrent_searches() {
    let (db, _g) = make_db(2_000, 16);
    let db = Arc::new(db);
    let mut handles = Vec::new();
    let n_workers = 8;

    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for _ in 0..n_workers {
        let db = db.clone();
        let started = started.clone();
        let release = release.clone();
        handles.push(std::thread::spawn(move || {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Wait until the main thread observes the inflight count.
            while !release.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = db
                    .search(
                        "inflight",
                        SearchRequest {
                            graph: None,
                            vector: vec![0.01; 16],
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
            }
        }));
    }

    // Wait until all workers ramped.
    while started.load(std::sync::atomic::Ordering::SeqCst) < n_workers {
        std::thread::sleep(Duration::from_millis(1));
    }
    // Give them a moment to all be inside `search` at least once.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    let mut max_seen = 0;
    while std::time::Instant::now() < deadline {
        let now = db.search_inflight();
        if now > max_seen {
            max_seen = now;
        }
        if max_seen >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    release.store(true, std::sync::atomic::Ordering::SeqCst);
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.search_inflight(), 0, "counter must drain to zero");
    assert!(
        max_seen >= 2,
        "expected to observe >= 2 concurrent searches, got {max_seen}"
    );
}
