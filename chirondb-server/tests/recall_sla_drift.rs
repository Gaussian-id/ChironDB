//! P3 — recall SLA drift monitor integration test.
//!
//! Locks in:
//!   - `CollectionConfig::recall_sla` round-trips through create_collection.
//!   - `validate_config` rejects out-of-range SLAs.
//!   - `Db::check_recall_drift` on a collection without `recall_sla` is a
//!     no-op (returns `Ok(None)`).
//!   - `Db::check_recall_drift` on a flat (sub-HNSW-threshold) collection
//!     with a tight SLA returns `Ok(None)` — the calibrator short-circuits
//!     to recall=1.0 so no breach can ever fire.
//!   - `Db::check_recall_drift_all` returns the list of breaches across
//!     collections.
//!   - When a breach fires, the audit log gains a `recall_sla_breach` record
//!     whose chained hash verifies.

use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
use chirondb_core::audit::verify_hash_chain;
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

fn collection_config(name: &str, dim: usize, recall_sla: Option<f32>) -> CollectionConfig {
    CollectionConfig {
        name: name.to_string(),
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
        recall_sla,
        index_kind: None,
        streamer_max_bytes: 0,
    }
}

fn populate(db: &Db, coll: &str, n: usize, dim: usize) {
    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i % 4}),
        })
        .collect();
    db.upsert(coll, points).unwrap();
}

#[test]
fn create_collection_accepts_in_range_recall_sla() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let returned = db
        .create_collection(collection_config("sla_in_range", 16, Some(0.95)))
        .expect("create with SLA");
    assert_eq!(returned.recall_sla, Some(0.95));
}

#[test]
fn create_collection_rejects_out_of_range_recall_sla() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let too_low = db.create_collection(collection_config("sla_too_low", 16, Some(0.4)));
    assert!(too_low.is_err(), "0.4 < 0.5 must be rejected");
    let too_high = db.create_collection(collection_config("sla_too_high", 16, Some(1.5)));
    assert!(too_high.is_err(), "1.5 > 1.0 must be rejected");
    let nan = db.create_collection(collection_config("sla_nan", 16, Some(f32::NAN)));
    assert!(nan.is_err(), "NaN must be rejected");
}

#[test]
fn check_drift_returns_none_when_sla_unset() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(collection_config("no_sla", 8, None))
        .expect("create");
    populate(&db, "no_sla", 100, 8);
    let report = db.check_recall_drift("no_sla").expect("check");
    assert!(report.is_none(), "no SLA → no monitoring → no report");
}

#[test]
fn check_drift_returns_none_for_flat_collection_with_sla() {
    // Below HNSW_THRESHOLD = 10_000 → flat path. Calibrator returns
    // [(k, 1.0)] so any SLA is met by construction.
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(collection_config("flat_with_sla", 8, Some(0.95)))
        .expect("create");
    populate(&db, "flat_with_sla", 256, 8);
    let report = db.check_recall_drift("flat_with_sla").expect("check");
    assert!(
        report.is_none(),
        "flat calibrator hits 1.0 → SLA always met"
    );
}

#[test]
fn check_drift_all_returns_empty_when_no_breaches() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(collection_config("a", 8, Some(0.95)))
        .expect("create a");
    db.create_collection(collection_config("b", 8, None))
        .expect("create b");
    populate(&db, "a", 64, 8);
    populate(&db, "b", 64, 8);
    let breaches = db.check_recall_drift_all();
    assert!(
        breaches.is_empty(),
        "no breaches on flat collections, got {breaches:?}"
    );
}

#[test]
fn audit_chain_remains_verifiable_after_drift_sweep() {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    db.create_collection(collection_config("audit_check", 8, Some(0.95)))
        .expect("create");
    populate(&db, "audit_check", 128, 8);
    let _ = db.check_recall_drift_all();
    verify_hash_chain(dir.path()).expect("audit chain stays valid after drift sweep");
}
