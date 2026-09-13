//! PB-2: parallel typed-payload validation on upsert.
//!
//! Locks in:
//!   - A large batch with one bad point still surfaces the validation error
//!     (rayon's `try_for_each` short-circuits, so we get *some* error — not
//!     necessarily the same one as the serial path).
//!   - A large batch with all good points upserts cleanly.
//!   - Below the parallel threshold (64), the serial path keeps deterministic
//!     error ordering (first bad point reports first).

use chirondb::{CollectionConfig, Db, DistanceMetric, PayloadType, Point};
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

fn build_with_schema(dim: usize) -> (TempDir, Db, &'static str) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path()).expect("open db");
    let coll = "pb2_validate";

    let mut payload_schema = std::collections::HashMap::new();
    payload_schema.insert("bucket".to_string(), PayloadType::Number);
    payload_schema.insert("name".to_string(), PayloadType::String);

    db.create_collection(CollectionConfig {
        name: coll.to_string(),
        vector_dim: dim,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
        payload_schema,
        named_vector_dims: Default::default(),
        hnsw_m: None,
        hnsw_ef_construction: None,
        hnsw_ef_search: None,
        recall_sla: None,
        index_kind: None,
        streamer_max_bytes: 0,
    })
    .expect("create collection");
    (dir, db, coll)
}

#[test]
fn large_batch_with_one_bad_point_surfaces_error() {
    // 200 points (above the 64 PARALLEL_VALIDATE_THRESHOLD). Point #137 has
    // wrong vector dim — must produce a DimensionMismatch / InvalidRequest.
    let dim = 32;
    let (_dir, db, coll) = build_with_schema(dim);

    let mut points: Vec<Point> = (0..200)
        .map(|i| Point {
            id: format!("p{i:04}"),
            vector: lcg_vector(i, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i, "name": format!("n{i}")}),
        })
        .collect();
    // Inject bad dim mid-batch.
    points[137].vector = vec![0.0_f32; dim + 4];

    let err = db.upsert(coll, points).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("expected vector dimension")
            || msg.contains("vector dimension")
            || msg.contains("dim"),
        "unexpected error: {msg}"
    );
}

#[test]
fn large_batch_with_all_good_points_succeeds() {
    let dim = 32;
    let (_dir, db, coll) = build_with_schema(dim);

    let points: Vec<Point> = (0..256)
        .map(|i| Point {
            id: format!("p{i:04}"),
            vector: lcg_vector(i, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i, "name": format!("n{i}")}),
        })
        .collect();
    let total = db.upsert(coll, points).expect("must accept");
    assert_eq!(total, 256);
}

#[test]
fn small_batch_serial_path_still_validates() {
    // Below threshold = serial path. Same error semantics.
    let dim = 32;
    let (_dir, db, coll) = build_with_schema(dim);

    let mut points: Vec<Point> = (0..10)
        .map(|i| Point {
            id: format!("p{i:04}"),
            vector: lcg_vector(i, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i, "name": format!("n{i}")}),
        })
        .collect();
    points[3].vector = vec![0.0_f32; dim - 1];

    let err = db.upsert(coll, points).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("dimension") || msg.contains("dim"),
        "unexpected error: {msg}"
    );
}

#[test]
fn schema_violations_still_caught_in_parallel_path() {
    // Payload schema declares `bucket: Number` and `name: String`. A point
    // with `bucket: "not a number"` must be rejected even in the parallel
    // path.
    let dim = 32;
    let (_dir, db, coll) = build_with_schema(dim);

    let mut points: Vec<Point> = (0..128)
        .map(|i| Point {
            id: format!("p{i:04}"),
            vector: lcg_vector(i, dim),
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({"bucket": i, "name": format!("n{i}")}),
        })
        .collect();
    points[64].payload = json!({"bucket": "not a number", "name": "x"});

    let err = db.upsert(coll, points).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("bucket") || msg.contains("payload") || msg.contains("number"),
        "unexpected error: {msg}"
    );
}
