//! RT-20 / RT-21 — opt-in write-path bounds on dense vector norms and sparse
//! vector size/weights. `None` keeps the previous unbounded behavior.
use super::*;

fn bounded_config(name: &str) -> CollectionConfig {
    let mut config = ls_vec_config(name);
    config.metric = DistanceMetric::Dot;
    config.named_vector_dims = HashMap::from([("title".to_string(), 2)]);
    config.max_vector_norm = Some(10.0);
    config.max_sparse_nnz = Some(3);
    config.max_sparse_weight = Some(5.0);
    config
}

fn dense(id: &str, vector: Vec<f32>) -> Point {
    Point {
        id: id.to_string(),
        vector,
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: serde_json::Value::Null,
    }
}

fn with_sparse(id: &str, indices: Vec<u32>, values: Vec<f32>) -> Point {
    let mut point = dense(id, vec![1.0, 0.0]);
    point.sparse_vector = Some(SparseVector { indices, values });
    point
}

fn invalid_request_message(result: crate::Result<usize>) -> String {
    match result {
        Err(GaussError::InvalidRequest(message)) => message,
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

#[test]
fn dense_norm_limit_rejects_over_and_accepts_at_or_under() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(bounded_config("docs")).unwrap();

    // 6-8-0 → norm exactly 10: at the limit is accepted.
    db.upsert("docs", vec![dense("at", vec![6.0, 8.0])])
        .unwrap();
    db.upsert("docs", vec![dense("under", vec![1.0, 1.0])])
        .unwrap();
    let message = invalid_request_message(db.upsert("docs", vec![dense("over", vec![6.0, 8.1])]));
    assert!(message.contains("max_vector_norm"), "{message}");
    assert!(message.contains("dense vector"), "{message}");
    assert!(message.contains("10"), "{message}");

    // The RT-20 attack shape: a single 1e6-norm point is refused.
    let message = invalid_request_message(db.upsert("docs", vec![dense("huge", vec![1.0e6, 0.0])]));
    assert!(message.contains("1000000"), "{message}");

    // Batch is atomic: one bad point rejects the whole request.
    assert!(
        db.upsert(
            "docs",
            vec![dense("ok", vec![1.0, 0.0]), dense("bad", vec![100.0, 0.0])]
        )
        .is_err()
    );
    let ids: HashSet<String> = db
        .get_points(
            "docs",
            &["at", "under", "over", "huge", "ok", "bad"].map(String::from),
        )
        .unwrap()
        .into_iter()
        .map(|point| point.id)
        .collect();
    assert_eq!(ids, HashSet::from(["at".to_string(), "under".to_string()]));
}

#[test]
fn dense_norm_limit_covers_named_vectors() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(bounded_config("docs")).unwrap();

    let mut ok = dense("ok", vec![1.0, 0.0]);
    ok.vectors.insert("title".to_string(), vec![0.0, 9.0]);
    db.upsert("docs", vec![ok]).unwrap();

    let mut bad = dense("bad", vec![1.0, 0.0]);
    bad.vectors.insert("title".to_string(), vec![0.0, 11.0]);
    let message = invalid_request_message(db.upsert("docs", vec![bad]));
    assert!(message.contains("named vector 'title'"), "{message}");
    assert!(message.contains("max_vector_norm"), "{message}");
}

#[test]
fn unset_limits_keep_previous_unbounded_behavior() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    let mut config = ls_vec_config("docs");
    config.metric = DistanceMetric::Dot;
    db.create_collection(config).unwrap();

    let many = 200u32;
    db.upsert(
        "docs",
        vec![
            dense("huge", vec![1.0e6, 0.0]),
            with_sparse("heavy", (0..many).collect(), vec![1000.0; many as usize]),
        ],
    )
    .unwrap();
}

#[test]
fn sparse_nnz_and_weight_limits_apply_to_writes() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(bounded_config("docs")).unwrap();

    // At both limits: 3 entries, |weight| == 5 (negative weights use abs).
    db.upsert(
        "docs",
        vec![with_sparse("at", vec![1, 2, 3], vec![5.0, -5.0, 0.5])],
    )
    .unwrap();

    let message = invalid_request_message(db.upsert(
        "docs",
        vec![with_sparse("nnz", vec![1, 2, 3, 4], vec![1.0; 4])],
    ));
    assert!(message.contains("max_sparse_nnz"), "{message}");
    assert!(message.contains('4') && message.contains('3'), "{message}");

    let message =
        invalid_request_message(db.upsert("docs", vec![with_sparse("weight", vec![1], vec![5.5])]));
    assert!(message.contains("max_sparse_weight"), "{message}");
    assert!(message.contains("5.5"), "{message}");

    let message = invalid_request_message(db.upsert(
        "docs",
        vec![with_sparse("negative", vec![1], vec![-1000.0])],
    ));
    assert!(message.contains("max_sparse_weight"), "{message}");
}

#[test]
fn query_sparse_vectors_are_not_subject_to_write_limits() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    db.create_collection(bounded_config("docs")).unwrap();
    db.upsert("docs", vec![with_sparse("doc", vec![7], vec![1.0])])
        .unwrap();

    // Query sparse vector exceeds both nnz (3) and weight (5) limits.
    let response = db
        .hybrid_search(
            "docs",
            HybridSearchRequest {
                graph: None,
                vector: Some(vec![1.0e6, 0.0]),
                vector_name: None,
                sparse_vector: Some(SparseVector {
                    indices: (100..150).chain(std::iter::once(7)).collect(),
                    values: vec![1000.0; 51],
                }),
                k: 5,
                filter: None,
                budget_ms: None,
                fusion: crate::HybridFusion::Rrf,
                dense_weight: 1.0,
                sparse_weight: 1.0,
            },
        )
        .unwrap();
    assert_eq!(response.hits[0].id, "doc");
}

#[test]
fn invalid_limit_values_are_rejected_at_create() {
    let temp = TempDir::new().unwrap();
    let db = Db::open(temp.path()).unwrap();
    for (index, bad) in [0.0, -1.0, f32::NAN, f32::INFINITY, f32::NEG_INFINITY]
        .into_iter()
        .enumerate()
    {
        let mut config = ls_vec_config(&format!("norm{index}"));
        config.max_vector_norm = Some(bad);
        assert!(
            matches!(db.create_collection(config), Err(GaussError::InvalidRequest(message)) if message.contains("max_vector_norm")),
            "max_vector_norm {bad} must be rejected"
        );
        let mut config = ls_vec_config(&format!("weight{index}"));
        config.max_sparse_weight = Some(bad);
        assert!(
            matches!(db.create_collection(config), Err(GaussError::InvalidRequest(message)) if message.contains("max_sparse_weight")),
            "max_sparse_weight {bad} must be rejected"
        );
    }
    let mut config = ls_vec_config("nnz");
    config.max_sparse_nnz = Some(0);
    assert!(matches!(
        db.create_collection(config),
        Err(GaussError::InvalidRequest(message)) if message.contains("max_sparse_nnz")
    ));
    assert!(db.list_collections().is_empty());
}

#[test]
fn limits_survive_catalog_reopen_and_snapshot() {
    let sandbox = TempDir::new().unwrap();
    let root = sandbox.path().join("db");
    let snapshot = sandbox.path().join("snapshot");
    let db = Db::open(&root).unwrap();
    db.create_collection(bounded_config("docs")).unwrap();
    db.create_collection(ls_vec_config("plain")).unwrap();
    db.snapshot(&snapshot).unwrap();
    drop(db);

    let assert_limits = |db: &Db| {
        let configs = db.list_collections();
        let docs = configs.iter().find(|c| c.name == "docs").unwrap();
        assert_eq!(docs.max_vector_norm, Some(10.0));
        assert_eq!(docs.max_sparse_nnz, Some(3));
        assert_eq!(docs.max_sparse_weight, Some(5.0));
        let plain = configs.iter().find(|c| c.name == "plain").unwrap();
        assert_eq!(plain.max_vector_norm, None);
        assert_eq!(plain.max_sparse_nnz, None);
        assert_eq!(plain.max_sparse_weight, None);
        // Enforcement is live after reload, not just the stored value.
        assert!(
            db.upsert("docs", vec![dense("x", vec![100.0, 0.0])])
                .is_err()
        );
        db.upsert("plain", vec![dense("x", vec![100.0, 0.0])])
            .unwrap();
    };

    let reopened = Db::open(&root).unwrap();
    assert_limits(&reopened);
    drop(reopened);

    let fork = Db::open(&snapshot).unwrap();
    assert_limits(&fork);
}

#[test]
fn legacy_catalog_without_limit_fields_loads_unbounded() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join(super::super::CATALOG_FILE),
        serde_json::to_vec(&json!({
            "collections": [{"name": "legacy", "vector_dim": 2, "metric": "dot"}]
        }))
        .unwrap(),
    )
    .unwrap();
    let catalog = super::super::read_catalog(temp.path()).unwrap();
    let legacy = &catalog.collections[0];
    assert_eq!(legacy.name, "legacy");
    assert_eq!(legacy.max_vector_norm, None);
    assert_eq!(legacy.max_sparse_nnz, None);
    assert_eq!(legacy.max_sparse_weight, None);
}

#[test]
fn wal_create_collection_record_round_trips_limits() {
    for config in [bounded_config("docs"), ls_vec_config("plain")] {
        let entry = WalEntry::CreateCollection {
            config: config.clone(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        let back: WalEntry = serde_json::from_value(json).unwrap();
        let WalEntry::CreateCollection { config: back } = back else {
            panic!("unexpected WAL entry");
        };
        assert_eq!(back.max_vector_norm, config.max_vector_norm);
        assert_eq!(back.max_sparse_nnz, config.max_sparse_nnz);
        assert_eq!(back.max_sparse_weight, config.max_sparse_weight);
    }
}

/// RT-20 follow-up: with no `max_vector_norm`, an extreme-norm vector on a
/// `dot` collection is still accepted but is reported for a log warning.
#[test]
fn extreme_norm_is_reported_only_for_unbounded_dot_collections() {
    use crate::db::{extreme_vector_norm, validate_point};
    let mut unbounded_dot = ls_vec_config("extreme-dot");
    unbounded_dot.metric = DistanceMetric::Dot;
    let poison = dense("poison", vec![1.0e6, 0.0]);
    let benign = dense("benign", vec![12.0, 5.0]);
    assert_eq!(extreme_vector_norm(&unbounded_dot, &poison), Some(1.0e6));
    assert_eq!(extreme_vector_norm(&unbounded_dot, &benign), None);
    assert!(validate_point(&unbounded_dot, &poison).is_ok());

    let mut named = poison.clone();
    named.vector = vec![1.0, 0.0];
    named.vectors = HashMap::from([("title".to_string(), vec![0.0, 2.0e4])]);
    unbounded_dot.named_vector_dims = HashMap::from([("title".to_string(), 2)]);
    assert_eq!(extreme_vector_norm(&unbounded_dot, &named), Some(2.0e4));

    let mut cosine = ls_vec_config("extreme-cosine");
    cosine.metric = DistanceMetric::Cosine;
    assert_eq!(extreme_vector_norm(&cosine, &poison), None);

    let bounded = bounded_config("extreme-bounded");
    assert_eq!(extreme_vector_norm(&bounded, &poison), None);
}
