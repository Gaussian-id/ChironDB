use super::*;

fn request(filter: Option<Filter>, name: Option<&str>, payload: bool) -> SearchRequest {
    SearchRequest {
        vector: vec![1.0, 2.0],
        vector_name: name.map(str::to_string),
        k: 7,
        filter,
        graph: None,
        budget_ms: None,
        consistency: None,
        ef_search: None,
        recall_target: Some(1.0),
        with_payload: Some(payload),
    }
}

fn check(db: &Db, points: &HashMap<String, Point>) {
    let filters = [
        None,
        Some(Filter(json!({"tenant": "a"}))),
        Some(Filter(json!({"tenant": {"in": ["a", "b"]}}))),
        Some(Filter(json!({"price": {"gte": 5, "lte": 6}}))),
        Some(Filter(json!({"literal.path": "right"}))),
        Some(Filter(json!({"nested.value": 1}))),
        Some(Filter(json!({"tenant": "absent"}))),
    ];
    for filter in filters {
        for name in [None, Some("named")] {
            for payload in [false, true] {
                let request = request(filter.clone(), name, payload);
                let mut oracle: Vec<_> = points
                    .values()
                    .filter(|point| {
                        filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&point.payload))
                    })
                    .filter_map(|point| {
                        let vector = crate::search::point_vector(point, name)?;
                        Some((
                            point.id.clone(),
                            DistanceMetric::L2.score(&request.vector, vector).unwrap(),
                        ))
                    })
                    .collect();
                oracle.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                oracle.truncate(7);
                let result = db.search("docs", request).unwrap();
                assert!(!result.degraded);
                assert_eq!(
                    result
                        .hits
                        .iter()
                        .map(|hit| (hit.id.clone(), hit.score))
                        .collect::<Vec<_>>(),
                    oracle,
                    "filter={filter:?}, named={name:?}"
                );
                for hit in result.hits {
                    assert_eq!(
                        hit.payload,
                        if payload {
                            points[&hit.id].payload.clone()
                        } else {
                            serde_json::Value::Null
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn dense_streaming_preserves_filters_scores_visibility_and_named_vectors_after_reopen() {
    lifecycle(false);
}

#[test]
fn partial_named_vectors_match_exact_filtered_oracle_after_reopen() {
    lifecycle(true);
}

fn lifecycle(partial_named: bool) {
    crate::relational::wal_decode::with_isolated_test_storage(|| {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        let config: CollectionConfig = serde_json::from_value(json!({
            "name":"docs", "vector_dim":2, "metric":"l2", "shards":1, "replicas":1,
            "named_vector_dims":{"named":2}
        }))
        .unwrap();
        db.create_collection(config).unwrap();
        let mut points: HashMap<_, _> = (0usize..257)
            .map(|i| {
                let point = Point {
                    id: format!("p{i:04}"),
                    vector: vec![(i % 7) as f32, 1.0],
                    vectors: if partial_named && i.is_multiple_of(3) {
                        HashMap::new()
                    } else {
                        HashMap::from([("named".into(), vec![1.0, (i % 7) as f32])])
                    },
                    sparse_vector: None,
                    payload: json!({"tenant": if i.is_multiple_of(2) {"a"} else {"b"},
                    "price": if i.is_multiple_of(2) {json!([1,10])} else {json!([5])},
                    "literal.path": "wrong", "literal":{"path":"right"},
                    "nested":{"value":i%2}, "body":"x".repeat(1024)}),
                };
                (point.id.clone(), point)
            })
            .collect();
        db.upsert("docs", points.values().cloned().collect())
            .unwrap();
        check(&db, &points);
        db.compact_collection("docs").unwrap();
        check(&db, &points);
        let mut updated = points["p0000"].clone();
        updated.payload = json!({"tenant":"b", "price":[5], "literal.path":"right"});
        updated.vector = vec![3.0, 1.0];
        db.upsert("docs", vec![updated.clone()]).unwrap();
        points.insert(updated.id.clone(), updated);
        db.delete("docs", &["p0001".into()]).unwrap();
        points.remove("p0001");
        check(&db, &points);
        drop(db);
        let reopened = Db::open(temp.path()).unwrap();
        check(&reopened, &points);
        reopened.compact_collection("docs").unwrap();
        check(&reopened, &points);
    });
}
