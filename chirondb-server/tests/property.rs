use std::collections::{HashMap, HashSet};

use chirondb::{CollectionConfig, Db, DistanceMetric, Filter, Point, SearchRequest, SparseVector};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use serde_json::json;
use tempfile::TempDir;

#[derive(Clone, Debug)]
enum Op {
    Upsert { id: u8, x: i16, y: i16 },
    Delete { id: u8 },
    Compact,
    Reopen,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0_u8..8, -20_i16..=20, -20_i16..=20).prop_map(|(id, x, y)| Op::Upsert { id, x, y }),
        (0_u8..8).prop_map(|id| Op::Delete { id }),
        Just(Op::Compact),
        Just(Op::Reopen),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mutation_compaction_and_reopen_match_model(ops in prop::collection::vec(op_strategy(), 1..64)) {
        let temp = TempDir::new().unwrap();
        let mut db = open_seeded_db(temp.path());
        let mut model = HashMap::<String, Point>::new();

        for op in ops {
            match op {
                Op::Upsert { id, x, y } => {
                    let point = model_point(id, x, y);
                    db.upsert("docs", vec![point.clone()]).unwrap();
                    model.insert(point.id.clone(), point);
                }
                Op::Delete { id } => {
                    let point_id = point_id(id);
                    db.delete("docs", std::slice::from_ref(&point_id)).unwrap();
                    model.remove(&point_id);
                }
                Op::Compact => {
                    db.compact_collection("docs").unwrap();
                }
                Op::Reopen => {
                    drop(db);
                    db = Db::open(temp.path()).unwrap();
                }
            }

            assert_model_matches_db(&db, &model);
        }
    }
}

fn open_seeded_db(path: &std::path::Path) -> Db {
    let db = Db::open(path).unwrap();
    db.create_collection(CollectionConfig {
        name: "docs".to_string(),
        vector_dim: 2,
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
    .unwrap();
    db
}

fn model_point(id: u8, x: i16, y: i16) -> Point {
    let id = point_id(id);
    let slot = id_slot(&id);
    let vector = vec![x as f32 / 10.0, y as f32 / 10.0];
    Point {
        id,
        vector: vector.clone(),
        vectors: HashMap::from([("image".to_string(), vec![vector[1], vector[0]])]),
        sparse_vector: Some(SparseVector {
            indices: vec![(x.unsigned_abs() % 5) as u32],
            values: vec![(y.unsigned_abs() as f32 + 1.0) / 10.0],
        }),
        payload: json!({
            "bucket": if x % 2 == 0 { "even" } else { "odd" },
            "slot": slot,
        }),
    }
}

fn point_id(id: u8) -> String {
    format!("p-{id}")
}

fn id_slot(id: &str) -> u8 {
    id.strip_prefix("p-")
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn assert_model_matches_db(db: &Db, model: &HashMap<String, Point>) {
    let even_filter = Filter(json!({"bucket": "even"}));
    assert_eq!(db.count("docs", None).unwrap().count, model.len());
    assert_eq!(
        db.count("docs", Some(even_filter.clone())).unwrap().count,
        model
            .values()
            .filter(|point| even_filter.matches(&point.payload))
            .count()
    );

    assert_search_matches(db, model, None, None);
    assert_search_matches(db, model, Some("image"), None);
    assert_search_matches(db, model, None, Some(even_filter));
}

fn assert_search_matches(
    db: &Db,
    model: &HashMap<String, Point>,
    vector_name: Option<&str>,
    filter: Option<Filter>,
) {
    // V5 primary rows are deliberately scaled-f16 rather than bit-identical
    // inserted f32 values. Preserve top-k correctness while allowing only
    // quantization-sized reordering at a score tie/boundary.
    const SCORE_EPSILON: f32 = 0.002;
    let query = vec![1.0, 0.0];
    let actual = db
        .search(
            "docs",
            SearchRequest {
                graph: None,
                vector: query.clone(),
                vector_name: vector_name.map(ToString::to_string),
                k: 3,
                filter: filter.clone(),
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
        )
        .unwrap()
        .hits
        .into_iter()
        .map(|hit| (hit.id, hit.score))
        .collect::<Vec<_>>();
    let expected = exact_ranked(model, &query, vector_name, filter.as_ref());
    let expected_len = expected.len().min(3);
    assert_eq!(actual.len(), expected_len);

    let unique = actual
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), actual.len());

    if expected_len == 0 {
        return;
    }
    let cutoff = expected[expected_len - 1].1;
    for (id, score) in expected.iter().take(expected_len) {
        if *score > cutoff + SCORE_EPSILON {
            assert!(
                unique.contains(id.as_str()),
                "materially above-boundary point {id} was omitted: score={score}, cutoff={cutoff}"
            );
        }
    }
    let mut actual_model_scores = Vec::with_capacity(actual.len());
    for (id, stored_score) in &actual {
        let point = model.get(id).expect("search returned an unknown point id");
        assert!(filter.as_ref().is_none_or(|f| f.matches(&point.payload)));
        let vector = match vector_name {
            Some(name) => point
                .vectors
                .get(name)
                .expect("search returned a point without the requested vector"),
            None => &point.vector,
        };
        let model_score = DistanceMetric::Cosine.score(&query, vector).unwrap();
        assert!(
            (stored_score - model_score).abs() <= SCORE_EPSILON,
            "stored score drift for {id}: stored={stored_score}, model={model_score}"
        );
        assert!(
            model_score + SCORE_EPSILON >= cutoff,
            "{id} fell below the admissible top-k boundary: score={model_score}, cutoff={cutoff}"
        );
        actual_model_scores.push(model_score);
    }
    for scores in actual_model_scores.windows(2) {
        assert!(
            scores[0] + SCORE_EPSILON >= scores[1],
            "search reordered materially different scores: {} before {}",
            scores[0],
            scores[1]
        );
    }
}

fn exact_ranked(
    model: &HashMap<String, Point>,
    query: &[f32],
    vector_name: Option<&str>,
    filter: Option<&Filter>,
) -> Vec<(String, f32)> {
    let mut scored = model
        .values()
        .filter(|point| filter.is_none_or(|filter| filter.matches(&point.payload)))
        .filter_map(|point| {
            let vector = match vector_name {
                Some(name) => point.vectors.get(name)?,
                None => &point.vector,
            };
            let score = DistanceMetric::Cosine.score(query, vector).unwrap();
            Some((point.id.clone(), score))
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored
}
