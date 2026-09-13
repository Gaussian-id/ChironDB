use std::collections::BTreeMap;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, SearchRequest};
use serde_json::json;
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum Op {
    Upsert(&'static str, [f32; 2]),
    Delete(&'static str),
    CrashReopen,
}

#[test]
fn jepsen_style_single_node_history_survives_reopen_nemesis() {
    let temp = TempDir::new().unwrap();
    let mut db = open_with_collection(temp.path());
    let mut model = BTreeMap::new();

    let history = [
        Op::Upsert("a", [1.0, 0.0]),
        Op::Upsert("b", [0.8, 0.2]),
        Op::CrashReopen,
        Op::Delete("a"),
        Op::Upsert("c", [0.0, 1.0]),
        Op::CrashReopen,
        Op::Upsert("b", [0.7, 0.3]),
        Op::Delete("missing"),
        Op::CrashReopen,
    ];

    for op in history {
        match op {
            Op::Upsert(id, vector) => {
                db.upsert("jepsen", vec![point(id, vector)]).unwrap();
                model.insert(id.to_string(), vector);
            }
            Op::Delete(id) => {
                db.delete("jepsen", &[id.to_string()]).unwrap();
                model.remove(id);
            }
            Op::CrashReopen => {
                drop(db);
                db = Db::open(temp.path()).unwrap();
            }
        }
        assert_linearizable_set_state(&db, &model);
    }
}

fn open_with_collection(path: &std::path::Path) -> Db {
    let db = Db::open(path).unwrap();
    if db.list_collections().is_empty() {
        db.create_collection(CollectionConfig {
            name: "jepsen".to_string(),
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
    }
    db
}

fn point(id: &str, vector: [f32; 2]) -> Point {
    Point {
        id: id.to_string(),
        vector: vector.to_vec(),
        vectors: Default::default(),
        sparse_vector: None,
        payload: json!({"id": id}),
    }
}

fn assert_linearizable_set_state(db: &Db, model: &BTreeMap<String, [f32; 2]>) {
    assert_eq!(db.count("jepsen", None).unwrap().count, model.len());

    let response = db
        .search(
            "jepsen",
            SearchRequest {
                graph: None,
                vector: vec![1.0, 0.0],
                vector_name: None,
                k: 10,
                filter: None,
                budget_ms: None,
                consistency: None,
                ef_search: None,
                recall_target: None,
                with_payload: None,
            },
        )
        .unwrap();
    let observed = response
        .hits
        .into_iter()
        .map(|hit| hit.id)
        .collect::<Vec<_>>();
    let expected = exact_cosine_order(model);
    assert_eq!(observed, expected);
}

fn exact_cosine_order(model: &BTreeMap<String, [f32; 2]>) -> Vec<String> {
    let mut scored = model
        .iter()
        .map(|(id, vector)| {
            let norm = (vector[0] * vector[0] + vector[1] * vector[1]).sqrt();
            let score = if norm == 0.0 { 0.0 } else { vector[0] / norm };
            (id.clone(), score)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.into_iter().map(|(id, _)| id).collect()
}
