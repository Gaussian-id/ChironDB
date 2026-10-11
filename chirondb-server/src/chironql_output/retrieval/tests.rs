use super::*;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn point() -> Point {
    Point {
        id: "chunk-日本語".into(),
        vector: vec![0.1, -0.0, f32::MAX],
        vectors: HashMap::from([("named".into(), vec![0.7181532, f32::MIN_POSITIVE])]),
        sparse_vector: Some(crate::SparseVector {
            indices: vec![1, u32::MAX],
            values: vec![0.1, -0.0],
        }),
        payload: json!({"integer":i64::MAX,"text":"日本語\n","nested":[null,true]}),
    }
}
#[test]
fn moved_point_and_hit_rows_match_serde_numeric_and_optional_fields() {
    let mut p = point();
    p.payload["text"] = Value::String("x".repeat(8192));
    let text = p.payload["text"].as_str().unwrap().as_ptr();
    let expected = serde_json::to_value(&p).unwrap();
    let id = p.id.as_ptr();
    let mut memory = QueryMemory::new().unwrap();
    let result = points(vec![p], Some("cursor".into()), true, "points", &mut memory).unwrap();
    assert_eq!(result.rows[0], expected);
    assert_eq!(
        serde_json::to_vec(&result.rows[0]).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(result.rows[0]["id"].as_str().unwrap().as_ptr(), id);
    assert_eq!(
        result.rows[0]["payload"]["text"].as_str().unwrap().as_ptr(),
        text
    );
    assert_eq!(result.columns, ["id", "vector", "vectors", "payload"]);
    assert_eq!(result.next.as_deref(), Some("cursor"));
    let p = point();
    let expected = json!({"id":p.id,"payload":p.payload});
    assert_eq!(
        points(vec![p], None, false, "view", &mut memory)
            .unwrap()
            .rows[0],
        expected
    );
    for score in [0.1_f32, -0.0, f32::MAX, f32::NAN, f32::INFINITY] {
        let hit = SearchHit {
            id: "hit".into(),
            score,
            payload: json!({"value":u64::MAX}),
        };
        let expected = serde_json::to_value(&hit).unwrap();
        let result = hits(vec![hit], "hits", &mut memory).unwrap();
        assert_eq!(
            serde_json::to_vec(&result.rows[0]).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
    }
    let mut p = point();
    p.sparse_vector = None;
    p.vectors.clear();
    p.vector.clear();
    let expected = serde_json::to_value(&p).unwrap();
    assert_eq!(
        points(vec![p], None, true, "empty", &mut memory)
            .unwrap()
            .rows[0],
        expected
    );
}

#[test]
fn randomized_retrieval_conversion_matches_independent_serde_oracle() {
    let mut seed = 0x331a_2508_u64;
    for round in 0..96 {
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as u32
        };
        let mut p = point();
        p.id = format!("row-{round}");
        p.vector = (0..next() % 24).map(|_| f32::from_bits(next())).collect();
        p.vectors = HashMap::from([(
            format!("name-{round}"),
            (0..next() % 12).map(|_| f32::from_bits(next())).collect(),
        )]);
        if next() % 2 == 0 {
            p.sparse_vector = None;
        }
        p.payload = json!({"id":next(),"nested":[null,{"text":format!("日本語-{round}"),"negative":-(next() as i64)}]});
        let expected = serde_json::to_value(&p).unwrap();
        let mut memory = QueryMemory::new().unwrap();
        assert_eq!(
            points(vec![p], None, true, "random", &mut memory)
                .unwrap()
                .rows[0],
            expected,
            "{round}"
        );
        let hit = SearchHit {
            id: format!("hit-{round}"),
            score: f32::from_bits(next()),
            payload: expected,
        };
        let expected = serde_json::to_value(&hit).unwrap();
        assert_eq!(
            hits(vec![hit], "random", &mut memory).unwrap().rows[0],
            expected,
            "{round}"
        );
    }
}

#[test]
fn nested_array_conversion_polls_cancellation_between_bounded_batches() {
    let flag = Arc::new(AtomicBool::new(false));
    let mut memory = QueryMemory::new().unwrap();
    memory.admit(slots(4096).unwrap()).unwrap();
    memory.cancel_with(flag.clone());
    let mut converted = 0;
    let result = array((0..4096_u32).collect(), &memory, |value| {
        converted += 1;
        if converted == 1001 {
            flag.store(true, Ordering::Release);
        }
        Ok(Value::from(value))
    });
    assert!(result.is_err_and(|e| e.to_string().contains("query canceled")));
    assert_eq!(converted, 1024);
}
fn node_row(payload: bool) -> GraphTraversalNodeRow {
    GraphTraversalNodeRow {
        id: "node".into(),
        depth: 7,
        payload: payload.then(|| json!({"big":i64::MAX})),
    }
}
fn edge_row(properties: bool) -> GraphTraversalEdgeRow {
    GraphTraversalEdgeRow {
        id: serde_json::from_value(json!("e1:00000000-0000-0000-0000-000000000001")).unwrap(),
        source: "a".into(),
        target: "b".into(),
        edge_type: "cites".into(),
        properties: properties.then(|| json!({"kind":"source"})),
    }
}
#[test]
fn nested_graph_rows_match_serde_without_cloning_payloads() {
    let mut memory = QueryMemory::new().unwrap();
    for payload in [false, true] {
        let n = node_row(payload);
        assert_eq!(node(n.clone()), serde_json::to_value(&n).unwrap());
        let e = edge_row(payload);
        assert_eq!(edge(e.clone()), serde_json::to_value(&e).unwrap());
        for rows in [
            GraphTraversalRows::Nodes(vec![n.clone()]),
            GraphTraversalRows::Edges(vec![e.clone()]),
            GraphTraversalRows::Paths(vec![GraphTraversalPathRow {
                nodes: vec![n],
                edges: vec![e],
            }]),
        ] {
            let expected = serde_json::to_value(&rows).unwrap()["rows"].clone();
            let result = graph(
                GraphTraversalQueryResult {
                    result: rows,
                    stats: TraversalStats::default(),
                    truncation: None,
                    warnings: vec![],
                    graph_epoch: GraphEpoch::from_raw(9).unwrap(),
                },
                payload,
                "graph",
                &mut memory,
            )
            .unwrap();
            assert_eq!(result.rows, expected.as_array().unwrap().clone());
            assert_eq!(result.stats.graph_epoch, Some(9));
        }
    }
    let mut n = node_row(true);
    n.payload.as_mut().unwrap()["text"] = Value::String("日本語".repeat(2048));
    let pointer = n.payload.as_ref().unwrap()["text"]
        .as_str()
        .unwrap()
        .as_ptr();
    let result = graph(
        GraphTraversalQueryResult {
            result: GraphTraversalRows::Nodes(vec![n]),
            stats: TraversalStats::default(),
            truncation: None,
            warnings: vec![],
            graph_epoch: GraphEpoch::from_raw(9).unwrap(),
        },
        true,
        "pointer",
        &mut memory,
    )
    .unwrap();
    assert_eq!(
        result.rows[0]["payload"]["text"].as_str().unwrap().as_ptr(),
        pointer
    );
}
#[test]
fn receiver_refusal_and_cancellation_precede_json_construction() {
    const CHILD: &str = "CHIRON_RETRIEVAL_RECEIVER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","chironql_output::retrieval::tests::receiver_refusal_and_cancellation_precede_json_construction","--nocapture"]).env(CHILD,"1").status().unwrap().success());
        return;
    }
    let mut profile = crate::resource_profile::ResourceProfile::from_limits(1 << 30, 1);
    profile.sql_pool_bytes = 256 * 1024;
    crate::resource_profile::install(profile);
    let mut memory = QueryMemory::new().unwrap();
    let before = memory.bytes_for_test();
    let hit = SearchHit {
        id: "large".into(),
        score: 1.0,
        payload: Value::String("x".repeat(128 * 1024)),
    };
    assert!(hits(vec![hit], "refusal", &mut memory).is_err());
    assert_eq!(memory.bytes_for_test(), before);
    let result = hits(
        vec![SearchHit {
            id: "small".into(),
            score: 0.1,
            payload: json!({"x":"y"}),
        }],
        "owner",
        &mut memory,
    )
    .unwrap();
    let charge = memory.bytes_for_test();
    let output = super::super::QueryResult::new(result, memory);
    assert!(crate::response_buffer::ResponseReservation::new(128 * 1024 - charge).is_err());
    output
        .consume(|value| {
            assert_eq!(value.rows.len(), 1);
            assert!(crate::response_buffer::ResponseReservation::new(128 * 1024 - charge).is_err());
        })
        .unwrap();
    assert!(crate::response_buffer::ResponseReservation::new(120 * 1024).is_ok());
    let flag = Arc::new(AtomicBool::new(true));
    let mut memory = QueryMemory::new().unwrap();
    memory.cancel_with(flag.clone());
    assert!(points(vec![point()], None, true, "cancel", &mut memory).is_err());
    flag.store(false, Ordering::Release);
    assert!(points(vec![point()], None, true, "clear", &mut memory).is_ok());
}
