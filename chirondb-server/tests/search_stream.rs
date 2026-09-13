//! PB-3: SSE-streamed search response.
//!
//! Locks in:
//!   - `/search/stream` returns k hit events followed by a meta event and
//!     a `done` terminator.
//!   - Hit ordering matches the non-streaming `/search` endpoint.

use std::collections::HashMap;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point, api};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

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

async fn boot_server(n: usize, dim: usize) -> (TempDir, String, &'static str) {
    let data = TempDir::new().unwrap();
    let db = Db::open(data.path()).unwrap();
    let coll = "pb3_stream";
    db.create_collection(CollectionConfig {
        name: coll.to_string(),
        vector_dim: dim,
        metric: DistanceMetric::Cosine,
        shards: 1,
        replicas: 1,
        quantization: None,
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

    let points: Vec<Point> = (0..n)
        .map(|i| Point {
            id: format!("p{i:08}"),
            vector: lcg_vector(i as u64, dim),
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"bucket": i % 8}),
        })
        .collect();
    db.upsert(coll, points).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        api::serve_listener(db, listener).await.unwrap();
    });
    (data, format!("http://{addr}"), coll)
}

fn parse_sse_data_blocks(body: &str) -> Vec<String> {
    // Minimal SSE parser: split on blank-line separator, take `data:` payload.
    body.split("\n\n")
        .filter_map(|chunk| {
            for line in chunk.lines() {
                if let Some(rest) = line.strip_prefix("data:") {
                    return Some(rest.trim().to_string());
                }
            }
            None
        })
        .collect()
}

#[tokio::test]
async fn stream_emits_k_hits_then_meta_then_done() {
    let dim = 32;
    let k = 25;
    let (_data, base, coll) = boot_server(800, dim).await;

    let query = lcg_vector(7777, dim);
    let req = json!({
        "vector": query,
        "k": k,
    });

    let resp = reqwest::Client::new()
        .post(format!("{base}/collections/{coll}/search/stream"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status {:?}", resp.status());

    let body = resp.text().await.unwrap();
    let blocks = parse_sse_data_blocks(&body);

    // k hit events + 1 meta + 1 `done`.
    assert!(
        blocks.len() >= k + 2,
        "expected >= {} SSE blocks, got {}: {body}",
        k + 2,
        blocks.len()
    );

    let done = blocks.last().unwrap();
    assert_eq!(done, "done", "last block must be `done`");

    let meta = &blocks[blocks.len() - 2];
    let meta_json: Value = serde_json::from_str(meta).unwrap();
    assert!(meta_json["meta"]["elapsed_ms"].is_number());
    assert!(meta_json["meta"]["searched"].is_number());

    // Hit events parse as JSON with id + score + payload fields.
    let hit_events = &blocks[..k];
    for h in hit_events {
        let v: Value = serde_json::from_str(h).unwrap();
        assert!(v["id"].is_string(), "hit must have id: {h}");
        assert!(v["score"].is_number(), "hit must have score: {h}");
    }
}

#[tokio::test]
async fn stream_hit_order_matches_non_streaming_search() {
    let dim = 32;
    let k = 15;
    let (_data, base, coll) = boot_server(800, dim).await;
    let query = lcg_vector(13_579, dim);
    let req = json!({
        "vector": query,
        "k": k,
    });

    let client = reqwest::Client::new();
    let plain: Value = client
        .post(format!("{base}/collections/{coll}/search"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let plain_ids: Vec<String> = plain["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap().to_string())
        .collect();

    let stream_body = client
        .post(format!("{base}/collections/{coll}/search/stream"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let blocks = parse_sse_data_blocks(&stream_body);
    let stream_ids: Vec<String> = blocks[..k]
        .iter()
        .map(|b| {
            let v: Value = serde_json::from_str(b).unwrap();
            v["id"].as_str().unwrap().to_string()
        })
        .collect();

    assert_eq!(
        plain_ids, stream_ids,
        "/search/stream hit order must match /search exactly"
    );
}
