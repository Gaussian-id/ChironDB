//! Explicit, ignored acceptance run over complete official BEIR test queries.
use super::*;
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::TempDir;

#[derive(Deserialize)]
struct Document {
    id: String,
    text: String,
    vector: Vec<f32>,
}
#[derive(Deserialize)]
struct Dataset {
    dim: usize,
    corpus: Vec<Document>,
    queries: Vec<Document>,
    qrels: HashMap<String, HashMap<String, u32>>,
}

#[test]
#[ignore = "requires BEIR_DATASET and BEIR_REPORT; run in release mode"]
fn beir_native_acceptance() {
    let path = std::env::var("BEIR_DATASET").expect("BEIR_DATASET");
    let output = std::env::var("BEIR_REPORT").expect("BEIR_REPORT");
    let raw = fs::read(&path).unwrap();
    let dataset: Dataset = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        dataset.queries.len(),
        dataset.qrels.len(),
        "all official test queries required"
    );
    let root = TempDir::new().unwrap();
    let db = Db::open(root.path()).unwrap();
    db.create_collection(
        serde_json::from_value(json!({"name":"beir","vector_dim":dataset.dim,"metric":"cosine"}))
            .unwrap(),
    )
    .unwrap();
    let built = Instant::now();
    let points = dataset
        .corpus
        .iter()
        .map(|doc| Point {
            id: doc.id.clone(),
            vector: doc.vector.clone(),
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: json!({"text":doc.text}),
        })
        .collect();
    db.upsert("beir", points).unwrap();
    let indexing_s = built.elapsed().as_secs_f64();
    let compact = Instant::now();
    db.compact_collection("beir").unwrap();
    let compact_s = compact.elapsed().as_secs_f64();
    drop(db);
    let recovery = Instant::now();
    let db = Db::open(root.path()).unwrap();
    let recovery_s = recovery.elapsed().as_secs_f64();
    let scope = TenantScope::system();
    let mut reports = Vec::new();
    for mode in ["dense", "bm25_native", "hybrid_native"] {
        let mut ndcg = 0.0;
        let mut recall = 0.0;
        let mut latencies = Vec::new();
        let mut rankings = BTreeMap::new();
        for query in &dataset.queries {
            let started = Instant::now();
            let hits: Vec<String> = match mode {
                "dense" => {
                    let request =
                        serde_json::from_value(json!({"vector":query.vector,"k":10})).unwrap();
                    db.search_scoped("beir", request, &scope)
                        .unwrap()
                        .hits
                        .into_iter()
                        .map(|hit| hit.id)
                        .collect()
                }
                "bm25_native" => {
                    let coll = db.get_coll("beir").unwrap();
                    let col = coll.read();
                    col.sparse_index
                        .text
                        .search("text", &query.text, None, 10, &|_| true, &|| false)
                        .ranked
                        .into_iter()
                        .map(|hit| hit.id)
                        .collect()
                }
                _ => {
                    let result = db
                        .text_hybrid_search_scoped(
                            "beir",
                            TextHybridSearchRequest {
                                vector: query.vector.clone(),
                                query: query.text.clone(),
                                text_field: "text".into(),
                                k: 10,
                                filter: None,
                                budget_ms: None,
                            },
                            &scope,
                        )
                        .unwrap();
                    assert!(!result.degraded);
                    result.hits.into_iter().map(|hit| hit.id).collect()
                }
            };
            latencies.push(started.elapsed().as_secs_f64() * 1000.0);
            let qrels = &dataset.qrels[&query.id];
            let dcg: f64 = hits
                .iter()
                .enumerate()
                .map(|(i, id)| f64::from(*qrels.get(id).unwrap_or(&0)) / (i as f64 + 2.0).log2())
                .sum();
            let mut ideal: Vec<_> = qrels.values().copied().collect();
            ideal.sort_unstable_by(|a, b| b.cmp(a));
            let idcg: f64 = ideal
                .into_iter()
                .take(10)
                .enumerate()
                .map(|(i, rel)| f64::from(rel) / (i as f64 + 2.0).log2())
                .sum();
            ndcg += if idcg > 0.0 { dcg / idcg } else { 0.0 };
            let relevant = qrels.values().filter(|rel| **rel > 0).count();
            recall += hits
                .iter()
                .filter(|id| qrels.get(*id).is_some_and(|rel| *rel > 0))
                .count() as f64
                / relevant.max(1) as f64;
            rankings.insert(query.id.clone(), hits);
        }
        latencies.sort_by(f64::total_cmp);
        let percentile =
            |p: f64| latencies[((latencies.len() as f64 * p).ceil() as usize).saturating_sub(1)];
        reports.push(json!({"mode":mode,"ndcg_at_10":ndcg/dataset.queries.len() as f64,"recall_at_10":recall/dataset.queries.len() as f64,"p50_ms":percentile(0.50),"p95_ms":percentile(0.95),"p99_ms":percentile(0.99),"rankings":rankings}));
    }
    let report = json!({"dataset":path,"dataset_sha256":Sha256::digest(&raw).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),"n_corpus":dataset.corpus.len(),"n_queries":dataset.queries.len(),"indexing_s":indexing_s,"compaction_s":compact_s,"recovery_s":recovery_s,"modes":reports});
    fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
