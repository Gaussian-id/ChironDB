//! P-A regression: legacy standalone IVF is no longer a user-selectable index.

use std::collections::HashMap;

use chirondb::{CollectionConfig, Db, DistanceMetric, GaussError};
use tempfile::TempDir;

#[test]
fn ivf_index_kind_is_rejected() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let error = db
        .create_collection(CollectionConfig {
            name: "iv".to_string(),
            vector_dim: 64,
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
            index_kind: Some("ivf".to_string()),
            streamer_max_bytes: 0,
        })
        .unwrap_err();
    assert!(matches!(error, GaussError::InvalidRequest(message)
        if message.contains("LS-VEC is the sole index")));
}
