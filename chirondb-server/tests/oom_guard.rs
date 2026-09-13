//! OOM guard.
//!
//! Build a moderate workload and assert RSS stays bounded across an
//! upsert/delete churn loop. This catches obvious leaks and unbounded growth
//! before they bite production. Phase 6 (`MemoryGovernor`) will add hard-budget
//! enforcement; this gate is the smoke test that runs in CI on every phase.
//!
//! Overrides:
//!   `GAUSSDB_OOM_POINTS`        (default 4000)
//!   `GAUSSDB_OOM_CYCLES`        (default 200)
//!   `GAUSSDB_OOM_DELTA_MB_MAX`  (default 256) — max RSS growth across churn.

use std::collections::HashMap;

use chirondb::{CollectionConfig, Db, DistanceMetric, Point};
use serde_json::json;
use tempfile::TempDir;

const COLLECTION: &str = "oom_gate";
const DIM: usize = 128;

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_mb(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn lcg_vector(seed: u64, dim: usize) -> Vec<f32> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    (0..dim)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let v = ((state >> 32) as u32) as f32 / u32::MAX as f32;
            v * 2.0 - 1.0
        })
        .collect()
}

/// Cross-platform best-effort resident-set size in bytes.
/// Returns 0 on unsupported platforms — caller should treat as "skip".
pub fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm")
            && let Some(field) = s.split_whitespace().nth(1)
            && let Ok(pages) = field.parse::<u64>()
        {
            return pages * 4096;
        }
        0
    }
    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id().to_string();
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .ok();
        if let Some(o) = out
            && let Ok(s) = String::from_utf8(o.stdout)
            && let Ok(kb) = s.trim().parse::<u64>()
        {
            return kb * 1024;
        }
        0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

fn build_db(path: &std::path::Path) -> Db {
    let db = Db::open(path).expect("open db");
    db.create_collection(CollectionConfig {
        name: COLLECTION.to_string(),
        vector_dim: DIM,
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
    .expect("create collection");
    db
}

fn make_point(idx: usize) -> Point {
    Point {
        id: format!("p{idx:08}"),
        vector: lcg_vector(idx as u64, DIM),
        vectors: HashMap::new(),
        sparse_vector: None,
        payload: json!({"bucket": idx % 16}),
    }
}

#[test]
fn upsert_delete_cycle_does_not_balloon_rss() {
    let dir = TempDir::new().expect("tempdir");
    let db = build_db(dir.path());

    let n = env_count("GAUSSDB_OOM_POINTS", 4_000);
    let cycles = env_count("GAUSSDB_OOM_CYCLES", 200);
    let delta_max_mb = env_mb("GAUSSDB_OOM_DELTA_MB_MAX", 256);

    let seed_points: Vec<Point> = (0..n).map(make_point).collect();
    db.upsert(COLLECTION, seed_points).expect("seed upsert");
    db.compact_collection(COLLECTION).expect("compact");

    let baseline = rss_bytes();
    if baseline == 0 {
        eprintln!("rss_bytes unsupported on this platform — skipping oom_guard");
        return;
    }

    for cycle in 0..cycles {
        let churn_id = n + cycle;
        db.upsert(COLLECTION, vec![make_point(churn_id)])
            .expect("churn upsert");
        let target = format!("p{churn_id:08}");
        db.delete(COLLECTION, std::slice::from_ref(&target))
            .expect("churn delete");
    }

    let after = rss_bytes();
    let delta = after.saturating_sub(baseline);
    let delta_mb = delta / (1024 * 1024);
    eprintln!(
        "oom_guard baseline={}MB after={}MB delta={}MB (max {}MB)",
        baseline / (1024 * 1024),
        after / (1024 * 1024),
        delta_mb,
        delta_max_mb
    );

    assert!(
        delta_mb <= delta_max_mb,
        "RSS grew by {delta_mb} MB after {cycles} churn cycles (limit {delta_max_mb} MB) — possible leak"
    );
}
