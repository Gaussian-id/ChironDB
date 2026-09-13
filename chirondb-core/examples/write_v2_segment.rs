//! P2E: write a V2 segment file on disk. Used by the manual smoke test
//! of `gaussctl migrate-segment` against a real V2 segment.
//!
//! Usage: `cargo run -p chirondb-core --example write_v2_segment -- /path/to/root`

use std::env;
use std::fs;
use std::path::PathBuf;

use chirondb_core::Point;
use chirondb_core::segment::write_segment_v2_legacy;
use serde_json::json;

fn main() {
    let root = env::args()
        .nth(1)
        .expect("usage: write_v2_segment <root-dir>");
    let seg_dir = PathBuf::from(&root).join("sg-smoke");
    fs::create_dir_all(&seg_dir).unwrap();
    let path = seg_dir.join("vec.gdx");
    let points = vec![
        Point {
            id: "s0".into(),
            vector: vec![0.1, 0.2, 0.3, 0.4],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        },
        Point {
            id: "s1".into(),
            vector: vec![0.5, 0.6, 0.7, 0.8],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        },
        Point {
            id: "s2".into(),
            vector: vec![0.9, 1.0, 1.1, 1.2],
            vectors: Default::default(),
            sparse_vector: None,
            payload: json!({}),
        },
    ];
    write_segment_v2_legacy(&path, &points).unwrap();
    println!("wrote V2 segment: {}", path.display());
}
