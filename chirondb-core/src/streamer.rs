//! Mutable streamer segment (paper §VII.D / LS-Vec rework D1).
//!
//! The streamer is the collection's live, append-only write buffer: the
//! points inserted since the last seal, plus the in-memory index that serves
//! them. It is today's live path (points map + incremental HNSW insert)
//! wrapped in its own struct so it can be capped, frozen, and sealed as a
//! unit — the seal handoff `mem::replace`s the whole streamer, so freezing
//! is O(1) and never clones a point.
//!
//! Phase 1 (multi-segment serving skeleton): pure structural move of
//! `Collection.points` / `Collection.h2qg` / `Collection.named_h2qg` into
//! this struct — no cap, no seal yet. The cap + background seal land in
//! Phase 2.

use std::collections::HashMap;

use crate::Point;
use crate::h2qg::H2qgIndex;

const MEMORY_PRESSURE_SEAL_MIN_BYTES: usize = 64 * 1024 * 1024;

/// The mutable streamer: live points + their in-memory dense indexes.
#[derive(Debug)]
pub struct Streamer {
    /// Full-fidelity live points (vector + payload + named vectors), keyed
    /// by point id. Bounded by the streamer cap from Phase 2 onward.
    pub points: HashMap<String, Point>,
    /// In-memory HNSW over the unnamed vector field. `None` while the
    /// streamer is below `HNSW_THRESHOLD` (flat scan serves it).
    pub hnsw: Option<H2qgIndex>,
    /// Per-named-vector-field in-memory HNSW indexes.
    pub named_hnsw: HashMap<String, H2qgIndex>,
    /// First WAL LSN represented by this streamer's mutations.
    pub base_lsn: u64,
    /// Running logical byte estimate used by the seal threshold.
    vector_bytes: usize,
}

impl Streamer {
    pub fn new() -> Self {
        Self::with_base_lsn(0)
    }

    pub fn with_base_lsn(base_lsn: u64) -> Self {
        Self {
            points: HashMap::new(),
            hnsw: None,
            named_hnsw: HashMap::new(),
            base_lsn,
            vector_bytes: 0,
        }
    }

    pub fn insert(&mut self, point: Point) -> Option<Point> {
        let new_bytes = point_bytes(&point);
        let old = self.points.insert(point.id.clone(), point);
        self.vector_bytes = self
            .vector_bytes
            .saturating_add(new_bytes)
            .saturating_sub(old.as_ref().map(point_bytes).unwrap_or(0));
        old
    }

    pub fn remove(&mut self, id: &str) -> Option<Point> {
        let old = self.points.remove(id);
        self.vector_bytes = self
            .vector_bytes
            .saturating_sub(old.as_ref().map(point_bytes).unwrap_or(0));
        old
    }

    pub fn take_points(&mut self) -> HashMap<String, Point> {
        self.vector_bytes = 0;
        std::mem::take(&mut self.points)
    }

    pub fn estimated_bytes(&self) -> usize {
        self.vector_bytes
    }

    pub fn should_seal(&self, max_bytes: usize) -> bool {
        self.vector_bytes >= max_bytes
            || (self.vector_bytes >= MEMORY_PRESSURE_SEAL_MIN_BYTES
                && cgroup_memory_usage_and_limit()
                    .is_some_and(|(used, limit)| under_memory_pressure(used, limit)))
    }

    pub fn refresh_point_bytes(&mut self, old_bytes: usize, id: &str) {
        let new_bytes = self.points.get(id).map(point_bytes).unwrap_or(0);
        self.vector_bytes = self
            .vector_bytes
            .saturating_add(new_bytes)
            .saturating_sub(old_bytes);
    }
}

fn under_memory_pressure(used: u64, limit: u64) -> bool {
    limit > 0 && used.saturating_mul(4) >= limit.saturating_mul(3)
}

pub(crate) fn memory_pressure() -> bool {
    cgroup_memory_usage_and_limit().is_some_and(|(used, limit)| under_memory_pressure(used, limit))
}

#[cfg(target_os = "linux")]
fn cgroup_memory_usage_and_limit() -> Option<(u64, u64)> {
    for (usage_path, limit_path) in [
        ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
        (
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ),
    ] {
        let Some(used) = read_cgroup_bytes(usage_path) else {
            continue;
        };
        let Some(limit) = read_cgroup_bytes(limit_path) else {
            continue;
        };
        if limit < (1_u64 << 60) {
            return Some((used, limit));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_cgroup_bytes(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_usage_and_limit() -> Option<(u64, u64)> {
    None
}

pub(crate) fn point_bytes(point: &Point) -> usize {
    point.id.len()
        + point.vector.len() * std::mem::size_of::<f32>()
        + point
            .vectors
            .iter()
            .map(|(name, vector)| name.len() + vector.len() * std::mem::size_of::<f32>())
            .sum::<usize>()
        + point
            .sparse_vector
            .as_ref()
            .map(|vector| {
                vector.indices.len() * std::mem::size_of::<u32>()
                    + vector.values.len() * std::mem::size_of::<f32>()
            })
            .unwrap_or(0)
        + json_bytes(&point.payload)
}

fn json_bytes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 0,
        serde_json::Value::Bool(_) => 1,
        serde_json::Value::Number(_) => 8,
        serde_json::Value::String(value) => value.len(),
        serde_json::Value::Array(values) => values.iter().map(json_bytes).sum(),
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(key, value)| key.len() + json_bytes(value))
            .sum(),
    }
}

impl Default for Streamer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Streamer, under_memory_pressure};
    use crate::Point;

    fn point(id: &str, dim: usize, payload: serde_json::Value) -> Point {
        Point {
            id: id.to_string(),
            vector: vec![1.0; dim],
            vectors: Default::default(),
            sparse_vector: None,
            payload,
        }
    }

    #[test]
    fn accounting_tracks_insert_replace_remove_and_take() {
        let mut streamer = Streamer::with_base_lsn(42);
        streamer.insert(point("a", 4, json!({"x": "one"})));
        let first = streamer.estimated_bytes();
        assert!(first >= 16);
        assert_eq!(streamer.base_lsn, 42);

        streamer.insert(point("a", 8, json!({"x": "two"})));
        assert!(streamer.estimated_bytes() > first);
        let max = streamer.estimated_bytes();
        assert!(streamer.should_seal(max));

        streamer.remove("a");
        assert_eq!(streamer.estimated_bytes(), 0);
        streamer.insert(point("b", 2, json!(null)));
        assert_eq!(streamer.take_points().len(), 1);
        assert_eq!(streamer.estimated_bytes(), 0);
    }

    #[test]
    fn byte_cap_seals_at_boundary_not_before() {
        let mut streamer = Streamer::new();
        streamer.insert(point("a", 4, json!(null)));
        let boundary = streamer.estimated_bytes();

        assert!(!streamer.should_seal(boundary + 1));
        assert!(streamer.should_seal(boundary));
    }

    #[test]
    fn memory_pressure_starts_at_three_quarters_of_cgroup_limit() {
        let gib = 1024_u64 * 1024 * 1024;
        assert!(!under_memory_pressure(4 * gib, 6 * gib));
        assert!(under_memory_pressure(9 * gib / 2, 6 * gib));
        assert!(under_memory_pressure(5 * gib, 6 * gib));
        assert!(!under_memory_pressure(1, 0));
    }
}
