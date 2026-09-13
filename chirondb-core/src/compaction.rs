//! Multi-factor compaction scoring for index optimizer decisions.
//! The existing auto-compact path triggers solely on WAL byte count.
//! This module provides a richer signal combining WAL-to-segment ratio
//! and deletion density so the optimizer can make smarter decisions.

/// All statistics about one collection needed to compute a score.
#[derive(Clone, Debug)]
pub struct CollectionCompactionStats {
    /// Collection name.
    pub name: String,
    /// Bytes currently in the live (un-compacted) WAL.
    pub wal_bytes: u64,
    /// Bytes in the sealed segment on disk (0 if never compacted).
    pub segment_bytes: u64,
    /// Number of live (un-deleted) points in memory.
    pub live_points: usize,
    /// Number of live points at the time of the last compaction (0 if never
    /// compacted).  Used to estimate how many WAL mutations have occurred.
    pub compacted_point_count: usize,
    /// Total WAL entry count since last compaction.
    pub wal_entry_count: usize,
    /// Number of delete WAL entries since last compaction.
    pub wal_delete_count: usize,
}

/// Exact graph-maintenance census for one pinned graph generation.
///
/// Physical edge records are outgoing rows scanned once. Directed entries
/// include every stored direction (CSR plus CSC when present), which is the
/// byte-reclaim denominator used by the maintenance trigger.
#[derive(Clone, Debug, PartialEq)]
pub struct GraphMaintenanceStats {
    pub generation: u64,
    pub physical_edge_records: u64,
    pub reclaimable_edge_records: u64,
    pub directed_entries: u64,
    pub reclaimable_directed_entries: u64,
    pub adjacency_bytes: u64,
    pub estimated_reclaimable_bytes: u64,
    pub live_nodes: u64,
    pub mean_fragments_per_node: f64,
    pub p95_fragments_per_node: u32,
    pub max_fragments_per_node: u32,
}

pub const GRAPH_DEAD_EDGE_PERCENT_TRIGGER: u64 = 20;
pub const GRAPH_P95_FRAGMENTS_TRIGGER: u32 = 4;
pub const GRAPH_MAX_FRAGMENTS_TRIGGER: u32 = 32;

impl GraphMaintenanceStats {
    /// Rev 3.4 §13.2 uses strict thresholds: equality does not trigger.
    pub fn requires_compaction(&self) -> bool {
        // The byte estimate is proportional to directed entries. Compare the
        // exact counts so rounding the displayed byte estimate cannot turn an
        // exact 20% boundary into a false trigger.
        let dead_edge_trigger = self.directed_entries != 0
            && u128::from(self.reclaimable_directed_entries) * 100
                > u128::from(self.directed_entries) * u128::from(GRAPH_DEAD_EDGE_PERCENT_TRIGGER);
        dead_edge_trigger
            || self.p95_fragments_per_node > GRAPH_P95_FRAGMENTS_TRIGGER
            || self.max_fragments_per_node > GRAPH_MAX_FRAGMENTS_TRIGGER
    }
}

/// Scoring weights used by `score`.
#[derive(Clone, Debug)]
pub struct CompactionWeights {
    /// Weight for the WAL-to-segment byte ratio component.
    pub wal_ratio_weight: f32,
    /// Weight for the deletion-density component.
    pub deletion_density_weight: f32,
    /// Minimum WAL bytes before any score is assigned (prevents thrashing on
    /// tiny collections).
    pub min_wal_bytes: u64,
}

/// Immutable segment inputs used by the internal size-tiered merge selector.
/// `position` is stable collection order (oldest to newest).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentTierStats {
    pub(crate) position: usize,
    pub(crate) physical_points: usize,
    pub(crate) live_points: usize,
}

const SIZE_TIER_MIN_FAN_IN: usize = 4;
const SIZE_TIER_MAX_FAN_IN: usize = 8;
const TOMBSTONE_REWRITE_PERCENT: usize = 20;

/// Select one bounded immutable merge without rewriting unrelated tiers.
///
/// Tombstone-heavy segments are vacuumed first. Otherwise the oldest four to
/// eight segments in the smallest populated power-of-two size tier are
/// selected. A fully dead segment is paired with one live anchor because the
/// persisted LS-VEC format does not install empty segments. All other merges
/// stay within one physical-size tier.
pub(crate) fn select_size_tier(segments: &[SegmentTierStats]) -> Vec<usize> {
    if let Some(dead) = segments
        .iter()
        .find(|segment| segment.physical_points > 0 && segment.live_points == 0)
        && let Some(anchor) = segments.iter().find(|segment| segment.live_points > 0)
    {
        // A manifest cannot install an empty LS-VEC segment. Pair one fully
        // dead segment with a single live anchor so compaction can reclaim the
        // dead directory without falling back to a full-corpus rewrite.
        return vec![dead.position, anchor.position];
    }
    if let Some(segment) = segments.iter().find(|segment| {
        segment.live_points > 0
            && segment.physical_points > segment.live_points
            && segment
                .physical_points
                .saturating_sub(segment.live_points)
                .saturating_mul(100)
                >= segment
                    .physical_points
                    .saturating_mul(TOMBSTONE_REWRITE_PERCENT)
    }) {
        return vec![segment.position];
    }

    let mut tiers = std::collections::BTreeMap::<u32, Vec<usize>>::new();
    for segment in segments.iter().filter(|segment| segment.live_points > 0) {
        let tier = usize::BITS - segment.physical_points.max(1).leading_zeros() - 1;
        tiers.entry(tier).or_default().push(segment.position);
    }
    tiers
        .into_values()
        .find(|tier| tier.len() >= SIZE_TIER_MIN_FAN_IN)
        .map(|tier| tier.into_iter().take(SIZE_TIER_MAX_FAN_IN).collect())
        .unwrap_or_default()
}

impl Default for CompactionWeights {
    fn default() -> Self {
        Self {
            wal_ratio_weight: 0.6,
            deletion_density_weight: 0.4,
            min_wal_bytes: 65_536, // 64 KiB
        }
    }
}

/// Returns a score in [0.0, 1.0] for how urgently a collection needs
/// compaction.  Higher is more urgent.
///
/// Score = w_ratio × wal_ratio_score + w_delete × deletion_density_score
///
/// - `wal_ratio_score` = wal_bytes / (wal_bytes + segment_bytes), in [0, 1].
///   Approaches 1.0 when the WAL dominates the segment.
/// - `deletion_density_score` = delete_entries / max(1, total_entries), in [0, 1].
///   Approaches 1.0 when most WAL entries are deletes (stale data to vacuum).
pub fn score(stats: &CollectionCompactionStats, weights: &CompactionWeights) -> f32 {
    if stats.wal_bytes < weights.min_wal_bytes {
        return 0.0;
    }

    let wal_ratio = stats.wal_bytes as f32 / (stats.wal_bytes + stats.segment_bytes).max(1) as f32;

    let deletion_density = stats.wal_delete_count as f32 / stats.wal_entry_count.max(1) as f32;

    (weights.wal_ratio_weight * wal_ratio + weights.deletion_density_weight * deletion_density)
        .clamp(0.0, 1.0)
}

/// Returns collection names sorted by descending compaction score, filtered
/// to those meeting or exceeding `min_score`.
pub fn ranked_candidates(
    all_stats: &[CollectionCompactionStats],
    min_score: f32,
    weights: &CompactionWeights,
) -> Vec<(String, f32)> {
    let mut scored: Vec<(String, f32)> = all_stats
        .iter()
        .map(|s| (s.name.clone(), score(s, weights)))
        .filter(|&(_, s)| s >= min_score)
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(
        wal_bytes: u64,
        segment_bytes: u64,
        entries: usize,
        deletes: usize,
    ) -> CollectionCompactionStats {
        CollectionCompactionStats {
            name: "test".to_string(),
            wal_bytes,
            segment_bytes,
            live_points: 100,
            compacted_point_count: 100,
            wal_entry_count: entries,
            wal_delete_count: deletes,
        }
    }

    #[test]
    fn below_min_wal_scores_zero() {
        let w = CompactionWeights::default();
        assert_eq!(score(&stats(1024, 0, 10, 0), &w), 0.0);
    }

    #[test]
    fn pure_wal_no_segment_scores_high() {
        let w = CompactionWeights::default();
        let s = score(&stats(1_000_000, 0, 100, 0), &w);
        assert!(s > 0.5, "wal-only should score >0.5, got {s}");
    }

    #[test]
    fn high_deletion_density_raises_score() {
        let w = CompactionWeights::default();
        let no_deletes = score(&stats(500_000, 500_000, 100, 0), &w);
        let all_deletes = score(&stats(500_000, 500_000, 100, 100), &w);
        assert!(all_deletes > no_deletes, "high deletes should raise score");
    }

    #[test]
    fn ranked_candidates_sorted_descending() {
        let w = CompactionWeights::default();
        let all = vec![
            stats(500_000, 500_000, 100, 0),
            stats(1_000_000, 100_000, 200, 50),
            stats(100_000, 2_000_000, 10, 0),
        ];
        let named: Vec<CollectionCompactionStats> = all
            .into_iter()
            .enumerate()
            .map(|(i, mut s)| {
                s.name = i.to_string();
                s
            })
            .collect();
        let ranked = ranked_candidates(&named, 0.0, &w);
        for window in ranked.windows(2) {
            assert!(window[0].1 >= window[1].1, "must be sorted descending");
        }
    }

    #[test]
    fn min_score_filter_excludes_below_threshold() {
        let w = CompactionWeights::default();
        let all = vec![
            {
                let mut s = stats(1_000_000, 0, 100, 0);
                s.name = "big".into();
                s
            },
            {
                let mut s = stats(10_000, 0, 5, 0);
                s.name = "tiny".into();
                s
            },
        ];
        let ranked = ranked_candidates(&all, 0.5, &w);
        assert!(ranked.iter().all(|(_, s)| *s >= 0.5));
        assert!(ranked.iter().any(|(n, _)| n == "big"));
    }

    fn graph_stats(
        directed_entries: u64,
        reclaimable_directed_entries: u64,
        p95: u32,
        max: u32,
    ) -> GraphMaintenanceStats {
        GraphMaintenanceStats {
            generation: 7,
            physical_edge_records: 10,
            reclaimable_edge_records: 0,
            directed_entries,
            reclaimable_directed_entries,
            adjacency_bytes: 101,
            estimated_reclaimable_bytes: 21,
            live_nodes: 2,
            mean_fragments_per_node: 1.0,
            p95_fragments_per_node: p95,
            max_fragments_per_node: max,
        }
    }

    #[test]
    fn graph_maintenance_thresholds_are_strict_and_fixed() {
        assert!(!graph_stats(100, 20, 4, 32).requires_compaction());
        assert!(graph_stats(100, 21, 4, 32).requires_compaction());
        assert!(graph_stats(0, 0, 5, 32).requires_compaction());
        assert!(graph_stats(0, 0, 4, 33).requires_compaction());
    }

    #[test]
    fn size_tier_selects_oldest_bounded_fan_in_without_mixing_sizes() {
        let segments = [
            SegmentTierStats {
                position: 0,
                physical_points: 100,
                live_points: 100,
            },
            SegmentTierStats {
                position: 1,
                physical_points: 120,
                live_points: 120,
            },
            SegmentTierStats {
                position: 2,
                physical_points: 127,
                live_points: 127,
            },
            SegmentTierStats {
                position: 3,
                physical_points: 90,
                live_points: 90,
            },
            SegmentTierStats {
                position: 4,
                physical_points: 1024,
                live_points: 1024,
            },
        ];
        assert_eq!(select_size_tier(&segments), [0, 1, 2, 3]);
    }

    #[test]
    fn tombstone_pressure_rewrites_only_the_first_eligible_segment() {
        let segments = [
            SegmentTierStats {
                position: 0,
                physical_points: 100,
                live_points: 79,
            },
            SegmentTierStats {
                position: 1,
                physical_points: 100,
                live_points: 60,
            },
        ];
        assert_eq!(select_size_tier(&segments), [0]);
    }

    #[test]
    fn fully_dead_segment_is_reclaimed_with_one_live_anchor() {
        let segments = [
            SegmentTierStats {
                position: 0,
                physical_points: 100,
                live_points: 100,
            },
            SegmentTierStats {
                position: 1,
                physical_points: 64,
                live_points: 0,
            },
            SegmentTierStats {
                position: 2,
                physical_points: 4096,
                live_points: 4096,
            },
        ];
        assert_eq!(select_size_tier(&segments), [1, 0]);
    }

    #[test]
    fn sparse_tiers_do_not_trigger_a_full_corpus_merge() {
        let segments = (0..6)
            .map(|position| SegmentTierStats {
                position,
                physical_points: 1usize << (position + 4),
                live_points: 1usize << (position + 4),
            })
            .collect::<Vec<_>>();
        assert!(select_size_tier(&segments).is_empty());
    }
}
