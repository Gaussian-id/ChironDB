//! Exact maintenance census over one manifest-pinned graph generation.

use std::collections::{BTreeSet, HashMap};

use roaring::RoaringTreemap;

use super::{GraphGeneration, fragments::FragmentLocation};
use crate::{
    GaussError, Result, compaction::GraphMaintenanceStats, encryption::PersistentFile, graph::Nid,
    graph_group::AdjacencyEdge, graph_resolver::PointIncarnationResolver,
};

impl GraphGeneration {
    pub(crate) fn maintenance_stats(
        &self,
        resolver: &PointIncarnationResolver,
        edge_tombstones: &RoaringTreemap,
    ) -> Result<GraphMaintenanceStats> {
        let mut fragments = resolver
            .live_bindings()
            .map(|(_, nid)| (nid, BTreeSet::new()))
            .collect::<HashMap<Nid, BTreeSet<FragmentLocation>>>();
        let mut census = EdgeCensus::default();
        let mut expected_records = 0_u64;
        let mut expected_directed = 0_u64;
        let mut adjacency_bytes = 0_u64;

        for (index, base) in self.bases.iter().enumerate() {
            adjacency_bytes = checked_add(
                adjacency_bytes,
                u64::try_from(
                    PersistentFile::open(&base.dir.join(crate::graph_edge::EDGE_FILE))?.len(),
                )
                .map_err(|_| overflow("graph adjacency byte count"))?,
                "graph adjacency byte count",
            )?;
            let copies = 1 + u64::from(base.adjacency.has_csc());
            expected_records = checked_add(
                expected_records,
                base.adjacency.edge_count(),
                "graph physical edge count",
            )?;
            expected_directed = checked_add(
                expected_directed,
                checked_add(
                    base.adjacency.edge_count(),
                    base.adjacency.incoming_edge_count(),
                    "graph base directed-entry count",
                )?,
                "graph directed-entry count",
            )?;
            for (group, namespace) in base.adjacency.namespaces().iter().enumerate() {
                for row in 0..namespace.row_count {
                    let nid = base.adjacency.row_nid(&base.nids, group, row)?;
                    if let Some(locations) = fragments.get_mut(&nid) {
                        locations.insert(FragmentLocation::Base(index));
                    }
                    for edge in base.adjacency.edges(&base.nids, group, row, false)? {
                        census.record(edge?, copies, resolver, edge_tombstones)?;
                    }
                }
            }
        }

        for (index, delta) in self.deltas.iter().enumerate() {
            adjacency_bytes = checked_add(
                adjacency_bytes,
                u64::try_from(PersistentFile::open(&delta.path)?.len())
                    .map_err(|_| overflow("graph adjacency byte count"))?,
                "graph adjacency byte count",
            )?;
            expected_records = checked_add(
                expected_records,
                delta.reader.edge_count(),
                "graph physical edge count",
            )?;
            expected_directed = checked_add(
                expected_directed,
                delta
                    .reader
                    .edge_count()
                    .checked_mul(2)
                    .ok_or_else(|| overflow("graph delta directed-entry count"))?,
                "graph directed-entry count",
            )?;
            for (group, namespace) in delta.reader.namespaces().iter().enumerate() {
                for row in 0..namespace.row_count {
                    let nid = delta.reader.row_nid(group, row)?;
                    if let Some(locations) = fragments.get_mut(&nid) {
                        locations.insert(FragmentLocation::Delta(index));
                    }
                    for edge in delta.reader.edges(group, row, false)? {
                        census.record(edge?, 2, resolver, edge_tombstones)?;
                    }
                }
            }
        }

        if census.physical_records != expected_records
            || census.directed_entries != expected_directed
            || census.reclaimable_directed_entries > census.directed_entries
        {
            return Err(GaussError::InvalidRequest(
                "graph maintenance census disagrees with admitted adjacency metadata".into(),
            ));
        }

        let mut fragment_counts = fragments
            .into_values()
            .map(|locations| {
                u32::try_from(locations.len())
                    .map_err(|_| overflow("graph fragments-per-node count"))
            })
            .collect::<Result<Vec<_>>>()?;
        fragment_counts.sort_unstable();
        let live_nodes =
            u64::try_from(fragment_counts.len()).map_err(|_| overflow("graph live-node count"))?;
        let total_fragments = fragment_counts.iter().try_fold(0_u64, |total, count| {
            checked_add(total, u64::from(*count), "graph fragment count")
        })?;
        let mean_fragments_per_node = if live_nodes == 0 {
            0.0
        } else {
            total_fragments as f64 / live_nodes as f64
        };
        let p95_fragments_per_node = if fragment_counts.is_empty() {
            0
        } else {
            let rank = ((fragment_counts.len() as u128) * 95).div_ceil(100) as usize;
            fragment_counts[rank - 1]
        };
        let max_fragments_per_node = fragment_counts.last().copied().unwrap_or(0);
        let estimated_reclaimable_bytes = proportional_bytes(
            adjacency_bytes,
            census.reclaimable_directed_entries,
            census.directed_entries,
        )?;

        Ok(GraphMaintenanceStats {
            generation: self.manifest.generation,
            physical_edge_records: census.physical_records,
            reclaimable_edge_records: census.reclaimable_records,
            directed_entries: census.directed_entries,
            reclaimable_directed_entries: census.reclaimable_directed_entries,
            adjacency_bytes,
            estimated_reclaimable_bytes,
            live_nodes,
            mean_fragments_per_node,
            p95_fragments_per_node,
            max_fragments_per_node,
        })
    }
}

#[derive(Default)]
struct EdgeCensus {
    physical_records: u64,
    reclaimable_records: u64,
    directed_entries: u64,
    reclaimable_directed_entries: u64,
}

impl EdgeCensus {
    fn record(
        &mut self,
        edge: AdjacencyEdge,
        stored_directions: u64,
        resolver: &PointIncarnationResolver,
        tombstones: &RoaringTreemap,
    ) -> Result<()> {
        self.physical_records = checked_add(self.physical_records, 1, "graph physical edge count")?;
        self.directed_entries = checked_add(
            self.directed_entries,
            stored_directions,
            "graph directed-entry count",
        )?;
        let reclaimable = tombstones.contains(edge.edge_id.raw())
            || resolver.live_point_id(edge.source).is_none()
            || resolver.live_point_id(edge.target).is_none();
        if reclaimable {
            self.reclaimable_records =
                checked_add(self.reclaimable_records, 1, "graph reclaimable edge count")?;
            self.reclaimable_directed_entries = checked_add(
                self.reclaimable_directed_entries,
                stored_directions,
                "graph reclaimable directed-entry count",
            )?;
        }
        Ok(())
    }
}

fn proportional_bytes(bytes: u64, selected: u64, total: u64) -> Result<u64> {
    if total == 0 {
        return Ok(0);
    }
    if selected > total {
        return Err(GaussError::InvalidRequest(
            "graph reclaimable entries exceed physical entries".into(),
        ));
    }
    let numerator = u128::from(bytes) * u128::from(selected);
    let denominator = u128::from(total);
    let quotient = numerator / denominator;
    let rounded = quotient + u128::from(numerator % denominator != 0);
    u64::try_from(rounded).map_err(|_| overflow("graph reclaimable byte estimate"))
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right).ok_or_else(|| overflow(label))
}

fn overflow(label: &str) -> GaussError {
    GaussError::InvalidRequest(format!("{label} overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{env, fs, process::Command};

    use crate::graph::Nid;

    const MODE: &str = "CHIRONDB_GRAPH_MAINTENANCE_TEST_MODE";
    const ROOT: &str = "CHIRONDB_GRAPH_MAINTENANCE_TEST_ROOT";
    const TEST: &str = "graph_generation::maintenance::tests::maintenance_census_uses_one_generation_overlay_and_live_resolver";

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(1, counter).unwrap()
    }

    #[test]
    fn maintenance_census_uses_one_generation_overlay_and_live_resolver() {
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = tempfile::tempdir().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, root.path())
                        .status()
                        .unwrap()
                        .success(),
                    "{mode} maintenance child failed"
                );
            }
            return;
        };
        let root = std::path::PathBuf::from(env::var_os(ROOT).unwrap());
        if mode == "encrypted" {
            let keyring = root.join("keyring.json");
            fs::write(
                &keyring,
                serde_json::json!({
                    "version": 1,
                    "active_key_id": "graph-maintenance",
                    "keys": [{
                        "id": "graph-maintenance",
                        "key_base64": STANDARD.encode([71_u8; 32])
                    }]
                })
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(&keyring).unwrap(),
                true,
            )
            .unwrap();
        }

        let (manifest, _) = crate::graph_generation::tests::fixture(&root);
        let generation = GraphGeneration::load_candidate(&root, manifest).unwrap();
        let mut resolver = PointIncarnationResolver::default();
        resolver.bind_live("p0".into(), nid(1)).unwrap();
        resolver.bind_live("p1".into(), nid(2)).unwrap();

        let stats = generation
            .maintenance_stats(&resolver, generation.overlay.edge_tombstones())
            .unwrap();
        assert_eq!(stats.generation, 1);
        assert_eq!(stats.physical_edge_records, 2);
        assert_eq!(stats.reclaimable_edge_records, 1);
        assert_eq!(stats.directed_entries, 4);
        assert_eq!(stats.reclaimable_directed_entries, 2);
        assert_eq!(
            stats.estimated_reclaimable_bytes,
            stats.adjacency_bytes.div_ceil(2)
        );
        assert_eq!(stats.live_nodes, 2);
        assert_eq!(stats.mean_fragments_per_node, 2.0);
        assert_eq!(stats.p95_fragments_per_node, 2);
        assert_eq!(stats.max_fragments_per_node, 2);
        assert!(stats.requires_compaction());

        let clean = generation
            .maintenance_stats(&resolver, &RoaringTreemap::new())
            .unwrap();
        assert_eq!(clean.reclaimable_edge_records, 0);
        assert!(!clean.requires_compaction());

        resolver.retire("p0");
        let retired = generation
            .maintenance_stats(&resolver, &RoaringTreemap::new())
            .unwrap();
        assert_eq!(retired.reclaimable_edge_records, 2);
        assert_eq!(retired.live_nodes, 1);
        assert_eq!(retired.p95_fragments_per_node, 2);
        assert!(retired.requires_compaction());
    }
}
