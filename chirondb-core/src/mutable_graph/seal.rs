//! Frozen graph authority for the production vector sealer. Changes are kept
//! until manifest commit, and a tail mutation at the cut is never acknowledged.

use std::{fs, path::Path};

use super::*;
use crate::{
    checkpoint::{
        FragmentDirectoryManifest, GraphManifest, GraphRunDescriptor, GraphRunManifest,
        SegmentsManifest,
    },
    encryption::PersistentFile,
    graph_edge::{
        self, BaseAdjacency, BaseEdgeInput, BaseGroupInput, BaseNeighborInput, BaseRowInput,
    },
    graph_edgeid::{self, EdgeLedgerRun, EdgeLedgerRunKind, EdgeLedgerRunMetadata},
    graph_edgeprop::{self, EdgePropertyInput, EdgePropertyTable},
    graph_generation::{ArtifactFamily, artifact_path},
    graph_nid::{self, NidIndex},
    graph_tdelta::{self, DeltaEdgeInput, DeltaGroupInput, TopologyDelta},
};

#[derive(Clone, Debug, Default)]
pub(super) struct PersistChanges {
    pub(super) ledger: BTreeMap<EdgeId, u64>,
    pub(super) topology: BTreeMap<EdgeId, u64>,
    pub(super) properties: BTreeMap<EdgeId, u64>,
}

impl MutableGraphState {
    /// Called by both live GraphBatch apply and ordered WAL replay, before apply.
    pub(crate) fn track_persist_changes(
        &mut self,
        record_lsn: u64,
        mutations: &[EdgeMutation],
        deferred: &DeferredMutationPlan,
    ) {
        for mutation in mutations {
            match mutation {
                EdgeMutation::Relate(edge) => {
                    if !self.pending_edges.contains_key(&edge.edge_id) {
                        self.persist_changes.ledger.insert(edge.edge_id, record_lsn);
                    }
                    self.persist_changes
                        .topology
                        .insert(edge.edge_id, record_lsn);
                    self.persist_changes
                        .properties
                        .insert(edge.edge_id, record_lsn);
                }
                EdgeMutation::Properties(edge) => {
                    self.persist_changes
                        .properties
                        .insert(edge.edge_id, record_lsn);
                }
                EdgeMutation::Unrelate(_) => {} // Exact visibility belongs to the cut overlay.
            }
        }
        for edge_id in &deferred.created_edge_ids {
            self.persist_changes.ledger.insert(*edge_id, record_lsn);
        }
    }

    pub(crate) fn acknowledge_seal(&mut self, epoch: GraphEpoch, cut: u64) {
        if self.epoch == epoch {
            self.persist_changes.ledger.retain(|_, lsn| *lsn >= cut);
            self.persist_changes.topology.retain(|_, lsn| *lsn >= cut);
            self.persist_changes.properties.retain(|_, lsn| *lsn >= cut);
        }
    }
}

pub(crate) struct GraphSealSnapshot {
    pub(crate) expected: Option<SegmentsManifest>,
    pub(crate) epoch: GraphEpoch,
    pub(crate) generation: u64,
    cut: u64,
    control: recovery::GraphRecoveryControl,
    topology: Vec<MutableEdge>,
    properties: Vec<EdgePropertyInput>,
    ledger: Vec<EdgeId>,
    first_lsn: u64,
    previous: Option<GraphManifest>,
    segments: Vec<String>,
    overlay_version: u64,
}

impl GraphSealSnapshot {
    /// Caller owns the collection lock and has synced the WAL and live overlay.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        directory: &Path,
        collection: &str,
        cut: u64,
        lifecycle: crate::graph_lifecycle::GraphLifecycleState,
        resolver: &PointIncarnationResolver,
        graph: Option<&MutableGraphState>,
        segments: Vec<String>,
        overlays: &mut crate::overlay::OverlayStore,
    ) -> Result<Self> {
        let epoch = lifecycle
            .epoch()
            .ok_or_else(|| invalid("graph seal requires lifecycle history"))?;
        let empty_graph = MutableGraphState::new(epoch);
        let graph = match (lifecycle.is_enabled(), graph) {
            (true, Some(graph)) if graph.epoch == epoch => graph,
            (false, None) => &empty_graph,
            _ => return Err(invalid("mutable graph disagrees with lifecycle")),
        };
        let expected = crate::checkpoint::read_segments_manifest(directory)?;
        if expected.as_ref().map_or(&[][..], |m| m.segments.as_slice()) != segments {
            return Err(invalid(
                "live vector segments disagree with publication manifest",
            ));
        }
        let generation = expected
            .as_ref()
            .map_or(0, |m| m.generation)
            .checked_add(1)
            .ok_or_else(|| invalid("generation overflow"))?;
        let previous = expected
            .as_ref()
            .and_then(|m| m.graph.as_ref())
            .filter(|g| g.epoch == graph.epoch)
            .cloned();
        let first_lsn = previous.as_ref().map_or(0, |g| g.graph_batch_watermark);
        if cut <= first_lsn {
            return Err(invalid("seal cut must advance beyond the installed prefix"));
        }
        let control = recovery::GraphRecoveryControl::capture(
            collection,
            cut,
            resolver,
            graph,
            lifecycle.is_enabled(),
        )?;
        let topology = if previous.is_some() {
            graph
                .persist_changes
                .topology
                .keys()
                .map(|id| graph.hydrate_stored_edge(&graph.edges[id]))
                .collect::<Result<Vec<_>>>()?
        } else {
            graph
                .edges
                .values()
                .map(|edge| graph.hydrate_stored_edge(edge))
                .collect::<Result<Vec<_>>>()?
        };
        let property_ids: Vec<_> = if previous.is_some() {
            graph
                .persist_changes
                .properties
                .keys()
                .copied()
                .collect::<Vec<_>>()
        } else {
            graph.property_tail.keys().copied().collect()
        };
        let properties = property_ids
            .into_iter()
            .map(|edge_id| {
                Ok(EdgePropertyInput {
                    edge_id,
                    properties: graph
                        .stored_properties(edge_id)?
                        .as_object()
                        .expect("validated property document")
                        .clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let ledger = if previous.is_some() {
            graph.persist_changes.ledger.keys().copied().collect()
        } else {
            graph.edge_ids.iter().map(EdgeId::from_raw).collect()
        };
        let mut points = overlays.current().point_tombstones().clone();
        points.insert_bitmap(segment_id(cut), roaring::RoaringBitmap::new());
        let overlay_version = overlays.stage_cut(generation, points)?.version();
        Ok(Self {
            expected,
            epoch: graph.epoch,
            generation,
            cut,
            control,
            topology,
            properties,
            ledger,
            first_lsn,
            previous,
            segments,
            overlay_version,
        })
    }

    /// Write mandatory peers before promoting the unpublished vector marker.
    /// An incompletely backfilled buffer remains a legacy vector base; sparse
    /// catalog bindings and the global delta preserve assigned identities.
    pub(crate) fn write_base(&self, dir: &Path) -> Result<bool> {
        if !self.control.is_enabled() {
            return Ok(false);
        }
        let vectors = crate::seal::V4Store::open(dir)?;
        let Some(nids) = vectors
            .ids()
            .iter()
            .map(|id| self.control.live_nid(id))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(false);
        };
        let nids = NidIndex::build(nids, true)?;
        let mut groups: HashMap<GraphNamespace, BTreeMap<u32, BaseRowInput>> = HashMap::new();
        let mut properties = Vec::new();
        for edge in &self.topology {
            let (Some(source), Some(target)) = (nids.lookup(edge.source), nids.lookup(edge.target))
            else {
                continue;
            };
            let rows = groups.entry(edge.namespace.clone()).or_default();
            rows.entry(source)
                .or_insert_with(|| row(source))
                .outgoing
                .push(base_edge(edge, target));
            rows.entry(target)
                .or_insert_with(|| row(target))
                .incoming
                .push(base_edge(edge, source));
            properties.push(property(edge));
        }
        let adjacency = BaseAdjacency::build_with_options(
            &nids,
            groups
                .into_iter()
                .map(|(namespace, rows)| BaseGroupInput {
                    namespace,
                    rows: rows.into_values().collect(),
                })
                .collect(),
            true,
            false,
        )?;
        graph_nid::write(&dir.join(graph_nid::NID_FILE), &nids)?;
        graph_edge::write(&dir.join(graph_edge::EDGE_FILE), &adjacency)?;
        graph_edgeprop::write(
            &dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
            &EdgePropertyTable::build(properties)?,
        )?;
        crate::seal::graph::seal_candidate(dir)?;
        Ok(true)
    }

    /// Build the remaining immutable runs after the vector directory is durable.
    pub(crate) fn write_manifest(
        &self,
        collection: &Path,
        graph_base: bool,
    ) -> Result<SegmentsManifest> {
        let id = format!("g{}-l{}", self.generation, self.cut);
        let last_lsn = self.cut - 1; // WAL records carry frame START; cut is the next frame.
        let segment = segment_id(self.cut);
        let nids = if graph_base {
            Some(graph_nid::open(
                &collection
                    .join("searchers")
                    .join(&segment)
                    .join(graph_nid::NID_FILE),
            )?)
        } else {
            None
        };
        let mut deltas: HashMap<GraphNamespace, Vec<DeltaEdgeInput>> = HashMap::new();
        for edge in &self.topology {
            if nids
                .as_ref()
                .is_some_and(|n| n.lookup(edge.source).is_some() && n.lookup(edge.target).is_some())
            {
                continue;
            }
            deltas
                .entry(edge.namespace.clone())
                .or_default()
                .push(DeltaEdgeInput {
                    source_nid: edge.source,
                    target_nid: edge.target,
                    edge_id: edge.edge_id,
                    type_id: edge.type_id,
                });
        }
        let mut topology_deltas = self
            .previous
            .as_ref()
            .map_or_else(Vec::new, |g| g.topology_deltas.clone());
        let mut topology_parts = 0;
        if !deltas.is_empty() {
            TopologyDelta::build_partitioned(
                self.first_lsn,
                deltas
                    .into_iter()
                    .map(|(namespace, edges)| DeltaGroupInput { namespace, edges })
                    .collect(),
                |delta| {
                    let part_id = format!("{id}-p{topology_parts:016x}");
                    let path = prepare_path(collection, ArtifactFamily::Topology, &part_id)?;
                    graph_tdelta::write(&path, &delta)?;
                    topology_deltas.push(descriptor(&path, &part_id, self.first_lsn, last_lsn)?);
                    topology_parts += 1;
                    Ok(())
                },
            )?;
        }
        let edge_ledger = if let Some(previous) = &self.previous {
            let mut ledger = previous.edge_ledger.clone();
            if !self.ledger.is_empty() {
                ledger.runs.push(self.write_ledger(
                    collection,
                    &id,
                    EdgeLedgerRunKind::Delta,
                    last_lsn,
                )?);
            }
            ledger
        } else {
            GraphRunManifest {
                base: self.write_ledger(collection, &id, EdgeLedgerRunKind::Base, last_lsn)?,
                runs: Vec::new(),
            }
        };
        let edge_properties = if let Some(previous) = &self.previous {
            let mut properties = previous.edge_properties.clone();
            if !self.properties.is_empty() {
                properties
                    .runs
                    .push(self.write_properties(collection, &id, last_lsn)?);
            }
            properties
        } else {
            GraphRunManifest {
                base: self.write_properties(collection, &id, last_lsn)?,
                runs: Vec::new(),
            }
        };
        let recovery_path = prepare_path(collection, ArtifactFamily::Recovery, &id)?;
        self.control.write(&recovery_path)?;
        let mut base_segments = self
            .previous
            .as_ref()
            .map_or_else(Vec::new, |g| g.base_segments.clone());
        if graph_base {
            base_segments.push(segment.clone());
        }
        let mut segments = self.segments.clone();
        segments.push(segment);
        let catalog_overlay_generation =
            (base_segments.len() != segments.len()).then_some(self.generation);
        let mut manifest = SegmentsManifest {
            generation: self.generation,
            segments,
            graph: Some(GraphManifest {
                // Never downgrade after a cohort upgrade, including disabled
                // or newly enabled epochs where `previous` is intentionally None.
                version: self
                    .expected
                    .as_ref()
                    .and_then(|m| m.graph.as_ref())
                    .map_or(2, |g| g.version.max(2))
                    .max(if topology_parts > 1 { 3 } else { 2 }),
                epoch: self.epoch,
                graph_batch_watermark: self.cut,
                overlay_version: self.overlay_version,
                base_segments,
                topology_deltas,
                edge_ledger,
                edge_properties,
                fragment_directory: FragmentDirectoryManifest::Absent,
                fragment_catalog: None,
                recovery: Some(descriptor(&recovery_path, &id, 0, self.cut)?),
                catalog_overlay_generation,
                sketch: None,
            }),
        };
        crate::graph_generation::fragments::build_directory(
            collection,
            self.expected.as_ref(),
            &mut manifest,
        )?;
        Ok(manifest)
    }

    fn write_ledger(
        &self,
        collection: &Path,
        id: &str,
        kind: EdgeLedgerRunKind,
        last_lsn: u64,
    ) -> Result<GraphRunDescriptor> {
        let path = prepare_path(collection, ArtifactFamily::Ledger, id)?;
        graph_edgeid::write(
            &path,
            &EdgeLedgerRun::build(
                EdgeLedgerRunMetadata {
                    graph_epoch: self.epoch,
                    first_lsn: self.first_lsn,
                    last_lsn,
                    kind,
                },
                self.ledger.clone(),
            )?,
        )?;
        descriptor(&path, id, self.first_lsn, last_lsn)
    }

    fn write_properties(
        &self,
        collection: &Path,
        id: &str,
        last_lsn: u64,
    ) -> Result<GraphRunDescriptor> {
        let path = prepare_path(collection, ArtifactFamily::Properties, id)?;
        graph_edgeprop::write(&path, &EdgePropertyTable::build(self.properties.clone())?)?;
        descriptor(&path, id, self.first_lsn, last_lsn)
    }
}

fn segment_id(cut: u64) -> String {
    format!("sg-v6-{cut:020}")
}

fn property(edge: &MutableEdge) -> EdgePropertyInput {
    EdgePropertyInput {
        edge_id: edge.edge_id,
        properties: edge
            .properties
            .as_object()
            .expect("validated properties")
            .clone(),
    }
}

fn row(node_ordinal: u32) -> BaseRowInput {
    BaseRowInput {
        node_ordinal,
        outgoing: Vec::new(),
        incoming: Vec::new(),
    }
}

fn base_edge(edge: &MutableEdge, neighbor: u32) -> BaseEdgeInput {
    BaseEdgeInput {
        neighbor: BaseNeighborInput::LocalOrdinal(neighbor),
        edge_id: edge.edge_id,
        type_id: edge.type_id,
        weight: None,
    }
}

fn prepare_path(collection: &Path, family: ArtifactFamily, id: &str) -> Result<std::path::PathBuf> {
    let path = artifact_path(collection, family, id)?;
    fs::create_dir_all(path.parent().expect("artifact parent"))?;
    Ok(path)
}

fn descriptor(path: &Path, id: &str, first_lsn: u64, last_lsn: u64) -> Result<GraphRunDescriptor> {
    let file = PersistentFile::open(path)?;
    Ok(GraphRunDescriptor {
        id: id.into(),
        first_lsn,
        last_lsn,
        crc32: file.crc32(0..file.len())?,
    })
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph seal: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_cut_acknowledges_only_its_epoch_and_exclusive_prefix() {
        let mut graph = MutableGraphState::new(GraphEpoch::INITIAL);
        let before = EdgeId::from_parts(1, 1).unwrap();
        let at_cut = EdgeId::from_parts(1, 2).unwrap();
        let after = EdgeId::from_parts(1, 3).unwrap();
        for changes in [
            &mut graph.persist_changes.ledger,
            &mut graph.persist_changes.topology,
            &mut graph.persist_changes.properties,
        ] {
            changes.extend([(before, 99), (at_cut, 100), (after, 101)]);
        }
        // A newer property mutation replaces the dirty LSN; publishing an old
        // snapshot must not clear the new materialized value's dirty marker.
        graph.persist_changes.properties.insert(before, 102);
        graph.acknowledge_seal(GraphEpoch::from_raw(2).unwrap(), 100);
        assert_eq!(graph.persist_changes.ledger.len(), 3);
        graph.acknowledge_seal(GraphEpoch::INITIAL, 100);
        assert_eq!(
            graph.persist_changes.ledger,
            [(at_cut, 100), (after, 101)].into()
        );
        assert_eq!(graph.persist_changes.topology, graph.persist_changes.ledger);
        assert_eq!(graph.persist_changes.properties.len(), 3);
        graph.acknowledge_seal(GraphEpoch::INITIAL, 103);
        assert!(graph.persist_changes.ledger.is_empty());
        assert!(graph.persist_changes.topology.is_empty());
        assert!(graph.persist_changes.properties.is_empty());
    }
}
