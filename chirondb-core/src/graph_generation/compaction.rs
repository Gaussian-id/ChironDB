//! Frozen graph-compaction input, degree-ordered BFS locality, and bounded
//! external topology merge. This module prepares immutable work only; D3c
//! owns artifact emission and the single-manifest publication boundary.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::Path,
    sync::Arc,
};

use crate::{
    GaussError, Result,
    checkpoint::{
        FragmentDirectoryManifest, GraphManifest, GraphRunDescriptor, GraphRunManifest,
        SegmentsManifest,
    },
    encryption::PersistentFile,
    graph::{EdgeId, GraphEpoch, GraphNamespace, Nid, TypeId},
    graph_edge::{
        self, BaseAdjacency, BaseEdgeInput, BaseGroupInput, BaseNeighborInput, BaseRowInput,
    },
    graph_edgeid::{self, EdgeLedgerRun, EdgeLedgerRunKind, EdgeLedgerRunMetadata},
    graph_edgeprop::{self, EdgePropertyInput, EdgePropertyTable},
    graph_group::AdjacencyEdge,
    graph_nid::{self, NidIndex},
    graph_resolver::PointIncarnationResolver,
    mutable_graph::{
        MutableGraphState,
        recovery::{GraphRecoveryControl, topology::TopologySort},
    },
    overlay::OverlaySet,
};

use super::{ArtifactFamily, GraphGeneration, artifact_path, compaction_sort::*};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactionNode {
    pub(crate) point_id: String,
    pub(crate) nid: Nid,
    pub(crate) ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CompactionEdge {
    pub(crate) namespace_code: u32,
    pub(crate) source_ordinal: u32,
    pub(crate) type_id: TypeId,
    pub(crate) target_ordinal: u32,
    pub(crate) edge_id: EdgeId,
    pub(crate) source_nid: Nid,
    pub(crate) target_nid: Nid,
}

impl SortRow for CompactionEdge {
    const WIDTH: usize = 40;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.namespace_code.to_le_bytes());
        output.extend_from_slice(&self.source_ordinal.to_le_bytes());
        output.extend_from_slice(&self.type_id.raw().to_le_bytes());
        output.extend_from_slice(&self.target_ordinal.to_le_bytes());
        output.extend_from_slice(&self.edge_id.raw().to_le_bytes());
        output.extend_from_slice(&self.source_nid.raw().to_le_bytes());
        output.extend_from_slice(&self.target_nid.raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::WIDTH {
            return Err(invalid("compaction edge scratch row has the wrong width"));
        }
        let type_id = TypeId::from_raw(read_u32(bytes, 8));
        let edge_id = EdgeId::from_raw(read_u64(bytes, 16));
        let source_nid = Nid::from_raw(read_u64(bytes, 24));
        let target_nid = Nid::from_raw(read_u64(bytes, 32));
        validate_edge_id(edge_id)?;
        validate_nid(source_nid)?;
        validate_nid(target_nid)?;
        if type_id.raw() == 0 {
            return Err(invalid("compaction scratch contains TypeId=0"));
        }
        Ok(Self {
            namespace_code: read_u32(bytes, 0),
            source_ordinal: read_u32(bytes, 4),
            type_id,
            target_ordinal: read_u32(bytes, 12),
            edge_id,
            source_nid,
            target_nid,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IncidentRecord {
    node: Nid,
    neighbor: Nid,
}

impl SortRow for IncidentRecord {
    const WIDTH: usize = 16;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.node.raw().to_le_bytes());
        output.extend_from_slice(&self.neighbor.raw().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::WIDTH {
            return Err(invalid("incident scratch row has the wrong width"));
        }
        let node = Nid::from_raw(read_u64(bytes, 0));
        let neighbor = Nid::from_raw(read_u64(bytes, 8));
        validate_nid(node)?;
        validate_nid(neighbor)?;
        Ok(Self { node, neighbor })
    }
}

pub(crate) struct GraphCompactionPlan {
    pub(crate) source_generation: Arc<GraphGeneration>,
    pub(crate) resolver: PointIncarnationResolver,
    pub(crate) overlay: Arc<OverlaySet>,
    pub(crate) mutable: Option<MutableGraphState>,
    pub(crate) graph_epoch: GraphEpoch,
    pub(crate) graph_batch_watermark: u64,
    pub(crate) nodes: Vec<CompactionNode>,
    pub(crate) location_map: NidIndex,
    pub(crate) source_edge_records: u64,
    pub(crate) live_edge_records: u64,
    pub(crate) dropped_edge_records: u64,
    pub(crate) incident_sort: SortStats,
    pub(crate) edge_sort: SortStats,
    namespaces: Vec<GraphNamespace>,
    edges: SortedRun<CompactionEdge>,
}

pub(crate) struct CompactedGraphArtifacts {
    edge_ids: HashSet<EdgeId>,
    properties: Vec<EdgePropertyInput>,
}

impl CompactedGraphArtifacts {
    pub(crate) fn empty() -> Self {
        Self {
            edge_ids: HashSet::new(),
            properties: Vec::new(),
        }
    }
}

impl GraphCompactionPlan {
    pub(crate) fn prepare(
        generation: Arc<GraphGeneration>,
        resolver: PointIncarnationResolver,
        overlay: Arc<OverlaySet>,
        mutable: Option<MutableGraphState>,
        enabled: bool,
    ) -> Result<Self> {
        let graph = generation
            .manifest
            .graph
            .as_ref()
            .ok_or_else(|| invalid("compaction requires a graph manifest"))?;
        let graph_epoch = graph.epoch;
        let graph_batch_watermark = graph.graph_batch_watermark;
        if overlay.generation() != generation.manifest.generation
            || generation.overlay.generation() != generation.manifest.generation
            || overlay.version() < graph.overlay_version
        {
            return Err(invalid(
                "compaction generation and visibility snapshot disagree",
            ));
        }
        match (enabled, mutable.as_ref()) {
            (true, Some(state)) if state.epoch() == graph_epoch => {
                if state.edge_tombstones() != overlay.edge_tombstones() {
                    return Err(invalid(
                        "compaction mutable and overlay edge visibility disagree",
                    ));
                }
            }
            (false, None) => {}
            _ => return Err(invalid("compaction mutable state disagrees with lifecycle")),
        }

        let tail = mutable
            .as_ref()
            .into_iter()
            .flat_map(MutableGraphState::compaction_topology)
            .collect::<Vec<_>>();
        let mut incident_sort = ExternalSort::<IncidentRecord>::new()?;
        let mut namespace_set = HashSet::new();
        let mut source_edge_records = 0_u64;
        let mut live_edge_records = 0_u64;
        let mut dropped_edge_records = 0_u64;
        visit_unique_topology(&generation, &tail, |namespace, edge| {
            source_edge_records = checked_add(source_edge_records, 1, "source edge count")?;
            if edge_is_live(edge, &resolver, &overlay) {
                live_edge_records = checked_add(live_edge_records, 1, "live edge count")?;
                namespace_set.insert(namespace.clone());
                incident_sort.push(IncidentRecord {
                    node: edge.source,
                    neighbor: edge.target,
                })?;
                incident_sort.push(IncidentRecord {
                    node: edge.target,
                    neighbor: edge.source,
                })?;
            } else {
                dropped_edge_records = checked_add(dropped_edge_records, 1, "dropped edge count")?;
            }
            Ok(())
        })?;
        if checked_add(
            live_edge_records,
            dropped_edge_records,
            "classified edge count",
        )? != source_edge_records
        {
            return Err(invalid("compaction edge classification is incomplete"));
        }

        let (incident_run, incident_stats) = incident_sort.finish()?;
        let mut incident = IncidentIndex::build(incident_run)?;
        let nodes = degree_bfs_order(&resolver, &mut incident)?;
        drop(incident);
        let location_map =
            NidIndex::build(nodes.iter().map(|node| node.nid).collect::<Vec<_>>(), true)?;

        let mut namespaces = namespace_set.into_iter().collect::<Vec<_>>();
        namespaces.sort_unstable_by(compare_namespaces);
        let namespace_codes = namespaces
            .iter()
            .enumerate()
            .map(|(index, namespace)| {
                u32::try_from(index)
                    .map(|code| (namespace.clone(), code))
                    .map_err(|_| invalid("compaction namespace count exceeds u32"))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let mut edge_sort = ExternalSort::<CompactionEdge>::new()?;
        let mut second_source_count = 0_u64;
        let mut second_live_count = 0_u64;
        visit_unique_topology(&generation, &tail, |namespace, edge| {
            second_source_count = checked_add(second_source_count, 1, "second source edge count")?;
            if !edge_is_live(edge, &resolver, &overlay) {
                return Ok(());
            }
            second_live_count = checked_add(second_live_count, 1, "second live edge count")?;
            let namespace_code = *namespace_codes
                .get(namespace)
                .ok_or_else(|| invalid("live edge namespace disappeared between passes"))?;
            let source_ordinal = location_map
                .lookup(edge.source)
                .ok_or_else(|| invalid("live source Nid has no compaction location"))?;
            let target_ordinal = location_map
                .lookup(edge.target)
                .ok_or_else(|| invalid("live target Nid has no compaction location"))?;
            edge_sort.push(CompactionEdge {
                namespace_code,
                source_ordinal,
                type_id: edge.type_id,
                target_ordinal,
                edge_id: edge.edge_id,
                source_nid: edge.source,
                target_nid: edge.target,
            })
        })?;
        if second_source_count != source_edge_records || second_live_count != live_edge_records {
            return Err(invalid(
                "compaction topology changed between frozen merge passes",
            ));
        }
        let (edges, edge_stats) = edge_sort.finish()?;
        if edges.rows() != live_edge_records {
            return Err(invalid(
                "compaction sorted edge count disagrees with frozen topology",
            ));
        }

        Ok(Self {
            source_generation: generation,
            resolver,
            overlay,
            mutable,
            graph_epoch,
            graph_batch_watermark,
            nodes,
            location_map,
            source_edge_records,
            live_edge_records,
            dropped_edge_records,
            incident_sort: incident_stats,
            edge_sort: edge_stats,
            namespaces,
            edges,
        })
    }

    pub(crate) fn namespaces(&self) -> &[GraphNamespace] {
        &self.namespaces
    }

    pub(crate) fn visit_edges(
        &mut self,
        mut visit: impl FnMut(&GraphNamespace, CompactionEdge) -> Result<()>,
    ) -> Result<()> {
        let namespaces = &self.namespaces;
        self.edges.visit_all(|edge| {
            let namespace = namespaces
                .get(edge.namespace_code as usize)
                .ok_or_else(|| invalid("compaction edge has an unknown namespace code"))?;
            visit(namespace, edge)
        })
    }

    /// Emit one fully local CSR+CSC base in exactly the vector ordinal order
    /// selected by pass 1. Stable EdgeIds and TypeIds are duplicated in both
    /// directions by the checked base builder; long rows use its authenticated
    /// overflow chunks.
    pub(crate) fn emit_segment_graph(
        &mut self,
        candidate_dir: &Path,
    ) -> Result<CompactedGraphArtifacts> {
        let mut groups = HashMap::<GraphNamespace, BTreeMap<u32, BaseRowInput>>::new();
        let mut edge_ids = HashSet::new();
        let mut properties = Vec::new();
        let mutable = self.mutable.clone();
        let source_generation = Arc::clone(&self.source_generation);
        self.visit_edges(|namespace, edge| {
            if !edge_ids.insert(edge.edge_id) {
                return Err(invalid("compaction emitted a duplicate EdgeId"));
            }
            let rows = groups.entry(namespace.clone()).or_default();
            rows.entry(edge.source_ordinal)
                .or_insert_with(|| empty_row(edge.source_ordinal))
                .outgoing
                .push(local_edge(edge.target_ordinal, edge.edge_id, edge.type_id));
            rows.entry(edge.target_ordinal)
                .or_insert_with(|| empty_row(edge.target_ordinal))
                .incoming
                .push(local_edge(edge.source_ordinal, edge.edge_id, edge.type_id));
            let document = if let Some(mutable) = &mutable {
                mutable
                    .edge_properties(edge.edge_id)?
                    .map(|value| value.into_owned())
                    .ok_or_else(|| invalid("live edge has no mutable property authority"))?
            } else {
                serde_json::Value::Object(
                    source_generation
                        .edge_properties(edge.edge_id)?
                        .ok_or_else(|| invalid("live edge has no sealed property authority"))?,
                )
            };
            properties.push(EdgePropertyInput {
                edge_id: edge.edge_id,
                properties: document
                    .as_object()
                    .ok_or_else(|| invalid("edge property document is not an object"))?
                    .clone(),
            });
            Ok(())
        })?;
        if let Some(mutable) = &self.mutable {
            edge_ids.extend(mutable.compaction_pending_edge_ids());
        }
        let adjacency = BaseAdjacency::build_with_options(
            &self.location_map,
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
        graph_nid::write(&candidate_dir.join(graph_nid::NID_FILE), &self.location_map)?;
        graph_edge::write(&candidate_dir.join(graph_edge::EDGE_FILE), &adjacency)?;
        graph_edgeprop::write(
            &candidate_dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
            &EdgePropertyTable::build(properties.clone())?,
        )?;
        crate::seal::graph::seal_candidate(candidate_dir)?;
        Ok(CompactedGraphArtifacts {
            edge_ids,
            properties,
        })
    }

    /// Rebuild every collection-root graph artifact and return the sole
    /// vector+graph manifest candidate. The replacement overlay is empty at
    /// the cut because deleted rows and retired endpoint incarnations were
    /// removed physically.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_replacement_manifest(
        &self,
        collection: &Path,
        collection_name: &str,
        segment_id: &str,
        generation: u64,
        cut: u64,
        overlay_version: u64,
        enabled: bool,
        artifacts: &CompactedGraphArtifacts,
    ) -> Result<SegmentsManifest> {
        let last_lsn = cut
            .checked_sub(1)
            .ok_or_else(|| invalid("compaction cut cannot be zero"))?;
        let id = format!("g{generation}-l{cut}-compact");
        let graph_state;
        let graph = if let Some(graph) = self.mutable.as_ref() {
            graph
        } else {
            graph_state = MutableGraphState::new(self.graph_epoch);
            &graph_state
        };
        let control = GraphRecoveryControl::capture_compacted(
            collection_name,
            cut,
            &self.resolver,
            graph,
            enabled,
            self.live_edge_records,
            &artifacts.edge_ids,
        )?;

        let ledger_path = prepare_path(collection, ArtifactFamily::Ledger, &id)?;
        graph_edgeid::write(
            &ledger_path,
            &EdgeLedgerRun::build(
                EdgeLedgerRunMetadata {
                    graph_epoch: self.graph_epoch,
                    first_lsn: 0,
                    last_lsn,
                    kind: EdgeLedgerRunKind::Base,
                },
                artifacts.edge_ids.iter().copied().collect(),
            )?,
        )?;
        let properties_path = prepare_path(collection, ArtifactFamily::Properties, &id)?;
        graph_edgeprop::write(
            &properties_path,
            &EdgePropertyTable::build(artifacts.properties.clone())?,
        )?;
        let recovery_path = prepare_path(collection, ArtifactFamily::Recovery, &id)?;
        control.write(&recovery_path)?;

        let expected = self.source_generation.manifest.as_ref();
        let prior_version = expected
            .graph
            .as_ref()
            .map_or(2, |graph| graph.version.max(2));
        let mut manifest = SegmentsManifest {
            generation,
            segments: vec![segment_id.to_owned()],
            graph: Some(GraphManifest {
                version: prior_version,
                epoch: self.graph_epoch,
                graph_batch_watermark: cut,
                overlay_version,
                base_segments: enabled.then(|| segment_id.to_owned()).into_iter().collect(),
                topology_deltas: Vec::new(),
                edge_ledger: GraphRunManifest {
                    base: descriptor(&ledger_path, &id, 0, last_lsn)?,
                    runs: Vec::new(),
                },
                edge_properties: GraphRunManifest {
                    base: descriptor(&properties_path, &id, 0, last_lsn)?,
                    runs: Vec::new(),
                },
                fragment_directory: FragmentDirectoryManifest::Absent,
                fragment_catalog: None,
                recovery: Some(descriptor(&recovery_path, &id, 0, cut)?),
                catalog_overlay_generation: (!enabled).then_some(generation),
                sketch: None,
            }),
        };
        super::fragments::build_directory(collection, Some(expected), &mut manifest)?;
        Ok(manifest)
    }

    #[cfg(test)]
    pub(crate) fn scratch_is_encrypted(&mut self) -> Result<bool> {
        self.edges.first_frame_is_encrypted()
    }
}

struct IncidentIndex {
    run: SortedRun<IncidentRecord>,
    ranges: HashMap<Nid, std::ops::Range<u64>>,
}

impl IncidentIndex {
    fn build(mut run: SortedRun<IncidentRecord>) -> Result<Self> {
        let mut ranges = HashMap::<Nid, std::ops::Range<u64>>::new();
        let mut position = 0_u64;
        run.visit_all(|row| {
            let range = ranges.entry(row.node).or_insert(position..position);
            if range.end != position {
                return Err(invalid(
                    "incident scratch rows for one Nid are not contiguous",
                ));
            }
            position = position
                .checked_add(1)
                .ok_or_else(|| invalid("incident row position overflow"))?;
            range.end = position;
            Ok(())
        })?;
        if position != run.rows() {
            return Err(invalid("incident index row count mismatch"));
        }
        Ok(Self { run, ranges })
    }

    fn degree(&self, nid: Nid) -> u64 {
        self.ranges
            .get(&nid)
            .map_or(0, |range| range.end - range.start)
    }

    fn neighbors(&mut self, nid: Nid) -> Result<Vec<Nid>> {
        let Some(range) = self.ranges.get(&nid).cloned() else {
            return Ok(Vec::new());
        };
        let mut neighbors = Vec::with_capacity(
            usize::try_from(range.end - range.start)
                .map_err(|_| invalid("incident degree exceeds usize"))?,
        );
        self.run.visit_range(range.start, range.end, |row| {
            if row.node != nid {
                return Err(invalid("incident index range crosses a Nid boundary"));
            }
            neighbors.push(row.neighbor);
            Ok(())
        })?;
        Ok(neighbors)
    }
}

fn degree_bfs_order(
    resolver: &PointIncarnationResolver,
    incident: &mut IncidentIndex,
) -> Result<Vec<CompactionNode>> {
    let point_by_nid = resolver
        .live_bindings()
        .map(|(point_id, nid)| (nid, point_id.to_owned()))
        .collect::<HashMap<_, _>>();
    if point_by_nid.len() != resolver.live_len() {
        return Err(invalid("resolver has duplicate live Nid bindings"));
    }
    if point_by_nid.len() > u32::MAX as usize {
        return Err(invalid("compaction live-node count exceeds u32 format cap"));
    }
    let mut seeds = point_by_nid.keys().copied().collect::<Vec<_>>();
    seeds.sort_unstable_by(|left, right| {
        incident
            .degree(*right)
            .cmp(&incident.degree(*left))
            .then_with(|| left.cmp(right))
    });
    let mut visited = HashSet::with_capacity(seeds.len());
    let mut queue = VecDeque::new();
    let mut nodes = Vec::with_capacity(seeds.len());
    for seed in seeds {
        if !visited.insert(seed) {
            continue;
        }
        queue.push_back(seed);
        while let Some(nid) = queue.pop_front() {
            let ordinal = u32::try_from(nodes.len())
                .map_err(|_| invalid("compaction node ordinal exceeds u32"))?;
            nodes.push(CompactionNode {
                point_id: point_by_nid
                    .get(&nid)
                    .ok_or_else(|| invalid("BFS visited a non-live Nid"))?
                    .clone(),
                nid,
                ordinal,
            });
            let mut neighbors = incident.neighbors(nid)?;
            neighbors.sort_unstable_by(|left, right| {
                incident
                    .degree(*right)
                    .cmp(&incident.degree(*left))
                    .then_with(|| left.cmp(right))
            });
            for neighbor in neighbors {
                if !point_by_nid.contains_key(&neighbor) {
                    return Err(invalid("incident scratch references a retired Nid"));
                }
                if visited.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }
    }
    if nodes.len() != point_by_nid.len() {
        return Err(invalid("degree-BFS omitted live nodes"));
    }
    Ok(nodes)
}

fn visit_unique_topology(
    generation: &GraphGeneration,
    tail: &[(GraphNamespace, AdjacencyEdge)],
    mut visit: impl FnMut(&GraphNamespace, AdjacencyEdge) -> Result<()>,
) -> Result<()> {
    let mut sort = TopologySort::new();
    generation.visit_topology(|namespace, edge| {
        if generation.edge_namespaces.lookup(edge.edge_id)? != Some(namespace) {
            return Err(invalid(
                "sealed topology namespace disagrees with pinned ledger",
            ));
        }
        sort.push(edge)
    })?;
    let mut tail_namespaces = HashMap::<EdgeId, GraphNamespace>::with_capacity(tail.len());
    for (namespace, edge) in tail {
        if let Some(previous) = tail_namespaces.insert(edge.edge_id, namespace.clone())
            && previous != *namespace
        {
            return Err(invalid("mutable topology gives an EdgeId two namespaces"));
        }
        sort.push(*edge)?;
    }
    sort.visit_unique(|edge| {
        let sealed = generation.edge_namespaces.lookup(edge.edge_id)?;
        let tail = tail_namespaces.get(&edge.edge_id);
        let namespace = match (sealed, tail) {
            (Some(left), Some(right)) if left != right => {
                return Err(invalid(
                    "sealed and mutable topology disagree on edge namespace",
                ));
            }
            (Some(namespace), _) => namespace,
            (None, Some(namespace)) => namespace,
            (None, None) => return Err(invalid("topology edge has no namespace authority")),
        };
        visit(namespace, edge)
    })
}

fn edge_is_live(
    edge: AdjacencyEdge,
    resolver: &PointIncarnationResolver,
    overlay: &OverlaySet,
) -> bool {
    !overlay.edge_tombstones().contains(edge.edge_id.raw())
        && resolver.live_point_id(edge.source).is_some()
        && resolver.live_point_id(edge.target).is_some()
}

fn compare_namespaces(left: &GraphNamespace, right: &GraphNamespace) -> Ordering {
    match (left, right) {
        (GraphNamespace::Tenant(left), GraphNamespace::Tenant(right)) => {
            left.as_bytes().cmp(right.as_bytes())
        }
        (GraphNamespace::Tenant(_), GraphNamespace::AdminCrossTenant) => Ordering::Less,
        (GraphNamespace::AdminCrossTenant, GraphNamespace::Tenant(_)) => Ordering::Greater,
        (GraphNamespace::AdminCrossTenant, GraphNamespace::AdminCrossTenant) => Ordering::Equal,
    }
}

fn empty_row(node_ordinal: u32) -> BaseRowInput {
    BaseRowInput {
        node_ordinal,
        outgoing: Vec::new(),
        incoming: Vec::new(),
    }
}

fn local_edge(ordinal: u32, edge_id: EdgeId, type_id: TypeId) -> BaseEdgeInput {
    BaseEdgeInput {
        neighbor: BaseNeighborInput::LocalOrdinal(ordinal),
        edge_id,
        type_id,
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

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| invalid(&format!("{label} overflow")))
}

fn validate_nid(nid: Nid) -> Result<()> {
    if Nid::from_parts(nid.epoch(), nid.counter()) != Some(nid) {
        return Err(invalid("compaction scratch contains an invalid Nid"));
    }
    Ok(())
}

fn validate_edge_id(edge_id: EdgeId) -> Result<()> {
    if EdgeId::from_parts(edge_id.epoch(), edge_id.counter()) != Some(edge_id) {
        return Err(invalid("compaction scratch contains an invalid EdgeId"));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("checked width"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("checked width"))
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("invalid graph compaction input: {message}"))
}
