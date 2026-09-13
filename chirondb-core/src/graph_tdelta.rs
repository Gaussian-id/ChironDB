//! `tdelta.gdx` global-Nid topology deltas (Rev 3.4 Appendix C.3).

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use roaring::RoaringTreemap;

use crate::{
    GaussError, Result,
    graph::{
        EdgeId, GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, GraphNamespace, Nid, TypeId,
    },
    graph_artifact::{self, ArtifactSpec, CheckedArtifact, SectionPayload},
    graph_group::{
        self, AUTHENTICATED_CHUNK_BYTES, GroupPayload, GroupedSectionLayout, NamespaceDescriptor,
        NamespaceInput, TaggedNeighbor, WIDTH_TAGGED_NEIGHBOR, WIDTH_U32, WIDTH_U64,
    },
};

pub(crate) const TOPOLOGY_DELTA_FILE: &str = "tdelta.gdx";
pub(crate) const TOPOLOGY_DELTA_MAGIC: &[u8; 8] = b"GAUSTD01";

mod partition;

const SECTION_NAMESPACE_INDEX: u32 = 1;
const SECTION_NID_INDEX: u32 = 2;
const SECTION_OUT_OFFSETS: u32 = 3;
const SECTION_OUT_NEIGHBORS: u32 = 4;
const SECTION_OUT_EDGE_IDS: u32 = 5;
const SECTION_OUT_TYPES: u32 = 6;
const SECTION_IN_OFFSETS: u32 = 7;
const SECTION_IN_NEIGHBORS: u32 = 8;
const SECTION_IN_EDGE_IDS: u32 = 9;
const SECTION_IN_TYPES: u32 = 10;
const SECTION_BASE_LSN: u32 = 11;

const REQUIRED_SECTIONS: &[u32] = &[
    SECTION_NAMESPACE_INDEX,
    SECTION_NID_INDEX,
    SECTION_OUT_OFFSETS,
    SECTION_OUT_NEIGHBORS,
    SECTION_OUT_EDGE_IDS,
    SECTION_OUT_TYPES,
    SECTION_IN_OFFSETS,
    SECTION_IN_NEIGHBORS,
    SECTION_IN_EDGE_IDS,
    SECTION_IN_TYPES,
    SECTION_BASE_LSN,
];

const SPEC: ArtifactSpec = ArtifactSpec {
    magic: TOPOLOGY_DELTA_MAGIC,
    allowed_flags: 0,
    required_sections: REQUIRED_SECTIONS,
    optional_sections: &[],
    max_file_len: u64::MAX,
};

const MAX_DIRECTED_ENTRIES: u64 = u32::MAX as u64;
const MAX_ROW_FRAGMENT_BYTES: usize = AUTHENTICATED_CHUNK_BYTES - 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeltaEdgeInput {
    pub(crate) source_nid: Nid,
    pub(crate) target_nid: Nid,
    pub(crate) edge_id: EdgeId,
    pub(crate) type_id: TypeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeltaGroupInput {
    pub(crate) namespace: GraphNamespace,
    pub(crate) edges: Vec<DeltaEdgeInput>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectionalEdge {
    neighbor_nid: Nid,
    edge_id: EdgeId,
    type_id: TypeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeltaGroup {
    namespace: GraphNamespace,
    nids: Vec<Nid>,
    outgoing: Vec<Vec<DirectionalEdge>>,
    incoming: Vec<Vec<DirectionalEdge>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TopologyDelta {
    base_lsn: u64,
    groups: Vec<DeltaGroup>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodedDeltaEdge {
    pub(crate) neighbor_nid: Nid,
    pub(crate) edge_id: EdgeId,
    pub(crate) type_id: TypeId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedDeltaRow {
    pub(crate) nid: Nid,
    pub(crate) outgoing: Vec<DecodedDeltaEdge>,
    pub(crate) incoming: Vec<DecodedDeltaEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedDeltaGroup {
    pub(crate) namespace: GraphNamespace,
    pub(crate) rows: Vec<DecodedDeltaRow>,
}

pub(crate) struct OpenedTopologyDelta {
    artifact: CheckedArtifact,
    base_lsn: u64,
    namespaces: Vec<NamespaceDescriptor>,
    nids: GroupedSectionLayout,
    out_offsets: GroupedSectionLayout,
    out_neighbors: GroupedSectionLayout,
    out_edge_ids: GroupedSectionLayout,
    out_types: GroupedSectionLayout,
    in_offsets: GroupedSectionLayout,
    in_neighbors: GroupedSectionLayout,
    in_edge_ids: GroupedSectionLayout,
    in_types: GroupedSectionLayout,
}

impl TopologyDelta {
    pub(crate) fn build(base_lsn: u64, mut groups: Vec<DeltaGroupInput>) -> Result<Self> {
        if groups.is_empty() {
            return Err(invalid(
                "tdelta.gdx cannot represent an empty topology delta",
            ));
        }
        groups
            .sort_unstable_by(|left, right| compare_namespaces(&left.namespace, &right.namespace));
        if groups.windows(2).any(|pair| {
            compare_namespaces(&pair[0].namespace, &pair[1].namespace) != Ordering::Less
        }) {
            return Err(invalid("tdelta.gdx contains duplicate graph namespaces"));
        }

        let mut used_edge_ids = RoaringTreemap::new();
        let mut total_edges = 0_u64;
        let mut normalized = Vec::with_capacity(groups.len());
        for group in groups {
            if group.edges.is_empty() {
                return Err(invalid(
                    "tdelta.gdx cannot persist an empty namespace group",
                ));
            }
            let mut nid_set = BTreeSet::new();
            for edge in &group.edges {
                validate_nid(edge.source_nid)?;
                validate_nid(edge.target_nid)?;
                validate_edge_id(edge.edge_id)?;
                validate_type_id(edge.type_id)?;
                if !used_edge_ids.insert(edge.edge_id.raw()) {
                    return Err(invalid("tdelta.gdx contains a duplicate EdgeId"));
                }
                nid_set.insert(edge.source_nid);
                nid_set.insert(edge.target_nid);
            }
            total_edges = total_edges
                .checked_add(group.edges.len() as u64)
                .ok_or_else(|| invalid("tdelta.gdx directed-entry count overflow"))?;
            if total_edges > MAX_DIRECTED_ENTRIES {
                return Err(invalid("tdelta.gdx directed-entry count exceeds u32"));
            }
            let nids = nid_set.into_iter().collect::<Vec<_>>();
            let positions = nids
                .iter()
                .enumerate()
                .map(|(index, nid)| (nid.raw(), index))
                .collect::<BTreeMap<_, _>>();
            let mut outgoing = vec![Vec::new(); nids.len()];
            let mut incoming = vec![Vec::new(); nids.len()];
            for edge in group.edges {
                let source = positions[&edge.source_nid.raw()];
                let target = positions[&edge.target_nid.raw()];
                outgoing[source].push(DirectionalEdge {
                    neighbor_nid: edge.target_nid,
                    edge_id: edge.edge_id,
                    type_id: edge.type_id,
                });
                incoming[target].push(DirectionalEdge {
                    neighbor_nid: edge.source_nid,
                    edge_id: edge.edge_id,
                    type_id: edge.type_id,
                });
            }
            for row in outgoing.iter_mut().chain(&mut incoming) {
                row.sort_unstable_by_key(edge_sort_key);
                validate_row_fragment(row)?;
            }
            normalized.push(DeltaGroup {
                namespace: group.namespace,
                nids,
                outgoing,
                incoming,
            });
        }
        Ok(Self {
            base_lsn,
            groups: normalized,
        })
    }

    pub(crate) fn base_lsn(&self) -> u64 {
        self.base_lsn
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn edge_count(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|group| &group.outgoing)
            .map(|row| row.len() as u64)
            .sum()
    }
}

pub(crate) fn write(path: &Path, delta: &TopologyDelta) -> Result<()> {
    let namespace_inputs = delta
        .groups
        .iter()
        .map(|group| {
            Ok(NamespaceInput {
                namespace: group.namespace.clone(),
                row_count: u32::try_from(group.nids.len())
                    .map_err(|_| invalid("tdelta.gdx namespace row count exceeds u32"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let namespace_index = graph_group::encode_namespace_index(&namespace_inputs)?;

    let mut row_counts = Vec::with_capacity(delta.groups.len());
    let mut edge_counts = Vec::with_capacity(delta.groups.len());
    let mut nid_groups = Vec::with_capacity(delta.groups.len());
    let mut out = DirectionGroups::with_capacity(delta.groups.len());
    let mut incoming = DirectionGroups::with_capacity(delta.groups.len());
    for group in &delta.groups {
        row_counts.push(group.nids.len() as u64);
        nid_groups.push(
            group
                .nids
                .iter()
                .flat_map(|nid| nid.raw().to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let out_group = encode_direction(&group.outgoing)?;
        let in_group = encode_direction(&group.incoming)?;
        if out_group.edge_count != in_group.edge_count {
            return Err(invalid("tdelta.gdx outgoing/incoming counts disagree"));
        }
        edge_counts.push(out_group.edge_count);
        out.push(out_group);
        incoming.push(in_group);
    }

    let offset_counts = row_counts.iter().map(|count| count + 1).collect::<Vec<_>>();
    let nid_index = encode_grouped(WIDTH_U64, &row_counts, &nid_groups)?;
    let out_offsets = encode_grouped(WIDTH_U64, &offset_counts, &out.offsets)?;
    let out_neighbors = encode_grouped(WIDTH_TAGGED_NEIGHBOR, &edge_counts, &out.neighbors)?;
    let out_edge_ids = encode_grouped(WIDTH_U64, &edge_counts, &out.edge_ids)?;
    let out_types = encode_grouped(WIDTH_U32, &edge_counts, &out.types)?;
    let in_offsets = encode_grouped(WIDTH_U64, &offset_counts, &incoming.offsets)?;
    let in_neighbors = encode_grouped(WIDTH_TAGGED_NEIGHBOR, &edge_counts, &incoming.neighbors)?;
    let in_edge_ids = encode_grouped(WIDTH_U64, &edge_counts, &incoming.edge_ids)?;
    let in_types = encode_grouped(WIDTH_U32, &edge_counts, &incoming.types)?;
    let total_rows = checked_sum(&row_counts, "tdelta.gdx total row count overflow")?;
    let total_edges = checked_sum(&edge_counts, "tdelta.gdx total edge count overflow")?;
    let base_lsn = delta.base_lsn.to_le_bytes();

    graph_artifact::write_aligned(
        path,
        SPEC,
        0,
        &[
            SectionPayload {
                id: SECTION_NAMESPACE_INDEX,
                elem_count: delta.groups.len() as u64,
                bytes: &namespace_index,
            },
            SectionPayload {
                id: SECTION_NID_INDEX,
                elem_count: total_rows,
                bytes: &nid_index,
            },
            SectionPayload {
                id: SECTION_OUT_OFFSETS,
                elem_count: total_rows + delta.groups.len() as u64,
                bytes: &out_offsets,
            },
            SectionPayload {
                id: SECTION_OUT_NEIGHBORS,
                elem_count: total_edges,
                bytes: &out_neighbors,
            },
            SectionPayload {
                id: SECTION_OUT_EDGE_IDS,
                elem_count: total_edges,
                bytes: &out_edge_ids,
            },
            SectionPayload {
                id: SECTION_OUT_TYPES,
                elem_count: total_edges,
                bytes: &out_types,
            },
            SectionPayload {
                id: SECTION_IN_OFFSETS,
                elem_count: total_rows + delta.groups.len() as u64,
                bytes: &in_offsets,
            },
            SectionPayload {
                id: SECTION_IN_NEIGHBORS,
                elem_count: total_edges,
                bytes: &in_neighbors,
            },
            SectionPayload {
                id: SECTION_IN_EDGE_IDS,
                elem_count: total_edges,
                bytes: &in_edge_ids,
            },
            SectionPayload {
                id: SECTION_IN_TYPES,
                elem_count: total_edges,
                bytes: &in_types,
            },
            SectionPayload {
                id: SECTION_BASE_LSN,
                elem_count: 1,
                bytes: &base_lsn,
            },
        ],
        &[
            (SECTION_NID_INDEX, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_OUT_OFFSETS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_OUT_NEIGHBORS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_OUT_EDGE_IDS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_OUT_TYPES, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_OFFSETS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_NEIGHBORS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_EDGE_IDS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_TYPES, AUTHENTICATED_CHUNK_BYTES),
        ],
    )
}

pub(crate) fn open(path: &Path, inclusive_last_lsn: u64) -> Result<OpenedTopologyDelta> {
    let artifact = graph_artifact::open(path, SPEC)?;
    if artifact.flags() != 0 {
        return Err(corruption(path, "tdelta.gdx flags must be zero"));
    }
    let namespace_section = artifact
        .section(SECTION_NAMESPACE_INDEX)
        .expect("common loader requires tdelta namespace index");
    let namespaces = graph_group::decode_namespace_index(
        path,
        &artifact.read_section(SECTION_NAMESPACE_INDEX)?,
    )?;
    if namespaces.is_empty()
        || namespace_section.elem_count != namespaces.len() as u64
        || namespaces.iter().any(|namespace| namespace.row_count == 0)
    {
        return Err(corruption(path, "tdelta.gdx namespace index is invalid"));
    }
    let base_section = artifact
        .section(SECTION_BASE_LSN)
        .expect("common loader requires tdelta base LSN");
    let base_bytes = artifact.read_section(SECTION_BASE_LSN)?;
    if base_section.elem_count != 1 || base_bytes.len() != 8 {
        return Err(corruption(path, "tdelta.gdx base LSN section is invalid"));
    }
    let base_lsn = u64::from_le_bytes(base_bytes.as_ref().try_into().expect("checked base LSN"));
    if base_lsn > inclusive_last_lsn {
        return Err(corruption(
            path,
            "tdelta.gdx base LSN exceeds manifest last LSN",
        ));
    }

    let group_count = namespaces.len();
    let opened = OpenedTopologyDelta {
        nids: open_grouped(path, &artifact, SECTION_NID_INDEX, group_count, WIDTH_U64)?,
        out_offsets: open_grouped(path, &artifact, SECTION_OUT_OFFSETS, group_count, WIDTH_U64)?,
        out_neighbors: open_grouped(
            path,
            &artifact,
            SECTION_OUT_NEIGHBORS,
            group_count,
            WIDTH_TAGGED_NEIGHBOR,
        )?,
        out_edge_ids: open_grouped(
            path,
            &artifact,
            SECTION_OUT_EDGE_IDS,
            group_count,
            WIDTH_U64,
        )?,
        out_types: open_grouped(path, &artifact, SECTION_OUT_TYPES, group_count, WIDTH_U32)?,
        in_offsets: open_grouped(path, &artifact, SECTION_IN_OFFSETS, group_count, WIDTH_U64)?,
        in_neighbors: open_grouped(
            path,
            &artifact,
            SECTION_IN_NEIGHBORS,
            group_count,
            WIDTH_TAGGED_NEIGHBOR,
        )?,
        in_edge_ids: open_grouped(path, &artifact, SECTION_IN_EDGE_IDS, group_count, WIDTH_U64)?,
        in_types: open_grouped(path, &artifact, SECTION_IN_TYPES, group_count, WIDTH_U32)?,
        artifact,
        base_lsn,
        namespaces,
    };

    let mut seen_edge_ids = RoaringTreemap::new();
    let mut total_edges = 0_u64;
    for group_index in 0..opened.namespaces.len() {
        let group = opened.decode_group(path, group_index)?;
        for edge in group.rows.iter().flat_map(|row| &row.outgoing) {
            if !seen_edge_ids.insert(edge.edge_id.raw()) {
                return Err(corruption(path, "tdelta.gdx contains a duplicate EdgeId"));
            }
            total_edges = total_edges
                .checked_add(1)
                .ok_or_else(|| corruption(path, "tdelta.gdx directed-entry count overflow"))?;
        }
    }
    if total_edges > MAX_DIRECTED_ENTRIES {
        return Err(corruption(
            path,
            "tdelta.gdx directed-entry count exceeds u32",
        ));
    }
    Ok(opened)
}

pub(crate) struct DeltaEdges<'a> {
    columns: Option<graph_group::cursor::TopologyColumns<'a>>,
    node: Nid,
    incoming: bool,
}

impl Iterator for DeltaEdges<'_> {
    type Item = Result<graph_group::AdjacencyEdge>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.columns.as_mut()?.read_next().transpose().map(|edge| {
            let (neighbor, edge_id, type_id) = edge?;
            let TaggedNeighbor::Global(neighbor) = neighbor else {
                return Err(invalid("delta cursor contains local neighbor"));
            };
            Ok(graph_group::AdjacencyEdge {
                edge_id,
                source: if self.incoming { neighbor } else { self.node },
                target: if self.incoming { self.node } else { neighbor },
                type_id,
                local_base: None,
            })
        });
        if next.as_ref().is_none_or(Result::is_err) {
            self.columns = None;
        }
        next
    }
}

impl OpenedTopologyDelta {
    pub(crate) fn edges(&self, group: usize, row: u32, incoming: bool) -> Result<DeltaEdges<'_>> {
        if self
            .namespaces
            .get(group)
            .is_none_or(|ns| row >= ns.row_count)
        {
            return Err(invalid("delta cursor row exceeds namespace"));
        }
        let (
            offsets,
            ids,
            types,
            neighbors,
            offset_section,
            id_section,
            type_section,
            neighbor_section,
        ) = if incoming {
            (
                &self.in_offsets,
                &self.in_edge_ids,
                &self.in_types,
                &self.in_neighbors,
                SECTION_IN_OFFSETS,
                SECTION_IN_EDGE_IDS,
                SECTION_IN_TYPES,
                SECTION_IN_NEIGHBORS,
            )
        } else {
            (
                &self.out_offsets,
                &self.out_edge_ids,
                &self.out_types,
                &self.out_neighbors,
                SECTION_OUT_OFFSETS,
                SECTION_OUT_EDGE_IDS,
                SECTION_OUT_TYPES,
                SECTION_OUT_NEIGHBORS,
            )
        };
        let start = u64::from_le_bytes(graph_group::read_fixed(
            &self.artifact,
            offset_section,
            offsets,
            group,
            row,
        )?);
        let end = u64::from_le_bytes(graph_group::read_fixed(
            &self.artifact,
            offset_section,
            offsets,
            group,
            row + 1,
        )?);
        use graph_group::cursor::{Column, TopologyColumns};
        Ok(DeltaEdges {
            columns: Some(TopologyColumns::new(
                &self.artifact,
                Column {
                    section: id_section,
                    frame: &ids.frames[group],
                },
                Column {
                    section: type_section,
                    frame: &types.frames[group],
                },
                Column {
                    section: neighbor_section,
                    frame: &neighbors.frames[group],
                },
                start..end,
                None,
            )?),
            node: self.row_nid(group, row)?,
            incoming,
        })
    }

    pub(crate) fn namespaces(&self) -> &[NamespaceDescriptor] {
        &self.namespaces
    }

    pub(crate) fn row_nid(&self, group: usize, row: u32) -> Result<Nid> {
        Ok(Nid::from_raw(u64::from_le_bytes(graph_group::read_fixed(
            &self.artifact,
            SECTION_NID_INDEX,
            &self.nids,
            group,
            row,
        )?)))
    }

    pub(crate) fn find_row(&self, namespace: &GraphNamespace, nid: Nid) -> Result<Option<u32>> {
        let Some(group) = self
            .namespaces
            .iter()
            .position(|g| &g.namespace == namespace)
        else {
            return Ok(None);
        };
        let (mut lower, mut upper) = (0, self.namespaces[group].row_count);
        while lower < upper {
            let mid = lower + (upper - lower) / 2;
            match self.row_nid(group, mid)?.cmp(&nid) {
                Ordering::Less => lower = mid + 1,
                Ordering::Greater => upper = mid,
                Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }

    pub(crate) fn base_lsn(&self) -> u64 {
        self.base_lsn
    }

    pub(crate) fn group_count(&self) -> usize {
        self.namespaces.len()
    }

    pub(crate) fn edge_count(&self) -> u64 {
        self.out_edge_ids.semantic_elem_count
    }

    pub(crate) fn read_group(&self, path: &Path, group_index: usize) -> Result<DecodedDeltaGroup> {
        self.decode_group(path, group_index)
    }

    fn decode_group(&self, path: &Path, group_index: usize) -> Result<DecodedDeltaGroup> {
        let namespace = self
            .namespaces
            .get(group_index)
            .ok_or_else(|| invalid("tdelta.gdx namespace group index is out of bounds"))?;
        let nids = decode_u64s(&graph_group::read_group(
            &self.artifact,
            SECTION_NID_INDEX,
            &self.nids,
            group_index,
        )?)
        .into_iter()
        .map(Nid::from_raw)
        .collect::<Vec<_>>();
        if nids.len() != namespace.row_count as usize
            || self.nids.frames[group_index].elem_count != namespace.row_count as u64
            || nids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(corruption(path, "tdelta.gdx Nid index is invalid"));
        }
        for nid in &nids {
            validate_nid(*nid).map_err(|error| corruption(path, &error.to_string()))?;
        }

        let outgoing = self.decode_direction(
            path,
            group_index,
            &nids,
            DirectionSections {
                offsets_id: SECTION_OUT_OFFSETS,
                neighbors_id: SECTION_OUT_NEIGHBORS,
                edge_ids_id: SECTION_OUT_EDGE_IDS,
                types_id: SECTION_OUT_TYPES,
                offsets: &self.out_offsets,
                neighbors: &self.out_neighbors,
                edge_ids: &self.out_edge_ids,
                types: &self.out_types,
            },
        )?;
        let incoming = self.decode_direction(
            path,
            group_index,
            &nids,
            DirectionSections {
                offsets_id: SECTION_IN_OFFSETS,
                neighbors_id: SECTION_IN_NEIGHBORS,
                edge_ids_id: SECTION_IN_EDGE_IDS,
                types_id: SECTION_IN_TYPES,
                offsets: &self.in_offsets,
                neighbors: &self.in_neighbors,
                edge_ids: &self.in_edge_ids,
                types: &self.in_types,
            },
        )?;
        validate_mirrors(path, &nids, &outgoing, &incoming)?;

        Ok(DecodedDeltaGroup {
            namespace: namespace.namespace.clone(),
            rows: nids
                .into_iter()
                .zip(outgoing)
                .zip(incoming)
                .map(|((nid, outgoing), incoming)| DecodedDeltaRow {
                    nid,
                    outgoing,
                    incoming,
                })
                .collect(),
        })
    }

    fn decode_direction(
        &self,
        path: &Path,
        group_index: usize,
        nids: &[Nid],
        sections: DirectionSections<'_>,
    ) -> Result<Vec<Vec<DecodedDeltaEdge>>> {
        let offsets = decode_u64s(&graph_group::read_group(
            &self.artifact,
            sections.offsets_id,
            sections.offsets,
            group_index,
        )?);
        if sections.offsets.frames[group_index].elem_count != nids.len() as u64 + 1
            || offsets.len() != nids.len() + 1
            || offsets.first().copied() != Some(0)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
        {
            return Err(corruption(path, "tdelta.gdx direction offsets are invalid"));
        }
        let edge_count = offsets.last().copied().unwrap_or(0);
        if [
            sections.neighbors.frames[group_index].elem_count,
            sections.edge_ids.frames[group_index].elem_count,
            sections.types.frames[group_index].elem_count,
        ]
        .iter()
        .any(|count| *count != edge_count)
        {
            return Err(corruption(
                path,
                "tdelta.gdx direction parallel counts disagree",
            ));
        }

        let neighbors = graph_group::decode_tagged_neighbors(
            path,
            &graph_group::read_group(
                &self.artifact,
                sections.neighbors_id,
                sections.neighbors,
                group_index,
            )?,
            edge_count,
        )?;
        let edge_ids = decode_u64s(&graph_group::read_group(
            &self.artifact,
            sections.edge_ids_id,
            sections.edge_ids,
            group_index,
        )?);
        let types = decode_u32s(&graph_group::read_group(
            &self.artifact,
            sections.types_id,
            sections.types,
            group_index,
        )?);
        if neighbors.len() != edge_ids.len() || neighbors.len() != types.len() {
            return Err(corruption(
                path,
                "tdelta.gdx direction payload widths disagree",
            ));
        }

        let known_nids = nids.iter().map(|nid| nid.raw()).collect::<BTreeSet<_>>();
        let mut rows = Vec::with_capacity(nids.len());
        for row_index in 0..nids.len() {
            let start = usize::try_from(offsets[row_index])
                .map_err(|_| corruption(path, "tdelta.gdx row start exceeds usize"))?;
            let end = usize::try_from(offsets[row_index + 1])
                .map_err(|_| corruption(path, "tdelta.gdx row end exceeds usize"))?;
            if end > neighbors.len() {
                return Err(corruption(path, "tdelta.gdx row exceeds direction arrays"));
            }
            let mut row = Vec::with_capacity(end - start);
            for index in start..end {
                let neighbor_nid = match neighbors[index] {
                    TaggedNeighbor::Global(nid) => nid,
                    TaggedNeighbor::LocalDelta(_) => {
                        return Err(corruption(
                            path,
                            "tdelta.gdx contains a local tagged neighbour",
                        ));
                    }
                };
                validate_nid(neighbor_nid).map_err(|error| corruption(path, &error.to_string()))?;
                if !known_nids.contains(&neighbor_nid.raw()) {
                    return Err(corruption(
                        path,
                        "tdelta.gdx neighbour is absent from the delta Nid index",
                    ));
                }
                let edge_id = EdgeId::from_raw(edge_ids[index]);
                validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
                let type_id = TypeId::from_raw(types[index]);
                validate_type_id(type_id).map_err(|error| corruption(path, &error.to_string()))?;
                row.push(DecodedDeltaEdge {
                    neighbor_nid,
                    edge_id,
                    type_id,
                });
            }
            if row
                .windows(2)
                .any(|pair| decoded_edge_sort_key(&pair[0]) >= decoded_edge_sort_key(&pair[1]))
            {
                return Err(corruption(
                    path,
                    "tdelta.gdx row is not sorted by type, Nid, and EdgeId",
                ));
            }
            validate_decoded_row_fragment(&row)
                .map_err(|error| corruption(path, &error.to_string()))?;
            rows.push(row);
        }
        Ok(rows)
    }
}

struct EncodedDirection {
    edge_count: u64,
    offsets: Vec<u8>,
    neighbors: Vec<u8>,
    edge_ids: Vec<u8>,
    types: Vec<u8>,
}

struct DirectionGroups {
    offsets: Vec<Vec<u8>>,
    neighbors: Vec<Vec<u8>>,
    edge_ids: Vec<Vec<u8>>,
    types: Vec<Vec<u8>>,
}

impl DirectionGroups {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            offsets: Vec::with_capacity(capacity),
            neighbors: Vec::with_capacity(capacity),
            edge_ids: Vec::with_capacity(capacity),
            types: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, direction: EncodedDirection) {
        self.offsets.push(direction.offsets);
        self.neighbors.push(direction.neighbors);
        self.edge_ids.push(direction.edge_ids);
        self.types.push(direction.types);
    }
}

struct DirectionSections<'a> {
    offsets_id: u32,
    neighbors_id: u32,
    edge_ids_id: u32,
    types_id: u32,
    offsets: &'a GroupedSectionLayout,
    neighbors: &'a GroupedSectionLayout,
    edge_ids: &'a GroupedSectionLayout,
    types: &'a GroupedSectionLayout,
}

fn encode_direction(rows: &[Vec<DirectionalEdge>]) -> Result<EncodedDirection> {
    let edge_count = rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.len() as u64)
            .ok_or_else(|| invalid("tdelta.gdx direction edge count overflow"))
    })?;
    let edge_capacity = usize::try_from(edge_count)
        .map_err(|_| invalid("tdelta.gdx direction edge count exceeds usize"))?;
    let mut offsets = Vec::with_capacity(rows.len() + 1);
    let mut neighbors = Vec::with_capacity(edge_capacity);
    let mut edge_ids = Vec::with_capacity(
        edge_capacity
            .checked_mul(8)
            .ok_or_else(|| invalid("tdelta.gdx EdgeId buffer length overflow"))?,
    );
    let mut types = Vec::with_capacity(
        edge_capacity
            .checked_mul(4)
            .ok_or_else(|| invalid("tdelta.gdx TypeId buffer length overflow"))?,
    );
    offsets.push(0_u64);
    for row in rows {
        for edge in row {
            neighbors.push(TaggedNeighbor::Global(edge.neighbor_nid));
            edge_ids.extend_from_slice(&edge.edge_id.raw().to_le_bytes());
            types.extend_from_slice(&edge.type_id.raw().to_le_bytes());
        }
        offsets.push(neighbors.len() as u64);
    }
    Ok(EncodedDirection {
        edge_count,
        offsets: offsets.into_iter().flat_map(u64::to_le_bytes).collect(),
        neighbors: graph_group::encode_tagged_neighbors(&neighbors)?,
        edge_ids,
        types,
    })
}

fn validate_mirrors(
    path: &Path,
    nids: &[Nid],
    outgoing: &[Vec<DecodedDeltaEdge>],
    incoming: &[Vec<DecodedDeltaEdge>],
) -> Result<()> {
    let mut out = BTreeMap::new();
    let mut inbound = BTreeMap::new();
    for (source, row) in nids.iter().zip(outgoing) {
        for edge in row {
            if out
                .insert(
                    edge.edge_id.raw(),
                    (source.raw(), edge.neighbor_nid.raw(), edge.type_id.raw()),
                )
                .is_some()
            {
                return Err(corruption(path, "tdelta.gdx duplicates an outgoing EdgeId"));
            }
        }
    }
    for (target, row) in nids.iter().zip(incoming) {
        for edge in row {
            if inbound
                .insert(
                    edge.edge_id.raw(),
                    (edge.neighbor_nid.raw(), target.raw(), edge.type_id.raw()),
                )
                .is_some()
            {
                return Err(corruption(path, "tdelta.gdx duplicates an incoming EdgeId"));
            }
        }
    }
    if out != inbound {
        return Err(corruption(
            path,
            "tdelta.gdx outgoing/incoming edge mirrors disagree",
        ));
    }
    Ok(())
}

fn validate_row_fragment(row: &[DirectionalEdge]) -> Result<()> {
    let decoded = row
        .iter()
        .map(|edge| DecodedDeltaEdge {
            neighbor_nid: edge.neighbor_nid,
            edge_id: edge.edge_id,
            type_id: edge.type_id,
        })
        .collect::<Vec<_>>();
    validate_decoded_row_fragment(&decoded)
}

fn validate_decoded_row_fragment(row: &[DecodedDeltaEdge]) -> Result<()> {
    let neighbors = row
        .iter()
        .map(|edge| TaggedNeighbor::Global(edge.neighbor_nid))
        .collect::<Vec<_>>();
    let neighbor_bytes = graph_group::encode_tagged_neighbors(&neighbors)?.len();
    let edge_id_bytes = row
        .len()
        .checked_mul(8)
        .ok_or_else(|| invalid("tdelta.gdx row EdgeId length overflow"))?;
    let type_bytes = row
        .len()
        .checked_mul(4)
        .ok_or_else(|| invalid("tdelta.gdx row TypeId length overflow"))?;
    if neighbor_bytes > MAX_ROW_FRAGMENT_BYTES
        || edge_id_bytes > MAX_ROW_FRAGMENT_BYTES
        || type_bytes > MAX_ROW_FRAGMENT_BYTES
    {
        return Err(invalid(
            "tdelta.gdx row exceeds one fragment and must be split by fragdir.gdx",
        ));
    }
    Ok(())
}

fn encode_grouped(width: u32, counts: &[u64], groups: &[Vec<u8>]) -> Result<Vec<u8>> {
    if counts.len() != groups.len() {
        return Err(invalid("tdelta.gdx grouped payload count mismatch"));
    }
    let payloads = counts
        .iter()
        .zip(groups)
        .map(|(elem_count, bytes)| GroupPayload {
            elem_count: *elem_count,
            bytes,
        })
        .collect::<Vec<_>>();
    graph_group::encode_grouped_section(width, &payloads)
}

fn open_grouped(
    path: &Path,
    artifact: &CheckedArtifact,
    section_id: u32,
    group_count: usize,
    width: u32,
) -> Result<GroupedSectionLayout> {
    graph_group::open_grouped_section(path, artifact, section_id, group_count, width)
}

fn checked_sum(values: &[u64], message: &str) -> Result<u64> {
    values.iter().try_fold(0_u64, |total, value| {
        total.checked_add(*value).ok_or_else(|| invalid(message))
    })
}

fn edge_sort_key(edge: &DirectionalEdge) -> (u32, u64, u64) {
    (
        edge.type_id.raw(),
        edge.neighbor_nid.raw(),
        edge.edge_id.raw(),
    )
}

fn decoded_edge_sort_key(edge: &DecodedDeltaEdge) -> (u32, u64, u64) {
    (
        edge.type_id.raw(),
        edge.neighbor_nid.raw(),
        edge.edge_id.raw(),
    )
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

fn validate_nid(nid: Nid) -> Result<()> {
    if nid.raw() == 0
        || nid.epoch() == 0
        || nid.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || nid.counter() == 0
        || nid.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("tdelta.gdx contains an invalid Nid"));
    }
    Ok(())
}

fn validate_edge_id(edge_id: EdgeId) -> Result<()> {
    if edge_id.raw() == 0
        || edge_id.epoch() == 0
        || edge_id.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || edge_id.counter() == 0
        || edge_id.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("tdelta.gdx contains an invalid EdgeId"));
    }
    Ok(())
}

fn validate_type_id(type_id: TypeId) -> Result<()> {
    if type_id.raw() == 0 {
        return Err(invalid("tdelta.gdx contains reserved TypeId=0"));
    }
    Ok(())
}

fn decode_u32s(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("validated u32 group width")))
        .collect()
}

fn decode_u64s(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|raw| u64::from_le_bytes(raw.try_into().expect("validated u64 group width")))
        .collect()
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn corruption(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    use super::*;

    const ENCRYPTED_HELPER_ENV: &str = "CHIRONDB_GRAPH_TDELTA_ENCRYPTED_HELPER_DIR";

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(41, counter).unwrap()
    }

    fn edge_id(counter: u64) -> EdgeId {
        EdgeId::from_parts(41, counter).unwrap()
    }

    fn type_id(raw: u32) -> TypeId {
        TypeId::from_raw(raw)
    }

    fn fixture() -> TopologyDelta {
        TopologyDelta::build(
            77,
            vec![
                DeltaGroupInput {
                    namespace: GraphNamespace::AdminCrossTenant,
                    edges: vec![DeltaEdgeInput {
                        source_nid: nid(10),
                        target_nid: nid(11),
                        edge_id: edge_id(4),
                        type_id: type_id(3),
                    }],
                },
                DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    edges: vec![
                        DeltaEdgeInput {
                            source_nid: nid(1),
                            target_nid: nid(2),
                            edge_id: edge_id(2),
                            type_id: type_id(2),
                        },
                        DeltaEdgeInput {
                            source_nid: nid(1),
                            target_nid: nid(2),
                            edge_id: edge_id(1),
                            type_id: type_id(1),
                        },
                        DeltaEdgeInput {
                            source_nid: nid(2),
                            target_nid: nid(2),
                            edge_id: edge_id(3),
                            type_id: type_id(1),
                        },
                    ],
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn topology_delta_round_trips_two_directions_multi_edges_and_self_loops() {
        let delta = fixture();
        assert_eq!(delta.base_lsn(), 77);
        assert_eq!(delta.group_count(), 2);
        assert_eq!(delta.edge_count(), 4);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(TOPOLOGY_DELTA_FILE);
        write(&path, &delta).unwrap();
        let opened = open(&path, 99).unwrap();
        assert_eq!(opened.base_lsn(), 77);
        assert_cursor_matches(&opened, &path);
        assert_eq!(opened.group_count(), 2);
        assert_eq!(opened.edge_count(), 4);

        let tenant = opened.read_group(&path, 0).unwrap();
        assert_eq!(tenant.namespace, GraphNamespace::Tenant("acme".to_string()));
        assert_eq!(tenant.rows.len(), 2);
        assert_eq!(tenant.rows[0].nid, nid(1));
        assert_eq!(tenant.rows[0].outgoing.len(), 2);
        assert_eq!(tenant.rows[0].outgoing[0].edge_id, edge_id(1));
        assert!(tenant.rows[0].incoming.is_empty());
        assert_eq!(tenant.rows[1].incoming.len(), 3);
        assert_eq!(tenant.rows[1].outgoing[0].edge_id, edge_id(3));

        let admin = opened.read_group(&path, 1).unwrap();
        assert_eq!(admin.namespace, GraphNamespace::AdminCrossTenant);
        assert_eq!(admin.rows.len(), 2);
    }

    #[test]
    fn builder_rejects_empty_duplicate_invalid_and_unfragmented_hub_state() {
        assert!(TopologyDelta::build(0, vec![]).is_err());
        let duplicate = DeltaGroupInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            edges: vec![
                DeltaEdgeInput {
                    source_nid: nid(1),
                    target_nid: nid(2),
                    edge_id: edge_id(1),
                    type_id: type_id(1),
                },
                DeltaEdgeInput {
                    source_nid: nid(2),
                    target_nid: nid(1),
                    edge_id: edge_id(1),
                    type_id: type_id(1),
                },
            ],
        };
        assert!(TopologyDelta::build(1, vec![duplicate]).is_err());
        assert!(
            TopologyDelta::build(
                1,
                vec![DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    edges: vec![DeltaEdgeInput {
                        source_nid: Nid::UNASSIGNED,
                        target_nid: nid(2),
                        edge_id: edge_id(2),
                        type_id: type_id(1),
                    }],
                }]
            )
            .is_err()
        );

        let hub_edges = (1..=4_200)
            .map(|counter| DeltaEdgeInput {
                source_nid: nid(1),
                target_nid: nid(counter + 1),
                edge_id: edge_id(counter),
                type_id: type_id(1),
            })
            .collect();
        assert!(
            TopologyDelta::build(
                1,
                vec![DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    edges: hub_edges,
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn loader_rejects_manifest_lsn_count_and_local_neighbor_corruption() {
        let delta = fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(TOPOLOGY_DELTA_FILE);
        write(&path, &delta).unwrap();
        assert!(open(&path, 76).is_err());

        let mut bad_count = fs::read(&path).unwrap();
        let table_entry = graph_artifact::COMMON_HEADER_BYTES
            + (SECTION_OUT_EDGE_IDS as usize - 1) * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        bad_count[table_entry + 24..table_entry + 32].copy_from_slice(&5_u64.to_le_bytes());
        repair_header_crc(&mut bad_count);
        fs::write(&path, bad_count).unwrap();
        assert!(open(&path, 99).is_err());

        write(&path, &delta).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let layout = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_OUT_NEIGHBORS,
            2,
            WIDTH_TAGGED_NEIGHBOR,
        )
        .unwrap();
        let mut bad_neighbor = fs::read(&path).unwrap();
        let payload = artifact.section(SECTION_OUT_NEIGHBORS).unwrap().offset
            + layout.frames[0].payload_offset;
        let blob = payload + (layout.frames[0].elem_count as usize + 1) * 8;
        bad_neighbor[blob] = 0;
        fs::write(&path, bad_neighbor).unwrap();
        assert!(open(&path, 99).is_err());
    }

    #[test]
    fn grouped_delta_sections_and_frames_are_chunk_aligned() {
        let delta = fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(TOPOLOGY_DELTA_FILE);
        write(&path, &delta).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        for (section_id, width) in [
            (SECTION_NID_INDEX, WIDTH_U64),
            (SECTION_OUT_OFFSETS, WIDTH_U64),
            (SECTION_OUT_NEIGHBORS, WIDTH_TAGGED_NEIGHBOR),
            (SECTION_OUT_EDGE_IDS, WIDTH_U64),
            (SECTION_OUT_TYPES, WIDTH_U32),
            (SECTION_IN_OFFSETS, WIDTH_U64),
            (SECTION_IN_NEIGHBORS, WIDTH_TAGGED_NEIGHBOR),
            (SECTION_IN_EDGE_IDS, WIDTH_U64),
            (SECTION_IN_TYPES, WIDTH_U32),
        ] {
            let section = artifact.section(section_id).unwrap();
            assert!(section.offset.is_multiple_of(AUTHENTICATED_CHUNK_BYTES));
            let layout =
                graph_group::open_grouped_section(&path, &artifact, section_id, 2, width).unwrap();
            assert!(layout.frames.iter().all(|frame| {
                (section.offset + frame.payload_offset - 16)
                    .is_multiple_of(AUTHENTICATED_CHUNK_BYTES)
            }));
        }
    }

    #[test]
    fn topology_delta_uses_authenticated_chunks_when_encryption_is_enabled() {
        if env::var_os(ENCRYPTED_HELPER_ENV).is_some() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("graph_tdelta::tests::encrypted_topology_delta_helper")
            .arg("--nocapture")
            .env(ENCRYPTED_HELPER_ENV, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(status.success(), "encrypted tdelta helper failed: {status}");
    }

    #[test]
    fn encrypted_topology_delta_helper() {
        let Some(root) = env::var_os(ENCRYPTED_HELPER_ENV) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let keyring_path = root.join("keyring.json");
        fs::write(
            &keyring_path,
            json!({
                "version": 1,
                "active_key_id": "g1-tdelta",
                "keys": [{
                    "id": "g1-tdelta",
                    "key_base64": STANDARD.encode([61_u8; 32]),
                }],
            })
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(&keyring_path).unwrap(),
            true,
        )
        .unwrap();
        let path = root.join(TOPOLOGY_DELTA_FILE);
        write(&path, &fixture()).unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], crate::encryption::MAGIC);
        let opened = open(&path, 99).unwrap();
        assert_eq!(opened.edge_count(), 4);
        assert_cursor_matches(&opened, &path);
        drop(opened);
        let mut ciphertext = fs::read(&path).unwrap();
        *ciphertext
            .last_mut()
            .expect("encrypted tdelta is non-empty") ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(open(&path, 99).is_err());
    }

    fn assert_cursor_matches(opened: &OpenedTopologyDelta, path: &Path) {
        for group in 0..opened.group_count() {
            let decoded = opened.read_group(path, group).unwrap();
            for (row, expected) in decoded.rows.iter().enumerate() {
                for (incoming, edges) in [(false, &expected.outgoing), (true, &expected.incoming)] {
                    let expected = edges
                        .iter()
                        .map(|edge| graph_group::AdjacencyEdge {
                            edge_id: edge.edge_id,
                            source: if incoming {
                                edge.neighbor_nid
                            } else {
                                expected.nid
                            },
                            target: if incoming {
                                expected.nid
                            } else {
                                edge.neighbor_nid
                            },
                            type_id: edge.type_id,
                            local_base: None,
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        opened
                            .edges(group, row as u32, incoming)
                            .unwrap()
                            .collect::<Result<Vec<_>>>()
                            .unwrap(),
                        expected
                    );
                }
            }
            assert!(
                opened
                    .edges(group, decoded.rows.len() as u32, false)
                    .is_err()
            );
        }
        assert!(opened.edges(opened.group_count(), 0, false).is_err());
    }

    fn repair_header_crc(bytes: &mut [u8]) {
        let section_count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let table_end = graph_artifact::COMMON_HEADER_BYTES
            + section_count * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        let mut crc_input = Vec::new();
        crc_input.extend_from_slice(&bytes[..28]);
        crc_input.extend_from_slice(&bytes[graph_artifact::COMMON_HEADER_BYTES..table_end]);
        bytes[28..32].copy_from_slice(&crc_fast::crc32_iscsi(&crc_input).to_le_bytes());
    }
}
