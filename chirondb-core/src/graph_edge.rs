//! `edge.gdx` base outgoing adjacency (Rev 3.4 Appendix C.2).

pub(crate) mod cursor;

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
        NamespaceInput, TaggedNeighbor, WIDTH_F32, WIDTH_OVERFLOW_CHAIN, WIDTH_TAGGED_NEIGHBOR,
        WIDTH_U16, WIDTH_U32, WIDTH_U64,
    },
    graph_nid::NidIndex,
};

pub(crate) const EDGE_FILE: &str = "edge.gdx";
pub(crate) const EDGE_MAGIC: &[u8; 8] = b"GAUSEG03";

const FLAG_CSC: u32 = 1;
const FLAG_OVERFLOW: u32 = 1 << 1;
const FLAG_WEIGHTS: u32 = 1 << 2;
const FLAG_TYPE_REMAP: u32 = 1 << 3;

const SECTION_TYPE_REMAP: u32 = 1;
const SECTION_NAMESPACE_INDEX: u32 = 2;
const SECTION_NODE_ORDS: u32 = 3;
const SECTION_OUT_OFFSETS: u32 = 4;
const SECTION_OUT_NEIGHBORS: u32 = 5;
const SECTION_OUT_EDGE_IDS: u32 = 6;
const SECTION_OUT_TYPES: u32 = 7;
const SECTION_OUT_WEIGHTS: u32 = 8;
const SECTION_IN_OFFSETS: u32 = 9;
const SECTION_IN_NEIGHBORS: u32 = 10;
const SECTION_IN_EDGE_IDS: u32 = 11;
const SECTION_IN_TYPES: u32 = 12;
const SECTION_IN_WEIGHTS: u32 = 13;
const SECTION_OVERFLOW: u32 = 14;

const OVERFLOW_DIRECTORY_HEADER_BYTES: usize = 8;
const OVERFLOW_CHAIN_RECORD_BYTES: usize = 32;
const OVERFLOW_CHUNK_HEADER_BYTES: usize = 16;
const OVERFLOW_CHUNK_PAYLOAD_BYTES: usize = AUTHENTICATED_CHUNK_BYTES - OVERFLOW_CHUNK_HEADER_BYTES;
const OVERFLOW_MAX_CHAIN_DEPTH: usize = 1_024;

const REQUIRED_BASE_OUT_SECTIONS: &[u32] = &[
    SECTION_NAMESPACE_INDEX,
    SECTION_NODE_ORDS,
    SECTION_OUT_OFFSETS,
    SECTION_OUT_NEIGHBORS,
    SECTION_OUT_EDGE_IDS,
    SECTION_OUT_TYPES,
];
const OPTIONAL_SECTIONS: &[u32] = &[
    SECTION_TYPE_REMAP,
    SECTION_OUT_WEIGHTS,
    SECTION_IN_OFFSETS,
    SECTION_IN_NEIGHBORS,
    SECTION_IN_EDGE_IDS,
    SECTION_IN_TYPES,
    SECTION_IN_WEIGHTS,
    SECTION_OVERFLOW,
];

const SPEC: ArtifactSpec = ArtifactSpec {
    magic: EDGE_MAGIC,
    allowed_flags: FLAG_CSC | FLAG_OVERFLOW | FLAG_WEIGHTS | FLAG_TYPE_REMAP,
    required_sections: REQUIRED_BASE_OUT_SECTIONS,
    optional_sections: OPTIONAL_SECTIONS,
    max_file_len: u64::MAX,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaseNeighborInput {
    LocalOrdinal(u32),
    GlobalNid(Nid),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct BaseEdgeInput {
    pub(crate) neighbor: BaseNeighborInput,
    pub(crate) edge_id: EdgeId,
    pub(crate) type_id: TypeId,
    pub(crate) weight: Option<f32>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BaseRowInput {
    pub(crate) node_ordinal: u32,
    pub(crate) outgoing: Vec<BaseEdgeInput>,
    pub(crate) incoming: Vec<BaseEdgeInput>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BaseGroupInput {
    pub(crate) namespace: GraphNamespace,
    pub(crate) rows: Vec<BaseRowInput>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct NormalizedBaseEdge {
    stored_neighbor: TaggedNeighbor,
    neighbor_nid: Nid,
    neighbor_ordinal: Option<u32>,
    edge_id: EdgeId,
    type_id: TypeId,
    weight: Option<f32>,
}

#[derive(Clone, Debug, PartialEq)]
struct NormalizedBaseRow {
    node_ordinal: u32,
    outgoing: Vec<NormalizedBaseEdge>,
    incoming: Vec<NormalizedBaseEdge>,
}

#[derive(Clone, Debug, PartialEq)]
struct NormalizedBaseGroup {
    namespace: GraphNamespace,
    rows: Vec<NormalizedBaseRow>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BaseAdjacency {
    groups: Vec<NormalizedBaseGroup>,
    include_csc: bool,
    type_remap: Option<Vec<TypeId>>,
    weighted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct DecodedBaseEdge {
    pub(crate) neighbor_nid: Nid,
    pub(crate) edge_id: EdgeId,
    pub(crate) type_id: TypeId,
    pub(crate) stored_neighbor: TaggedNeighbor,
    pub(crate) weight: Option<f32>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecodedBaseRow {
    pub(crate) node_ordinal: u32,
    pub(crate) outgoing: Vec<DecodedBaseEdge>,
    pub(crate) incoming: Vec<DecodedBaseEdge>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecodedBaseGroup {
    pub(crate) namespace: GraphNamespace,
    pub(crate) rows: Vec<DecodedBaseRow>,
}

pub(crate) struct OpenedBaseAdjacency {
    artifact: CheckedArtifact,
    namespaces: Vec<NamespaceDescriptor>,
    node_ords: GroupedSectionLayout,
    out_offsets: GroupedSectionLayout,
    out_neighbors: GroupedSectionLayout,
    out_edge_ids: GroupedSectionLayout,
    out_types: GroupedSectionLayout,
    out_weights: Option<GroupedSectionLayout>,
    in_offsets: Option<GroupedSectionLayout>,
    in_neighbors: Option<GroupedSectionLayout>,
    in_edge_ids: Option<GroupedSectionLayout>,
    in_types: Option<GroupedSectionLayout>,
    in_weights: Option<GroupedSectionLayout>,
    overflow: Option<GroupedSectionLayout>,
    type_remap: Option<Vec<TypeId>>,
    out_edge_count: u64,
    in_edge_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BaseDirection {
    Outgoing = 0,
    Incoming = 1,
}

impl BaseDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
        }
    }
}

#[derive(Clone, Debug)]
struct OverflowChainInput {
    row_index: u32,
    direction: BaseDirection,
    edges: Vec<NormalizedBaseEdge>,
}

#[derive(Debug)]
struct EncodedOverflow {
    chain_count: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct OverflowChainRecord {
    row_index: u32,
    direction: BaseDirection,
    first_chunk: u32,
    chunk_count: u32,
    total_entries: u32,
    total_bytes: u32,
}

#[derive(Debug)]
struct PackedOverflowChunk {
    payload: Vec<u8>,
    entry_count: u32,
}

impl BaseAdjacency {
    pub(crate) fn build(nid_index: &NidIndex, groups: Vec<BaseGroupInput>) -> Result<Self> {
        Self::build_with_options(nid_index, groups, false, false)
    }

    pub(crate) fn build_with_options(
        nid_index: &NidIndex,
        mut groups: Vec<BaseGroupInput>,
        include_csc: bool,
        use_type_remap: bool,
    ) -> Result<Self> {
        groups
            .sort_unstable_by(|left, right| compare_namespaces(&left.namespace, &right.namespace));
        if groups.windows(2).any(|pair| {
            compare_namespaces(&pair[0].namespace, &pair[1].namespace) != Ordering::Less
        }) {
            return Err(invalid("edge.gdx contains duplicate graph namespaces"));
        }

        let mut used_out_edge_ids = RoaringTreemap::new();
        let mut used_in_edge_ids = RoaringTreemap::new();
        let mut type_ids = BTreeSet::new();
        let mut weight_mode = None;
        let mut normalized_groups = Vec::with_capacity(groups.len());
        for mut group in groups {
            if group.rows.is_empty() {
                return Err(invalid("edge.gdx cannot persist an empty namespace group"));
            }
            group.rows.sort_unstable_by_key(|row| row.node_ordinal);
            if group
                .rows
                .windows(2)
                .any(|pair| pair[0].node_ordinal == pair[1].node_ordinal)
            {
                return Err(invalid("edge.gdx contains a duplicate node ordinal"));
            }
            let mut normalized_rows = Vec::with_capacity(group.rows.len());
            for row in group.rows {
                local_nid(nid_index, row.node_ordinal)?;
                if !include_csc && !row.incoming.is_empty() {
                    return Err(invalid("edge.gdx incoming rows require the CSC option"));
                }
                let outgoing = normalize_direction(
                    nid_index,
                    row.node_ordinal,
                    row.outgoing,
                    &mut used_out_edge_ids,
                    &mut type_ids,
                    &mut weight_mode,
                    "outgoing",
                )?;
                let incoming = normalize_direction(
                    nid_index,
                    row.node_ordinal,
                    row.incoming,
                    &mut used_in_edge_ids,
                    &mut type_ids,
                    &mut weight_mode,
                    "incoming",
                )?;
                normalized_rows.push(NormalizedBaseRow {
                    node_ordinal: row.node_ordinal,
                    outgoing,
                    incoming,
                });
            }
            normalized_groups.push(NormalizedBaseGroup {
                namespace: group.namespace,
                rows: normalized_rows,
            });
        }
        if include_csc {
            validate_local_mirrors(&normalized_groups)?;
        }
        for (label, count) in [
            (
                "outgoing",
                normalized_groups
                    .iter()
                    .flat_map(|group| &group.rows)
                    .map(|row| row.outgoing.len() as u64)
                    .sum::<u64>(),
            ),
            (
                "incoming",
                normalized_groups
                    .iter()
                    .flat_map(|group| &group.rows)
                    .map(|row| row.incoming.len() as u64)
                    .sum::<u64>(),
            ),
        ] {
            if count > u32::MAX as u64 {
                return Err(invalid(format!(
                    "edge.gdx {label} entries exceed the per-fragment u32 cap"
                )));
            }
        }
        let type_remap = if use_type_remap {
            if type_ids.is_empty() {
                return Err(invalid("edge.gdx cannot emit an empty type remap"));
            }
            if type_ids.len() > u16::MAX as usize + 1 {
                return Err(invalid("edge.gdx type remap exceeds 65,536 entries"));
            }
            Some(type_ids.into_iter().collect())
        } else {
            None
        };
        Ok(Self {
            groups: normalized_groups,
            include_csc,
            type_remap,
            weighted: weight_mode.unwrap_or(false),
        })
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn edge_count(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|group| &group.rows)
            .map(|row| row.outgoing.len() as u64)
            .sum()
    }

    pub(crate) fn incoming_edge_count(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|group| &group.rows)
            .map(|row| row.incoming.len() as u64)
            .sum()
    }
}

pub(crate) fn write(path: &Path, adjacency: &BaseAdjacency) -> Result<()> {
    let namespace_inputs = adjacency
        .groups
        .iter()
        .map(|group| {
            Ok(NamespaceInput {
                namespace: group.namespace.clone(),
                row_count: u32::try_from(group.rows.len())
                    .map_err(|_| invalid("edge.gdx namespace row count exceeds u32"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let namespace_index = graph_group::encode_namespace_index(&namespace_inputs)?;

    let mut node_counts = Vec::with_capacity(adjacency.groups.len());
    let mut node_groups = Vec::with_capacity(adjacency.groups.len());
    for group in &adjacency.groups {
        node_counts.push(group.rows.len() as u64);
        node_groups.push(
            group
                .rows
                .iter()
                .flat_map(|row| row.node_ordinal.to_le_bytes())
                .collect::<Vec<_>>(),
        );
    }
    let node_ords = encode_grouped(WIDTH_U32, &node_counts, &node_groups)?;
    let type_codes = adjacency.type_remap.as_ref().map(|types| {
        types
            .iter()
            .enumerate()
            .map(|(index, type_id)| (type_id.raw(), index as u16))
            .collect::<BTreeMap<_, _>>()
    });
    let outgoing = encode_direction(
        &adjacency.groups,
        |row| &row.outgoing,
        BaseDirection::Outgoing,
        type_codes.as_ref(),
        adjacency.weighted,
    )?;
    let incoming = adjacency
        .include_csc
        .then(|| {
            encode_direction(
                &adjacency.groups,
                |row| &row.incoming,
                BaseDirection::Incoming,
                type_codes.as_ref(),
                adjacency.weighted,
            )
        })
        .transpose()?;
    let overflow = encode_overflow_section(
        adjacency.groups.len(),
        &outgoing.overflow_groups,
        incoming
            .as_ref()
            .map(|direction| direction.overflow_groups.as_slice()),
        type_codes.as_ref(),
        adjacency.weighted,
    )?;
    let total_rows = node_counts.iter().try_fold(0_u64, |total, count| {
        total
            .checked_add(*count)
            .ok_or_else(|| invalid("edge.gdx total row count overflow"))
    })?;
    let type_remap_bytes = adjacency.type_remap.as_ref().map(|types| {
        types
            .iter()
            .flat_map(|type_id| type_id.raw().to_le_bytes())
            .collect::<Vec<_>>()
    });
    let mut sections = Vec::new();
    if let Some(bytes) = type_remap_bytes.as_deref() {
        sections.push(SectionPayload {
            id: SECTION_TYPE_REMAP,
            elem_count: adjacency
                .type_remap
                .as_ref()
                .expect("remap bytes exist")
                .len() as u64,
            bytes,
        });
    }
    sections.extend([
        SectionPayload {
            id: SECTION_NAMESPACE_INDEX,
            elem_count: adjacency.groups.len() as u64,
            bytes: &namespace_index,
        },
        SectionPayload {
            id: SECTION_NODE_ORDS,
            elem_count: total_rows,
            bytes: &node_ords,
        },
        SectionPayload {
            id: SECTION_OUT_OFFSETS,
            elem_count: outgoing.offset_count,
            bytes: &outgoing.offsets,
        },
        SectionPayload {
            id: SECTION_OUT_NEIGHBORS,
            elem_count: outgoing.edge_count,
            bytes: &outgoing.neighbors,
        },
        SectionPayload {
            id: SECTION_OUT_EDGE_IDS,
            elem_count: outgoing.edge_count,
            bytes: &outgoing.edge_ids,
        },
        SectionPayload {
            id: SECTION_OUT_TYPES,
            elem_count: outgoing.edge_count,
            bytes: &outgoing.types,
        },
    ]);
    if let Some(bytes) = outgoing.weights.as_deref() {
        sections.push(SectionPayload {
            id: SECTION_OUT_WEIGHTS,
            elem_count: outgoing.edge_count,
            bytes,
        });
    }
    if let Some(incoming) = incoming.as_ref() {
        sections.extend([
            SectionPayload {
                id: SECTION_IN_OFFSETS,
                elem_count: incoming.offset_count,
                bytes: &incoming.offsets,
            },
            SectionPayload {
                id: SECTION_IN_NEIGHBORS,
                elem_count: incoming.edge_count,
                bytes: &incoming.neighbors,
            },
            SectionPayload {
                id: SECTION_IN_EDGE_IDS,
                elem_count: incoming.edge_count,
                bytes: &incoming.edge_ids,
            },
            SectionPayload {
                id: SECTION_IN_TYPES,
                elem_count: incoming.edge_count,
                bytes: &incoming.types,
            },
        ]);
        if let Some(bytes) = incoming.weights.as_deref() {
            sections.push(SectionPayload {
                id: SECTION_IN_WEIGHTS,
                elem_count: incoming.edge_count,
                bytes,
            });
        }
    }
    if let Some(overflow) = overflow.as_ref() {
        sections.push(SectionPayload {
            id: SECTION_OVERFLOW,
            elem_count: overflow.chain_count,
            bytes: &overflow.bytes,
        });
    }
    sections.sort_unstable_by_key(|section| section.id);
    let flags = if adjacency.include_csc { FLAG_CSC } else { 0 }
        | if adjacency.weighted { FLAG_WEIGHTS } else { 0 }
        | if adjacency.type_remap.is_some() {
            FLAG_TYPE_REMAP
        } else {
            0
        }
        | if overflow.is_some() { FLAG_OVERFLOW } else { 0 };
    let mut alignments = vec![
        (SECTION_NODE_ORDS, AUTHENTICATED_CHUNK_BYTES),
        (SECTION_OUT_OFFSETS, AUTHENTICATED_CHUNK_BYTES),
        (SECTION_OUT_NEIGHBORS, AUTHENTICATED_CHUNK_BYTES),
        (SECTION_OUT_EDGE_IDS, AUTHENTICATED_CHUNK_BYTES),
        (SECTION_OUT_TYPES, AUTHENTICATED_CHUNK_BYTES),
    ];
    if adjacency.weighted {
        alignments.push((SECTION_OUT_WEIGHTS, AUTHENTICATED_CHUNK_BYTES));
    }
    if adjacency.include_csc {
        alignments.extend([
            (SECTION_IN_OFFSETS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_NEIGHBORS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_EDGE_IDS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_IN_TYPES, AUTHENTICATED_CHUNK_BYTES),
        ]);
        if adjacency.weighted {
            alignments.push((SECTION_IN_WEIGHTS, AUTHENTICATED_CHUNK_BYTES));
        }
    }
    if overflow.is_some() {
        alignments.push((SECTION_OVERFLOW, AUTHENTICATED_CHUNK_BYTES));
    }
    graph_artifact::write_aligned(path, SPEC, flags, &sections, &alignments)
}

pub(crate) fn open(path: &Path, nid_index: &NidIndex) -> Result<OpenedBaseAdjacency> {
    let artifact = graph_artifact::open(path, SPEC)?;
    let has_csc = artifact.flags() & FLAG_CSC != 0;
    let has_overflow = artifact.flags() & FLAG_OVERFLOW != 0;
    let has_weights = artifact.flags() & FLAG_WEIGHTS != 0;
    let has_type_remap = artifact.flags() & FLAG_TYPE_REMAP != 0;
    let csc_sections = [
        SECTION_IN_OFFSETS,
        SECTION_IN_NEIGHBORS,
        SECTION_IN_EDGE_IDS,
        SECTION_IN_TYPES,
    ];
    if csc_sections
        .iter()
        .any(|section| artifact.section(*section).is_some())
        != has_csc
        || artifact.section(SECTION_TYPE_REMAP).is_some() != has_type_remap
        || artifact.section(SECTION_OVERFLOW).is_some() != has_overflow
        || artifact.section(SECTION_OUT_WEIGHTS).is_some() != has_weights
        || artifact.section(SECTION_IN_WEIGHTS).is_some() != (has_csc && has_weights)
    {
        return Err(corruption(
            path,
            "edge.gdx optional flags and sections disagree",
        ));
    }
    let type_remap = if has_type_remap {
        Some(decode_type_remap(path, &artifact)?)
    } else {
        None
    };
    let type_width = if has_type_remap { WIDTH_U16 } else { WIDTH_U32 };
    let namespace_section = artifact
        .section(SECTION_NAMESPACE_INDEX)
        .expect("common loader requires edge namespace index");
    let namespaces = graph_group::decode_namespace_index(
        path,
        &artifact.read_section(SECTION_NAMESPACE_INDEX)?,
    )?;
    if namespace_section.elem_count != namespaces.len() as u64 {
        return Err(corruption(
            path,
            "edge.gdx namespace count disagrees with section table",
        ));
    }
    if namespaces.iter().any(|namespace| namespace.row_count == 0) {
        return Err(corruption(
            path,
            "edge.gdx contains an empty namespace group",
        ));
    }
    let group_count = namespaces.len();
    let node_ords = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_NODE_ORDS,
        group_count,
        WIDTH_U32,
    )?;
    let out_offsets = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_OUT_OFFSETS,
        group_count,
        WIDTH_U64,
    )?;
    let out_neighbors = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_OUT_NEIGHBORS,
        group_count,
        WIDTH_TAGGED_NEIGHBOR,
    )?;
    let out_edge_ids = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_OUT_EDGE_IDS,
        group_count,
        WIDTH_U64,
    )?;
    let out_types = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_OUT_TYPES,
        group_count,
        type_width,
    )?;
    let out_weights = has_weights
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_OUT_WEIGHTS,
                group_count,
                WIDTH_F32,
            )
        })
        .transpose()?;
    let in_offsets = has_csc
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_IN_OFFSETS,
                group_count,
                WIDTH_U64,
            )
        })
        .transpose()?;
    let in_neighbors = has_csc
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_IN_NEIGHBORS,
                group_count,
                WIDTH_TAGGED_NEIGHBOR,
            )
        })
        .transpose()?;
    let in_edge_ids = has_csc
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_IN_EDGE_IDS,
                group_count,
                WIDTH_U64,
            )
        })
        .transpose()?;
    let in_types = has_csc
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_IN_TYPES,
                group_count,
                type_width,
            )
        })
        .transpose()?;
    let in_weights = (has_csc && has_weights)
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_IN_WEIGHTS,
                group_count,
                WIDTH_F32,
            )
        })
        .transpose()?;
    let overflow = has_overflow
        .then(|| {
            graph_group::open_grouped_section(
                path,
                &artifact,
                SECTION_OVERFLOW,
                group_count,
                WIDTH_OVERFLOW_CHAIN,
            )
        })
        .transpose()?;
    if has_overflow
        && overflow
            .as_ref()
            .is_none_or(|layout| layout.semantic_elem_count == 0)
    {
        return Err(corruption(
            path,
            "edge.gdx overflow flag requires at least one chain",
        ));
    }

    let mut opened = OpenedBaseAdjacency {
        artifact,
        namespaces,
        node_ords,
        out_offsets,
        out_neighbors,
        out_edge_ids,
        out_types,
        out_weights,
        in_offsets,
        in_neighbors,
        in_edge_ids,
        in_types,
        in_weights,
        overflow,
        type_remap,
        out_edge_count: 0,
        in_edge_count: 0,
    };
    let mut seen_out_edge_ids = RoaringTreemap::new();
    let mut seen_in_edge_ids = RoaringTreemap::new();
    let mut decoded_groups = Vec::with_capacity(opened.namespaces.len());
    let mut out_edge_count = 0_u64;
    let mut in_edge_count = 0_u64;
    for group_index in 0..opened.namespaces.len() {
        let group = opened.decode_group(path, nid_index, group_index)?;
        out_edge_count = group.rows.iter().try_fold(out_edge_count, |total, row| {
            total
                .checked_add(row.outgoing.len() as u64)
                .ok_or_else(|| corruption(path, "edge.gdx outgoing edge count overflow"))
        })?;
        in_edge_count = group.rows.iter().try_fold(in_edge_count, |total, row| {
            total
                .checked_add(row.incoming.len() as u64)
                .ok_or_else(|| corruption(path, "edge.gdx incoming edge count overflow"))
        })?;
        for edge in group.rows.iter().flat_map(|row| &row.outgoing) {
            if !seen_out_edge_ids.insert(edge.edge_id.raw()) {
                return Err(corruption(
                    path,
                    "edge.gdx contains a duplicate outgoing EdgeId",
                ));
            }
        }
        for edge in group.rows.iter().flat_map(|row| &row.incoming) {
            if !seen_in_edge_ids.insert(edge.edge_id.raw()) {
                return Err(corruption(
                    path,
                    "edge.gdx contains a duplicate incoming EdgeId",
                ));
            }
        }
        decoded_groups.push(group);
    }
    opened.out_edge_count = out_edge_count;
    opened.in_edge_count = in_edge_count;
    if has_csc {
        validate_decoded_local_mirrors(path, nid_index, &decoded_groups)?;
    }
    if let Some(remap) = &opened.type_remap {
        let used = decoded_groups
            .iter()
            .flat_map(|group| &group.rows)
            .flat_map(|row| row.outgoing.iter().chain(&row.incoming))
            .map(|edge| edge.type_id.raw())
            .collect::<BTreeSet<_>>();
        if used.len() != remap.len() || remap.iter().any(|type_id| !used.contains(&type_id.raw())) {
            return Err(corruption(
                path,
                "edge.gdx type remap contains an unused entry",
            ));
        }
    }
    Ok(opened)
}

impl OpenedBaseAdjacency {
    pub(crate) fn namespaces(&self) -> &[NamespaceDescriptor] {
        &self.namespaces
    }

    pub(crate) fn row_nid(&self, nids: &NidIndex, group: usize, row: u32) -> Result<Nid> {
        local_nid(nids, self.row_ordinal(group, row)?)
    }

    fn row_ordinal(&self, group: usize, row: u32) -> Result<u32> {
        Ok(u32::from_le_bytes(graph_group::read_fixed(
            &self.artifact,
            SECTION_NODE_ORDS,
            &self.node_ords,
            group,
            row,
        )?))
    }

    pub(crate) fn find_row(
        &self,
        nids: &NidIndex,
        namespace: &GraphNamespace,
        nid: Nid,
    ) -> Result<Option<u32>> {
        let Some(ordinal) = nids.lookup(nid) else {
            return Ok(None);
        };
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
            match self.row_ordinal(group, mid)?.cmp(&ordinal) {
                Ordering::Less => lower = mid + 1,
                Ordering::Greater => upper = mid,
                Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }

    pub(crate) fn group_count(&self) -> usize {
        self.namespaces.len()
    }

    pub(crate) fn edge_count(&self) -> u64 {
        self.out_edge_count
    }

    pub(crate) fn incoming_edge_count(&self) -> u64 {
        self.in_edge_count
    }

    pub(crate) fn read_group(
        &self,
        path: &Path,
        nid_index: &NidIndex,
        group_index: usize,
    ) -> Result<DecodedBaseGroup> {
        self.decode_group(path, nid_index, group_index)
    }

    fn decode_group(
        &self,
        path: &Path,
        nid_index: &NidIndex,
        group_index: usize,
    ) -> Result<DecodedBaseGroup> {
        let namespace = self
            .namespaces
            .get(group_index)
            .ok_or_else(|| invalid("edge.gdx namespace group index is out of bounds"))?;
        let node_bytes = graph_group::read_group(
            &self.artifact,
            SECTION_NODE_ORDS,
            &self.node_ords,
            group_index,
        )?;
        let node_ordinals = decode_u32s(&node_bytes);
        if node_ordinals.len() != namespace.row_count as usize
            || self.node_ords.frames[group_index].elem_count != namespace.row_count as u64
            || node_ordinals.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(corruption(path, "edge.gdx node ordinals are invalid"));
        }
        for ordinal in &node_ordinals {
            local_nid(nid_index, *ordinal).map_err(|error| corruption(path, &error.to_string()))?;
        }

        let mut outgoing = self.decode_direction(
            path,
            nid_index,
            group_index,
            &node_ordinals,
            DirectionSections {
                label: "outgoing",
                offsets_id: SECTION_OUT_OFFSETS,
                neighbors_id: SECTION_OUT_NEIGHBORS,
                edge_ids_id: SECTION_OUT_EDGE_IDS,
                types_id: SECTION_OUT_TYPES,
                weights_id: self.out_weights.as_ref().map(|_| SECTION_OUT_WEIGHTS),
                offsets: &self.out_offsets,
                neighbors: &self.out_neighbors,
                edge_ids: &self.out_edge_ids,
                types: &self.out_types,
                weights: self.out_weights.as_ref(),
            },
        )?;
        let mut incoming = if let (Some(offsets), Some(neighbors), Some(edge_ids), Some(types)) = (
            self.in_offsets.as_ref(),
            self.in_neighbors.as_ref(),
            self.in_edge_ids.as_ref(),
            self.in_types.as_ref(),
        ) {
            self.decode_direction(
                path,
                nid_index,
                group_index,
                &node_ordinals,
                DirectionSections {
                    label: "incoming",
                    offsets_id: SECTION_IN_OFFSETS,
                    neighbors_id: SECTION_IN_NEIGHBORS,
                    edge_ids_id: SECTION_IN_EDGE_IDS,
                    types_id: SECTION_IN_TYPES,
                    weights_id: self.in_weights.as_ref().map(|_| SECTION_IN_WEIGHTS),
                    offsets,
                    neighbors,
                    edge_ids,
                    types,
                    weights: self.in_weights.as_ref(),
                },
            )?
        } else {
            vec![Vec::new(); node_ordinals.len()]
        };
        let chain_presence = self.decode_overflow_group(
            path,
            nid_index,
            group_index,
            &node_ordinals,
            &mut outgoing,
            &mut incoming,
        )?;
        validate_row_chunking(
            path,
            &outgoing,
            &incoming,
            &chain_presence,
            self.type_remap.is_some(),
            self.out_weights.is_some(),
        )?;
        let rows = node_ordinals
            .into_iter()
            .zip(outgoing)
            .zip(incoming)
            .map(|((node_ordinal, outgoing), incoming)| DecodedBaseRow {
                node_ordinal,
                outgoing,
                incoming,
            })
            .collect();
        Ok(DecodedBaseGroup {
            namespace: namespace.namespace.clone(),
            rows,
        })
    }

    fn decode_direction(
        &self,
        path: &Path,
        nid_index: &NidIndex,
        group_index: usize,
        node_ordinals: &[u32],
        sections: DirectionSections<'_>,
    ) -> Result<Vec<Vec<DecodedBaseEdge>>> {
        let offsets = decode_u64s(&graph_group::read_group(
            &self.artifact,
            sections.offsets_id,
            sections.offsets,
            group_index,
        )?);
        if sections.offsets.frames[group_index].elem_count != node_ordinals.len() as u64 + 1
            || offsets.len() != node_ordinals.len() + 1
            || offsets.first().copied() != Some(0)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
        {
            return Err(corruption(
                path,
                &format!("edge.gdx {} offsets are invalid", sections.label),
            ));
        }
        let edge_count = offsets.last().copied().unwrap_or(0);
        if [
            sections.neighbors.frames[group_index].elem_count,
            sections.edge_ids.frames[group_index].elem_count,
            sections.types.frames[group_index].elem_count,
        ]
        .iter()
        .any(|count| *count != edge_count)
            || sections
                .weights
                .is_some_and(|weights| weights.frames[group_index].elem_count != edge_count)
        {
            return Err(corruption(
                path,
                &format!("edge.gdx {} parallel counts disagree", sections.label),
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
        let type_bytes = graph_group::read_group(
            &self.artifact,
            sections.types_id,
            sections.types,
            group_index,
        )?;
        let types = if let Some(remap) = &self.type_remap {
            decode_u16s(&type_bytes)
                .into_iter()
                .map(|local| {
                    remap
                        .get(local as usize)
                        .copied()
                        .ok_or_else(|| corruption(path, "edge.gdx local type code exceeds remap"))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            decode_u32s(&type_bytes)
                .into_iter()
                .map(TypeId::from_raw)
                .collect()
        };
        let weights = if let (Some(id), Some(layout)) = (sections.weights_id, sections.weights) {
            Some(decode_f32s(&graph_group::read_group(
                &self.artifact,
                id,
                layout,
                group_index,
            )?))
        } else {
            None
        };
        if edge_ids.len() != neighbors.len()
            || types.len() != neighbors.len()
            || weights
                .as_ref()
                .is_some_and(|values| values.len() != neighbors.len())
        {
            return Err(corruption(
                path,
                &format!("edge.gdx {} payload widths disagree", sections.label),
            ));
        }

        let mut rows = Vec::with_capacity(node_ordinals.len());
        for (row_index, node_ordinal) in node_ordinals.iter().copied().enumerate() {
            let start = usize::try_from(offsets[row_index])
                .map_err(|_| corruption(path, "edge.gdx row start exceeds usize"))?;
            let end = usize::try_from(offsets[row_index + 1])
                .map_err(|_| corruption(path, "edge.gdx row end exceeds usize"))?;
            if end > neighbors.len() {
                return Err(corruption(path, "edge.gdx row exceeds direction arrays"));
            }
            let mut edges = Vec::with_capacity(end - start);
            for index in start..end {
                let edge_id = EdgeId::from_raw(edge_ids[index]);
                validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
                let type_id = types[index];
                validate_type_id(type_id).map_err(|error| corruption(path, &error.to_string()))?;
                let neighbor_nid =
                    resolve_neighbor(path, nid_index, node_ordinal, neighbors[index])?;
                edges.push(DecodedBaseEdge {
                    neighbor_nid,
                    edge_id,
                    type_id,
                    stored_neighbor: neighbors[index],
                    weight: weights.as_ref().map(|values| values[index]),
                });
            }
            if edges
                .windows(2)
                .any(|pair| decoded_edge_sort_key(&pair[0]) >= decoded_edge_sort_key(&pair[1]))
            {
                return Err(corruption(
                    path,
                    &format!(
                        "edge.gdx {} row is not sorted by type, Nid, and EdgeId",
                        sections.label
                    ),
                ));
            }
            rows.push(edges);
        }
        Ok(rows)
    }

    fn decode_overflow_group(
        &self,
        path: &Path,
        nid_index: &NidIndex,
        group_index: usize,
        node_ordinals: &[u32],
        outgoing: &mut [Vec<DecodedBaseEdge>],
        incoming: &mut [Vec<DecodedBaseEdge>],
    ) -> Result<BTreeMap<(u32, BaseDirection), usize>> {
        let Some(layout) = &self.overflow else {
            return Ok(BTreeMap::new());
        };
        let frame = layout
            .frames
            .get(group_index)
            .ok_or_else(|| corruption(path, "edge.gdx overflow group index is invalid"))?;
        if frame.payload_len < OVERFLOW_DIRECTORY_HEADER_BYTES {
            return Err(corruption(path, "truncated edge.gdx overflow directory"));
        }
        let header_end = frame
            .payload_offset
            .checked_add(OVERFLOW_DIRECTORY_HEADER_BYTES)
            .ok_or_else(|| corruption(path, "edge.gdx overflow header range overflows"))?;
        let header = self
            .artifact
            .read_section_range(SECTION_OVERFLOW, frame.payload_offset..header_end)?;
        let chain_count = read_u32_at(path, &header, 0, "overflow chain count")? as usize;
        let max_chains = node_ordinals
            .len()
            .checked_mul(if self.in_offsets.is_some() { 2 } else { 1 })
            .ok_or_else(|| corruption(path, "edge.gdx overflow chain bound overflows"))?;
        if read_u32_at(path, &header, 4, "overflow reserved header")? != 0
            || frame.elem_count != chain_count as u64
            || chain_count > max_chains
        {
            return Err(corruption(
                path,
                "edge.gdx overflow directory metadata disagrees",
            ));
        }
        if chain_count == 0 {
            if frame.payload_len != OVERFLOW_DIRECTORY_HEADER_BYTES {
                return Err(corruption(
                    path,
                    "empty edge.gdx overflow group is non-canonical",
                ));
            }
            return Ok(BTreeMap::new());
        }
        let records_len = chain_count
            .checked_mul(OVERFLOW_CHAIN_RECORD_BYTES)
            .ok_or_else(|| corruption(path, "edge.gdx overflow directory length overflows"))?;
        let directory_end = OVERFLOW_DIRECTORY_HEADER_BYTES
            .checked_add(records_len)
            .ok_or_else(|| corruption(path, "edge.gdx overflow directory end overflows"))?;
        if directory_end > frame.payload_len {
            return Err(corruption(path, "truncated edge.gdx overflow records"));
        }
        let records_end = frame
            .payload_offset
            .checked_add(directory_end)
            .ok_or_else(|| corruption(path, "edge.gdx overflow record range overflows"))?;
        let records_bytes = self
            .artifact
            .read_section_range(SECTION_OVERFLOW, header_end..records_end)?;
        let mut records = Vec::with_capacity(chain_count);
        let mut expected_first_chunk = 0_u32;
        let mut previous_key = None;
        for raw in records_bytes.chunks_exact(OVERFLOW_CHAIN_RECORD_BYTES) {
            let direction = match raw[4] {
                0 => BaseDirection::Outgoing,
                1 if self.in_offsets.is_some() => BaseDirection::Incoming,
                _ => return Err(corruption(path, "edge.gdx overflow direction is invalid")),
            };
            if raw[5] != 0
                || u16::from_le_bytes(raw[6..8].try_into().expect("overflow reserved width")) != 0
                || u64::from_le_bytes(raw[24..32].try_into().expect("overflow reserved width")) != 0
            {
                return Err(corruption(
                    path,
                    "edge.gdx overflow chain reserved fields are non-zero",
                ));
            }
            let record = OverflowChainRecord {
                row_index: read_u32_at(path, raw, 0, "overflow row index")?,
                direction,
                first_chunk: read_u32_at(path, raw, 8, "overflow first chunk")?,
                chunk_count: read_u32_at(path, raw, 12, "overflow chunk count")?,
                total_entries: read_u32_at(path, raw, 16, "overflow entry total")?,
                total_bytes: read_u32_at(path, raw, 20, "overflow byte total")?,
            };
            if record.row_index as usize >= node_ordinals.len()
                || record.chunk_count == 0
                || record.chunk_count as usize > OVERFLOW_MAX_CHAIN_DEPTH
                || record.total_entries == 0
                || record.total_bytes == 0
                || record.first_chunk != expected_first_chunk
            {
                return Err(corruption(
                    path,
                    "edge.gdx overflow chain record is invalid",
                ));
            }
            let maximum_bytes = (record.chunk_count as u64)
                .checked_mul(OVERFLOW_CHUNK_PAYLOAD_BYTES as u64)
                .ok_or_else(|| corruption(path, "edge.gdx overflow byte bound overflows"))?;
            if u64::from(record.total_bytes) > maximum_bytes
                || u64::from(record.total_entries) > u64::from(record.total_bytes) / 12
            {
                return Err(corruption(
                    path,
                    "edge.gdx overflow chain totals exceed structural bounds",
                ));
            }
            let key = (record.row_index, record.direction);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(corruption(
                    path,
                    "edge.gdx overflow chain records are not canonical",
                ));
            }
            expected_first_chunk = expected_first_chunk
                .checked_add(record.chunk_count)
                .ok_or_else(|| corruption(path, "edge.gdx overflow chunk count overflows"))?;
            previous_key = Some(key);
            records.push(record);
        }
        let arena_offset = overflow_arena_payload_offset(directory_end)
            .map_err(|error| corruption(path, &error.to_string()))?;
        if arena_offset > frame.payload_len {
            return Err(corruption(
                path,
                "edge.gdx overflow arena offset exceeds group",
            ));
        }
        let arena_start = frame
            .payload_offset
            .checked_add(arena_offset)
            .ok_or_else(|| corruption(path, "edge.gdx overflow arena range overflows"))?;
        let padding = self
            .artifact
            .read_section_range(SECTION_OVERFLOW, records_end..arena_start)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(corruption(
                path,
                "edge.gdx overflow directory padding is non-zero",
            ));
        }
        let arena_len = (expected_first_chunk as usize)
            .checked_mul(AUTHENTICATED_CHUNK_BYTES)
            .ok_or_else(|| corruption(path, "edge.gdx overflow arena length overflows"))?;
        if arena_offset.checked_add(arena_len) != Some(frame.payload_len) {
            return Err(corruption(path, "edge.gdx overflow arena length disagrees"));
        }

        let mut presence = BTreeMap::new();
        for record in records {
            let row_index = record.row_index as usize;
            let inline_count = match record.direction {
                BaseDirection::Outgoing => outgoing[row_index].len(),
                BaseDirection::Incoming => incoming[row_index].len(),
            };
            if presence
                .insert((record.row_index, record.direction), inline_count)
                .is_some()
            {
                return Err(corruption(path, "duplicate edge.gdx overflow chain"));
            }
            let mut decoded = Vec::new();
            let mut decoded_bytes = 0_u32;
            let mut previous_chunk_len = None;
            for chain_index in 0..record.chunk_count {
                let chunk_index = record
                    .first_chunk
                    .checked_add(chain_index)
                    .ok_or_else(|| corruption(path, "edge.gdx overflow chunk index overflows"))?;
                let chunk_offset = arena_start
                    .checked_add(
                        (chunk_index as usize)
                            .checked_mul(AUTHENTICATED_CHUNK_BYTES)
                            .ok_or_else(|| {
                                corruption(path, "edge.gdx overflow chunk range overflows")
                            })?,
                    )
                    .ok_or_else(|| corruption(path, "edge.gdx overflow chunk offset overflows"))?;
                let chunk_end = chunk_offset
                    .checked_add(AUTHENTICATED_CHUNK_BYTES)
                    .ok_or_else(|| corruption(path, "edge.gdx overflow chunk end overflows"))?;
                let chunk = self
                    .artifact
                    .read_section_range(SECTION_OVERFLOW, chunk_offset..chunk_end)?;
                let expected_next = if chain_index + 1 == record.chunk_count {
                    u32::MAX
                } else {
                    chunk_index + 1
                };
                let next_chunk = read_u32_at(path, &chunk, 0, "overflow next chunk")?;
                let entry_count = read_u32_at(path, &chunk, 4, "overflow chunk entries")?;
                let byte_len = read_u32_at(path, &chunk, 8, "overflow chunk bytes")? as usize;
                if next_chunk != expected_next
                    || entry_count == 0
                    || byte_len == 0
                    || byte_len > OVERFLOW_CHUNK_PAYLOAD_BYTES
                    || read_u32_at(path, &chunk, 12, "overflow chunk reserved")? != 0
                {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chunk header is invalid",
                    ));
                }
                if entry_count as usize > byte_len / 12 {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chunk entry count exceeds its bytes",
                    ));
                }
                let payload_end = OVERFLOW_CHUNK_HEADER_BYTES
                    .checked_add(byte_len)
                    .ok_or_else(|| corruption(path, "edge.gdx overflow payload end overflows"))?;
                if chunk[payload_end..].iter().any(|byte| *byte != 0) {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chunk padding is non-zero",
                    ));
                }
                let payload = &chunk[OVERFLOW_CHUNK_HEADER_BYTES..payload_end];
                let mut cursor = 0_usize;
                let first_before = decoded.len();
                for _ in 0..entry_count {
                    let remaining = payload.get(cursor..).ok_or_else(|| {
                        corruption(path, "edge.gdx overflow tuple cursor exceeds chunk")
                    })?;
                    let (edge, consumed) = decode_overflow_tuple(
                        path,
                        nid_index,
                        node_ordinals[row_index],
                        remaining,
                        self.type_remap.as_deref(),
                        self.out_weights.is_some(),
                    )?;
                    cursor = cursor.checked_add(consumed).ok_or_else(|| {
                        corruption(path, "edge.gdx overflow tuple cursor overflows")
                    })?;
                    decoded.push(edge);
                }
                if cursor != payload.len() || decoded.len() == first_before {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chunk tuple bytes disagree",
                    ));
                }
                let first_tuple_len = tuple_encoded_len(
                    path,
                    &decoded[first_before],
                    self.type_remap.is_some(),
                    self.out_weights.is_some(),
                )?;
                if previous_chunk_len.is_some_and(|previous| {
                    previous + first_tuple_len <= OVERFLOW_CHUNK_PAYLOAD_BYTES
                }) {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chunks are not greedily packed",
                    ));
                }
                previous_chunk_len = Some(byte_len);
                decoded_bytes = decoded_bytes
                    .checked_add(byte_len as u32)
                    .ok_or_else(|| corruption(path, "edge.gdx overflow byte total overflows"))?;
            }
            if decoded.len() != record.total_entries as usize || decoded_bytes != record.total_bytes
            {
                return Err(corruption(path, "edge.gdx overflow chain totals disagree"));
            }
            match record.direction {
                BaseDirection::Outgoing => outgoing[row_index].extend(decoded),
                BaseDirection::Incoming => incoming[row_index].extend(decoded),
            }
        }
        Ok(presence)
    }
}

struct EncodedDirection {
    edge_count: u64,
    offset_count: u64,
    offsets: Vec<u8>,
    neighbors: Vec<u8>,
    edge_ids: Vec<u8>,
    types: Vec<u8>,
    weights: Option<Vec<u8>>,
    overflow_groups: Vec<Vec<OverflowChainInput>>,
}

struct DirectionSections<'a> {
    label: &'static str,
    offsets_id: u32,
    neighbors_id: u32,
    edge_ids_id: u32,
    types_id: u32,
    weights_id: Option<u32>,
    offsets: &'a GroupedSectionLayout,
    neighbors: &'a GroupedSectionLayout,
    edge_ids: &'a GroupedSectionLayout,
    types: &'a GroupedSectionLayout,
    weights: Option<&'a GroupedSectionLayout>,
}

fn encode_direction(
    groups: &[NormalizedBaseGroup],
    rows: impl Fn(&NormalizedBaseRow) -> &[NormalizedBaseEdge],
    direction: BaseDirection,
    type_codes: Option<&BTreeMap<u32, u16>>,
    weighted: bool,
) -> Result<EncodedDirection> {
    let mut edge_counts = Vec::with_capacity(groups.len());
    let mut offset_counts = Vec::with_capacity(groups.len());
    let mut offset_groups = Vec::with_capacity(groups.len());
    let mut neighbor_groups = Vec::with_capacity(groups.len());
    let mut edge_id_groups = Vec::with_capacity(groups.len());
    let mut type_groups = Vec::with_capacity(groups.len());
    let mut weight_groups = Vec::with_capacity(groups.len());
    let mut overflow_groups = Vec::with_capacity(groups.len());
    for group in groups {
        let mut offsets = vec![0_u64];
        let mut neighbors = Vec::new();
        let mut edge_ids = Vec::new();
        let mut types = Vec::new();
        let mut weights = Vec::new();
        let mut overflow_chains = Vec::new();
        for (row_index, row) in group.rows.iter().enumerate() {
            let row_edges = rows(row);
            let inline_count = maximal_edge_prefix(row_edges, type_codes.is_some(), weighted)?;
            for edge in &row_edges[..inline_count] {
                neighbors.push(edge.stored_neighbor);
                edge_ids.extend_from_slice(&edge.edge_id.raw().to_le_bytes());
                if let Some(codes) = type_codes {
                    let code = codes
                        .get(&edge.type_id.raw())
                        .ok_or_else(|| invalid("edge.gdx type is absent from local remap"))?;
                    types.extend_from_slice(&code.to_le_bytes());
                } else {
                    types.extend_from_slice(&edge.type_id.raw().to_le_bytes());
                }
                if weighted {
                    weights.extend_from_slice(
                        &edge
                            .weight
                            .ok_or_else(|| invalid("edge.gdx weighted entry has no weight"))?
                            .to_le_bytes(),
                    );
                }
            }
            if inline_count != row_edges.len() {
                overflow_chains.push(OverflowChainInput {
                    row_index: u32::try_from(row_index)
                        .map_err(|_| invalid("edge.gdx overflow row index exceeds u32"))?,
                    direction,
                    edges: row_edges[inline_count..].to_vec(),
                });
            }
            offsets.push(neighbors.len() as u64);
        }
        let edge_count = neighbors.len() as u64;
        edge_counts.push(edge_count);
        offset_counts.push(group.rows.len() as u64 + 1);
        offset_groups.push(offsets.into_iter().flat_map(u64::to_le_bytes).collect());
        neighbor_groups.push(graph_group::encode_tagged_neighbors(&neighbors)?);
        edge_id_groups.push(edge_ids);
        type_groups.push(types);
        if weighted {
            weight_groups.push(weights);
        }
        overflow_groups.push(overflow_chains);
    }
    let edge_count = checked_sum(&edge_counts, "edge.gdx total direction edge count overflow")?;
    let offset_count = checked_sum(
        &offset_counts,
        "edge.gdx total direction offset count overflow",
    )?;
    Ok(EncodedDirection {
        edge_count,
        offset_count,
        offsets: encode_grouped(WIDTH_U64, &offset_counts, &offset_groups)?,
        neighbors: encode_grouped(WIDTH_TAGGED_NEIGHBOR, &edge_counts, &neighbor_groups)?,
        edge_ids: encode_grouped(WIDTH_U64, &edge_counts, &edge_id_groups)?,
        types: encode_grouped(
            if type_codes.is_some() {
                WIDTH_U16
            } else {
                WIDTH_U32
            },
            &edge_counts,
            &type_groups,
        )?,
        weights: weighted
            .then(|| encode_grouped(WIDTH_F32, &edge_counts, &weight_groups))
            .transpose()?,
        overflow_groups,
    })
}

fn encode_overflow_section(
    group_count: usize,
    outgoing: &[Vec<OverflowChainInput>],
    incoming: Option<&[Vec<OverflowChainInput>]>,
    type_codes: Option<&BTreeMap<u32, u16>>,
    weighted: bool,
) -> Result<Option<EncodedOverflow>> {
    if outgoing.len() != group_count || incoming.is_some_and(|groups| groups.len() != group_count) {
        return Err(invalid("edge.gdx overflow group count disagrees"));
    }
    let mut chain_counts = Vec::with_capacity(group_count);
    let mut group_bytes = Vec::with_capacity(group_count);
    for group_index in 0..group_count {
        let mut chains = Vec::new();
        chains.extend_from_slice(&outgoing[group_index]);
        if let Some(incoming) = incoming {
            chains.extend_from_slice(&incoming[group_index]);
        }
        chains.sort_unstable_by_key(|chain| (chain.row_index, chain.direction));
        if chains.windows(2).any(|pair| {
            (pair[0].row_index, pair[0].direction) >= (pair[1].row_index, pair[1].direction)
        }) {
            return Err(invalid("edge.gdx contains duplicate overflow chains"));
        }
        chain_counts.push(chains.len() as u64);
        group_bytes.push(encode_overflow_group(&chains, type_codes, weighted)?);
    }
    let chain_count = checked_sum(
        &chain_counts,
        "edge.gdx total overflow chain count overflows",
    )?;
    if chain_count == 0 {
        return Ok(None);
    }
    let payloads = chain_counts
        .iter()
        .zip(&group_bytes)
        .map(|(elem_count, bytes)| GroupPayload {
            elem_count: *elem_count,
            bytes,
        })
        .collect::<Vec<_>>();
    Ok(Some(EncodedOverflow {
        chain_count,
        bytes: graph_group::encode_grouped_section(WIDTH_OVERFLOW_CHAIN, &payloads)?,
    }))
}

fn encode_overflow_group(
    chains: &[OverflowChainInput],
    type_codes: Option<&BTreeMap<u32, u16>>,
    weighted: bool,
) -> Result<Vec<u8>> {
    if chains.is_empty() {
        return Ok(vec![0; OVERFLOW_DIRECTORY_HEADER_BYTES]);
    }
    if chains.len() > u32::MAX as usize {
        return Err(invalid("edge.gdx overflow chain count exceeds u32"));
    }
    let mut prepared = Vec::with_capacity(chains.len());
    let mut total_chunks = 0_u32;
    for chain in chains {
        if chain.edges.is_empty() || chain.edges.len() > u32::MAX as usize {
            return Err(invalid("edge.gdx overflow chain entry count is invalid"));
        }
        let chunks = pack_overflow_chunks(&chain.edges, type_codes, weighted)?;
        if chunks.is_empty() || chunks.len() > OVERFLOW_MAX_CHAIN_DEPTH {
            return Err(invalid("edge.gdx overflow chain depth is invalid"));
        }
        let chunk_count = u32::try_from(chunks.len())
            .map_err(|_| invalid("edge.gdx overflow chain depth exceeds u32"))?;
        let total_bytes = chunks.iter().try_fold(0_u32, |total, chunk| {
            total
                .checked_add(
                    u32::try_from(chunk.payload.len())
                        .map_err(|_| invalid("edge.gdx overflow chunk length exceeds u32"))?,
                )
                .ok_or_else(|| invalid("edge.gdx overflow chain byte total overflows"))
        })?;
        let record = OverflowChainRecord {
            row_index: chain.row_index,
            direction: chain.direction,
            first_chunk: total_chunks,
            chunk_count,
            total_entries: chain.edges.len() as u32,
            total_bytes,
        };
        total_chunks = total_chunks
            .checked_add(chunk_count)
            .ok_or_else(|| invalid("edge.gdx overflow chunk total overflows"))?;
        prepared.push((record, chunks));
    }
    let records_len = chains
        .len()
        .checked_mul(OVERFLOW_CHAIN_RECORD_BYTES)
        .ok_or_else(|| invalid("edge.gdx overflow record bytes overflow"))?;
    let directory_end = OVERFLOW_DIRECTORY_HEADER_BYTES
        .checked_add(records_len)
        .ok_or_else(|| invalid("edge.gdx overflow directory bytes overflow"))?;
    let arena_offset = overflow_arena_payload_offset(directory_end)?;
    let arena_len = (total_chunks as usize)
        .checked_mul(AUTHENTICATED_CHUNK_BYTES)
        .ok_or_else(|| invalid("edge.gdx overflow arena bytes overflow"))?;
    let total_len = arena_offset
        .checked_add(arena_len)
        .ok_or_else(|| invalid("edge.gdx overflow group bytes overflow"))?;
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&(chains.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for (record, _) in &prepared {
        bytes.extend_from_slice(&record.row_index.to_le_bytes());
        bytes.push(record.direction as u8);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&record.first_chunk.to_le_bytes());
        bytes.extend_from_slice(&record.chunk_count.to_le_bytes());
        bytes.extend_from_slice(&record.total_entries.to_le_bytes());
        bytes.extend_from_slice(&record.total_bytes.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
    }
    bytes.resize(arena_offset, 0);
    for (record, chunks) in prepared {
        for (index, chunk) in chunks.into_iter().enumerate() {
            let chunk_index = record.first_chunk + index as u32;
            let next_chunk = if index + 1 == record.chunk_count as usize {
                u32::MAX
            } else {
                chunk_index + 1
            };
            bytes.extend_from_slice(&next_chunk.to_le_bytes());
            bytes.extend_from_slice(&chunk.entry_count.to_le_bytes());
            bytes.extend_from_slice(&(chunk.payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&0_u32.to_le_bytes());
            bytes.extend_from_slice(&chunk.payload);
            let padding = AUTHENTICATED_CHUNK_BYTES
                .checked_sub(OVERFLOW_CHUNK_HEADER_BYTES)
                .and_then(|value| value.checked_sub(chunk.payload.len()))
                .ok_or_else(|| invalid("edge.gdx overflow chunk padding underflows"))?;
            let padded_len = bytes
                .len()
                .checked_add(padding)
                .ok_or_else(|| invalid("edge.gdx overflow output length overflows"))?;
            bytes.resize(padded_len, 0);
        }
    }
    debug_assert_eq!(bytes.len(), total_len);
    Ok(bytes)
}

fn pack_overflow_chunks(
    edges: &[NormalizedBaseEdge],
    type_codes: Option<&BTreeMap<u32, u16>>,
    weighted: bool,
) -> Result<Vec<PackedOverflowChunk>> {
    let mut chunks = Vec::new();
    let mut index = 0_usize;
    while index < edges.len() {
        let mut payload = Vec::new();
        let mut entry_count = 0_u32;
        while index < edges.len() {
            let tuple = encode_overflow_tuple(&edges[index], type_codes, weighted)?;
            if tuple.is_empty() || tuple.len() > OVERFLOW_CHUNK_PAYLOAD_BYTES {
                return Err(invalid("edge.gdx overflow tuple size is invalid"));
            }
            if !payload.is_empty() && payload.len() + tuple.len() > OVERFLOW_CHUNK_PAYLOAD_BYTES {
                break;
            }
            payload.extend_from_slice(&tuple);
            index += 1;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| invalid("edge.gdx overflow chunk entry count overflows"))?;
        }
        chunks.push(PackedOverflowChunk {
            payload,
            entry_count,
        });
    }
    Ok(chunks)
}

fn encode_overflow_tuple(
    edge: &NormalizedBaseEdge,
    type_codes: Option<&BTreeMap<u32, u16>>,
    weighted: bool,
) -> Result<Vec<u8>> {
    let mut bytes = graph_group::encode_tagged_neighbor(edge.stored_neighbor)?;
    bytes.extend_from_slice(&edge.edge_id.raw().to_le_bytes());
    if let Some(codes) = type_codes {
        bytes.extend_from_slice(
            &codes
                .get(&edge.type_id.raw())
                .ok_or_else(|| invalid("edge.gdx overflow type is absent from local remap"))?
                .to_le_bytes(),
        );
    } else {
        bytes.extend_from_slice(&edge.type_id.raw().to_le_bytes());
    }
    if weighted {
        bytes.extend_from_slice(
            &edge
                .weight
                .ok_or_else(|| invalid("edge.gdx weighted overflow entry has no weight"))?
                .to_le_bytes(),
        );
    }
    Ok(bytes)
}

fn maximal_edge_prefix(
    edges: &[NormalizedBaseEdge],
    remapped: bool,
    weighted: bool,
) -> Result<usize> {
    let mut bytes = 0_usize;
    let mut count = 0_usize;
    for edge in edges {
        let tuple_len = normalized_tuple_len(edge, remapped, weighted)?;
        let Some(next) = bytes.checked_add(tuple_len) else {
            break;
        };
        if next > OVERFLOW_CHUNK_PAYLOAD_BYTES {
            break;
        }
        bytes = next;
        count += 1;
    }
    Ok(count)
}

fn normalized_tuple_len(
    edge: &NormalizedBaseEdge,
    remapped: bool,
    weighted: bool,
) -> Result<usize> {
    graph_group::tagged_neighbor_encoded_len(edge.stored_neighbor)?
        .checked_add(8)
        .and_then(|value| value.checked_add(if remapped { 2 } else { 4 }))
        .and_then(|value| value.checked_add(if weighted { 4 } else { 0 }))
        .ok_or_else(|| invalid("edge.gdx tuple encoded length overflows"))
}

fn overflow_arena_payload_offset(directory_end: usize) -> Result<usize> {
    OVERFLOW_CHUNK_HEADER_BYTES
        .checked_add(directory_end)
        .and_then(|value| value.checked_add(AUTHENTICATED_CHUNK_BYTES - 1))
        .map(|value| value & !(AUTHENTICATED_CHUNK_BYTES - 1))
        .and_then(|value| value.checked_sub(OVERFLOW_CHUNK_HEADER_BYTES))
        .ok_or_else(|| invalid("edge.gdx overflow arena alignment overflows"))
}

fn decode_overflow_tuple(
    path: &Path,
    nid_index: &NidIndex,
    node_ordinal: u32,
    bytes: &[u8],
    type_remap: Option<&[TypeId]>,
    weighted: bool,
) -> Result<(DecodedBaseEdge, usize)> {
    let (stored_neighbor, neighbor_len) = graph_group::decode_tagged_neighbor_prefix(path, bytes)?;
    let type_width = if type_remap.is_some() { 2 } else { 4 };
    let required_tail = 8_usize
        .checked_add(type_width)
        .and_then(|value| value.checked_add(if weighted { 4 } else { 0 }))
        .ok_or_else(|| corruption(path, "edge.gdx overflow tuple width overflows"))?;
    let end = neighbor_len
        .checked_add(required_tail)
        .ok_or_else(|| corruption(path, "edge.gdx overflow tuple end overflows"))?;
    if end > bytes.len() {
        return Err(corruption(path, "truncated edge.gdx overflow tuple"));
    }
    let edge_id = EdgeId::from_raw(u64::from_le_bytes(
        bytes[neighbor_len..neighbor_len + 8]
            .try_into()
            .expect("checked overflow EdgeId width"),
    ));
    validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
    let type_start = neighbor_len + 8;
    let type_id = if let Some(remap) = type_remap {
        let code = u16::from_le_bytes(
            bytes[type_start..type_start + 2]
                .try_into()
                .expect("checked overflow type width"),
        );
        remap
            .get(code as usize)
            .copied()
            .ok_or_else(|| corruption(path, "edge.gdx overflow type code exceeds remap"))?
    } else {
        TypeId::from_raw(u32::from_le_bytes(
            bytes[type_start..type_start + 4]
                .try_into()
                .expect("checked overflow type width"),
        ))
    };
    validate_type_id(type_id).map_err(|error| corruption(path, &error.to_string()))?;
    let weight_start = type_start + type_width;
    let weight = if weighted {
        let value = f32::from_le_bytes(
            bytes[weight_start..weight_start + 4]
                .try_into()
                .expect("checked overflow weight width"),
        );
        if !value.is_finite() {
            return Err(corruption(path, "edge.gdx overflow weight is non-finite"));
        }
        Some(value)
    } else {
        None
    };
    let neighbor_nid = resolve_neighbor(path, nid_index, node_ordinal, stored_neighbor)?;
    Ok((
        DecodedBaseEdge {
            neighbor_nid,
            edge_id,
            type_id,
            stored_neighbor,
            weight,
        },
        end,
    ))
}

fn validate_row_chunking(
    path: &Path,
    outgoing: &[Vec<DecodedBaseEdge>],
    incoming: &[Vec<DecodedBaseEdge>],
    presence: &BTreeMap<(u32, BaseDirection), usize>,
    remapped: bool,
    weighted: bool,
) -> Result<()> {
    for (direction, rows) in [
        (BaseDirection::Outgoing, outgoing),
        (BaseDirection::Incoming, incoming),
    ] {
        for (row_index, edges) in rows.iter().enumerate() {
            if edges
                .windows(2)
                .any(|pair| decoded_edge_sort_key(&pair[0]) >= decoded_edge_sort_key(&pair[1]))
            {
                return Err(corruption(
                    path,
                    &format!(
                        "edge.gdx {} row is not sorted after overflow expansion",
                        direction.label()
                    ),
                ));
            }
            let lengths = edges
                .iter()
                .map(|edge| tuple_encoded_len(path, edge, remapped, weighted))
                .collect::<Result<Vec<_>>>()?;
            let key = (
                u32::try_from(row_index)
                    .map_err(|_| corruption(path, "edge.gdx row index exceeds u32"))?,
                direction,
            );
            if let Some(inline_count) = presence.get(&key).copied() {
                if inline_count >= lengths.len() {
                    return Err(corruption(
                        path,
                        "edge.gdx overflow chain has no suffix entries",
                    ));
                }
                let inline_bytes = lengths[..inline_count]
                    .iter()
                    .try_fold(0_usize, |total, length| total.checked_add(*length))
                    .ok_or_else(|| corruption(path, "edge.gdx inline row bytes overflow"))?;
                if inline_bytes > OVERFLOW_CHUNK_PAYLOAD_BYTES
                    || inline_bytes
                        .checked_add(lengths[inline_count])
                        .is_some_and(|value| value <= OVERFLOW_CHUNK_PAYLOAD_BYTES)
                {
                    return Err(corruption(
                        path,
                        "edge.gdx inline/overflow row split is non-canonical",
                    ));
                }
            } else {
                let total = lengths
                    .iter()
                    .try_fold(0_usize, |sum, length| sum.checked_add(*length))
                    .ok_or_else(|| corruption(path, "edge.gdx inline row bytes overflow"))?;
                if total > OVERFLOW_CHUNK_PAYLOAD_BYTES {
                    return Err(corruption(
                        path,
                        "edge.gdx overlong inline row has no overflow chain",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn tuple_encoded_len(
    path: &Path,
    edge: &DecodedBaseEdge,
    remapped: bool,
    weighted: bool,
) -> Result<usize> {
    let neighbor_len = graph_group::tagged_neighbor_encoded_len(edge.stored_neighbor)
        .map_err(|error| corruption(path, &error.to_string()))?;
    neighbor_len
        .checked_add(8)
        .and_then(|value| value.checked_add(if remapped { 2 } else { 4 }))
        .and_then(|value| value.checked_add(if weighted { 4 } else { 0 }))
        .ok_or_else(|| corruption(path, "edge.gdx tuple encoded length overflows"))
}

fn read_u32_at(path: &Path, bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| corruption(path, &format!("edge.gdx {field} offset overflows")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| corruption(path, &format!("truncated edge.gdx {field}")))?;
    Ok(u32::from_le_bytes(
        raw.try_into().expect("checked edge.gdx u32 field width"),
    ))
}

fn encode_grouped(width: u32, counts: &[u64], groups: &[Vec<u8>]) -> Result<Vec<u8>> {
    if counts.len() != groups.len() {
        return Err(invalid("edge.gdx grouped payload count mismatch"));
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

fn normalize_direction(
    nid_index: &NidIndex,
    node_ordinal: u32,
    edges: Vec<BaseEdgeInput>,
    used_edge_ids: &mut RoaringTreemap,
    type_ids: &mut BTreeSet<TypeId>,
    weight_mode: &mut Option<bool>,
    label: &str,
) -> Result<Vec<NormalizedBaseEdge>> {
    let mut normalized = Vec::with_capacity(edges.len());
    for edge in edges {
        validate_edge_id(edge.edge_id)?;
        if !used_edge_ids.insert(edge.edge_id.raw()) {
            return Err(invalid(format!(
                "edge.gdx contains a duplicate {label} EdgeId"
            )));
        }
        validate_type_id(edge.type_id)?;
        type_ids.insert(edge.type_id);
        if edge.weight.is_some_and(|weight| !weight.is_finite()) {
            return Err(invalid("edge.gdx contains a non-finite weight"));
        }
        let weighted = edge.weight.is_some();
        if weight_mode.is_some_and(|mode| mode != weighted) {
            return Err(invalid("edge.gdx weight column must be total"));
        }
        *weight_mode = Some(weighted);
        let (stored_neighbor, neighbor_nid, neighbor_ordinal) = match edge.neighbor {
            BaseNeighborInput::LocalOrdinal(neighbor_ordinal) => {
                let neighbor_nid = local_nid(nid_index, neighbor_ordinal)?;
                let delta = i64::from(neighbor_ordinal) - i64::from(node_ordinal);
                (
                    TaggedNeighbor::LocalDelta(delta),
                    neighbor_nid,
                    Some(neighbor_ordinal),
                )
            }
            BaseNeighborInput::GlobalNid(neighbor_nid) => {
                validate_nid(neighbor_nid)?;
                if nid_index.lookup(neighbor_nid).is_some() {
                    return Err(invalid(
                        "edge.gdx global neighbour must be retagged as local",
                    ));
                }
                (TaggedNeighbor::Global(neighbor_nid), neighbor_nid, None)
            }
        };
        normalized.push(NormalizedBaseEdge {
            stored_neighbor,
            neighbor_nid,
            neighbor_ordinal,
            edge_id: edge.edge_id,
            type_id: edge.type_id,
            weight: edge.weight,
        });
    }
    normalized.sort_unstable_by_key(edge_sort_key);
    Ok(normalized)
}

fn validate_local_mirrors(groups: &[NormalizedBaseGroup]) -> Result<()> {
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    for (group_index, group) in groups.iter().enumerate() {
        for row in &group.rows {
            for edge in &row.outgoing {
                if let Some(target_ordinal) = edge.neighbor_ordinal {
                    outgoing.insert(
                        edge.edge_id.raw(),
                        mirror_value(
                            group_index,
                            row.node_ordinal,
                            target_ordinal,
                            edge.type_id,
                            edge.weight,
                        ),
                    );
                }
            }
            for edge in &row.incoming {
                if let Some(source_ordinal) = edge.neighbor_ordinal {
                    incoming.insert(
                        edge.edge_id.raw(),
                        mirror_value(
                            group_index,
                            source_ordinal,
                            row.node_ordinal,
                            edge.type_id,
                            edge.weight,
                        ),
                    );
                }
            }
        }
    }
    if outgoing != incoming {
        return Err(invalid(
            "edge.gdx local-local outgoing/incoming mirrors disagree",
        ));
    }
    Ok(())
}

fn validate_decoded_local_mirrors(
    path: &Path,
    nid_index: &NidIndex,
    groups: &[DecodedBaseGroup],
) -> Result<()> {
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    for (group_index, group) in groups.iter().enumerate() {
        for row in &group.rows {
            for edge in &row.outgoing {
                if let TaggedNeighbor::LocalDelta(delta) = edge.stored_neighbor {
                    let target = checked_local_ordinal(path, row.node_ordinal, delta)?;
                    local_nid(nid_index, target)
                        .map_err(|error| corruption(path, &error.to_string()))?;
                    outgoing.insert(
                        edge.edge_id.raw(),
                        mirror_value(
                            group_index,
                            row.node_ordinal,
                            target,
                            edge.type_id,
                            edge.weight,
                        ),
                    );
                }
            }
            for edge in &row.incoming {
                if let TaggedNeighbor::LocalDelta(delta) = edge.stored_neighbor {
                    let source = checked_local_ordinal(path, row.node_ordinal, delta)?;
                    local_nid(nid_index, source)
                        .map_err(|error| corruption(path, &error.to_string()))?;
                    incoming.insert(
                        edge.edge_id.raw(),
                        mirror_value(
                            group_index,
                            source,
                            row.node_ordinal,
                            edge.type_id,
                            edge.weight,
                        ),
                    );
                }
            }
        }
    }
    if outgoing != incoming {
        return Err(corruption(
            path,
            "edge.gdx local-local outgoing/incoming mirrors disagree",
        ));
    }
    Ok(())
}

fn mirror_value(
    group_index: usize,
    source: u32,
    target: u32,
    type_id: TypeId,
    weight: Option<f32>,
) -> (usize, u32, u32, u32, Option<u32>) {
    (
        group_index,
        source,
        target,
        type_id.raw(),
        weight.map(f32::to_bits),
    )
}

fn resolve_neighbor(
    path: &Path,
    nid_index: &NidIndex,
    node_ordinal: u32,
    neighbor: TaggedNeighbor,
) -> Result<Nid> {
    match neighbor {
        TaggedNeighbor::LocalDelta(delta) => {
            let ordinal = checked_local_ordinal(path, node_ordinal, delta)?;
            local_nid(nid_index, ordinal).map_err(|error| corruption(path, &error.to_string()))
        }
        TaggedNeighbor::Global(nid) => {
            validate_nid(nid).map_err(|error| corruption(path, &error.to_string()))?;
            if nid_index.lookup(nid).is_some() {
                return Err(corruption(
                    path,
                    "edge.gdx global neighbour was not retagged local",
                ));
            }
            Ok(nid)
        }
    }
}

fn checked_local_ordinal(path: &Path, node_ordinal: u32, delta: i64) -> Result<u32> {
    let ordinal = i64::from(node_ordinal)
        .checked_add(delta)
        .ok_or_else(|| corruption(path, "edge.gdx local ordinal delta overflows"))?;
    u32::try_from(ordinal).map_err(|_| corruption(path, "edge.gdx local ordinal is out of range"))
}

fn decode_type_remap(path: &Path, artifact: &CheckedArtifact) -> Result<Vec<TypeId>> {
    let section = artifact
        .section(SECTION_TYPE_REMAP)
        .expect("type remap section agrees with flag");
    if section.elem_count == 0 || section.elem_count > u16::MAX as u64 + 1 {
        return Err(corruption(path, "edge.gdx type remap count is invalid"));
    }
    let bytes = artifact.read_section(SECTION_TYPE_REMAP)?;
    if bytes.len() != section.elem_count as usize * 4 {
        return Err(corruption(path, "edge.gdx type remap length disagrees"));
    }
    let types = decode_u32s(&bytes)
        .into_iter()
        .map(TypeId::from_raw)
        .collect::<Vec<_>>();
    for type_id in &types {
        validate_type_id(*type_id).map_err(|error| corruption(path, &error.to_string()))?;
    }
    if types.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(corruption(
            path,
            "edge.gdx type remap is not strictly sorted",
        ));
    }
    Ok(types)
}

fn checked_sum(counts: &[u64], message: &str) -> Result<u64> {
    counts.iter().try_fold(0_u64, |total, count| {
        total.checked_add(*count).ok_or_else(|| invalid(message))
    })
}

fn local_nid(nid_index: &NidIndex, ordinal: u32) -> Result<Nid> {
    let nid = nid_index
        .nid_for_ordinal(ordinal)
        .ok_or_else(|| invalid("edge.gdx local ordinal is out of range"))?;
    validate_nid(nid)?;
    Ok(nid)
}

fn validate_nid(nid: Nid) -> Result<()> {
    if nid.raw() == 0
        || nid.epoch() == 0
        || nid.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || nid.counter() == 0
        || nid.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("edge.gdx contains an invalid Nid"));
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
        return Err(invalid("edge.gdx contains an invalid EdgeId"));
    }
    Ok(())
}

fn validate_type_id(type_id: TypeId) -> Result<()> {
    if type_id.raw() == 0 {
        return Err(invalid("edge.gdx contains reserved TypeId=0"));
    }
    Ok(())
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

fn edge_sort_key(edge: &NormalizedBaseEdge) -> (u32, u64, u64) {
    (
        edge.type_id.raw(),
        edge.neighbor_nid.raw(),
        edge.edge_id.raw(),
    )
}

fn decoded_edge_sort_key(edge: &DecodedBaseEdge) -> (u32, u64, u64) {
    (
        edge.type_id.raw(),
        edge.neighbor_nid.raw(),
        edge.edge_id.raw(),
    )
}

fn decode_u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|raw| u16::from_le_bytes(raw.try_into().expect("validated u16 group width")))
        .collect()
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

fn decode_f32s(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|raw| f32::from_le_bytes(raw.try_into().expect("validated f32 group width")))
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

    const ENCRYPTED_HELPER_ENV: &str = "CHIRONDB_GRAPH_EDGE_ENCRYPTED_HELPER_DIR";

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(31, counter).unwrap()
    }

    fn edge_id(counter: u64) -> EdgeId {
        EdgeId::from_parts(31, counter).unwrap()
    }

    fn type_id(raw: u32) -> TypeId {
        TypeId::from_raw(raw)
    }

    fn edge(neighbor: BaseNeighborInput, edge: u64, r#type: u32) -> BaseEdgeInput {
        BaseEdgeInput {
            neighbor,
            edge_id: edge_id(edge),
            type_id: type_id(r#type),
            weight: None,
        }
    }

    fn weighted_edge(
        neighbor: BaseNeighborInput,
        edge: u64,
        r#type: u32,
        weight: f32,
    ) -> BaseEdgeInput {
        BaseEdgeInput {
            neighbor,
            edge_id: edge_id(edge),
            type_id: type_id(r#type),
            weight: Some(weight),
        }
    }

    fn optional_fixture() -> (NidIndex, BaseAdjacency) {
        let nid_index = NidIndex::build(vec![nid(1), nid(2), nid(3)], true).unwrap();
        let adjacency = BaseAdjacency::build_with_options(
            &nid_index,
            vec![BaseGroupInput {
                namespace: GraphNamespace::Tenant("acme".to_string()),
                rows: vec![
                    BaseRowInput {
                        node_ordinal: 2,
                        outgoing: vec![weighted_edge(
                            BaseNeighborInput::GlobalNid(nid(91)),
                            3,
                            9,
                            3.0,
                        )],
                        incoming: vec![],
                    },
                    BaseRowInput {
                        node_ordinal: 0,
                        outgoing: vec![weighted_edge(
                            BaseNeighborInput::LocalOrdinal(1),
                            1,
                            9,
                            1.5,
                        )],
                        incoming: vec![weighted_edge(
                            BaseNeighborInput::GlobalNid(nid(92)),
                            4,
                            2,
                            4.0,
                        )],
                    },
                    BaseRowInput {
                        node_ordinal: 1,
                        outgoing: vec![weighted_edge(
                            BaseNeighborInput::LocalOrdinal(1),
                            2,
                            2,
                            2.0,
                        )],
                        incoming: vec![
                            weighted_edge(BaseNeighborInput::LocalOrdinal(1), 2, 2, 2.0),
                            weighted_edge(BaseNeighborInput::LocalOrdinal(0), 1, 9, 1.5),
                        ],
                    },
                ],
            }],
            true,
            true,
        )
        .unwrap();
        (nid_index, adjacency)
    }

    fn overflow_fixture(edge_count: u32) -> (NidIndex, BaseAdjacency) {
        let nid_index = NidIndex::build(vec![nid(1)], true).unwrap();
        let outgoing = (0..edge_count)
            .map(|index| {
                edge(
                    BaseNeighborInput::GlobalNid(nid(10_000 + u64::from(index))),
                    1 + u64::from(index),
                    7,
                )
            })
            .collect();
        let adjacency = BaseAdjacency::build(
            &nid_index,
            vec![BaseGroupInput {
                namespace: GraphNamespace::Tenant("acme".to_string()),
                rows: vec![BaseRowInput {
                    node_ordinal: 0,
                    outgoing,
                    incoming: vec![],
                }],
            }],
        )
        .unwrap();
        (nid_index, adjacency)
    }

    fn mirrored_overflow_fixture(edge_count: u32) -> (NidIndex, BaseAdjacency) {
        let nid_index = NidIndex::build(vec![nid(1), nid(2)], true).unwrap();
        let outgoing = (0..edge_count)
            .map(|index| {
                weighted_edge(
                    BaseNeighborInput::LocalOrdinal(1),
                    1 + u64::from(index),
                    7,
                    1.25,
                )
            })
            .collect::<Vec<_>>();
        let incoming = (0..edge_count)
            .map(|index| {
                weighted_edge(
                    BaseNeighborInput::LocalOrdinal(0),
                    1 + u64::from(index),
                    7,
                    1.25,
                )
            })
            .collect::<Vec<_>>();
        let adjacency = BaseAdjacency::build_with_options(
            &nid_index,
            vec![BaseGroupInput {
                namespace: GraphNamespace::Tenant("acme".to_string()),
                rows: vec![
                    BaseRowInput {
                        node_ordinal: 0,
                        outgoing,
                        incoming: vec![],
                    },
                    BaseRowInput {
                        node_ordinal: 1,
                        outgoing: vec![],
                        incoming,
                    },
                ],
            }],
            true,
            true,
        )
        .unwrap();
        (nid_index, adjacency)
    }

    fn fixture() -> (NidIndex, BaseAdjacency) {
        let nid_index =
            NidIndex::build(vec![nid(1), nid(2), nid(3), Nid::UNASSIGNED], true).unwrap();
        let adjacency = BaseAdjacency::build(
            &nid_index,
            vec![
                BaseGroupInput {
                    namespace: GraphNamespace::AdminCrossTenant,
                    rows: vec![BaseRowInput {
                        node_ordinal: 2,
                        outgoing: vec![edge(BaseNeighborInput::GlobalNid(nid(91)), 6, 3)],
                        incoming: vec![],
                    }],
                },
                BaseGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    rows: vec![
                        BaseRowInput {
                            node_ordinal: 1,
                            outgoing: vec![],
                            incoming: vec![],
                        },
                        BaseRowInput {
                            node_ordinal: 0,
                            outgoing: vec![
                                edge(BaseNeighborInput::LocalOrdinal(2), 2, 2),
                                edge(BaseNeighborInput::LocalOrdinal(1), 1, 1),
                                edge(BaseNeighborInput::LocalOrdinal(1), 3, 1),
                            ],
                            incoming: vec![],
                        },
                    ],
                },
            ],
        )
        .unwrap();
        (nid_index, adjacency)
    }

    #[test]
    fn base_outgoing_round_trips_namespaces_multi_edges_and_empty_rows() {
        let (nid_index, adjacency) = fixture();
        assert_eq!(adjacency.group_count(), 2);
        assert_eq!(adjacency.edge_count(), 4);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();
        let opened = open(&path, &nid_index).unwrap();
        assert_cursor_matches(&opened, &path, &nid_index);
        assert_eq!(opened.group_count(), 2);
        assert_eq!(opened.edge_count(), 4);

        let tenant = opened.read_group(&path, &nid_index, 0).unwrap();
        assert_eq!(tenant.namespace, GraphNamespace::Tenant("acme".to_string()));
        assert_eq!(tenant.rows[0].node_ordinal, 0);
        assert_eq!(tenant.rows[0].outgoing.len(), 3);
        assert_eq!(tenant.rows[0].outgoing[0].neighbor_nid, nid(2));
        assert_eq!(tenant.rows[0].outgoing[0].edge_id, edge_id(1));
        assert_eq!(tenant.rows[0].outgoing[1].edge_id, edge_id(3));
        assert_eq!(tenant.rows[0].outgoing[2].neighbor_nid, nid(3));
        assert!(tenant.rows[1].outgoing.is_empty());
        assert!(tenant.rows[0].incoming.is_empty());

        let admin = opened.read_group(&path, &nid_index, 1).unwrap();
        assert_eq!(admin.namespace, GraphNamespace::AdminCrossTenant);
        assert_eq!(admin.rows[0].outgoing[0].neighbor_nid, nid(91));
    }

    #[test]
    fn empty_base_adjacency_is_canonical_and_readable() {
        let nid_index = NidIndex::build(vec![], false).unwrap();
        let adjacency = BaseAdjacency::build(&nid_index, vec![]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();
        let opened = open(&path, &nid_index).unwrap();
        assert_eq!(opened.group_count(), 0);
        assert_eq!(opened.edge_count(), 0);
    }

    #[test]
    fn optional_csc_type_remap_and_weights_round_trip_without_cross_pointers() {
        let (nid_index, adjacency) = optional_fixture();
        assert_eq!(adjacency.edge_count(), 3);
        assert_eq!(adjacency.incoming_edge_count(), 3);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        assert_eq!(artifact.flags(), FLAG_CSC | FLAG_WEIGHTS | FLAG_TYPE_REMAP);
        assert_eq!(
            decode_u32s(&artifact.read_section(SECTION_TYPE_REMAP).unwrap()),
            vec![2, 9]
        );
        let type_layout =
            graph_group::open_grouped_section(&path, &artifact, SECTION_OUT_TYPES, 1, WIDTH_U16)
                .unwrap();
        assert_eq!(type_layout.semantic_elem_count, 3);

        let opened = open(&path, &nid_index).unwrap();
        assert_cursor_matches(&opened, &path, &nid_index);
        assert_eq!(opened.edge_count(), 3);
        assert_eq!(opened.incoming_edge_count(), 3);
        let group = opened.read_group(&path, &nid_index, 0).unwrap();
        assert_eq!(group.rows[0].node_ordinal, 0);
        assert_eq!(group.rows[0].outgoing[0].type_id, type_id(9));
        assert_eq!(group.rows[0].outgoing[0].weight, Some(1.5));
        assert_eq!(group.rows[0].incoming[0].neighbor_nid, nid(92));
        assert_eq!(group.rows[1].incoming.len(), 2);
        assert_eq!(group.rows[2].outgoing[0].neighbor_nid, nid(91));
    }

    #[test]
    fn overflow_round_trips_canonical_inline_prefix_and_multi_chunk_suffix() {
        let (nid_index, adjacency) = overflow_fixture(8_000);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();

        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        assert_eq!(artifact.flags(), FLAG_OVERFLOW);
        let offsets =
            graph_group::open_grouped_section(&path, &artifact, SECTION_OUT_OFFSETS, 1, WIDTH_U64)
                .unwrap();
        let inline = decode_u64s(
            &graph_group::read_group(&artifact, SECTION_OUT_OFFSETS, &offsets, 0).unwrap(),
        )[1];
        assert!(inline > 0 && inline < 8_000);
        let overflow = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_OVERFLOW,
            1,
            WIDTH_OVERFLOW_CHAIN,
        )
        .unwrap();
        assert_eq!(overflow.semantic_elem_count, 1);
        let record = artifact
            .read_section_range(
                SECTION_OVERFLOW,
                overflow.frames[0].payload_offset + OVERFLOW_DIRECTORY_HEADER_BYTES
                    ..overflow.frames[0].payload_offset
                        + OVERFLOW_DIRECTORY_HEADER_BYTES
                        + OVERFLOW_CHAIN_RECORD_BYTES,
            )
            .unwrap();
        assert!(read_u32_at(&path, &record, 12, "test chunk count").unwrap() >= 2);

        let opened = open(&path, &nid_index).unwrap();
        assert_cursor_matches(&opened, &path, &nid_index);
        assert_eq!(opened.edge_count(), 8_000);
        let group = opened.read_group(&path, &nid_index, 0).unwrap();
        assert_eq!(group.rows[0].outgoing.len(), 8_000);
        assert_eq!(group.rows[0].outgoing[0].edge_id, edge_id(1));
        assert_eq!(group.rows[0].outgoing[7_999].edge_id, edge_id(8_000));
    }

    #[test]
    fn overflow_starts_only_after_the_maximal_inline_tuple_prefix() {
        let (_, large) = overflow_fixture(8_000);
        let edges = &large.groups[0].rows[0].outgoing;
        let inline_count = maximal_edge_prefix(edges, false, false).unwrap();
        assert!(inline_count > 0 && inline_count + 1 < edges.len());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        let (fit_nids, fit) = overflow_fixture(inline_count as u32);
        write(&path, &fit).unwrap();
        assert_eq!(graph_artifact::open(&path, SPEC).unwrap().flags(), 0);
        assert_eq!(
            open(&path, &fit_nids).unwrap().edge_count(),
            inline_count as u64
        );

        let (over_nids, over) = overflow_fixture(inline_count as u32 + 1);
        write(&path, &over).unwrap();
        assert_eq!(
            graph_artifact::open(&path, SPEC).unwrap().flags(),
            FLAG_OVERFLOW
        );
        assert_eq!(
            open(&path, &over_nids).unwrap().edge_count(),
            inline_count as u64 + 1
        );
    }

    #[test]
    fn overflow_round_trips_csc_remap_weights_and_local_mirrors() {
        let (nid_index, adjacency) = mirrored_overflow_fixture(9_000);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        assert_eq!(
            artifact.flags(),
            FLAG_CSC | FLAG_OVERFLOW | FLAG_WEIGHTS | FLAG_TYPE_REMAP
        );
        let overflow = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_OVERFLOW,
            1,
            WIDTH_OVERFLOW_CHAIN,
        )
        .unwrap();
        assert_eq!(overflow.semantic_elem_count, 2);

        let opened = open(&path, &nid_index).unwrap();
        assert_cursor_matches(&opened, &path, &nid_index);
        assert_eq!(opened.edge_count(), 9_000);
        assert_eq!(opened.incoming_edge_count(), 9_000);
        let group = opened.read_group(&path, &nid_index, 0).unwrap();
        assert_eq!(group.rows[0].outgoing.len(), 9_000);
        assert_eq!(group.rows[1].incoming.len(), 9_000);
        assert!(
            group.rows[0]
                .outgoing
                .iter()
                .all(|edge| edge.type_id == type_id(7) && edge.weight == Some(1.25))
        );
    }

    #[test]
    fn overflow_loader_rejects_links_totals_and_nonzero_padding() {
        let (nid_index, adjacency) = overflow_fixture(8_000);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);

        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let overflow = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_OVERFLOW,
            1,
            WIDTH_OVERFLOW_CHAIN,
        )
        .unwrap();
        let frame = overflow.frames[0];
        let record_offset = artifact.section(SECTION_OVERFLOW).unwrap().offset
            + frame.payload_offset
            + OVERFLOW_DIRECTORY_HEADER_BYTES;
        let directory_end = OVERFLOW_DIRECTORY_HEADER_BYTES + OVERFLOW_CHAIN_RECORD_BYTES;
        let arena_offset = overflow_arena_payload_offset(directory_end).unwrap();
        let chunk_offset = artifact.section(SECTION_OVERFLOW).unwrap().offset
            + frame.payload_offset
            + arena_offset;

        let mut bad_link = fs::read(&path).unwrap();
        bad_link[chunk_offset..chunk_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, bad_link).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let mut bad_entry_count = fs::read(&path).unwrap();
        bad_entry_count[chunk_offset + 4..chunk_offset + 8]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, bad_entry_count).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let mut bad_total = fs::read(&path).unwrap();
        bad_total[record_offset + 16..record_offset + 20].copy_from_slice(&1_u32.to_le_bytes());
        fs::write(&path, bad_total).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let mut bad_padding = fs::read(&path).unwrap();
        let byte_len = u32::from_le_bytes(
            bad_padding[chunk_offset + 8..chunk_offset + 12]
                .try_into()
                .unwrap(),
        ) as usize;
        bad_padding[chunk_offset + OVERFLOW_CHUNK_HEADER_BYTES + byte_len] = 1;
        fs::write(&path, bad_padding).unwrap();
        assert!(open(&path, &nid_index).is_err());
    }

    #[test]
    fn optional_builder_rejects_mirror_weight_and_csc_contract_violations() {
        let nid_index = NidIndex::build(vec![nid(1), nid(2)], false).unwrap();
        let group = |outgoing, incoming| BaseGroupInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            rows: vec![
                BaseRowInput {
                    node_ordinal: 0,
                    outgoing,
                    incoming: vec![],
                },
                BaseRowInput {
                    node_ordinal: 1,
                    outgoing: vec![],
                    incoming,
                },
            ],
        };
        let outgoing = weighted_edge(BaseNeighborInput::LocalOrdinal(1), 1, 3, 1.0);
        assert!(
            BaseAdjacency::build_with_options(
                &nid_index,
                vec![group(vec![outgoing], vec![])],
                true,
                false,
            )
            .is_err()
        );
        let incoming = weighted_edge(BaseNeighborInput::LocalOrdinal(0), 1, 4, 1.0);
        assert!(
            BaseAdjacency::build_with_options(
                &nid_index,
                vec![group(vec![outgoing], vec![incoming])],
                true,
                false,
            )
            .is_err()
        );
        let incoming = weighted_edge(BaseNeighborInput::LocalOrdinal(0), 1, 3, 1.0);
        let mut unweighted = edge(BaseNeighborInput::LocalOrdinal(1), 1, 3);
        unweighted.edge_id = edge_id(2);
        assert!(
            BaseAdjacency::build_with_options(
                &nid_index,
                vec![group(vec![unweighted], vec![incoming])],
                true,
                false,
            )
            .is_err()
        );
        let mut non_finite = outgoing;
        non_finite.weight = Some(f32::NAN);
        assert!(
            BaseAdjacency::build_with_options(
                &nid_index,
                vec![group(vec![non_finite], vec![incoming])],
                true,
                false,
            )
            .is_err()
        );
        assert!(BaseAdjacency::build(&nid_index, vec![group(vec![], vec![incoming])],).is_err());
    }

    #[test]
    fn builder_retags_and_rejects_invalid_or_duplicate_identities() {
        let nid_index = NidIndex::build(vec![nid(1), nid(2)], false).unwrap();
        let group = |edges| BaseGroupInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            rows: vec![BaseRowInput {
                node_ordinal: 0,
                outgoing: edges,
                incoming: vec![],
            }],
        };
        assert!(
            BaseAdjacency::build(
                &nid_index,
                vec![group(vec![edge(
                    BaseNeighborInput::GlobalNid(nid(2)),
                    1,
                    1,
                )])]
            )
            .is_err()
        );
        assert!(
            BaseAdjacency::build(
                &nid_index,
                vec![group(vec![
                    edge(BaseNeighborInput::LocalOrdinal(1), 1, 1),
                    edge(BaseNeighborInput::LocalOrdinal(1), 1, 1),
                ])]
            )
            .is_err()
        );
        assert!(
            BaseAdjacency::build(
                &nid_index,
                vec![group(vec![edge(BaseNeighborInput::LocalOrdinal(9), 2, 1,)])]
            )
            .is_err()
        );
    }

    #[test]
    fn loader_rejects_parallel_count_and_local_range_corruption() {
        let (nid_index, adjacency) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();

        let mut bad_count = fs::read(&path).unwrap();
        let table_entry = graph_artifact::COMMON_HEADER_BYTES
            + (SECTION_OUT_EDGE_IDS as usize - 2) * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        let count_offset = table_entry + 24;
        bad_count[count_offset..count_offset + 8].copy_from_slice(&5_u64.to_le_bytes());
        let mut crc_input = Vec::new();
        crc_input.extend_from_slice(&bad_count[..28]);
        let section_count = u32::from_le_bytes(bad_count[24..28].try_into().unwrap()) as usize;
        let table_end = graph_artifact::COMMON_HEADER_BYTES
            + section_count * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        crc_input.extend_from_slice(&bad_count[graph_artifact::COMMON_HEADER_BYTES..table_end]);
        bad_count[28..32].copy_from_slice(&crc_fast::crc32_iscsi(&crc_input).to_le_bytes());
        fs::write(&path, bad_count).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
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
        let first_blob_byte = payload + (layout.frames[0].elem_count as usize + 1) * 8;
        bad_neighbor[first_blob_byte + 1] = 0x7e;
        fs::write(&path, bad_neighbor).unwrap();
        assert!(open(&path, &nid_index).is_err());
    }

    #[test]
    fn optional_loader_rejects_remap_weight_flag_and_mirror_corruption() {
        let (nid_index, adjacency) = optional_fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);

        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let remap = artifact.section(SECTION_TYPE_REMAP).unwrap();
        let mut bad_remap = fs::read(&path).unwrap();
        bad_remap[remap.offset..remap.offset + 4].copy_from_slice(&0_u32.to_le_bytes());
        fs::write(&path, bad_remap).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let weights =
            graph_group::open_grouped_section(&path, &artifact, SECTION_OUT_WEIGHTS, 1, WIDTH_F32)
                .unwrap();
        let section = artifact.section(SECTION_OUT_WEIGHTS).unwrap();
        let mut bad_weight = fs::read(&path).unwrap();
        let first = section.offset + weights.frames[0].payload_offset;
        bad_weight[first..first + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        fs::write(&path, bad_weight).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let mut bad_flag = fs::read(&path).unwrap();
        let flags = u32::from_le_bytes(bad_flag[12..16].try_into().unwrap()) & !FLAG_TYPE_REMAP;
        bad_flag[12..16].copy_from_slice(&flags.to_le_bytes());
        repair_header_crc(&mut bad_flag);
        fs::write(&path, bad_flag).unwrap();
        assert!(open(&path, &nid_index).is_err());

        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let edge_ids =
            graph_group::open_grouped_section(&path, &artifact, SECTION_IN_EDGE_IDS, 1, WIDTH_U64)
                .unwrap();
        let section = artifact.section(SECTION_IN_EDGE_IDS).unwrap();
        let mut bad_mirror = fs::read(&path).unwrap();
        let last = section.offset + edge_ids.frames[0].payload_offset + 16;
        bad_mirror[last..last + 8].copy_from_slice(&edge_id(9).raw().to_le_bytes());
        fs::write(&path, bad_mirror).unwrap();
        assert!(open(&path, &nid_index).is_err());
    }

    #[test]
    fn every_grouped_section_and_frame_is_chunk_aligned() {
        let (nid_index, adjacency) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_FILE);
        write(&path, &adjacency).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        for (section_id, width) in [
            (SECTION_NODE_ORDS, WIDTH_U32),
            (SECTION_OUT_OFFSETS, WIDTH_U64),
            (SECTION_OUT_NEIGHBORS, WIDTH_TAGGED_NEIGHBOR),
            (SECTION_OUT_EDGE_IDS, WIDTH_U64),
            (SECTION_OUT_TYPES, WIDTH_U32),
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
        open(&path, &nid_index).unwrap();
    }

    #[test]
    fn base_adjacency_uses_authenticated_chunks_when_encryption_is_enabled() {
        if env::var_os(ENCRYPTED_HELPER_ENV).is_some() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("graph_edge::tests::encrypted_base_adjacency_helper")
            .arg("--nocapture")
            .env(ENCRYPTED_HELPER_ENV, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "encrypted edge.gdx helper failed: {status}"
        );
    }

    #[test]
    fn encrypted_base_adjacency_helper() {
        let Some(root) = env::var_os(ENCRYPTED_HELPER_ENV) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let keyring_path = root.join("keyring.json");
        fs::write(
            &keyring_path,
            json!({
                "version": 1,
                "active_key_id": "g1-edge",
                "keys": [{
                    "id": "g1-edge",
                    "key_base64": STANDARD.encode([53_u8; 32]),
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
        let path = root.join(EDGE_FILE);
        let (nid_index, adjacency) = overflow_fixture(8_000);
        write(&path, &adjacency).unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], crate::encryption::MAGIC);
        let opened = open(&path, &nid_index).unwrap();
        assert_cursor_matches(&opened, &path, &nid_index);
        assert_eq!(opened.edge_count(), 8_000);
        drop(opened);
        for (name, (nids, adjacency)) in [
            ("optional.gdx", optional_fixture()),
            ("mirrored.gdx", mirrored_overflow_fixture(8_000)),
        ] {
            let path = root.join(name);
            write(&path, &adjacency).unwrap();
            assert_cursor_matches(&open(&path, &nids).unwrap(), &path, &nids);
        }
        let mut ciphertext = fs::read(&path).unwrap();
        *ciphertext
            .last_mut()
            .expect("encrypted edge.gdx is non-empty") ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(open(&path, &nid_index).is_err());
    }

    fn assert_cursor_matches(opened: &OpenedBaseAdjacency, path: &Path, nids: &NidIndex) {
        for group in 0..opened.group_count() {
            let decoded = opened.read_group(path, nids, group).unwrap();
            for (row, expected) in decoded.rows.iter().enumerate() {
                for (incoming, edges) in [(false, &expected.outgoing), (true, &expected.incoming)] {
                    if incoming && !opened.has_csc() {
                        continue;
                    }
                    let cursor = opened.edges(nids, group, row as u32, incoming).unwrap();
                    let node = local_nid(nids, expected.node_ordinal).unwrap();
                    assert_eq!(
                        cursor.collect::<Result<Vec<_>>>().unwrap(),
                        edges
                            .iter()
                            .map(|edge| graph_group::AdjacencyEdge {
                                edge_id: edge.edge_id,
                                source: if incoming { edge.neighbor_nid } else { node },
                                target: if incoming { node } else { edge.neighbor_nid },
                                type_id: edge.type_id,
                                local_base: matches!(
                                    edge.stored_neighbor,
                                    TaggedNeighbor::LocalDelta(_)
                                )
                                .then_some(u32::MAX),
                            })
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(
                        opened
                            .edges(nids, group, row as u32, incoming)
                            .unwrap()
                            .take(3)
                            .count(),
                        edges.len().min(3)
                    );
                }
            }
            assert!(
                opened
                    .edges(nids, group, decoded.rows.len() as u32, false)
                    .is_err()
            );
        }
        assert!(opened.edges(nids, opened.group_count(), 0, false).is_err());
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
