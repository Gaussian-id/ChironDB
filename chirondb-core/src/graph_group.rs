//! Shared namespace/group and tagged-neighbour codecs for graph artifacts.

use std::{borrow::Cow, cmp::Ordering, ops::Range, path::Path};

use crate::{
    GaussError, Result,
    graph::{
        EdgeId, GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, GraphNamespace, Nid, TypeId,
    },
    graph_artifact::CheckedArtifact,
};

pub(crate) mod cursor;

pub(crate) const AUTHENTICATED_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const WIDTH_U16: u32 = 1;
pub(crate) const WIDTH_U32: u32 = 2;
pub(crate) const WIDTH_U64: u32 = 3;
pub(crate) const WIDTH_F32: u32 = 4;
pub(crate) const WIDTH_TAGGED_NEIGHBOR: u32 = 5;
pub(crate) const WIDTH_FRAGMENT_REF: u32 = 6;
pub(crate) const WIDTH_OVERFLOW_CHAIN: u32 = 7;

const NAMESPACE_HEADER_BYTES: usize = 16;
const NAMESPACE_RECORD_BYTES: usize = 24;
const GROUP_HEADER_BYTES: usize = 16;
const FRAME_HEADER_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInput {
    pub(crate) namespace: GraphNamespace,
    pub(crate) row_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceDescriptor {
    pub(crate) namespace: GraphNamespace,
    pub(crate) row_start: u32,
    pub(crate) row_count: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupPayload<'a> {
    pub(crate) elem_count: u64,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GroupFrame {
    pub(crate) elem_count: u64,
    pub(crate) payload_offset: usize,
    pub(crate) payload_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupedSectionLayout {
    pub(crate) semantic_elem_count: u64,
    pub(crate) frames: Vec<GroupFrame>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaggedNeighbor {
    LocalDelta(i64),
    Global(Nid),
}

pub(crate) fn encode_namespace_index(inputs: &[NamespaceInput]) -> Result<Vec<u8>> {
    if inputs.len() > u32::MAX as usize {
        return Err(invalid("graph namespace count exceeds u32"));
    }
    validate_namespace_order(inputs.iter().map(|input| &input.namespace))?;
    let record_bytes = inputs
        .len()
        .checked_mul(NAMESPACE_RECORD_BYTES)
        .ok_or_else(|| invalid("graph namespace record length overflow"))?;
    let mut strings = Vec::new();
    let mut records = Vec::with_capacity(record_bytes);
    let mut row_start = 0_u32;
    for input in inputs {
        let (kind, name) = match &input.namespace {
            GraphNamespace::Tenant(name) => (0_u8, name.as_bytes()),
            GraphNamespace::AdminCrossTenant => (1_u8, &[][..]),
        };
        let name_offset = u32::try_from(strings.len())
            .map_err(|_| invalid("graph namespace string area exceeds u32"))?;
        let name_len =
            u32::try_from(name.len()).map_err(|_| invalid("graph namespace name exceeds u32"))?;
        let next_row = row_start
            .checked_add(input.row_count)
            .ok_or_else(|| invalid("graph namespace row count exceeds u32"))?;
        records.push(kind);
        records.push(0);
        records.extend_from_slice(&0_u16.to_le_bytes());
        records.extend_from_slice(&name_offset.to_le_bytes());
        records.extend_from_slice(&name_len.to_le_bytes());
        records.extend_from_slice(&row_start.to_le_bytes());
        records.extend_from_slice(&input.row_count.to_le_bytes());
        records.extend_from_slice(&0_u32.to_le_bytes());
        strings.extend_from_slice(name);
        row_start = next_row;
    }
    let record_bytes_u32 = u32::try_from(record_bytes)
        .map_err(|_| invalid("graph namespace record area exceeds u32"))?;
    let string_bytes_u64 = u64::try_from(strings.len())
        .map_err(|_| invalid("graph namespace string area exceeds u64"))?;
    let mut bytes = Vec::with_capacity(NAMESPACE_HEADER_BYTES + records.len() + strings.len());
    bytes.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&record_bytes_u32.to_le_bytes());
    bytes.extend_from_slice(&string_bytes_u64.to_le_bytes());
    bytes.extend_from_slice(&records);
    bytes.extend_from_slice(&strings);
    Ok(bytes)
}

pub(crate) fn decode_namespace_index(
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<NamespaceDescriptor>> {
    if bytes.len() < NAMESPACE_HEADER_BYTES {
        return Err(corruption(path, "truncated graph namespace header"));
    }
    let count = read_u32(bytes, 0) as usize;
    let record_bytes = read_u32(bytes, 4) as usize;
    let expected_record_bytes = count
        .checked_mul(NAMESPACE_RECORD_BYTES)
        .ok_or_else(|| corruption(path, "graph namespace record length overflow"))?;
    if record_bytes != expected_record_bytes {
        return Err(corruption(path, "graph namespace record length mismatch"));
    }
    let string_bytes = usize::try_from(read_u64(bytes, 8))
        .map_err(|_| corruption(path, "graph namespace string length exceeds usize"))?;
    let string_start = NAMESPACE_HEADER_BYTES
        .checked_add(record_bytes)
        .ok_or_else(|| corruption(path, "graph namespace string offset overflow"))?;
    let expected_len = string_start
        .checked_add(string_bytes)
        .ok_or_else(|| corruption(path, "graph namespace total length overflow"))?;
    if bytes.len() != expected_len {
        return Err(corruption(path, "graph namespace total length mismatch"));
    }
    let strings = &bytes[string_start..];
    let mut descriptors = Vec::with_capacity(count);
    let mut expected_name_offset = 0_usize;
    let mut expected_row_start = 0_u32;
    for index in 0..count {
        let start = NAMESPACE_HEADER_BYTES + index * NAMESPACE_RECORD_BYTES;
        let record = &bytes[start..start + NAMESPACE_RECORD_BYTES];
        let kind = record[0];
        if record[1] != 0 || read_u16(record, 2) != 0 || read_u32(record, 20) != 0 {
            return Err(corruption(
                path,
                "graph namespace reserved fields are non-zero",
            ));
        }
        let name_offset = read_u32(record, 4) as usize;
        let name_len = read_u32(record, 8) as usize;
        if name_offset != expected_name_offset {
            return Err(corruption(
                path,
                "graph namespace string ranges are not canonical",
            ));
        }
        let name_end = name_offset
            .checked_add(name_len)
            .ok_or_else(|| corruption(path, "graph namespace name range overflow"))?;
        if name_end > strings.len() {
            return Err(corruption(path, "graph namespace name exceeds string area"));
        }
        let namespace = match kind {
            0 if name_len != 0 => GraphNamespace::Tenant(
                std::str::from_utf8(&strings[name_offset..name_end])
                    .map_err(|_| corruption(path, "graph tenant namespace is not UTF-8"))?
                    .to_string(),
            ),
            1 if name_len == 0 => GraphNamespace::AdminCrossTenant,
            _ => return Err(corruption(path, "graph namespace kind/name is invalid")),
        };
        let row_start = read_u32(record, 12);
        let row_count = read_u32(record, 16);
        if row_start != expected_row_start {
            return Err(corruption(
                path,
                "graph namespace row ranges are not cumulative",
            ));
        }
        expected_row_start = row_start
            .checked_add(row_count)
            .ok_or_else(|| corruption(path, "graph namespace row range overflow"))?;
        expected_name_offset = name_end;
        descriptors.push(NamespaceDescriptor {
            namespace,
            row_start,
            row_count,
        });
    }
    if expected_name_offset != strings.len() {
        return Err(corruption(
            path,
            "graph namespace string area is not fully owned",
        ));
    }
    validate_namespace_order(descriptors.iter().map(|entry| &entry.namespace))
        .map_err(|error| corruption(path, &error.to_string()))?;
    Ok(descriptors)
}

pub(crate) fn encode_grouped_section(
    width_code: u32,
    groups: &[GroupPayload<'_>],
) -> Result<Vec<u8>> {
    validate_width_code(width_code)?;
    if groups.len() > u32::MAX as usize {
        return Err(invalid("graph grouped-section count exceeds u32"));
    }
    let semantic_elem_count = groups.iter().try_fold(0_u64, |total, group| {
        validate_group_payload(width_code, group.elem_count, group.bytes)?;
        total
            .checked_add(group.elem_count)
            .ok_or_else(|| invalid("graph grouped-section element count overflow"))
    })?;
    let offset_count = groups
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid("graph grouped-section offset count overflow"))?;
    let directory_bytes = offset_count
        .checked_mul(8)
        .ok_or_else(|| invalid("graph grouped-section directory length overflow"))?;
    let prefix_len = GROUP_HEADER_BYTES
        .checked_add(directory_bytes)
        .ok_or_else(|| invalid("graph grouped-section prefix overflow"))?;
    if groups.is_empty() {
        let mut bytes = Vec::with_capacity(prefix_len);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&width_code.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&(prefix_len as u64).to_le_bytes());
        return Ok(bytes);
    }

    let mut offsets = Vec::with_capacity(offset_count);
    let mut next = align_chunk(prefix_len)?;
    for group in groups {
        offsets.push(next);
        next = next
            .checked_add(FRAME_HEADER_BYTES)
            .and_then(|value| value.checked_add(group.bytes.len()))
            .ok_or_else(|| invalid("graph group frame length overflow"))?;
        if offsets.len() < groups.len() {
            next = align_chunk(next)?;
        }
    }
    offsets.push(next);
    let mut bytes = Vec::with_capacity(next);
    bytes.extend_from_slice(&(groups.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&width_code.to_le_bytes());
    bytes.extend_from_slice(&semantic_elem_count.to_le_bytes());
    for offset in &offsets {
        bytes.extend_from_slice(&(*offset as u64).to_le_bytes());
    }
    for (group, offset) in groups.iter().zip(offsets.iter().copied()) {
        bytes.resize(offset, 0);
        bytes.extend_from_slice(&group.elem_count.to_le_bytes());
        bytes.extend_from_slice(&(group.bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(group.bytes);
    }
    debug_assert_eq!(bytes.len(), next);
    Ok(bytes)
}

pub(crate) fn open_grouped_section(
    path: &Path,
    artifact: &CheckedArtifact,
    section_id: u32,
    expected_groups: usize,
    expected_width_code: u32,
) -> Result<GroupedSectionLayout> {
    validate_width_code(expected_width_code)
        .map_err(|error| corruption(path, &error.to_string()))?;
    let section = artifact
        .section(section_id)
        .ok_or_else(|| corruption(path, "required grouped section is absent"))?;
    if !section.offset.is_multiple_of(AUTHENTICATED_CHUNK_BYTES)
        || section.length < GROUP_HEADER_BYTES + 8
    {
        return Err(corruption(
            path,
            "graph grouped section is not chunk-aligned",
        ));
    }
    let header = artifact.read_section_range(section_id, 0..GROUP_HEADER_BYTES)?;
    let group_count = read_u32(&header, 0) as usize;
    if group_count != expected_groups || read_u32(&header, 4) != expected_width_code {
        return Err(corruption(path, "graph grouped-section metadata disagrees"));
    }
    let semantic_elem_count = read_u64(&header, 8);
    if section.elem_count != semantic_elem_count {
        return Err(corruption(
            path,
            "graph grouped-section count disagrees with section table",
        ));
    }
    let offset_count = group_count
        .checked_add(1)
        .ok_or_else(|| corruption(path, "graph grouped-section offset count overflow"))?;
    let directory_len = offset_count
        .checked_mul(8)
        .ok_or_else(|| corruption(path, "graph grouped-section directory overflow"))?;
    let directory_end = GROUP_HEADER_BYTES
        .checked_add(directory_len)
        .ok_or_else(|| corruption(path, "graph grouped-section prefix overflow"))?;
    if directory_end > section.length {
        return Err(corruption(
            path,
            "truncated graph grouped-section directory",
        ));
    }
    let directory = artifact.read_section_range(section_id, GROUP_HEADER_BYTES..directory_end)?;
    let offsets = directory
        .chunks_exact(8)
        .map(|bytes| {
            usize::try_from(u64::from_le_bytes(
                bytes.try_into().expect("group offset width"),
            ))
            .map_err(|_| corruption(path, "graph group offset exceeds usize"))
        })
        .collect::<Result<Vec<_>>>()?;
    if offsets.len() != offset_count || offsets.last().copied() != Some(section.length) {
        return Err(corruption(
            path,
            "graph grouped-section terminal offset disagrees",
        ));
    }
    if group_count == 0 {
        if semantic_elem_count != 0 || offsets[0] != directory_end {
            return Err(corruption(
                path,
                "empty graph grouped section is non-canonical",
            ));
        }
        return Ok(GroupedSectionLayout {
            semantic_elem_count,
            frames: Vec::new(),
        });
    }
    let initial_padding = artifact.read_section_range(section_id, directory_end..offsets[0])?;
    if initial_padding.iter().any(|byte| *byte != 0) {
        return Err(corruption(
            path,
            "graph grouped-section initial padding is non-zero",
        ));
    }

    let mut frames = Vec::with_capacity(group_count);
    let mut total = 0_u64;
    for index in 0..group_count {
        let offset = offsets[index];
        let next = offsets[index + 1];
        if offset < directory_end
            || offset >= next
            || !offset.is_multiple_of(AUTHENTICATED_CHUNK_BYTES)
        {
            return Err(corruption(path, "graph group frame offset is invalid"));
        }
        let header_end = offset
            .checked_add(FRAME_HEADER_BYTES)
            .ok_or_else(|| corruption(path, "graph group frame header overflow"))?;
        if header_end > next {
            return Err(corruption(path, "truncated graph group frame header"));
        }
        let frame_header = artifact.read_section_range(section_id, offset..header_end)?;
        let elem_count = read_u64(&frame_header, 0);
        let payload_len = usize::try_from(read_u64(&frame_header, 8))
            .map_err(|_| corruption(path, "graph group payload length exceeds usize"))?;
        let payload_end = header_end
            .checked_add(payload_len)
            .ok_or_else(|| corruption(path, "graph group payload range overflow"))?;
        if payload_end > next || (index + 1 == group_count && payload_end != next) {
            return Err(corruption(path, "graph group payload length disagrees"));
        }
        if index + 1 < group_count {
            let padding = artifact.read_section_range(section_id, payload_end..next)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(corruption(path, "graph group padding is non-zero"));
            }
        }
        validate_group_width(expected_width_code, elem_count, payload_len)
            .map_err(|error| corruption(path, &error.to_string()))?;
        if expected_width_code == WIDTH_F32 {
            let payload = artifact.read_section_range(section_id, header_end..payload_end)?;
            validate_finite_f32(&payload).map_err(|error| corruption(path, &error.to_string()))?;
        }
        total = total
            .checked_add(elem_count)
            .ok_or_else(|| corruption(path, "graph grouped-section element count overflow"))?;
        frames.push(GroupFrame {
            elem_count,
            payload_offset: header_end,
            payload_len,
        });
    }
    if total != semantic_elem_count {
        return Err(corruption(
            path,
            "graph grouped-section element total disagrees",
        ));
    }
    Ok(GroupedSectionLayout {
        semantic_elem_count,
        frames,
    })
}

pub(crate) fn read_group<'a>(
    artifact: &'a CheckedArtifact,
    section_id: u32,
    layout: &GroupedSectionLayout,
    group_index: usize,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    let frame = layout
        .frames
        .get(group_index)
        .ok_or_else(|| invalid("graph group index is out of bounds"))?;
    let end = frame
        .payload_offset
        .checked_add(frame.payload_len)
        .ok_or_else(|| invalid("graph group read range overflow"))?;
    artifact.read_section_range(section_id, frame.payload_offset..end)
}

/// A fixed-width row identity read without decoding adjacency lists.
pub(crate) fn read_fixed<const N: usize>(
    artifact: &CheckedArtifact,
    section_id: u32,
    layout: &GroupedSectionLayout,
    group_index: usize,
    row: u32,
) -> Result<[u8; N]> {
    let frame = layout
        .frames
        .get(group_index)
        .ok_or_else(|| invalid("graph group index is out of bounds"))?;
    if u64::from(row) >= frame.elem_count {
        return Err(invalid("graph row hint is out of bounds"));
    }
    let start = (row as usize)
        .checked_mul(N)
        .and_then(|offset| frame.payload_offset.checked_add(offset))
        .ok_or_else(|| invalid("graph row identity range overflow"))?;
    let end = start
        .checked_add(N)
        .ok_or_else(|| invalid("graph row identity range overflow"))?;
    let frame_end = frame
        .payload_offset
        .checked_add(frame.payload_len)
        .ok_or_else(|| invalid("graph frame range overflow"))?;
    if end > frame_end {
        return Err(invalid("graph row identity exceeds frame"));
    }
    Ok(artifact
        .read_section_range(section_id, start..end)?
        .as_ref()
        .try_into()
        .expect("checked fixed width"))
}

/// Identity and structure decoded from one authorized adjacency candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdjacencyEdge {
    pub(crate) edge_id: EdgeId,
    pub(crate) source: Nid,
    pub(crate) target: Nid,
    pub(crate) type_id: TypeId,
    /// Base-segment index for a tagged local reference. `None` means the
    /// candidate is global (delta or mutable tail).
    pub(crate) local_base: Option<u32>,
}

/// Physical work or a cooperative boundary in a scoped adjacency scan.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AdjacencyStep {
    Edge(AdjacencyEdge),
    /// Give the executor control between rows/plans, including empty rows.
    Checkpoint,
}

impl AdjacencyStep {
    pub(crate) fn edge(self) -> Option<AdjacencyEdge> {
        match self {
            Self::Edge(id) => Some(id),
            Self::Checkpoint => None,
        }
    }
}

/// Lazy checked EdgeId column range. At most one chunk-sized buffer is held;
/// a hub never allocates a Vec proportional to its degree during traversal.
pub(crate) struct EdgeIdCursor<'a> {
    artifact: &'a CheckedArtifact,
    section: u32,
    next: usize,
    end: usize,
    buffer: Cow<'a, [u8]>,
    position: usize,
    failed: bool,
}

impl<'a> EdgeIdCursor<'a> {
    pub(crate) fn new(
        artifact: &'a CheckedArtifact,
        section: u32,
        frame: &GroupFrame,
        range: Range<u64>,
    ) -> Result<Self> {
        if range.start > range.end || range.end > frame.elem_count {
            return Err(invalid("graph EdgeId cursor range exceeds frame"));
        }
        let offset = |value: u64| {
            usize::try_from(value)
                .ok()
                .and_then(|value| value.checked_mul(8))
                .filter(|value| *value <= frame.payload_len)
                .and_then(|value| frame.payload_offset.checked_add(value))
                .ok_or_else(|| invalid("graph EdgeId cursor range overflow"))
        };
        Ok(Self {
            artifact,
            section,
            next: offset(range.start)?,
            end: offset(range.end)?,
            buffer: Cow::Borrowed(&[]),
            position: 0,
            failed: false,
        })
    }

    fn read_next(&mut self) -> Result<Option<EdgeId>> {
        if self.position == self.buffer.len() {
            if self.next == self.end {
                return Ok(None);
            }
            let end = self
                .next
                .saturating_add(AUTHENTICATED_CHUNK_BYTES)
                .min(self.end);
            self.buffer = Cow::Borrowed(&[]);
            self.buffer = self
                .artifact
                .read_section_range(self.section, self.next..end)?;
            self.position = 0;
            self.next = end;
        }
        let end = self.position + 8;
        let id = EdgeId::from_raw(u64::from_le_bytes(
            self.buffer[self.position..end]
                .try_into()
                .expect("checked EdgeId width"),
        ));
        self.position = end;
        Ok(Some(id))
    }
}

impl Iterator for EdgeIdCursor<'_> {
    type Item = Result<EdgeId>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.read_next() {
            Ok(id) => id.map(Ok),
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

pub(crate) fn encode_tagged_neighbors(neighbors: &[TaggedNeighbor]) -> Result<Vec<u8>> {
    let offset_count = neighbors
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid("tagged-neighbour offset count overflow"))?;
    let mut offsets = Vec::with_capacity(offset_count);
    let mut blob = Vec::new();
    for neighbor in neighbors {
        offsets.push(blob.len() as u64);
        blob.extend_from_slice(&encode_tagged_neighbor(*neighbor)?);
    }
    offsets.push(blob.len() as u64);
    let mut bytes = Vec::with_capacity(offsets.len() * 8 + blob.len());
    for offset in offsets {
        bytes.extend_from_slice(&offset.to_le_bytes());
    }
    bytes.extend_from_slice(&blob);
    Ok(bytes)
}

pub(crate) fn decode_tagged_neighbors(
    path: &Path,
    bytes: &[u8],
    elem_count: u64,
) -> Result<Vec<TaggedNeighbor>> {
    let count = usize::try_from(elem_count)
        .map_err(|_| corruption(path, "tagged-neighbour count exceeds usize"))?;
    let offset_count = count
        .checked_add(1)
        .ok_or_else(|| corruption(path, "tagged-neighbour offset count overflow"))?;
    let offset_bytes = offset_count
        .checked_mul(8)
        .ok_or_else(|| corruption(path, "tagged-neighbour offset bytes overflow"))?;
    if offset_bytes > bytes.len() {
        return Err(corruption(path, "truncated tagged-neighbour offsets"));
    }
    let offsets = bytes[..offset_bytes]
        .chunks_exact(8)
        .map(|raw| {
            usize::try_from(u64::from_le_bytes(
                raw.try_into().expect("tagged-neighbour offset width"),
            ))
            .map_err(|_| corruption(path, "tagged-neighbour offset exceeds usize"))
        })
        .collect::<Result<Vec<_>>>()?;
    let blob = &bytes[offset_bytes..];
    if offsets.first().copied() != Some(0) || offsets.last().copied() != Some(blob.len()) {
        return Err(corruption(
            path,
            "tagged-neighbour terminal offsets disagree",
        ));
    }
    let mut decoded = Vec::with_capacity(count);
    for pair in offsets.windows(2) {
        if pair[0] >= pair[1] || pair[1] > blob.len() {
            return Err(corruption(path, "tagged-neighbour ranges are invalid"));
        }
        let entry = &blob[pair[0]..pair[1]];
        let (neighbor, consumed) = decode_tagged_neighbor_prefix(path, entry)?;
        if consumed != entry.len() {
            return Err(corruption(
                path,
                "tagged-neighbour entry has trailing bytes",
            ));
        }
        decoded.push(neighbor);
    }
    Ok(decoded)
}

pub(crate) fn encode_tagged_neighbor(neighbor: TaggedNeighbor) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(tagged_neighbor_encoded_len(neighbor)?);
    match neighbor {
        TaggedNeighbor::LocalDelta(delta) => {
            bytes.push(0);
            encode_uleb128(zigzag_encode(delta), &mut bytes);
        }
        TaggedNeighbor::Global(nid) => {
            validate_nid(nid)?;
            bytes.push(1);
            encode_uleb128(nid.raw(), &mut bytes);
        }
    }
    Ok(bytes)
}

pub(crate) fn tagged_neighbor_encoded_len(neighbor: TaggedNeighbor) -> Result<usize> {
    let value = match neighbor {
        TaggedNeighbor::LocalDelta(delta) => zigzag_encode(delta),
        TaggedNeighbor::Global(nid) => {
            validate_nid(nid)?;
            nid.raw()
        }
    };
    let leb_bytes = if value == 0 {
        1
    } else {
        ((u64::BITS - value.leading_zeros()) as usize).div_ceil(7)
    };
    Ok(1 + leb_bytes)
}

pub(crate) fn decode_tagged_neighbor_prefix(
    path: &Path,
    bytes: &[u8],
) -> Result<(TaggedNeighbor, usize)> {
    let Some(tag) = bytes.first().copied() else {
        return Err(corruption(path, "truncated tagged-neighbour entry"));
    };
    let mut end = None;
    for (index, byte) in bytes.iter().copied().skip(1).take(10).enumerate() {
        if byte & 0x80 == 0 {
            end = Some(index + 2);
            break;
        }
    }
    let end = end.ok_or_else(|| corruption(path, "invalid tagged-neighbour LEB128 length"))?;
    let value = decode_canonical_uleb128(path, &bytes[1..end])?;
    let neighbor = match tag {
        0 => TaggedNeighbor::LocalDelta(zigzag_decode(value)),
        1 => {
            let nid = Nid::from_raw(value);
            validate_nid(nid).map_err(|error| corruption(path, &error.to_string()))?;
            TaggedNeighbor::Global(nid)
        }
        _ => return Err(corruption(path, "unknown tagged-neighbour kind")),
    };
    Ok((neighbor, end))
}

fn validate_namespace_order<'a>(
    namespaces: impl IntoIterator<Item = &'a GraphNamespace>,
) -> Result<()> {
    let mut previous: Option<&GraphNamespace> = None;
    for namespace in namespaces {
        if matches!(namespace, GraphNamespace::Tenant(name) if name.is_empty()) {
            return Err(invalid("tenant graph namespace cannot be empty"));
        }
        if previous.is_some_and(|value| compare_namespaces(value, namespace) != Ordering::Less) {
            return Err(invalid("graph namespaces are not strictly canonical"));
        }
        previous = Some(namespace);
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

fn validate_width_code(width_code: u32) -> Result<()> {
    if !matches!(
        width_code,
        WIDTH_U16
            | WIDTH_U32
            | WIDTH_U64
            | WIDTH_F32
            | WIDTH_TAGGED_NEIGHBOR
            | WIDTH_FRAGMENT_REF
            | WIDTH_OVERFLOW_CHAIN
    ) {
        return Err(invalid("unknown graph grouped-section width code"));
    }
    Ok(())
}

fn validate_group_width(width_code: u32, elem_count: u64, payload_len: usize) -> Result<()> {
    let width = match width_code {
        WIDTH_U16 => Some(2_usize),
        WIDTH_U32 | WIDTH_F32 => Some(4),
        WIDTH_U64 => Some(8),
        WIDTH_FRAGMENT_REF => Some(16),
        WIDTH_TAGGED_NEIGHBOR | WIDTH_OVERFLOW_CHAIN => None,
        _ => return Err(invalid("unknown graph grouped-section width code")),
    };
    if let Some(width) = width {
        let count = usize::try_from(elem_count)
            .map_err(|_| invalid("graph group element count exceeds usize"))?;
        let expected = count
            .checked_mul(width)
            .ok_or_else(|| invalid("graph group fixed-width length overflow"))?;
        if payload_len != expected {
            return Err(invalid("graph group fixed-width length mismatch"));
        }
    }
    Ok(())
}

fn validate_group_payload(width_code: u32, elem_count: u64, bytes: &[u8]) -> Result<()> {
    validate_group_width(width_code, elem_count, bytes.len())?;
    if width_code == WIDTH_F32 {
        validate_finite_f32(bytes)?;
    }
    Ok(())
}

fn validate_finite_f32(bytes: &[u8]) -> Result<()> {
    if bytes
        .chunks_exact(4)
        .any(|raw| !f32::from_le_bytes(raw.try_into().expect("validated f32 width")).is_finite())
    {
        return Err(invalid("graph group contains a non-finite f32"));
    }
    Ok(())
}

fn align_chunk(value: usize) -> Result<usize> {
    value
        .checked_add(AUTHENTICATED_CHUNK_BYTES - 1)
        .map(|value| value & !(AUTHENTICATED_CHUNK_BYTES - 1))
        .ok_or_else(|| invalid("graph group chunk alignment overflow"))
}

fn encode_uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_canonical_uleb128(path: &Path, bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.len() > 10 {
        return Err(corruption(path, "invalid tagged-neighbour LEB128 length"));
    }
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let payload = (byte & 0x7f) as u64;
        if index == 9 && (byte & 0xfe) != 0 {
            return Err(corruption(path, "tagged-neighbour LEB128 overflows u64"));
        }
        value |= payload << (index * 7);
        let terminal = byte & 0x80 == 0;
        if terminal != (index + 1 == bytes.len()) {
            return Err(corruption(
                path,
                "tagged-neighbour LEB128 has trailing bytes",
            ));
        }
    }
    let mut canonical = Vec::new();
    encode_uleb128(value, &mut canonical);
    if canonical != bytes {
        return Err(corruption(path, "tagged-neighbour LEB128 is non-canonical"));
    }
    Ok(value)
}

fn zigzag_encode(value: i64) -> u64 {
    ((value as u64) << 1) ^ ((value >> 63) as u64)
}

fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ (-((value & 1) as i64))
}

fn validate_nid(nid: Nid) -> Result<()> {
    if nid.raw() == 0
        || nid.epoch() == 0
        || nid.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || nid.counter() == 0
        || nid.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("tagged neighbour contains an invalid Nid"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked u16 width"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked u32 width"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked u64 width"),
    )
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
    use std::fs;

    use super::*;
    use crate::graph_artifact::{self, ArtifactSpec, SectionPayload};

    const MAGIC: &[u8; 8] = b"GAUSGR01";
    const SPEC: ArtifactSpec = ArtifactSpec {
        magic: MAGIC,
        allowed_flags: 0,
        required_sections: &[1],
        optional_sections: &[],
        max_file_len: 4 * 1024 * 1024,
    };

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(19, counter).unwrap()
    }

    #[test]
    fn namespace_index_round_trips_canonical_tenants_and_admin() {
        let inputs = vec![
            NamespaceInput {
                namespace: GraphNamespace::Tenant("acme".to_string()),
                row_count: 2,
            },
            NamespaceInput {
                namespace: GraphNamespace::Tenant("globex".to_string()),
                row_count: 3,
            },
            NamespaceInput {
                namespace: GraphNamespace::AdminCrossTenant,
                row_count: 1,
            },
        ];
        let bytes = encode_namespace_index(&inputs).unwrap();
        let decoded = decode_namespace_index(Path::new("namespace_index"), &bytes).unwrap();
        assert_eq!(decoded[0].row_start, 0);
        assert_eq!(decoded[1].row_start, 2);
        assert_eq!(decoded[2].row_start, 5);
        assert_eq!(decoded[2].namespace, GraphNamespace::AdminCrossTenant);

        let reversed = vec![inputs[1].clone(), inputs[0].clone()];
        assert!(encode_namespace_index(&reversed).is_err());
        assert!(
            encode_namespace_index(&[NamespaceInput {
                namespace: GraphNamespace::Tenant(String::new()),
                row_count: 1,
            }])
            .is_err()
        );
    }

    #[test]
    fn namespace_loader_rejects_noncanonical_string_and_row_ranges() {
        let inputs = [NamespaceInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            row_count: 2,
        }];
        let bytes = encode_namespace_index(&inputs).unwrap();

        let mut bad_name = bytes.clone();
        bad_name[NAMESPACE_HEADER_BYTES + 4..NAMESPACE_HEADER_BYTES + 8]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert!(decode_namespace_index(Path::new("bad-name"), &bad_name).is_err());

        let mut bad_rows = bytes;
        bad_rows[NAMESPACE_HEADER_BYTES + 12..NAMESPACE_HEADER_BYTES + 16]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert!(decode_namespace_index(Path::new("bad-rows"), &bad_rows).is_err());
    }

    #[test]
    fn grouped_sections_align_frames_and_reject_padding_or_width_corruption() {
        let first = [1_u32, 2]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let second = [3_u32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let grouped = encode_grouped_section(
            WIDTH_U32,
            &[
                GroupPayload {
                    elem_count: 2,
                    bytes: &first,
                },
                GroupPayload {
                    elem_count: 1,
                    bytes: &second,
                },
            ],
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("group.gdx");
        graph_artifact::write_aligned(
            &path,
            SPEC,
            0,
            &[SectionPayload {
                id: 1,
                elem_count: 3,
                bytes: &grouped,
            }],
            &[(1, AUTHENTICATED_CHUNK_BYTES)],
        )
        .unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let layout =
            open_grouped_section(Path::new("group.gdx"), &artifact, 1, 2, WIDTH_U32).unwrap();
        assert_eq!(layout.semantic_elem_count, 3);
        assert_eq!(&*read_group(&artifact, 1, &layout, 0).unwrap(), &first);
        assert_eq!(&*read_group(&artifact, 1, &layout, 1).unwrap(), &second);
        assert!(
            artifact
                .section(1)
                .unwrap()
                .offset
                .is_multiple_of(AUTHENTICATED_CHUNK_BYTES)
        );
        assert!(layout.frames[0].payload_offset < layout.frames[1].payload_offset);

        let mut corrupt = fs::read(&path).unwrap();
        let section_start = artifact.section(1).unwrap().offset;
        let first_end =
            section_start + layout.frames[0].payload_offset + layout.frames[0].payload_len;
        corrupt[first_end] = 1;
        fs::write(&path, corrupt).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        assert!(open_grouped_section(Path::new("group.gdx"), &artifact, 1, 2, WIDTH_U32).is_err());

        assert!(
            encode_grouped_section(
                WIDTH_U32,
                &[GroupPayload {
                    elem_count: 2,
                    bytes: &second,
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn empty_grouped_section_is_canonical() {
        let bytes = encode_grouped_section(WIDTH_U64, &[]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("empty.gdx");
        graph_artifact::write_aligned(
            &path,
            SPEC,
            0,
            &[SectionPayload {
                id: 1,
                elem_count: 0,
                bytes: &bytes,
            }],
            &[(1, AUTHENTICATED_CHUNK_BYTES)],
        )
        .unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let layout =
            open_grouped_section(Path::new("empty.gdx"), &artifact, 1, 0, WIDTH_U64).unwrap();
        assert!(layout.frames.is_empty());
    }

    #[test]
    fn tagged_neighbors_round_trip_extremes_and_reject_noncanonical_entries() {
        let neighbors = vec![
            TaggedNeighbor::LocalDelta(i64::MIN),
            TaggedNeighbor::LocalDelta(-1),
            TaggedNeighbor::LocalDelta(0),
            TaggedNeighbor::LocalDelta(i64::MAX),
            TaggedNeighbor::Global(nid(1)),
            TaggedNeighbor::Global(nid(GRAPH_ALLOCATOR_MAX_COUNTER)),
        ];
        let bytes = encode_tagged_neighbors(&neighbors).unwrap();
        assert_eq!(
            decode_tagged_neighbors(Path::new("neighbors"), &bytes, neighbors.len() as u64)
                .unwrap(),
            neighbors
        );

        let mut unknown_tag = encode_tagged_neighbors(&[TaggedNeighbor::LocalDelta(0)]).unwrap();
        unknown_tag[16] = 2;
        assert!(decode_tagged_neighbors(Path::new("tag"), &unknown_tag, 1).is_err());

        let mut overlong = Vec::new();
        overlong.extend_from_slice(&0_u64.to_le_bytes());
        overlong.extend_from_slice(&3_u64.to_le_bytes());
        overlong.extend_from_slice(&[0, 0x80, 0]);
        assert!(decode_tagged_neighbors(Path::new("leb"), &overlong, 1).is_err());

        assert!(encode_tagged_neighbors(&[TaggedNeighbor::Global(Nid::UNASSIGNED)]).is_err());
    }
}
