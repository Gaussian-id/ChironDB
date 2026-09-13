//! `fragdir.gdx` scoped fragment directory (Rev 3.4 Appendix C.7).

use std::{cmp::Ordering, path::Path};

use crate::{
    GaussError, Result,
    graph::{GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, GraphNamespace, Nid},
    graph_artifact::{self, ArtifactSpec, CheckedArtifact, SectionPayload},
    graph_group::{
        self, AUTHENTICATED_CHUNK_BYTES, GroupFrame, GroupPayload, GroupedSectionLayout,
        NamespaceDescriptor, NamespaceInput, WIDTH_FRAGMENT_REF, WIDTH_U32, WIDTH_U64,
    },
};

pub(crate) const FRAGMENT_DIRECTORY_FILE: &str = "fragdir.gdx";
pub(crate) const FRAGMENT_DIRECTORY_MAGIC: &[u8; 8] = b"GAUSFD01";

const FLAG_BLOOM: u32 = 1;
const FLAG_OVERLAY: u32 = 1 << 1;
const SECTION_NAMESPACE_INDEX: u32 = 1;
const SECTION_NID_INDEX: u32 = 2;
const SECTION_FRAGMENT_OFFSETS: u32 = 3;
const SECTION_FRAGMENT_REFS: u32 = 4;
const SECTION_BLOOM: u32 = 5;
const REQUIRED_SECTIONS: &[u32] = &[
    SECTION_NAMESPACE_INDEX,
    SECTION_NID_INDEX,
    SECTION_FRAGMENT_OFFSETS,
    SECTION_FRAGMENT_REFS,
];
const OPTIONAL_SECTIONS: &[u32] = &[SECTION_BLOOM];
const SPEC: ArtifactSpec = ArtifactSpec {
    magic: FRAGMENT_DIRECTORY_MAGIC,
    allowed_flags: FLAG_BLOOM | FLAG_OVERLAY,
    required_sections: REQUIRED_SECTIONS,
    optional_sections: OPTIONAL_SECTIONS,
    max_file_len: u64::MAX,
};

const FRAGMENT_REF_BYTES: usize = 16;
const BLOOM_HASHES: u32 = 7;
const BLOOM_BITS_PER_KEY: usize = 10;
const BLOOM_HEADER_BYTES: usize = 16;
const BLOOM_MIN_BITS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FragmentDirectoryRunKind {
    Base,
    Overlay,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FragmentReference {
    pub(crate) fragment_id: u64,
    pub(crate) row_hint: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FragmentRowInput {
    pub(crate) nid: Nid,
    pub(crate) fragments: Vec<FragmentReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FragmentGroupInput {
    pub(crate) namespace: GraphNamespace,
    pub(crate) rows: Vec<FragmentRowInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FragmentGroup {
    namespace: GraphNamespace,
    rows: Vec<FragmentRowInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FragmentDirectory {
    kind: FragmentDirectoryRunKind,
    include_bloom: bool,
    groups: Vec<FragmentGroup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedFragmentRow {
    pub(crate) nid: Nid,
    pub(crate) fragments: Vec<FragmentReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedFragmentGroup {
    pub(crate) namespace: GraphNamespace,
    pub(crate) rows: Vec<DecodedFragmentRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FragmentBloom {
    bit_count: u64,
    bits: Vec<u8>,
}

pub(crate) struct OpenedFragmentDirectory {
    artifact: CheckedArtifact,
    kind: FragmentDirectoryRunKind,
    namespaces: Vec<NamespaceDescriptor>,
    nids: GroupedSectionLayout,
    offsets: GroupedSectionLayout,
    fragments: GroupedSectionLayout,
    bloom: Option<FragmentBloom>,
}

impl FragmentDirectory {
    pub(crate) fn build(
        kind: FragmentDirectoryRunKind,
        include_bloom: bool,
        mut groups: Vec<FragmentGroupInput>,
    ) -> Result<Self> {
        if groups.is_empty() {
            return Err(invalid(
                "fragdir.gdx cannot represent an empty fragment directory",
            ));
        }
        groups
            .sort_unstable_by(|left, right| compare_namespaces(&left.namespace, &right.namespace));
        if groups.windows(2).any(|pair| {
            compare_namespaces(&pair[0].namespace, &pair[1].namespace) != Ordering::Less
        }) {
            return Err(invalid("fragdir.gdx contains duplicate graph namespaces"));
        }

        let mut normalized = Vec::with_capacity(groups.len());
        for mut group in groups {
            if group.rows.is_empty() {
                return Err(invalid(
                    "fragdir.gdx cannot persist an empty namespace group",
                ));
            }
            if group.rows.len() > u32::MAX as usize {
                return Err(invalid("fragdir.gdx namespace row count exceeds u32"));
            }
            group.rows.sort_unstable_by_key(|row| row.nid);
            if group.rows.windows(2).any(|pair| pair[0].nid == pair[1].nid) {
                return Err(invalid("fragdir.gdx contains a duplicate Nid in one group"));
            }

            let mut reference_count = 0_u64;
            for row in &mut group.rows {
                validate_nid(row.nid)?;
                if row.fragments.is_empty() {
                    return Err(invalid("fragdir.gdx row contains no fragment references"));
                }
                row.fragments.sort_unstable();
                if row
                    .fragments
                    .iter()
                    .any(|reference| reference.fragment_id == 0)
                {
                    return Err(invalid("fragdir.gdx contains reserved fragment ID zero"));
                }
                if row.fragments.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(invalid(
                        "fragdir.gdx contains a duplicate fragment reference in one row",
                    ));
                }
                reference_count = reference_count
                    .checked_add(row.fragments.len() as u64)
                    .ok_or_else(|| invalid("fragdir.gdx reference count overflow"))?;
            }
            if reference_count > u32::MAX as u64 {
                return Err(invalid(
                    "fragdir.gdx namespace reference count exceeds u32 offsets",
                ));
            }
            normalized.push(FragmentGroup {
                namespace: group.namespace,
                rows: group.rows,
            });
        }
        Ok(Self {
            kind,
            include_bloom,
            groups: normalized,
        })
    }

    pub(crate) fn kind(&self) -> FragmentDirectoryRunKind {
        self.kind
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn row_count(&self) -> u64 {
        self.groups
            .iter()
            .map(|group| group.rows.len() as u64)
            .sum()
    }

    pub(crate) fn reference_count(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|group| &group.rows)
            .map(|row| row.fragments.len() as u64)
            .sum()
    }
}

pub(crate) fn write(path: &Path, directory: &FragmentDirectory) -> Result<()> {
    let namespace_inputs = directory
        .groups
        .iter()
        .map(|group| {
            Ok(NamespaceInput {
                namespace: group.namespace.clone(),
                row_count: u32::try_from(group.rows.len())
                    .map_err(|_| invalid("fragdir.gdx namespace row count exceeds u32"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let namespace_index = graph_group::encode_namespace_index(&namespace_inputs)?;

    let mut row_counts = Vec::with_capacity(directory.groups.len());
    let mut reference_counts = Vec::with_capacity(directory.groups.len());
    let mut nid_groups = Vec::with_capacity(directory.groups.len());
    let mut offset_groups = Vec::with_capacity(directory.groups.len());
    let mut reference_groups = Vec::with_capacity(directory.groups.len());
    let mut bloom_nids = Vec::new();
    for group in &directory.groups {
        row_counts.push(group.rows.len() as u64);
        let mut nids = Vec::with_capacity(group.rows.len() * 8);
        let mut offsets = Vec::with_capacity((group.rows.len() + 1) * 4);
        let mut references = Vec::new();
        let mut next_offset = 0_u32;
        offsets.extend_from_slice(&next_offset.to_le_bytes());
        for row in &group.rows {
            nids.extend_from_slice(&row.nid.raw().to_le_bytes());
            bloom_nids.push(row.nid);
            for reference in &row.fragments {
                references.extend_from_slice(&reference.fragment_id.to_le_bytes());
                references.extend_from_slice(&reference.row_hint.to_le_bytes());
                references.extend_from_slice(&0_u32.to_le_bytes());
            }
            next_offset = next_offset
                .checked_add(row.fragments.len() as u32)
                .ok_or_else(|| invalid("fragdir.gdx group offset overflow"))?;
            offsets.extend_from_slice(&next_offset.to_le_bytes());
        }
        reference_counts.push(next_offset as u64);
        nid_groups.push(nids);
        offset_groups.push(offsets);
        reference_groups.push(references);
    }
    let offset_counts = row_counts.iter().map(|count| count + 1).collect::<Vec<_>>();
    let nid_index = encode_grouped(WIDTH_U64, &row_counts, &nid_groups)?;
    let fragment_offsets = encode_grouped(WIDTH_U32, &offset_counts, &offset_groups)?;
    let fragment_refs = encode_grouped(WIDTH_FRAGMENT_REF, &reference_counts, &reference_groups)?;
    let total_rows = checked_sum(&row_counts, "fragdir.gdx total row count overflow")?;
    let total_references = checked_sum(
        &reference_counts,
        "fragdir.gdx total reference count overflow",
    )?;
    let bloom = directory
        .include_bloom
        .then(|| FragmentBloom::build(&bloom_nids))
        .transpose()?;
    let bloom_bytes = bloom.as_ref().map(FragmentBloom::encode);

    let mut sections = vec![
        SectionPayload {
            id: SECTION_NAMESPACE_INDEX,
            elem_count: directory.groups.len() as u64,
            bytes: &namespace_index,
        },
        SectionPayload {
            id: SECTION_NID_INDEX,
            elem_count: total_rows,
            bytes: &nid_index,
        },
        SectionPayload {
            id: SECTION_FRAGMENT_OFFSETS,
            elem_count: total_rows + directory.groups.len() as u64,
            bytes: &fragment_offsets,
        },
        SectionPayload {
            id: SECTION_FRAGMENT_REFS,
            elem_count: total_references,
            bytes: &fragment_refs,
        },
    ];
    if let Some(bytes) = bloom_bytes.as_deref() {
        sections.push(SectionPayload {
            id: SECTION_BLOOM,
            elem_count: bloom.as_ref().expect("Bloom bytes exist").bit_count,
            bytes,
        });
    }
    let flags = match directory.kind {
        FragmentDirectoryRunKind::Base => 0,
        FragmentDirectoryRunKind::Overlay => FLAG_OVERLAY,
    } | if directory.include_bloom {
        FLAG_BLOOM
    } else {
        0
    };
    graph_artifact::write_aligned(
        path,
        SPEC,
        flags,
        &sections,
        &[
            (SECTION_NID_INDEX, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_FRAGMENT_OFFSETS, AUTHENTICATED_CHUNK_BYTES),
            (SECTION_FRAGMENT_REFS, AUTHENTICATED_CHUNK_BYTES),
        ],
    )
}

pub(crate) fn open(path: &Path) -> Result<OpenedFragmentDirectory> {
    let artifact = graph_artifact::open(path, SPEC)?;
    let has_bloom = artifact.flags() & FLAG_BLOOM != 0;
    if has_bloom != artifact.section(SECTION_BLOOM).is_some() {
        return Err(corruption(
            path,
            "fragdir.gdx Bloom flag and section disagree",
        ));
    }
    let kind = if artifact.flags() & FLAG_OVERLAY != 0 {
        FragmentDirectoryRunKind::Overlay
    } else {
        FragmentDirectoryRunKind::Base
    };
    let namespace_section = artifact
        .section(SECTION_NAMESPACE_INDEX)
        .expect("common loader requires fragment namespace index");
    let namespaces = graph_group::decode_namespace_index(
        path,
        &artifact.read_section(SECTION_NAMESPACE_INDEX)?,
    )?;
    if namespaces.is_empty()
        || namespace_section.elem_count != namespaces.len() as u64
        || namespaces.iter().any(|namespace| namespace.row_count == 0)
    {
        return Err(corruption(path, "fragdir.gdx namespace index is invalid"));
    }

    let group_count = namespaces.len();
    let nids = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_NID_INDEX,
        group_count,
        WIDTH_U64,
    )?;
    let offsets = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_FRAGMENT_OFFSETS,
        group_count,
        WIDTH_U32,
    )?;
    let fragments = graph_group::open_grouped_section(
        path,
        &artifact,
        SECTION_FRAGMENT_REFS,
        group_count,
        WIDTH_FRAGMENT_REF,
    )?;
    let total_rows = namespaces.iter().try_fold(0_u64, |total, namespace| {
        total
            .checked_add(namespace.row_count as u64)
            .ok_or_else(|| corruption(path, "fragdir.gdx total row count overflow"))
    })?;
    if nids.semantic_elem_count != total_rows
        || offsets.semantic_elem_count != total_rows + group_count as u64
    {
        return Err(corruption(
            path,
            "fragdir.gdx grouped section counts disagree",
        ));
    }

    let bloom = if has_bloom {
        let section = artifact
            .section(SECTION_BLOOM)
            .expect("Bloom section agrees with flag");
        Some(FragmentBloom::decode(
            path,
            &artifact.read_section(SECTION_BLOOM)?,
            section.elem_count,
            total_rows,
        )?)
    } else {
        None
    };
    let opened = OpenedFragmentDirectory {
        artifact,
        kind,
        namespaces,
        nids,
        offsets,
        fragments,
        bloom,
    };
    let mut total_references = 0_u64;
    for group_index in 0..opened.namespaces.len() {
        let group = opened.decode_group(path, group_index)?;
        total_references = total_references
            .checked_add(
                group
                    .rows
                    .iter()
                    .map(|row| row.fragments.len() as u64)
                    .sum::<u64>(),
            )
            .ok_or_else(|| corruption(path, "fragdir.gdx total reference count overflow"))?;
    }
    if total_references != opened.fragments.semantic_elem_count {
        return Err(corruption(path, "fragdir.gdx reference total disagrees"));
    }
    Ok(opened)
}

impl OpenedFragmentDirectory {
    pub(crate) fn kind(&self) -> FragmentDirectoryRunKind {
        self.kind
    }

    pub(crate) fn group_count(&self) -> usize {
        self.namespaces.len()
    }

    pub(crate) fn row_count(&self) -> u64 {
        self.nids.semantic_elem_count
    }

    pub(crate) fn reference_count(&self) -> u64 {
        self.fragments.semantic_elem_count
    }

    pub(crate) fn read_group(
        &self,
        path: &Path,
        group_index: usize,
    ) -> Result<DecodedFragmentGroup> {
        self.decode_group(path, group_index)
    }

    pub(crate) fn lookup(
        &self,
        path: &Path,
        namespace: &GraphNamespace,
        nid: Nid,
    ) -> Result<Option<Vec<FragmentReference>>> {
        validate_nid(nid).map_err(|error| corruption(path, &error.to_string()))?;
        let Some(group_index) = self
            .namespaces
            .iter()
            .position(|descriptor| &descriptor.namespace == namespace)
        else {
            return Ok(None);
        };
        if self
            .bloom
            .as_ref()
            .is_some_and(|bloom| !bloom.may_contain(nid))
        {
            return Ok(None);
        }
        let frame = &self.nids.frames[group_index];
        let mut lower = 0_usize;
        let mut upper = usize::try_from(frame.elem_count)
            .map_err(|_| corruption(path, "fragdir.gdx group row count exceeds usize"))?;
        let mut found = None;
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let raw = self.read_fixed(
                SECTION_NID_INDEX,
                frame,
                middle,
                8,
                8,
                "Nid binary-search read",
            )?;
            let candidate = u64::from_le_bytes(raw.as_ref().try_into().expect("checked Nid width"));
            match candidate.cmp(&nid.raw()) {
                Ordering::Less => lower = middle + 1,
                Ordering::Greater => upper = middle,
                Ordering::Equal => {
                    found = Some(middle);
                    break;
                }
            }
        }
        let Some(row_index) = found else {
            return Ok(None);
        };
        let offset_frame = &self.offsets.frames[group_index];
        let raw = self.read_fixed(
            SECTION_FRAGMENT_OFFSETS,
            offset_frame,
            row_index,
            4,
            8,
            "fragment offset pair read",
        )?;
        let start = u32::from_le_bytes(raw[0..4].try_into().expect("checked offset width"));
        let end = u32::from_le_bytes(raw[4..8].try_into().expect("checked offset width"));
        let fragment_frame = &self.fragments.frames[group_index];
        let byte_start = usize::try_from(start)
            .ok()
            .and_then(|value| value.checked_mul(FRAGMENT_REF_BYTES))
            .ok_or_else(|| corruption(path, "fragdir.gdx row reference start overflow"))?;
        let byte_end = usize::try_from(end)
            .ok()
            .and_then(|value| value.checked_mul(FRAGMENT_REF_BYTES))
            .ok_or_else(|| corruption(path, "fragdir.gdx row reference end overflow"))?;
        if start >= end || byte_end > fragment_frame.payload_len {
            return Err(corruption(
                path,
                "fragdir.gdx row reference range is invalid",
            ));
        }
        let section_start = fragment_frame
            .payload_offset
            .checked_add(byte_start)
            .ok_or_else(|| corruption(path, "fragdir.gdx reference range overflow"))?;
        let section_end = fragment_frame
            .payload_offset
            .checked_add(byte_end)
            .ok_or_else(|| corruption(path, "fragdir.gdx reference range overflow"))?;
        decode_references(
            path,
            &self
                .artifact
                .read_section_range(SECTION_FRAGMENT_REFS, section_start..section_end)?,
        )
        .map(Some)
    }

    fn read_fixed<'a>(
        &'a self,
        section_id: u32,
        frame: &GroupFrame,
        index: usize,
        stride: usize,
        width: usize,
        field: &str,
    ) -> Result<std::borrow::Cow<'a, [u8]>> {
        let start = index
            .checked_mul(stride)
            .and_then(|offset| frame.payload_offset.checked_add(offset))
            .ok_or_else(|| invalid(format!("fragdir.gdx {field} range overflow")))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| invalid(format!("fragdir.gdx {field} range overflow")))?;
        let frame_end = frame
            .payload_offset
            .checked_add(frame.payload_len)
            .ok_or_else(|| invalid("fragdir.gdx group frame range overflow"))?;
        if end > frame_end {
            return Err(invalid(format!("fragdir.gdx {field} is out of bounds")));
        }
        self.artifact.read_section_range(section_id, start..end)
    }

    fn decode_group(&self, path: &Path, group_index: usize) -> Result<DecodedFragmentGroup> {
        let namespace = self
            .namespaces
            .get(group_index)
            .ok_or_else(|| invalid("fragdir.gdx namespace group index is out of bounds"))?;
        let nids = decode_nids(
            path,
            &graph_group::read_group(&self.artifact, SECTION_NID_INDEX, &self.nids, group_index)?,
        )?;
        if nids.len() != namespace.row_count as usize
            || self.nids.frames[group_index].elem_count != namespace.row_count as u64
            || nids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(corruption(path, "fragdir.gdx Nid index is invalid"));
        }
        for nid in &nids {
            validate_nid(*nid).map_err(|error| corruption(path, &error.to_string()))?;
            if self
                .bloom
                .as_ref()
                .is_some_and(|bloom| !bloom.may_contain(*nid))
            {
                return Err(corruption(path, "fragdir.gdx Bloom has a false negative"));
            }
        }

        let offsets = decode_u32s(&graph_group::read_group(
            &self.artifact,
            SECTION_FRAGMENT_OFFSETS,
            &self.offsets,
            group_index,
        )?);
        if self.offsets.frames[group_index].elem_count != nids.len() as u64 + 1
            || offsets.len() != nids.len() + 1
            || offsets.first().copied() != Some(0)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
        {
            return Err(corruption(path, "fragdir.gdx fragment offsets are invalid"));
        }
        let references = decode_references(
            path,
            &graph_group::read_group(
                &self.artifact,
                SECTION_FRAGMENT_REFS,
                &self.fragments,
                group_index,
            )?,
        )?;
        if offsets.last().copied() != Some(references.len() as u32)
            || self.fragments.frames[group_index].elem_count != references.len() as u64
        {
            return Err(corruption(path, "fragdir.gdx reference counts disagree"));
        }
        let mut rows = Vec::with_capacity(nids.len());
        for (index, nid) in nids.into_iter().enumerate() {
            let start = offsets[index] as usize;
            let end = offsets[index + 1] as usize;
            if start >= end || end > references.len() {
                return Err(corruption(
                    path,
                    "fragdir.gdx row reference range is invalid",
                ));
            }
            let fragments = references[start..end].to_vec();
            if fragments.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(corruption(
                    path,
                    "fragdir.gdx row references are not strictly sorted",
                ));
            }
            rows.push(DecodedFragmentRow { nid, fragments });
        }
        Ok(DecodedFragmentGroup {
            namespace: namespace.namespace.clone(),
            rows,
        })
    }
}

impl FragmentBloom {
    fn build(nids: &[Nid]) -> Result<Self> {
        let bit_count = canonical_bloom_bits(nids.len())?;
        let mut bloom = Self {
            bit_count: bit_count as u64,
            bits: vec![0; bit_count / 8],
        };
        for nid in nids {
            bloom.insert(*nid);
        }
        Ok(bloom)
    }

    fn decode(path: &Path, bytes: &[u8], elem_count: u64, row_count: u64) -> Result<Self> {
        if bytes.len() < BLOOM_HEADER_BYTES {
            return Err(corruption(path, "truncated fragdir.gdx Bloom header"));
        }
        let bit_count = u64::from_le_bytes(bytes[0..8].try_into().expect("Bloom bit count"));
        let hashes = u32::from_le_bytes(bytes[8..12].try_into().expect("Bloom hash count"));
        let reserved = u32::from_le_bytes(bytes[12..16].try_into().expect("Bloom reserved"));
        let expected_bits = usize::try_from(row_count)
            .map_err(|_| corruption(path, "fragdir.gdx row count exceeds usize"))
            .and_then(|count| {
                canonical_bloom_bits(count).map_err(|error| corruption(path, &error.to_string()))
            })?;
        if bit_count != expected_bits as u64
            || bit_count < BLOOM_MIN_BITS as u64
            || !bit_count.is_multiple_of(64)
            || hashes != BLOOM_HASHES
            || reserved != 0
            || elem_count != bit_count
        {
            return Err(corruption(path, "invalid fragdir.gdx Bloom metadata"));
        }
        let bit_bytes = usize::try_from(bit_count / 8)
            .map_err(|_| corruption(path, "fragdir.gdx Bloom length exceeds usize"))?;
        if bytes.len() != BLOOM_HEADER_BYTES + bit_bytes {
            return Err(corruption(path, "fragdir.gdx Bloom length mismatch"));
        }
        Ok(Self {
            bit_count,
            bits: bytes[BLOOM_HEADER_BYTES..].to_vec(),
        })
    }

    fn insert(&mut self, nid: Nid) {
        for bit in bloom_positions(nid, self.bit_count) {
            self.bits[bit as usize / 8] |= 1 << (bit % 8);
        }
    }

    fn may_contain(&self, nid: Nid) -> bool {
        bloom_positions(nid, self.bit_count)
            .all(|bit| self.bits[bit as usize / 8] & (1 << (bit % 8)) != 0)
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BLOOM_HEADER_BYTES + self.bits.len());
        bytes.extend_from_slice(&self.bit_count.to_le_bytes());
        bytes.extend_from_slice(&BLOOM_HASHES.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&self.bits);
        bytes
    }
}

fn encode_grouped(width: u32, counts: &[u64], groups: &[Vec<u8>]) -> Result<Vec<u8>> {
    if counts.len() != groups.len() {
        return Err(invalid("fragdir.gdx grouped payload count mismatch"));
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

fn decode_nids(path: &Path, bytes: &[u8]) -> Result<Vec<Nid>> {
    if !bytes.len().is_multiple_of(8) {
        return Err(corruption(path, "fragdir.gdx Nid bytes are misaligned"));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|raw| Nid::from_raw(u64::from_le_bytes(raw.try_into().expect("Nid width"))))
        .collect())
}

fn decode_u32s(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("validated u32 group width")))
        .collect()
}

fn decode_references(path: &Path, bytes: &[u8]) -> Result<Vec<FragmentReference>> {
    if !bytes.len().is_multiple_of(FRAGMENT_REF_BYTES) {
        return Err(corruption(
            path,
            "fragdir.gdx fragment-reference bytes are misaligned",
        ));
    }
    bytes
        .chunks_exact(FRAGMENT_REF_BYTES)
        .map(|raw| {
            let fragment_id = u64::from_le_bytes(raw[0..8].try_into().expect("fragment ID width"));
            let row_hint = u32::from_le_bytes(raw[8..12].try_into().expect("row hint width"));
            let reserved = u32::from_le_bytes(raw[12..16].try_into().expect("reserved width"));
            if fragment_id == 0 || reserved != 0 {
                return Err(corruption(
                    path,
                    "fragdir.gdx fragment reference is invalid",
                ));
            }
            Ok(FragmentReference {
                fragment_id,
                row_hint,
            })
        })
        .collect()
}

fn checked_sum(counts: &[u64], message: &str) -> Result<u64> {
    counts.iter().try_fold(0_u64, |total, count| {
        total.checked_add(*count).ok_or_else(|| invalid(message))
    })
}

fn canonical_bloom_bits(key_count: usize) -> Result<usize> {
    let wanted = key_count
        .checked_mul(BLOOM_BITS_PER_KEY)
        .ok_or_else(|| invalid("fragdir.gdx Bloom size overflow"))?
        .max(BLOOM_MIN_BITS);
    wanted
        .checked_add(63)
        .map(|bits| bits & !63)
        .ok_or_else(|| invalid("fragdir.gdx Bloom alignment overflow"))
}

fn bloom_positions(nid: Nid, bit_count: u64) -> impl Iterator<Item = u64> {
    let first = splitmix64(nid.raw());
    let second = splitmix64(nid.raw() ^ 0x9e37_79b9_7f4a_7c15) | 1;
    (0..BLOOM_HASHES)
        .map(move |index| first.wrapping_add((index as u64).wrapping_mul(second)) % bit_count)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn validate_nid(nid: Nid) -> Result<()> {
    if !nid.is_assigned()
        || nid.epoch() == 0
        || nid.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || nid.counter() == 0
        || nid.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("fragdir.gdx contains an invalid Nid"));
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

    const ENCRYPTED_HELPER_ENV: &str = "CHIRONDB_GRAPH_FRAGDIR_ENCRYPTED_HELPER_DIR";

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(73, counter).unwrap()
    }

    fn reference(fragment_id: u64, row_hint: u32) -> FragmentReference {
        FragmentReference {
            fragment_id,
            row_hint,
        }
    }

    fn fixture(kind: FragmentDirectoryRunKind, include_bloom: bool) -> FragmentDirectory {
        FragmentDirectory::build(
            kind,
            include_bloom,
            vec![
                FragmentGroupInput {
                    namespace: GraphNamespace::AdminCrossTenant,
                    rows: vec![FragmentRowInput {
                        nid: nid(1),
                        fragments: vec![reference(90, 7)],
                    }],
                },
                FragmentGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    rows: vec![
                        FragmentRowInput {
                            nid: nid(2),
                            fragments: vec![reference(20, 1)],
                        },
                        FragmentRowInput {
                            nid: nid(1),
                            fragments: vec![reference(11, 3), reference(10, 8)],
                        },
                    ],
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn base_and_overlay_round_trip_with_scoped_bounded_lookup() {
        for kind in [
            FragmentDirectoryRunKind::Base,
            FragmentDirectoryRunKind::Overlay,
        ] {
            let directory = fixture(kind, true);
            assert_eq!(directory.kind(), kind);
            assert_eq!(directory.group_count(), 2);
            assert_eq!(directory.row_count(), 3);
            assert_eq!(directory.reference_count(), 4);
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join(FRAGMENT_DIRECTORY_FILE);
            write(&path, &directory).unwrap();
            let opened = open(&path).unwrap();
            assert_eq!(opened.kind(), kind);
            assert_eq!(opened.group_count(), 2);
            assert_eq!(opened.row_count(), 3);
            assert_eq!(opened.reference_count(), 4);

            let acme = GraphNamespace::Tenant("acme".to_string());
            assert_eq!(
                opened.lookup(&path, &acme, nid(1)).unwrap(),
                Some(vec![reference(10, 8), reference(11, 3)])
            );
            assert_eq!(opened.lookup(&path, &acme, nid(99)).unwrap(), None);
            assert_eq!(
                opened
                    .lookup(&path, &GraphNamespace::AdminCrossTenant, nid(1))
                    .unwrap(),
                Some(vec![reference(90, 7)])
            );
            let tenant = opened.read_group(&path, 0).unwrap();
            assert_eq!(tenant.namespace, acme);
            assert_eq!(tenant.rows[0].nid, nid(1));
        }
    }

    #[test]
    fn builder_rejects_empty_duplicate_and_invalid_rows() {
        assert!(FragmentDirectory::build(FragmentDirectoryRunKind::Base, false, vec![]).is_err());
        let group = FragmentGroupInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            rows: vec![FragmentRowInput {
                nid: nid(1),
                fragments: vec![reference(1, 0)],
            }],
        };
        assert!(
            FragmentDirectory::build(
                FragmentDirectoryRunKind::Base,
                false,
                vec![group.clone(), group.clone()],
            )
            .is_err()
        );
        let duplicate_nid = FragmentGroupInput {
            namespace: GraphNamespace::Tenant("acme".to_string()),
            rows: vec![group.rows[0].clone(), group.rows[0].clone()],
        };
        assert!(
            FragmentDirectory::build(FragmentDirectoryRunKind::Base, false, vec![duplicate_nid],)
                .is_err()
        );
        for row in [
            FragmentRowInput {
                nid: Nid::UNASSIGNED,
                fragments: vec![reference(1, 0)],
            },
            FragmentRowInput {
                nid: nid(1),
                fragments: vec![],
            },
            FragmentRowInput {
                nid: nid(1),
                fragments: vec![reference(0, 0)],
            },
            FragmentRowInput {
                nid: nid(1),
                fragments: vec![reference(1, 0), reference(1, 0)],
            },
        ] {
            assert!(
                FragmentDirectory::build(
                    FragmentDirectoryRunKind::Base,
                    false,
                    vec![FragmentGroupInput {
                        namespace: GraphNamespace::Tenant("acme".to_string()),
                        rows: vec![row],
                    }],
                )
                .is_err()
            );
        }
    }

    #[test]
    fn loader_rejects_reference_offset_and_flag_corruption() {
        let directory = fixture(FragmentDirectoryRunKind::Base, false);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(FRAGMENT_DIRECTORY_FILE);
        write(&path, &directory).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let layout = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_FRAGMENT_REFS,
            2,
            WIDTH_FRAGMENT_REF,
        )
        .unwrap();
        let section = artifact.section(SECTION_FRAGMENT_REFS).unwrap();
        let mut reserved = fs::read(&path).unwrap();
        reserved[section.offset + layout.frames[0].payload_offset + 12] = 1;
        fs::write(&path, reserved).unwrap();
        assert!(open(&path).is_err());

        write(&path, &directory).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let offsets = graph_group::open_grouped_section(
            &path,
            &artifact,
            SECTION_FRAGMENT_OFFSETS,
            2,
            WIDTH_U32,
        )
        .unwrap();
        let section = artifact.section(SECTION_FRAGMENT_OFFSETS).unwrap();
        let mut bad_offset = fs::read(&path).unwrap();
        let terminal = section.offset + offsets.frames[0].payload_offset + 8;
        bad_offset[terminal..terminal + 4].copy_from_slice(&99_u32.to_le_bytes());
        fs::write(&path, bad_offset).unwrap();
        assert!(open(&path).is_err());

        write(&path, &directory).unwrap();
        let mut bad_flag = fs::read(&path).unwrap();
        bad_flag[12..16].copy_from_slice(&FLAG_BLOOM.to_le_bytes());
        repair_header_crc(&mut bad_flag);
        fs::write(&path, bad_flag).unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn grouped_sections_are_chunk_aligned_and_bloom_false_negatives_fail_closed() {
        let directory = fixture(FragmentDirectoryRunKind::Overlay, true);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(FRAGMENT_DIRECTORY_FILE);
        write(&path, &directory).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        for (section_id, width) in [
            (SECTION_NID_INDEX, WIDTH_U64),
            (SECTION_FRAGMENT_OFFSETS, WIDTH_U32),
            (SECTION_FRAGMENT_REFS, WIDTH_FRAGMENT_REF),
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
        let bloom = artifact.section(SECTION_BLOOM).unwrap();
        let mut false_negative = fs::read(&path).unwrap();
        false_negative[bloom.offset + BLOOM_HEADER_BYTES..bloom.offset + bloom.length].fill(0);
        fs::write(&path, false_negative).unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn fragment_directory_uses_authenticated_chunks_when_encryption_is_enabled() {
        if env::var_os(ENCRYPTED_HELPER_ENV).is_some() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("graph_fragdir::tests::encrypted_fragment_directory_helper")
            .arg("--nocapture")
            .env(ENCRYPTED_HELPER_ENV, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "encrypted fragdir helper failed: {status}"
        );
    }

    #[test]
    fn encrypted_fragment_directory_helper() {
        let Some(root) = env::var_os(ENCRYPTED_HELPER_ENV) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let keyring_path = root.join("keyring.json");
        fs::write(
            &keyring_path,
            json!({
                "version": 1,
                "active_key_id": "g1-fragdir",
                "keys": [{
                    "id": "g1-fragdir",
                    "key_base64": STANDARD.encode([71_u8; 32]),
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
        let path = root.join(FRAGMENT_DIRECTORY_FILE);
        write(&path, &fixture(FragmentDirectoryRunKind::Overlay, true)).unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], crate::encryption::MAGIC);
        assert_eq!(open(&path).unwrap().reference_count(), 4);
        let mut ciphertext = fs::read(&path).unwrap();
        *ciphertext
            .last_mut()
            .expect("encrypted fragdir is non-empty") ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(open(&path).is_err());
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
