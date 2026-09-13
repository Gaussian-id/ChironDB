//! `edgeid.gdx` stable edge-existence ledger run (Rev 3.4 Appendix C).

use std::path::Path;

use crate::{
    GaussError, Result,
    graph::{EdgeId, GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, GraphEpoch},
    graph_artifact::{self, ArtifactSpec, SectionPayload},
};

pub(crate) const EDGEID_FILE: &str = "edgeid.gdx";
pub(crate) const EDGEID_MAGIC: &[u8; 8] = b"GAUSEI01";

const FLAG_BASE_RUN: u32 = 1;
const FLAG_DELTA_RUN: u32 = 1 << 1;
const SECTION_RUN_METADATA: u32 = 1;
const SECTION_SORTED_EDGE_IDS: u32 = 2;
const REQUIRED_SECTIONS: &[u32] = &[SECTION_RUN_METADATA, SECTION_SORTED_EDGE_IDS];
const RUN_METADATA_BYTES: usize = 32;
const VALIDATION_KEYS_PER_BATCH: usize = 8_192;

const SPEC: ArtifactSpec = ArtifactSpec {
    magic: EDGEID_MAGIC,
    allowed_flags: FLAG_BASE_RUN | FLAG_DELTA_RUN,
    required_sections: REQUIRED_SECTIONS,
    optional_sections: &[],
    max_file_len: u64::MAX,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeLedgerRunKind {
    Base,
    Delta,
}

impl EdgeLedgerRunKind {
    const fn flag(self) -> u32 {
        match self {
            Self::Base => FLAG_BASE_RUN,
            Self::Delta => FLAG_DELTA_RUN,
        }
    }

    const fn code(self) -> u32 {
        match self {
            Self::Base => 0,
            Self::Delta => 1,
        }
    }

    fn from_flag(flags: u32) -> Option<Self> {
        match flags {
            FLAG_BASE_RUN => Some(Self::Base),
            FLAG_DELTA_RUN => Some(Self::Delta),
            _ => None,
        }
    }

    fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Base),
            1 => Some(Self::Delta),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EdgeLedgerRunMetadata {
    pub(crate) graph_epoch: GraphEpoch,
    pub(crate) first_lsn: u64,
    pub(crate) last_lsn: u64,
    pub(crate) kind: EdgeLedgerRunKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EdgeLedgerRun {
    metadata: EdgeLedgerRunMetadata,
    edge_ids: Vec<EdgeId>,
}

pub(crate) struct OpenedEdgeLedgerRun {
    metadata: EdgeLedgerRunMetadata,
    artifact: graph_artifact::CheckedArtifact,
    count: usize,
    first: Option<EdgeId>,
    last: Option<EdgeId>,
}

impl EdgeLedgerRun {
    pub(crate) fn build(
        metadata: EdgeLedgerRunMetadata,
        mut edge_ids: Vec<EdgeId>,
    ) -> Result<Self> {
        validate_metadata(metadata)?;
        for edge_id in &edge_ids {
            validate_edge_id(*edge_id)?;
        }
        edge_ids.sort_unstable();
        if edge_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("edgeid.gdx contains a duplicate EdgeId"));
        }
        Ok(Self { metadata, edge_ids })
    }

    pub(crate) fn metadata(&self) -> EdgeLedgerRunMetadata {
        self.metadata
    }

    pub(crate) fn len(&self) -> usize {
        self.edge_ids.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.edge_ids.is_empty()
    }

    pub(crate) fn contains(&self, edge_id: EdgeId) -> bool {
        validate_edge_id(edge_id).is_ok() && self.edge_ids.binary_search(&edge_id).is_ok()
    }

    pub(crate) fn edge_ids(&self) -> &[EdgeId] {
        &self.edge_ids
    }
}

pub(crate) fn write(path: &Path, run: &EdgeLedgerRun) -> Result<()> {
    validate_metadata(run.metadata)?;
    validate_sorted_edge_ids(&run.edge_ids)?;
    let metadata = encode_metadata(run.metadata);
    let edge_ids = run
        .edge_ids
        .iter()
        .flat_map(|edge_id| edge_id.raw().to_le_bytes())
        .collect::<Vec<_>>();
    graph_artifact::write(
        path,
        SPEC,
        run.metadata.kind.flag(),
        &[
            SectionPayload {
                id: SECTION_RUN_METADATA,
                elem_count: 1,
                bytes: &metadata,
            },
            SectionPayload {
                id: SECTION_SORTED_EDGE_IDS,
                elem_count: run.edge_ids.len() as u64,
                bytes: &edge_ids,
            },
        ],
    )
}

pub(crate) fn open(path: &Path) -> Result<OpenedEdgeLedgerRun> {
    let artifact = graph_artifact::open(path, SPEC)?;
    let flag_kind = EdgeLedgerRunKind::from_flag(artifact.flags())
        .ok_or_else(|| corruption(path, "edgeid.gdx must select exactly one run kind"))?;
    let metadata_section = artifact
        .section(SECTION_RUN_METADATA)
        .expect("common loader requires edge-ledger metadata");
    if metadata_section.elem_count != 1 || metadata_section.length != RUN_METADATA_BYTES {
        return Err(corruption(path, "edgeid.gdx run metadata width is invalid"));
    }
    let metadata = decode_metadata(path, &artifact.read_section(SECTION_RUN_METADATA)?)?;
    if metadata.kind != flag_kind {
        return Err(corruption(
            path,
            "edgeid.gdx run metadata disagrees with flags",
        ));
    }

    let ids_section = artifact
        .section(SECTION_SORTED_EDGE_IDS)
        .expect("common loader requires sorted EdgeIds");
    let count = usize::try_from(ids_section.elem_count)
        .map_err(|_| corruption(path, "edgeid.gdx EdgeId count exceeds usize"))?;
    let expected_bytes = count
        .checked_mul(8)
        .ok_or_else(|| corruption(path, "edgeid.gdx EdgeId length overflow"))?;
    if ids_section.length != expected_bytes {
        return Err(corruption(path, "edgeid.gdx EdgeId length mismatch"));
    }
    let (first, last) = validate_persisted_edge_ids(path, &artifact, count)?;
    Ok(OpenedEdgeLedgerRun {
        metadata,
        artifact,
        count,
        first,
        last,
    })
}

impl OpenedEdgeLedgerRun {
    /// Iterate checked sorted keys without copying an entire run into RAM.
    pub(crate) fn keys(&self) -> Result<crate::graph_group::EdgeIdCursor<'_>> {
        let section = self
            .artifact
            .section(SECTION_SORTED_EDGE_IDS)
            .expect("checked ledger keys");
        crate::graph_group::EdgeIdCursor::new(
            &self.artifact,
            SECTION_SORTED_EDGE_IDS,
            &crate::graph_group::GroupFrame {
                elem_count: self.count as u64,
                payload_offset: 0,
                payload_len: section.length,
            },
            0..self.count as u64,
        )
    }

    pub(crate) fn metadata(&self) -> EdgeLedgerRunMetadata {
        self.metadata
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn contains(&self, edge_id: EdgeId) -> Result<bool> {
        self.find_edge(edge_id).map(|rank| rank.is_some())
    }

    /// Stable within this immutable run, never a persisted adjacency address.
    pub(crate) fn find_edge(&self, edge_id: EdgeId) -> Result<Option<usize>> {
        if validate_edge_id(edge_id).is_err()
            || self
                .first
                .zip(self.last)
                .is_none_or(|(first, last)| edge_id < first || edge_id > last)
        {
            return Ok(None);
        }
        let mut low = 0_usize;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            match self.edge_id_at(middle)?.cmp(&edge_id) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }

    pub(crate) fn edge_id_at(&self, index: usize) -> Result<EdgeId> {
        if index >= self.count {
            return Err(invalid("edgeid.gdx lookup index exceeds run length"));
        }
        let start = index
            .checked_mul(8)
            .ok_or_else(|| invalid("edgeid.gdx lookup offset overflow"))?;
        let end = start
            .checked_add(8)
            .ok_or_else(|| invalid("edgeid.gdx lookup range overflow"))?;
        let bytes = self
            .artifact
            .read_section_range(SECTION_SORTED_EDGE_IDS, start..end)?;
        Ok(EdgeId::from_raw(u64::from_le_bytes(
            bytes.as_ref().try_into().expect("checked EdgeId width"),
        )))
    }
}

fn validate_persisted_edge_ids(
    path: &Path,
    artifact: &graph_artifact::CheckedArtifact,
    count: usize,
) -> Result<(Option<EdgeId>, Option<EdgeId>)> {
    let mut previous = None;
    for batch_start in (0..count).step_by(VALIDATION_KEYS_PER_BATCH) {
        let batch_end = count.min(batch_start + VALIDATION_KEYS_PER_BATCH);
        let byte_start = batch_start
            .checked_mul(8)
            .ok_or_else(|| corruption(path, "edgeid.gdx validation offset overflow"))?;
        let byte_end = batch_end
            .checked_mul(8)
            .ok_or_else(|| corruption(path, "edgeid.gdx validation offset overflow"))?;
        let bytes = artifact.read_section_range(SECTION_SORTED_EDGE_IDS, byte_start..byte_end)?;
        for raw in bytes.chunks_exact(8) {
            let edge_id = EdgeId::from_raw(u64::from_le_bytes(
                raw.try_into().expect("checked EdgeId width"),
            ));
            validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
            if previous.is_some_and(|value| value >= edge_id) {
                return Err(corruption(
                    path,
                    "edgeid.gdx EdgeIds are not strictly sorted",
                ));
            }
            previous = Some(edge_id);
        }
    }
    let first = if count == 0 {
        None
    } else {
        let bytes = artifact.read_section_range(SECTION_SORTED_EDGE_IDS, 0..8)?;
        Some(EdgeId::from_raw(u64::from_le_bytes(
            bytes.as_ref().try_into().expect("checked EdgeId width"),
        )))
    };
    Ok((first, previous))
}

fn encode_metadata(metadata: EdgeLedgerRunMetadata) -> [u8; RUN_METADATA_BYTES] {
    let mut bytes = [0_u8; RUN_METADATA_BYTES];
    bytes[0..8].copy_from_slice(&metadata.graph_epoch.raw().to_le_bytes());
    bytes[8..16].copy_from_slice(&metadata.first_lsn.to_le_bytes());
    bytes[16..24].copy_from_slice(&metadata.last_lsn.to_le_bytes());
    bytes[24..28].copy_from_slice(&metadata.kind.code().to_le_bytes());
    bytes
}

fn decode_metadata(path: &Path, bytes: &[u8]) -> Result<EdgeLedgerRunMetadata> {
    if bytes.len() != RUN_METADATA_BYTES {
        return Err(corruption(path, "edgeid.gdx run metadata is truncated"));
    }
    let graph_epoch = GraphEpoch::from_raw(read_u64(bytes, 0))
        .ok_or_else(|| corruption(path, "edgeid.gdx graph epoch is invalid"))?;
    let first_lsn = read_u64(bytes, 8);
    let last_lsn = read_u64(bytes, 16);
    let kind = EdgeLedgerRunKind::from_code(read_u32(bytes, 24))
        .ok_or_else(|| corruption(path, "edgeid.gdx run kind is invalid"))?;
    if read_u32(bytes, 28) != 0 {
        return Err(corruption(path, "edgeid.gdx reserved metadata is non-zero"));
    }
    let metadata = EdgeLedgerRunMetadata {
        graph_epoch,
        first_lsn,
        last_lsn,
        kind,
    };
    validate_metadata(metadata).map_err(|error| corruption(path, &error.to_string()))?;
    Ok(metadata)
}

fn validate_metadata(metadata: EdgeLedgerRunMetadata) -> Result<()> {
    if metadata.first_lsn > metadata.last_lsn {
        return Err(invalid("edgeid.gdx first LSN exceeds last LSN"));
    }
    Ok(())
}

fn validate_sorted_edge_ids(edge_ids: &[EdgeId]) -> Result<()> {
    let mut previous = None;
    for edge_id in edge_ids {
        validate_edge_id(*edge_id)?;
        if previous.is_some_and(|value| value >= *edge_id) {
            return Err(invalid("edgeid.gdx EdgeIds are not strictly sorted"));
        }
        previous = Some(*edge_id);
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
        return Err(invalid("edgeid.gdx contains an invalid EdgeId"));
    }
    Ok(())
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

    fn edge(counter: u64) -> EdgeId {
        EdgeId::from_parts(23, counter).unwrap()
    }

    fn metadata(kind: EdgeLedgerRunKind) -> EdgeLedgerRunMetadata {
        EdgeLedgerRunMetadata {
            graph_epoch: GraphEpoch::from_raw(17).unwrap(),
            first_lsn: 41,
            last_lsn: 99,
            kind,
        }
    }

    #[test]
    fn base_and_delta_runs_round_trip_sorted_existence_keys() {
        for kind in [EdgeLedgerRunKind::Base, EdgeLedgerRunKind::Delta] {
            let run =
                EdgeLedgerRun::build(metadata(kind), vec![edge(3), edge(1), edge(2)]).unwrap();
            assert_eq!(run.edge_ids(), &[edge(1), edge(2), edge(3)]);
            assert!(run.contains(edge(2)));
            assert!(!run.contains(edge(9)));
            assert!(!run.is_empty());
            assert_eq!(run.len(), 3);
            assert_eq!(run.metadata().kind, kind);

            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join(EDGEID_FILE);
            write(&path, &run).unwrap();
            let reopened = open(&path).unwrap();
            assert_eq!(reopened.metadata(), run.metadata());
            assert_eq!(reopened.len(), run.len());
            assert!(reopened.contains(edge(1)).unwrap());
            assert!(reopened.contains(edge(3)).unwrap());
            assert!(!reopened.contains(edge(9)).unwrap());
        }

        let empty = EdgeLedgerRun::build(metadata(EdgeLedgerRunKind::Base), Vec::new()).unwrap();
        assert!(empty.is_empty());
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGEID_FILE);
        write(&path, &empty).unwrap();
        let reopened = open(&path).unwrap();
        assert!(reopened.is_empty());
        assert!(!reopened.contains(edge(1)).unwrap());
    }

    #[test]
    fn writer_rejects_invalid_ranges_duplicate_and_invalid_edge_ids() {
        let mut reversed = metadata(EdgeLedgerRunKind::Delta);
        reversed.first_lsn = 100;
        assert!(EdgeLedgerRun::build(reversed, vec![edge(1)]).is_err());
        assert!(
            EdgeLedgerRun::build(metadata(EdgeLedgerRunKind::Base), vec![edge(1), edge(1)],)
                .is_err()
        );
        assert!(
            EdgeLedgerRun::build(metadata(EdgeLedgerRunKind::Base), vec![EdgeId::from_raw(0)],)
                .is_err()
        );
        assert!(
            EdgeLedgerRun::build(metadata(EdgeLedgerRunKind::Base), vec![EdgeId::from_raw(1)],)
                .is_err()
        );
    }

    #[test]
    fn loader_rejects_flag_metadata_reserved_and_sorted_key_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGEID_FILE);
        let run = EdgeLedgerRun::build(metadata(EdgeLedgerRunKind::Base), vec![edge(1), edge(2)])
            .unwrap();

        write(&path, &run).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[12..16].copy_from_slice(&(FLAG_BASE_RUN | FLAG_DELTA_RUN).to_le_bytes());
        refresh_header_crc(&mut bytes);
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());

        write(&path, &run).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let metadata_offset = section_offset(&bytes, 0);
        bytes[metadata_offset + 24..metadata_offset + 28]
            .copy_from_slice(&EdgeLedgerRunKind::Delta.code().to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());

        write(&path, &run).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let metadata_offset = section_offset(&bytes, 0);
        bytes[metadata_offset + 28] = 1;
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());

        write(&path, &run).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let ids_offset = section_offset(&bytes, 1);
        bytes[ids_offset + 8..ids_offset + 16].copy_from_slice(&edge(1).raw().to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn multi_chunk_run_validates_and_probes_without_materializing_on_open() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGEID_FILE);
        let run = EdgeLedgerRun::build(
            metadata(EdgeLedgerRunKind::Delta),
            (1..=20_000).rev().map(edge).collect(),
        )
        .unwrap();
        write(&path, &run).unwrap();
        let reopened = open(&path).unwrap();
        assert_eq!(reopened.len(), 20_000);
        assert!(reopened.contains(edge(1)).unwrap());
        assert!(reopened.contains(edge(10_001)).unwrap());
        assert!(reopened.contains(edge(20_000)).unwrap());
        assert_eq!(reopened.find_edge(edge(1)).unwrap(), Some(0));
        assert_eq!(reopened.find_edge(edge(10_001)).unwrap(), Some(10_000));
        assert_eq!(reopened.find_edge(edge(20_000)).unwrap(), Some(19_999));
        assert_eq!(reopened.find_edge(edge(20_001)).unwrap(), None);
        assert!(!reopened.contains(edge(20_001)).unwrap());
        assert_eq!(
            reopened
                .keys()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            run.edge_ids()
        );
    }

    fn section_offset(bytes: &[u8], index: usize) -> usize {
        let start = graph_artifact::COMMON_HEADER_BYTES
            + index * graph_artifact::SECTION_TABLE_ENTRY_BYTES
            + 8;
        u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap()) as usize
    }

    fn refresh_header_crc(bytes: &mut [u8]) {
        let count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let table_end =
            graph_artifact::COMMON_HEADER_BYTES + count * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        let mut input = Vec::with_capacity(28 + table_end - graph_artifact::COMMON_HEADER_BYTES);
        input.extend_from_slice(&bytes[..28]);
        input.extend_from_slice(&bytes[graph_artifact::COMMON_HEADER_BYTES..table_end]);
        bytes[28..32].copy_from_slice(&crc_fast::crc32_iscsi(&input).to_le_bytes());
    }
}
