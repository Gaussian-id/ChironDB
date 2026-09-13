//! Bounded physical topology cursors over checked inline and overflow rows.

use super::*;
use crate::graph_group::{
    AdjacencyEdge,
    cursor::{Column, TopologyColumns},
};
use std::borrow::Cow;

pub(crate) struct BaseEdges<'a> {
    inline: Option<TopologyColumns<'a>>,
    overflow: Option<OverflowIds<'a>>,
    nids: &'a NidIndex,
    ordinal: u32,
    node: Nid,
    incoming: bool,
    failed: bool,
}

impl Iterator for BaseEdges<'_> {
    type Item = Result<AdjacencyEdge>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let next = if let Some(next) = self
            .inline
            .as_mut()
            .and_then(|columns| columns.read_next().transpose())
        {
            Some(next.and_then(|(stored_neighbor, edge_id, type_id)| {
                Ok((
                    resolve_neighbor(
                        Path::new(EDGE_FILE),
                        self.nids,
                        self.ordinal,
                        stored_neighbor,
                    )?,
                    edge_id,
                    type_id,
                    matches!(stored_neighbor, TaggedNeighbor::LocalDelta(_)),
                ))
            }))
        } else {
            self.inline = None; // Release inline chunks before loading overflow.
            self.overflow.as_mut().and_then(Iterator::next).map(|edge| {
                edge.map(|edge| {
                    (
                        edge.neighbor_nid,
                        edge.edge_id,
                        edge.type_id,
                        matches!(edge.stored_neighbor, TaggedNeighbor::LocalDelta(_)),
                    )
                })
            })
        }
        .map(|edge| {
            edge.map(|(neighbor, edge_id, type_id, local)| AdjacencyEdge {
                edge_id,
                source: if self.incoming { neighbor } else { self.node },
                target: if self.incoming { self.node } else { neighbor },
                type_id,
                // GraphGeneration's fragment cursor binds the concrete base
                // index after this row iterator returns.
                local_base: local.then_some(u32::MAX),
            })
        });
        self.failed = next.as_ref().is_some_and(Result::is_err);
        if self.failed {
            self.inline = None;
            self.overflow = None;
        }
        next
    }
}

impl OpenedBaseAdjacency {
    pub(crate) fn has_csc(&self) -> bool {
        self.in_offsets.is_some()
    }

    pub(crate) fn edges<'a>(
        &'a self,
        nids: &'a NidIndex,
        group: usize,
        row: u32,
        incoming: bool,
    ) -> Result<BaseEdges<'a>> {
        if self
            .namespaces
            .get(group)
            .is_none_or(|ns| row >= ns.row_count)
        {
            return Err(invalid("base cursor row exceeds namespace"));
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
                self.in_offsets
                    .as_ref()
                    .ok_or_else(|| invalid("base has no CSC"))?,
                self.in_edge_ids.as_ref().expect("checked CSC"),
                self.in_types.as_ref().expect("checked CSC"),
                self.in_neighbors.as_ref().expect("checked CSC"),
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
        let inline = TopologyColumns::new(
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
            self.type_remap.as_deref(),
        )?;
        let direction = if incoming {
            BaseDirection::Incoming
        } else {
            BaseDirection::Outgoing
        };
        let ordinal = self.row_ordinal(group, row)?;
        Ok(BaseEdges {
            inline: Some(inline),
            overflow: self.overflow_ids(nids, group, row, direction)?,
            nids,
            ordinal,
            node: local_nid(nids, ordinal)?,
            incoming,
            failed: false,
        })
    }

    fn overflow_ids<'a>(
        &'a self,
        nids: &'a NidIndex,
        group: usize,
        row: u32,
        direction: BaseDirection,
    ) -> Result<Option<OverflowIds<'a>>> {
        let Some(layout) = &self.overflow else {
            return Ok(None);
        };
        let frame = &layout.frames[group];
        // The checked opener already proves canonical sorted records and arena
        // ownership. Binary-search just this row/direction, without decoding hubs.
        let count = usize::try_from(frame.elem_count)
            .map_err(|_| invalid("overflow count exceeds usize"))?;
        let directory_end = count
            .checked_mul(OVERFLOW_CHAIN_RECORD_BYTES)
            .and_then(|v| v.checked_add(OVERFLOW_DIRECTORY_HEADER_BYTES))
            .ok_or_else(|| invalid("overflow directory range overflow"))?;
        let (mut lower, mut upper) = (0, count);
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let start = frame.payload_offset
                + OVERFLOW_DIRECTORY_HEADER_BYTES
                + middle * OVERFLOW_CHAIN_RECORD_BYTES;
            let raw = self
                .artifact
                .read_section_range(SECTION_OVERFLOW, start..start + OVERFLOW_CHAIN_RECORD_BYTES)?;
            let found_row = read_u32_at(Path::new(EDGE_FILE), &raw, 0, "overflow row")?;
            match (found_row, raw[4]).cmp(&(row, direction as u8)) {
                Ordering::Less => lower = middle + 1,
                Ordering::Greater => upper = middle,
                Ordering::Equal => {
                    let first = read_u32_at(Path::new(EDGE_FILE), &raw, 8, "first chunk")?;
                    let chunks = read_u32_at(Path::new(EDGE_FILE), &raw, 12, "chunk count")?;
                    let arena = frame
                        .payload_offset
                        .checked_add(overflow_arena_payload_offset(directory_end)?)
                        .ok_or_else(|| invalid("overflow arena offset overflow"))?;
                    return Ok(Some(OverflowIds {
                        base: self,
                        nids,
                        ordinal: self.row_ordinal(group, row)?,
                        arena,
                        next_chunk: first,
                        end_chunk: first
                            .checked_add(chunks)
                            .ok_or_else(|| invalid("overflow chunk range overflow"))?,
                        chunk: Cow::Borrowed(&[]),
                        position: 0,
                        payload_end: 0,
                        remaining: 0,
                        failed: false,
                    }));
                }
            }
        }
        Ok(None)
    }
}

struct OverflowIds<'a> {
    base: &'a OpenedBaseAdjacency,
    nids: &'a NidIndex,
    ordinal: u32,
    arena: usize,
    next_chunk: u32,
    end_chunk: u32,
    chunk: Cow<'a, [u8]>,
    position: usize,
    payload_end: usize,
    remaining: u32,
    failed: bool,
}

impl OverflowIds<'_> {
    fn read_next(&mut self) -> Result<Option<DecodedBaseEdge>> {
        let path = Path::new(EDGE_FILE);
        if self.remaining == 0 {
            if self.position != self.payload_end {
                return Err(corruption(path, "overflow cursor tuple count mismatch"));
            }
            if self.next_chunk == self.end_chunk {
                return Ok(None);
            }
            let start = (self.next_chunk as usize)
                .checked_mul(AUTHENTICATED_CHUNK_BYTES)
                .and_then(|v| self.arena.checked_add(v))
                .ok_or_else(|| corruption(path, "overflow cursor chunk range overflow"))?;
            let end = start
                .checked_add(AUTHENTICATED_CHUNK_BYTES)
                .ok_or_else(|| corruption(path, "overflow cursor chunk range overflow"))?;
            self.chunk = Cow::Borrowed(&[]);
            self.chunk = self
                .base
                .artifact
                .read_section_range(SECTION_OVERFLOW, start..end)?;
            let next = read_u32_at(path, &self.chunk, 0, "next chunk")?;
            let expected = if self.next_chunk + 1 == self.end_chunk {
                u32::MAX
            } else {
                self.next_chunk + 1
            };
            self.remaining = read_u32_at(path, &self.chunk, 4, "entry count")?;
            let bytes = read_u32_at(path, &self.chunk, 8, "payload bytes")? as usize;
            if next != expected
                || self.remaining == 0
                || bytes > OVERFLOW_CHUNK_PAYLOAD_BYTES
                || self.remaining as usize > bytes / 12
            {
                return Err(corruption(path, "invalid overflow cursor chunk"));
            }
            self.next_chunk += 1;
            self.position = OVERFLOW_CHUNK_HEADER_BYTES;
            self.payload_end = self.position + bytes;
        }
        let (edge, consumed) = decode_overflow_tuple(
            path,
            self.nids,
            self.ordinal,
            &self.chunk[self.position..self.payload_end],
            self.base.type_remap.as_deref(),
            self.base.out_weights.is_some(),
        )?;
        self.position += consumed;
        self.remaining -= 1;
        Ok(Some(edge))
    }
}

impl Iterator for OverflowIds<'_> {
    type Item = Result<DecodedBaseEdge>;
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
