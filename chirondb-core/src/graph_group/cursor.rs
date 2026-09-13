//! Bounded parallel topology-column reads; no degree-sized decoded row.

use super::*;

/// An admitted column's section and namespace frame.
#[derive(Clone, Copy)]
pub(crate) struct Column<'a> {
    pub(crate) section: u32,
    pub(crate) frame: &'a GroupFrame,
}

struct RangeCursor<'a> {
    artifact: &'a CheckedArtifact,
    section: u32,
    next: usize,
    end: usize,
    buffer: Cow<'a, [u8]>,
    position: usize,
}

impl<'a> RangeCursor<'a> {
    fn new(artifact: &'a CheckedArtifact, column: Column<'_>, range: Range<usize>) -> Result<Self> {
        if range.start > range.end || range.end > column.frame.payload_len {
            return Err(invalid("topology cursor range exceeds frame"));
        }
        let offset = |value| {
            column
                .frame
                .payload_offset
                .checked_add(value)
                .ok_or_else(|| invalid("topology cursor range overflow"))
        };
        Ok(Self {
            artifact,
            section: column.section,
            next: offset(range.start)?,
            end: offset(range.end)?,
            buffer: Cow::Borrowed(&[]),
            position: 0,
        })
    }

    fn read_into(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            if self.position == self.buffer.len() {
                if self.next == self.end {
                    return Err(invalid("truncated topology cursor column"));
                }
                let end = self
                    .next
                    .saturating_add(AUTHENTICATED_CHUNK_BYTES)
                    .min(self.end);
                self.buffer = Cow::Borrowed(&[]);
                self.buffer = self
                    .artifact
                    .read_section_range(self.section, self.next..end)?;
                self.next = end;
                self.position = 0;
            }
            let count = bytes.len().min(self.buffer.len() - self.position);
            bytes[..count].copy_from_slice(&self.buffer[self.position..self.position + count]);
            self.position += count;
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }
}

pub(crate) struct TopologyColumns<'a> {
    ids: EdgeIdCursor<'a>,
    types: RangeCursor<'a>,
    offsets: RangeCursor<'a>,
    neighbors: RangeCursor<'a>,
    previous_offset: u64,
    remap: Option<&'a [TypeId]>,
}

impl<'a> TopologyColumns<'a> {
    pub(crate) fn new(
        artifact: &'a CheckedArtifact,
        ids: Column<'a>,
        types: Column<'a>,
        neighbors: Column<'a>,
        range: Range<u64>,
        remap: Option<&'a [TypeId]>,
    ) -> Result<Self> {
        if range.start > range.end
            || range.end > ids.frame.elem_count
            || ids.frame.elem_count != types.frame.elem_count
            || ids.frame.elem_count != neighbors.frame.elem_count
        {
            return Err(invalid("topology cursor parallel counts/range disagree"));
        }
        let start =
            usize::try_from(range.start).map_err(|_| invalid("topology start exceeds usize"))?;
        let end = usize::try_from(range.end).map_err(|_| invalid("topology end exceeds usize"))?;
        let scaled = |value: usize, width: usize| {
            value
                .checked_mul(width)
                .ok_or_else(|| invalid("topology column range overflow"))
        };
        let offset_end = end
            .checked_add(1)
            .ok_or_else(|| invalid("topology offset count overflow"))?;
        let mut offsets = RangeCursor::new(
            artifact,
            neighbors,
            scaled(start, 8)?..scaled(offset_end, 8)?,
        )?;
        let first = u64::from_le_bytes(offsets.read()?);
        // Read only the terminal offset, not all neighbors preceding this row.
        let mut terminal =
            RangeCursor::new(artifact, neighbors, scaled(end, 8)?..scaled(offset_end, 8)?)?;
        let last = u64::from_le_bytes(terminal.read()?);
        let blob_start = usize::try_from(neighbors.frame.elem_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_mul(8))
            .ok_or_else(|| invalid("topology neighbor directory overflow"))?;
        let blob_offset = |offset: u64| {
            usize::try_from(offset)
                .ok()
                .and_then(|offset| blob_start.checked_add(offset))
                .ok_or_else(|| invalid("topology neighbor offset overflow"))
        };
        let width = if remap.is_some() { 2 } else { 4 };
        Ok(Self {
            ids: EdgeIdCursor::new(artifact, ids.section, ids.frame, range)?,
            types: RangeCursor::new(artifact, types, scaled(start, width)?..scaled(end, width)?)?,
            offsets,
            neighbors: RangeCursor::new(
                artifact,
                neighbors,
                blob_offset(first)?..blob_offset(last)?,
            )?,
            previous_offset: first,
            remap,
        })
    }

    pub(crate) fn read_next(&mut self) -> Result<Option<(TaggedNeighbor, EdgeId, TypeId)>> {
        let Some(id) = self.ids.next().transpose()? else {
            return Ok(None);
        };
        let next = u64::from_le_bytes(self.offsets.read()?);
        let len = next
            .checked_sub(self.previous_offset)
            .filter(|len| (2..=11).contains(len))
            .ok_or_else(|| invalid("invalid topology neighbor length"))? as usize;
        let mut bytes = [0; 11]; // tag plus at most ten canonical LEB128 bytes
        self.neighbors.read_into(&mut bytes[..len])?;
        let (neighbor, consumed) =
            decode_tagged_neighbor_prefix(Path::new("graph adjacency"), &bytes[..len])?;
        if consumed != len {
            return Err(invalid("topology neighbor has trailing bytes"));
        }
        self.previous_offset = next;
        let type_id = if let Some(remap) = self.remap {
            let local = u16::from_le_bytes(self.types.read()?);
            *remap
                .get(local as usize)
                .ok_or_else(|| invalid("topology type exceeds remap"))?
        } else {
            TypeId::from_raw(u32::from_le_bytes(self.types.read()?))
        };
        Ok(Some((neighbor, id, type_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_artifact::{self, ArtifactSpec, SectionPayload};

    #[test]
    fn parallel_columns_cross_chunks_plaintext_and_encrypted() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use std::{env, fs, process::Command};
        const MODE: &str = "CHIRONDB_TOPOLOGY_COLUMNS_MODE";
        const ROOT: &str = "CHIRONDB_TOPOLOGY_COLUMNS_ROOT";
        const TEST: &str =
            "graph_group::cursor::tests::parallel_columns_cross_chunks_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let temp = tempfile::tempdir().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, temp.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = std::path::PathBuf::from(env::var_os(ROOT).unwrap());
        if mode == "encrypted" {
            let path = root.join("keyring.json");
            fs::write(&path, serde_json::json!({"version":1,"active_key_id":"topology-columns","keys":[{"id":"topology-columns","key_base64":STANDARD.encode([97;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            crate::encryption::install_process_keyring(
                crate::encryption::Keyring::load(&path).unwrap(),
                true,
            )
            .unwrap();
        }
        let count = 20_013;
        let remap = [TypeId::from_raw(1), TypeId::from_raw(70_000)];
        let expected = (0..count)
            .map(|i| {
                let neighbor = match i % 3 {
                    0 => TaggedNeighbor::LocalDelta(-1),
                    1 => TaggedNeighbor::LocalDelta(400),
                    _ => TaggedNeighbor::Global(Nid::from_parts(3, i as u64 + 1).unwrap()),
                };
                (
                    neighbor,
                    EdgeId::from_parts(2, i as u64 + 1).unwrap(),
                    remap[i % 2],
                )
            })
            .collect::<Vec<_>>();
        for compact in [false, true] {
            let ids = expected
                .iter()
                .flat_map(|(_, id, _)| id.raw().to_le_bytes())
                .collect::<Vec<_>>();
            let types = if compact {
                (0..count)
                    .flat_map(|i| ((i % 2) as u16).to_le_bytes())
                    .collect::<Vec<_>>()
            } else {
                expected
                    .iter()
                    .flat_map(|(_, _, id)| id.raw().to_le_bytes())
                    .collect()
            };
            let neighbors =
                encode_tagged_neighbors(&expected.iter().map(|(n, _, _)| *n).collect::<Vec<_>>())
                    .unwrap();
            let spec = ArtifactSpec {
                magic: b"TESTCUR1",
                allowed_flags: 0,
                required_sections: &[1, 2, 3],
                optional_sections: &[],
                max_file_len: u64::MAX,
            };
            let path = root.join(format!("columns-{compact}.gdx"));
            let data = [&ids, &types, &neighbors];
            graph_artifact::write(
                &path,
                spec,
                0,
                &data
                    .iter()
                    .enumerate()
                    .map(|(i, bytes)| SectionPayload {
                        id: i as u32 + 1,
                        elem_count: count as u64,
                        bytes,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let artifact = graph_artifact::open(&path, spec).unwrap();
            let frames = data.map(|bytes| GroupFrame {
                elem_count: count as u64,
                payload_offset: 0,
                payload_len: bytes.len(),
            });
            let open = |range| {
                TopologyColumns::new(
                    &artifact,
                    Column {
                        section: 1,
                        frame: &frames[0],
                    },
                    Column {
                        section: 2,
                        frame: &frames[1],
                    },
                    Column {
                        section: 3,
                        frame: &frames[2],
                    },
                    range,
                    compact.then_some(remap.as_slice()),
                )
            };
            for range in [
                0..count as u64,
                31..count as u64 - 1,
                8191..8195,
                0..0,
                count as u64..count as u64,
            ] {
                let mut cursor = open(range.clone()).unwrap();
                for expected in &expected[range.start as usize..range.end as usize] {
                    assert_eq!(cursor.read_next().unwrap().unwrap(), *expected);
                    for len in [
                        cursor.ids.buffer.len(),
                        cursor.types.buffer.len(),
                        cursor.offsets.buffer.len(),
                        cursor.neighbors.buffer.len(),
                    ] {
                        assert!(len <= AUTHENTICATED_CHUNK_BYTES);
                    }
                }
                assert!(cursor.read_next().unwrap().is_none());
            }
            assert!(open(0..count as u64 + 1).is_err());
            let mut unavailable = open(0..1).unwrap();
            unavailable.types.section = 99; // Missing reader authority, no file mutation.
            assert!(
                unavailable
                    .read_next()
                    .unwrap_err()
                    .to_string()
                    .contains("absent")
            );
        }
    }
}
