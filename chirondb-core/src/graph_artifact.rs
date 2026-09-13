//! Checked Rev 3.4 Appendix C artifact envelope.
//!
//! Artifact-specific modules own section semantics. This module owns the
//! shared little-endian header/table, deterministic encoding, bounded
//! `PersistentFile` reads, and fail-closed structural validation.

use std::{borrow::Cow, collections::BTreeMap, ops::Range, path::Path};

use crate::{
    GaussError, Result,
    encryption::{FileType, PersistentFile, atomic_write_persistent},
};

pub(crate) const FORMAT_VERSION: u32 = 1;
pub(crate) const COMMON_HEADER_BYTES: usize = 32;
pub(crate) const SECTION_TABLE_ENTRY_BYTES: usize = 32;
pub(crate) const MAX_SECTIONS: u32 = 64;

#[derive(Clone, Copy)]
pub(crate) struct ArtifactSpec {
    pub(crate) magic: &'static [u8; 8],
    pub(crate) allowed_flags: u32,
    pub(crate) required_sections: &'static [u32],
    pub(crate) optional_sections: &'static [u32],
    pub(crate) max_file_len: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct SectionPayload<'a> {
    pub(crate) id: u32,
    pub(crate) elem_count: u64,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckedSection {
    pub(crate) offset: usize,
    pub(crate) length: usize,
    pub(crate) elem_count: u64,
}

pub(crate) struct CheckedArtifact {
    file: PersistentFile,
    flags: u32,
    sections: BTreeMap<u32, CheckedSection>,
}

impl CheckedArtifact {
    pub(crate) fn flags(&self) -> u32 {
        self.flags
    }

    pub(crate) fn section(&self, id: u32) -> Option<CheckedSection> {
        self.sections.get(&id).copied()
    }

    pub(crate) fn read_section(&self, id: u32) -> Result<Cow<'_, [u8]>> {
        let section = self
            .section(id)
            .ok_or_else(|| invalid(format!("graph artifact section {id} is absent")))?;
        self.read_section_range(id, 0..section.length)
    }

    pub(crate) fn read_section_range(&self, id: u32, range: Range<usize>) -> Result<Cow<'_, [u8]>> {
        let section = self
            .section(id)
            .ok_or_else(|| invalid(format!("graph artifact section {id} is absent")))?;
        if range.start > range.end || range.end > section.length {
            return Err(invalid(format!(
                "graph artifact section {id} range is out of bounds"
            )));
        }
        let start = section
            .offset
            .checked_add(range.start)
            .ok_or_else(|| invalid("graph artifact section range overflow"))?;
        let end = section
            .offset
            .checked_add(range.end)
            .ok_or_else(|| invalid("graph artifact section range overflow"))?;
        self.file.read_range(start..end)
    }
}

pub(crate) fn write(
    path: &Path,
    spec: ArtifactSpec,
    flags: u32,
    sections: &[SectionPayload<'_>],
) -> Result<()> {
    let bytes = encode_with_alignments(spec, flags, sections, &[])?;
    atomic_write_persistent(path, FileType::Segment, &bytes)
}

pub(crate) fn write_aligned(
    path: &Path,
    spec: ArtifactSpec,
    flags: u32,
    sections: &[SectionPayload<'_>],
    alignments: &[(u32, usize)],
) -> Result<()> {
    let bytes = encode_with_alignments(spec, flags, sections, alignments)?;
    atomic_write_persistent(path, FileType::Segment, &bytes)
}

pub(crate) fn open(path: &Path, spec: ArtifactSpec) -> Result<CheckedArtifact> {
    let file = PersistentFile::open(path)?;
    let file_len = u64::try_from(file.len())
        .map_err(|_| corruption(path, "graph artifact length exceeds u64"))?;
    if file.len() < COMMON_HEADER_BYTES || file_len > spec.max_file_len {
        return Err(corruption(
            path,
            "graph artifact length violates fixed limits",
        ));
    }

    let fixed = file.read_range(0..COMMON_HEADER_BYTES)?;
    if &fixed[0..8] != spec.magic {
        return Err(corruption(path, "bad graph artifact magic"));
    }
    let version = read_u32(&fixed, 8, "version");
    if version != FORMAT_VERSION {
        return Err(corruption(path, "unsupported graph artifact version"));
    }
    let flags = read_u32(&fixed, 12, "flags");
    validate_artifact_flags(spec, flags)
        .map_err(|_| corruption(path, "unknown graph artifact flags"))?;
    if read_u64(&fixed, 16, "file length") != file_len {
        return Err(corruption(path, "graph artifact file length mismatch"));
    }
    let section_count = read_u32(&fixed, 24, "section count");
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err(corruption(
            path,
            "graph artifact section count violates fixed limits",
        ));
    }
    let table_bytes = usize::try_from(section_count)
        .ok()
        .and_then(|count| count.checked_mul(SECTION_TABLE_ENTRY_BYTES))
        .ok_or_else(|| corruption(path, "graph artifact section table length overflow"))?;
    let header_bytes = COMMON_HEADER_BYTES
        .checked_add(table_bytes)
        .ok_or_else(|| corruption(path, "graph artifact header length overflow"))?;
    if header_bytes > file.len() {
        return Err(corruption(path, "truncated graph artifact section table"));
    }
    let table = file.read_range(COMMON_HEADER_BYTES..header_bytes)?;
    let expected_crc = read_u32(&fixed, 28, "header CRC32C");
    let mut crc_input = Vec::with_capacity(28 + table.len());
    crc_input.extend_from_slice(&fixed[..28]);
    crc_input.extend_from_slice(&table);
    if crc_fast::crc32_iscsi(&crc_input) != expected_crc {
        return Err(corruption(path, "graph artifact header CRC32C mismatch"));
    }

    let mut sections = BTreeMap::new();
    let mut ranges = Vec::with_capacity(section_count as usize);
    let mut previous_id = None;
    for index in 0..section_count as usize {
        let entry =
            &table[index * SECTION_TABLE_ENTRY_BYTES..(index + 1) * SECTION_TABLE_ENTRY_BYTES];
        let id = read_u32(entry, 0, "section id");
        if previous_id.is_some_and(|previous| previous >= id) {
            return Err(corruption(
                path,
                "graph artifact section ids are not strictly increasing",
            ));
        }
        previous_id = Some(id);
        if !known_section(spec, id) {
            return Err(corruption(path, "unknown graph artifact section"));
        }
        if read_u32(entry, 4, "section flags") != 0 {
            return Err(corruption(path, "unknown graph artifact section flags"));
        }
        let offset_u64 = read_u64(entry, 8, "section offset");
        let length_u64 = read_u64(entry, 16, "section length");
        let end_u64 = offset_u64
            .checked_add(length_u64)
            .ok_or_else(|| corruption(path, "graph artifact section range overflow"))?;
        if !offset_u64.is_multiple_of(8) || offset_u64 < header_bytes as u64 || end_u64 > file_len {
            return Err(corruption(path, "invalid graph artifact section range"));
        }
        let offset = usize::try_from(offset_u64)
            .map_err(|_| corruption(path, "graph artifact section offset exceeds usize"))?;
        let length = usize::try_from(length_u64)
            .map_err(|_| corruption(path, "graph artifact section length exceeds usize"))?;
        let section = CheckedSection {
            offset,
            length,
            elem_count: read_u64(entry, 24, "section element count"),
        };
        if sections.insert(id, section).is_some() {
            return Err(corruption(path, "duplicate graph artifact section"));
        }
        ranges.push((offset_u64, end_u64));
    }
    for required in spec.required_sections {
        if !sections.contains_key(required) {
            return Err(corruption(
                path,
                "required graph artifact section is absent",
            ));
        }
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(corruption(path, "overlapping graph artifact sections"));
        }
    }
    if ranges.last().is_none_or(|(_, end)| *end != file_len) {
        return Err(corruption(
            path,
            "graph artifact has trailing unowned bytes",
        ));
    }

    Ok(CheckedArtifact {
        file,
        flags,
        sections,
    })
}

fn encode(spec: ArtifactSpec, flags: u32, sections: &[SectionPayload<'_>]) -> Result<Vec<u8>> {
    encode_with_alignments(spec, flags, sections, &[])
}

fn encode_with_alignments(
    spec: ArtifactSpec,
    flags: u32,
    sections: &[SectionPayload<'_>],
    alignments: &[(u32, usize)],
) -> Result<Vec<u8>> {
    validate_artifact_flags(spec, flags)?;
    if sections.is_empty() || sections.len() > MAX_SECTIONS as usize {
        return Err(invalid(
            "graph artifact section count violates fixed limits",
        ));
    }
    let mut ordered = sections.to_vec();
    ordered.sort_unstable_by_key(|section| section.id);
    for pair in ordered.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(invalid("duplicate graph artifact section"));
        }
    }
    for section in &ordered {
        if !known_section(spec, section.id) {
            return Err(invalid(format!(
                "unknown graph artifact section {}",
                section.id
            )));
        }
    }
    for required in spec.required_sections {
        if !ordered.iter().any(|section| section.id == *required) {
            return Err(invalid(format!(
                "required graph artifact section {required} is absent"
            )));
        }
    }
    let mut section_alignments = BTreeMap::new();
    for (id, alignment) in alignments {
        if !known_section(spec, *id)
            || !ordered.iter().any(|section| section.id == *id)
            || !alignment.is_power_of_two()
            || !(8..=65_536).contains(alignment)
        {
            return Err(invalid("invalid graph artifact section alignment"));
        }
        if section_alignments.insert(*id, *alignment).is_some() {
            return Err(invalid("duplicate graph artifact section alignment"));
        }
    }

    let table_bytes = ordered
        .len()
        .checked_mul(SECTION_TABLE_ENTRY_BYTES)
        .ok_or_else(|| invalid("graph artifact section table length overflow"))?;
    let header_bytes = COMMON_HEADER_BYTES
        .checked_add(table_bytes)
        .ok_or_else(|| invalid("graph artifact header length overflow"))?;
    let mut next_offset = align_eight(header_bytes)?;
    let mut descriptors = Vec::with_capacity(ordered.len());
    for section in &ordered {
        let offset = align_to(
            next_offset,
            section_alignments.get(&section.id).copied().unwrap_or(8),
        )?;
        next_offset = offset
            .checked_add(section.bytes.len())
            .ok_or_else(|| invalid("graph artifact section length overflow"))?;
        descriptors.push((section, offset));
    }
    let last = descriptors
        .last()
        .expect("non-empty graph artifact has a final section");
    let file_len = last
        .1
        .checked_add(last.0.bytes.len())
        .ok_or_else(|| invalid("graph artifact file length overflow"))?;
    let file_len_u64 =
        u64::try_from(file_len).map_err(|_| invalid("graph artifact file length exceeds u64"))?;
    if file_len_u64 > spec.max_file_len {
        return Err(invalid("graph artifact exceeds fixed file-size limit"));
    }

    let mut prefix = Vec::with_capacity(28);
    prefix.extend_from_slice(spec.magic);
    prefix.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    prefix.extend_from_slice(&flags.to_le_bytes());
    prefix.extend_from_slice(&file_len_u64.to_le_bytes());
    prefix.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    let mut table = Vec::with_capacity(table_bytes);
    for (section, offset) in &descriptors {
        table.extend_from_slice(&section.id.to_le_bytes());
        table.extend_from_slice(&0_u32.to_le_bytes());
        table.extend_from_slice(&(*offset as u64).to_le_bytes());
        table.extend_from_slice(&(section.bytes.len() as u64).to_le_bytes());
        table.extend_from_slice(&section.elem_count.to_le_bytes());
    }
    let mut crc_input = prefix.clone();
    crc_input.extend_from_slice(&table);
    let mut bytes = Vec::with_capacity(file_len);
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(&crc_fast::crc32_iscsi(&crc_input).to_le_bytes());
    bytes.extend_from_slice(&table);
    bytes.resize(align_eight(bytes.len())?, 0);
    for (section, offset) in descriptors {
        bytes.resize(offset, 0);
        bytes.extend_from_slice(section.bytes);
    }
    debug_assert_eq!(bytes.len(), file_len);
    Ok(bytes)
}

fn validate_artifact_flags(spec: ArtifactSpec, flags: u32) -> Result<()> {
    if flags & !spec.allowed_flags != 0 {
        return Err(invalid("unknown graph artifact flags"));
    }
    Ok(())
}

fn known_section(spec: ArtifactSpec, id: u32) -> bool {
    spec.required_sections.contains(&id) || spec.optional_sections.contains(&id)
}

fn align_eight(value: usize) -> Result<usize> {
    align_to(value, 8)
}

fn align_to(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| invalid("graph artifact alignment overflow"))
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .unwrap_or_else(|_| panic!("checked {field} width")),
    )
}

fn read_u64(bytes: &[u8], offset: usize, field: &str) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .unwrap_or_else(|_| panic!("checked {field} width")),
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

    const MAGIC: &[u8; 8] = b"GAUSTE01";
    const REQUIRED: &[u32] = &[1, 2];
    const OPTIONAL: &[u32] = &[3];
    const STRICT_SPEC: ArtifactSpec = ArtifactSpec {
        magic: MAGIC,
        allowed_flags: 1,
        required_sections: REQUIRED,
        optional_sections: OPTIONAL,
        max_file_len: 1024 * 1024,
    };

    fn write_bytes(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
    }

    fn refresh_crc(bytes: &mut [u8]) {
        let count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let table_end = COMMON_HEADER_BYTES + count * SECTION_TABLE_ENTRY_BYTES;
        let mut input = Vec::with_capacity(28 + table_end - COMMON_HEADER_BYTES);
        input.extend_from_slice(&bytes[..28]);
        input.extend_from_slice(&bytes[COMMON_HEADER_BYTES..table_end]);
        bytes[28..32].copy_from_slice(&crc_fast::crc32_iscsi(&input).to_le_bytes());
    }

    #[test]
    fn common_envelope_round_trips_sections_in_stable_id_order() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact.gdx");
        write(
            &path,
            STRICT_SPEC,
            1,
            &[
                SectionPayload {
                    id: 2,
                    elem_count: 1,
                    bytes: b"second",
                },
                SectionPayload {
                    id: 1,
                    elem_count: 2,
                    bytes: b"first",
                },
            ],
        )
        .unwrap();
        let artifact = open(&path, STRICT_SPEC).unwrap();
        assert_eq!(artifact.flags(), 1);
        assert_eq!(&*artifact.read_section(1).unwrap(), b"first");
        assert_eq!(&*artifact.read_section(2).unwrap(), b"second");
        assert_eq!(artifact.section(1).unwrap().elem_count, 2);
        assert_eq!(&*artifact.read_section_range(1, 1..4).unwrap(), b"irs");
        assert!(artifact.read_section_range(1, 0..6).is_err());
    }

    #[test]
    fn common_loader_rejects_crc_unknown_overlap_truncation_and_flags() {
        let sections = [
            SectionPayload {
                id: 1,
                elem_count: 1,
                bytes: b"one",
            },
            SectionPayload {
                id: 2,
                elem_count: 1,
                bytes: b"two",
            },
        ];
        let valid = encode(STRICT_SPEC, 0, &sections).unwrap();
        let temp = tempfile::tempdir().unwrap();

        let crc = temp.path().join("crc.gdx");
        let mut corrupt_crc = valid.clone();
        corrupt_crc[28] ^= 1;
        write_bytes(&crc, &corrupt_crc);
        assert!(open(&crc, STRICT_SPEC).is_err());

        let unknown_spec = ArtifactSpec {
            optional_sections: &[3, 99],
            ..STRICT_SPEC
        };
        let unknown_bytes = encode(
            unknown_spec,
            0,
            &[
                sections[0],
                sections[1],
                SectionPayload {
                    id: 99,
                    elem_count: 0,
                    bytes: b"",
                },
            ],
        )
        .unwrap();
        let unknown = temp.path().join("unknown.gdx");
        write_bytes(&unknown, &unknown_bytes);
        assert!(open(&unknown, STRICT_SPEC).is_err());

        let overlap = temp.path().join("overlap.gdx");
        let mut overlap_bytes = valid.clone();
        let first_offset = overlap_bytes[40..48].to_vec();
        overlap_bytes[72..80].copy_from_slice(&first_offset);
        refresh_crc(&mut overlap_bytes);
        write_bytes(&overlap, &overlap_bytes);
        assert!(open(&overlap, STRICT_SPEC).is_err());

        let truncated = temp.path().join("truncated.gdx");
        write_bytes(&truncated, &valid[..valid.len() - 1]);
        assert!(open(&truncated, STRICT_SPEC).is_err());

        let flags = temp.path().join("flags.gdx");
        let mut flag_bytes = valid;
        flag_bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        refresh_crc(&mut flag_bytes);
        write_bytes(&flags, &flag_bytes);
        assert!(open(&flags, STRICT_SPEC).is_err());
    }

    #[test]
    fn common_writer_rejects_duplicate_missing_unknown_and_excess_sections() {
        let first = SectionPayload {
            id: 1,
            elem_count: 0,
            bytes: b"",
        };
        assert!(encode(STRICT_SPEC, 0, &[first, first]).is_err());
        assert!(encode(STRICT_SPEC, 0, &[first]).is_err());
        assert!(
            encode(
                STRICT_SPEC,
                0,
                &[
                    first,
                    SectionPayload {
                        id: 2,
                        elem_count: 0,
                        bytes: b"",
                    },
                    SectionPayload {
                        id: 99,
                        elem_count: 0,
                        bytes: b"",
                    },
                ],
            )
            .is_err()
        );
        let too_many = (1..=65)
            .map(|id| SectionPayload {
                id,
                elem_count: 0,
                bytes: b"",
            })
            .collect::<Vec<_>>();
        assert!(encode(STRICT_SPEC, 0, &too_many).is_err());
    }
}
