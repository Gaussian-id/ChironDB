//! `nid.gdx` segment handle/location artifact (Rev 3.4 Appendix C addendum).

use std::{collections::HashSet, path::Path};

use crate::{
    GaussError, Result,
    graph::{GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, Nid},
    graph_artifact::{self, ArtifactSpec, SectionPayload},
};

pub(crate) const NID_FILE: &str = "nid.gdx";
pub(crate) const NID_MAGIC: &[u8; 8] = b"GAUSNI01";

const FLAG_BLOOM: u32 = 1;
const SECTION_SORTED_NIDS: u32 = 1;
const SECTION_SORTED_ORDINALS: u32 = 2;
const SECTION_ORDINAL_TO_NID: u32 = 3;
const SECTION_BLOOM: u32 = 4;
const REQUIRED_SECTIONS: &[u32] = &[
    SECTION_SORTED_NIDS,
    SECTION_SORTED_ORDINALS,
    SECTION_ORDINAL_TO_NID,
];
const OPTIONAL_SECTIONS: &[u32] = &[SECTION_BLOOM];
const MAX_NID_FILE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const BLOOM_HASHES: u32 = 7;
const BLOOM_BITS_PER_KEY: usize = 10;
const BLOOM_HEADER_BYTES: usize = 16;
const BLOOM_MIN_BITS: usize = 64;

const SPEC: ArtifactSpec = ArtifactSpec {
    magic: NID_MAGIC,
    allowed_flags: FLAG_BLOOM,
    required_sections: REQUIRED_SECTIONS,
    optional_sections: OPTIONAL_SECTIONS,
    max_file_len: MAX_NID_FILE_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct NidBloom {
    bit_count: u64,
    bits: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NidIndex {
    sorted_nids: Vec<Nid>,
    sorted_ordinals: Vec<u32>,
    ordinal_to_nid: Vec<Nid>,
    bloom: Option<NidBloom>,
}

impl NidIndex {
    pub(crate) fn build(ordinal_to_nid: Vec<Nid>, include_bloom: bool) -> Result<Self> {
        if ordinal_to_nid.len() > u32::MAX as usize {
            return Err(invalid("nid.gdx point count exceeds u32 format cap"));
        }
        let mut seen = HashSet::with_capacity(ordinal_to_nid.len());
        let mut pairs = Vec::new();
        for (ordinal, nid) in ordinal_to_nid.iter().copied().enumerate() {
            if nid == Nid::UNASSIGNED {
                continue;
            }
            validate_nid(nid)?;
            if !seen.insert(nid) {
                return Err(invalid("nid.gdx contains a duplicate live Nid"));
            }
            pairs.push((nid, ordinal as u32));
        }
        pairs.sort_unstable_by_key(|(nid, _)| *nid);
        let (sorted_nids, sorted_ordinals): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let bloom = include_bloom
            .then(|| NidBloom::build(&sorted_nids))
            .transpose()?;
        Ok(Self {
            sorted_nids,
            sorted_ordinals,
            ordinal_to_nid,
            bloom,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.ordinal_to_nid.len()
    }

    pub(crate) fn lookup(&self, nid: Nid) -> Option<u32> {
        if nid == Nid::UNASSIGNED
            || self
                .sorted_nids
                .first()
                .zip(self.sorted_nids.last())
                .is_none_or(|(first, last)| nid < *first || nid > *last)
            || self
                .bloom
                .as_ref()
                .is_some_and(|bloom| !bloom.may_contain(nid))
        {
            return None;
        }
        self.sorted_nids
            .binary_search(&nid)
            .ok()
            .map(|index| self.sorted_ordinals[index])
    }

    pub(crate) fn nid_for_ordinal(&self, ordinal: u32) -> Option<Nid> {
        self.ordinal_to_nid
            .get(ordinal as usize)
            .copied()
            .filter(|nid| *nid != Nid::UNASSIGNED)
    }
}

impl NidBloom {
    fn build(nids: &[Nid]) -> Result<Self> {
        let wanted = nids
            .len()
            .checked_mul(BLOOM_BITS_PER_KEY)
            .ok_or_else(|| invalid("nid.gdx Bloom size overflow"))?
            .max(BLOOM_MIN_BITS);
        let bit_count = wanted
            .checked_add(63)
            .map(|bits| bits & !63)
            .ok_or_else(|| invalid("nid.gdx Bloom alignment overflow"))?;
        let mut bloom = Self {
            bit_count: bit_count as u64,
            bits: vec![0; bit_count / 8],
        };
        for nid in nids {
            bloom.insert(*nid);
        }
        Ok(bloom)
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

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BLOOM_HEADER_BYTES {
            return Err(invalid("truncated nid.gdx Bloom header"));
        }
        let bit_count = u64::from_le_bytes(bytes[0..8].try_into().expect("Bloom bit count"));
        let hashes = u32::from_le_bytes(bytes[8..12].try_into().expect("Bloom hash count"));
        let reserved = u32::from_le_bytes(bytes[12..16].try_into().expect("Bloom reserved"));
        if bit_count < BLOOM_MIN_BITS as u64
            || !bit_count.is_multiple_of(64)
            || hashes != BLOOM_HASHES
            || reserved != 0
        {
            return Err(invalid("invalid nid.gdx Bloom metadata"));
        }
        let bit_bytes = usize::try_from(bit_count / 8)
            .map_err(|_| invalid("nid.gdx Bloom length exceeds usize"))?;
        if bytes.len() != BLOOM_HEADER_BYTES + bit_bytes {
            return Err(invalid("nid.gdx Bloom length mismatch"));
        }
        Ok(Self {
            bit_count,
            bits: bytes[BLOOM_HEADER_BYTES..].to_vec(),
        })
    }
}

pub(crate) fn write(path: &Path, index: &NidIndex) -> Result<()> {
    let sorted_nids = encode_nids(&index.sorted_nids);
    let sorted_ordinals = encode_ordinals(&index.sorted_ordinals);
    let reverse = encode_nids(&index.ordinal_to_nid);
    let bloom = index.bloom.as_ref().map(NidBloom::encode);
    let mut sections = vec![
        SectionPayload {
            id: SECTION_SORTED_NIDS,
            elem_count: index.sorted_nids.len() as u64,
            bytes: &sorted_nids,
        },
        SectionPayload {
            id: SECTION_SORTED_ORDINALS,
            elem_count: index.sorted_ordinals.len() as u64,
            bytes: &sorted_ordinals,
        },
        SectionPayload {
            id: SECTION_ORDINAL_TO_NID,
            elem_count: index.ordinal_to_nid.len() as u64,
            bytes: &reverse,
        },
    ];
    if let Some(bloom) = bloom.as_deref() {
        sections.push(SectionPayload {
            id: SECTION_BLOOM,
            elem_count: index.bloom.as_ref().expect("Bloom bytes exist").bit_count,
            bytes: bloom,
        });
    }
    graph_artifact::write(
        path,
        SPEC,
        if index.bloom.is_some() { FLAG_BLOOM } else { 0 },
        &sections,
    )
}

pub(crate) fn open(path: &Path) -> Result<NidIndex> {
    let artifact = graph_artifact::open(path, SPEC)?;
    let has_bloom = artifact.flags() & FLAG_BLOOM != 0;
    if has_bloom != artifact.section(SECTION_BLOOM).is_some() {
        return Err(corruption(path, "nid.gdx Bloom flag and section disagree"));
    }
    let nids_section = artifact
        .section(SECTION_SORTED_NIDS)
        .expect("common loader requires sorted Nid section");
    let ordinals_section = artifact
        .section(SECTION_SORTED_ORDINALS)
        .expect("common loader requires sorted ordinal section");
    let reverse_section = artifact
        .section(SECTION_ORDINAL_TO_NID)
        .expect("common loader requires reverse Nid section");
    if nids_section.elem_count != ordinals_section.elem_count {
        return Err(corruption(path, "nid.gdx sorted section counts disagree"));
    }
    if reverse_section.elem_count > u32::MAX as u64 {
        return Err(corruption(path, "nid.gdx point count exceeds u32 cap"));
    }
    let sorted_nids = decode_nids(
        path,
        &artifact.read_section(SECTION_SORTED_NIDS)?,
        nids_section.elem_count,
        "sorted Nids",
    )?;
    let sorted_ordinals = decode_ordinals(
        path,
        &artifact.read_section(SECTION_SORTED_ORDINALS)?,
        ordinals_section.elem_count,
    )?;
    let ordinal_to_nid = decode_nids(
        path,
        &artifact.read_section(SECTION_ORDINAL_TO_NID)?,
        reverse_section.elem_count,
        "reverse Nids",
    )?;
    let bloom = if has_bloom {
        let section = artifact
            .section(SECTION_BLOOM)
            .expect("Bloom section agrees with flag");
        let bloom = NidBloom::decode(&artifact.read_section(SECTION_BLOOM)?)
            .map_err(|error| corruption(path, &error.to_string()))?;
        if section.elem_count != bloom.bit_count {
            return Err(corruption(path, "nid.gdx Bloom element count disagrees"));
        }
        Some(bloom)
    } else {
        None
    };
    validate_loaded(
        path,
        &sorted_nids,
        &sorted_ordinals,
        &ordinal_to_nid,
        bloom.as_ref(),
    )?;
    Ok(NidIndex {
        sorted_nids,
        sorted_ordinals,
        ordinal_to_nid,
        bloom,
    })
}

fn validate_loaded(
    path: &Path,
    sorted_nids: &[Nid],
    sorted_ordinals: &[u32],
    reverse: &[Nid],
    bloom: Option<&NidBloom>,
) -> Result<()> {
    if sorted_nids.len() != sorted_ordinals.len() || sorted_nids.len() > reverse.len() {
        return Err(corruption(path, "nid.gdx map cardinality is invalid"));
    }
    let mut previous = None;
    let mut seen_ordinals = HashSet::with_capacity(sorted_ordinals.len());
    for (nid, ordinal) in sorted_nids
        .iter()
        .copied()
        .zip(sorted_ordinals.iter().copied())
    {
        validate_nid(nid).map_err(|error| corruption(path, &error.to_string()))?;
        if previous.is_some_and(|value| value >= nid) {
            return Err(corruption(path, "nid.gdx Nids are not strictly sorted"));
        }
        previous = Some(nid);
        if ordinal as usize >= reverse.len() || !seen_ordinals.insert(ordinal) {
            return Err(corruption(path, "nid.gdx ordinal map is invalid"));
        }
        if reverse[ordinal as usize] != nid {
            return Err(corruption(path, "nid.gdx forward/reverse map disagrees"));
        }
        if bloom.is_some_and(|filter| !filter.may_contain(nid)) {
            return Err(corruption(path, "nid.gdx Bloom has a false negative"));
        }
    }
    let assigned = reverse
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, nid)| *nid != Nid::UNASSIGNED)
        .count();
    if assigned != sorted_nids.len() {
        return Err(corruption(path, "nid.gdx reverse map has an unindexed Nid"));
    }
    for nid in reverse
        .iter()
        .copied()
        .filter(|nid| *nid != Nid::UNASSIGNED)
    {
        validate_nid(nid).map_err(|error| corruption(path, &error.to_string()))?;
    }
    Ok(())
}

fn encode_nids(nids: &[Nid]) -> Vec<u8> {
    nids.iter()
        .flat_map(|nid| nid.raw().to_le_bytes())
        .collect()
}

fn encode_ordinals(ordinals: &[u32]) -> Vec<u8> {
    ordinals
        .iter()
        .flat_map(|ordinal| ordinal.to_le_bytes())
        .collect()
}

fn decode_nids(path: &Path, bytes: &[u8], elem_count: u64, field: &str) -> Result<Vec<Nid>> {
    let count = checked_width(path, bytes.len(), elem_count, 8, field)?;
    Ok(bytes
        .chunks_exact(8)
        .take(count)
        .map(|bytes| Nid::from_raw(u64::from_le_bytes(bytes.try_into().expect("Nid width"))))
        .collect())
}

fn decode_ordinals(path: &Path, bytes: &[u8], elem_count: u64) -> Result<Vec<u32>> {
    let count = checked_width(path, bytes.len(), elem_count, 4, "sorted ordinals")?;
    Ok(bytes
        .chunks_exact(4)
        .take(count)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("ordinal width")))
        .collect())
}

fn checked_width(
    path: &Path,
    actual_bytes: usize,
    elem_count: u64,
    width: usize,
    field: &str,
) -> Result<usize> {
    let count = usize::try_from(elem_count)
        .map_err(|_| corruption(path, &format!("nid.gdx {field} count exceeds usize")))?;
    let expected = count
        .checked_mul(width)
        .ok_or_else(|| corruption(path, &format!("nid.gdx {field} length overflow")))?;
    if actual_bytes != expected {
        return Err(corruption(
            path,
            &format!("nid.gdx {field} length mismatch"),
        ));
    }
    Ok(count)
}

fn validate_nid(nid: Nid) -> Result<()> {
    if !nid.is_assigned()
        || nid.epoch() == 0
        || nid.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || nid.counter() == 0
        || nid.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("nid.gdx contains an invalid Nid"));
    }
    Ok(())
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

    const ENCRYPTED_HELPER_ENV: &str = "CHIRONDB_GRAPH_NID_ENCRYPTED_HELPER_DIR";

    fn nid(counter: u64) -> Nid {
        Nid::from_parts(31, counter).unwrap()
    }

    #[test]
    fn nid_index_round_trips_sorted_and_reverse_maps_with_zero_sentinel() {
        let reverse = vec![nid(3), Nid::UNASSIGNED, nid(1), nid(2)];
        let index = NidIndex::build(reverse, true).unwrap();
        assert_eq!(index.len(), 4);
        assert_eq!(index.lookup(nid(1)), Some(2));
        assert_eq!(index.lookup(nid(2)), Some(3));
        assert_eq!(index.lookup(nid(3)), Some(0));
        assert_eq!(index.lookup(nid(99)), None);
        assert_eq!(index.lookup(Nid::from_parts(30, 99).unwrap()), None);
        assert_eq!(index.lookup(Nid::UNASSIGNED), None);
        assert_eq!(index.nid_for_ordinal(1), None);

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(NID_FILE);
        write(&path, &index).unwrap();
        let reopened = open(&path).unwrap();
        assert_eq!(reopened, index);
    }

    #[test]
    fn nid_index_rejects_duplicate_invalid_and_forward_reverse_corruption() {
        assert!(NidIndex::build(vec![nid(1), nid(1)], false).is_err());
        assert!(NidIndex::build(vec![Nid::from_raw(1)], false).is_err());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(NID_FILE);
        let index = NidIndex::build(vec![nid(1), nid(2)], false).unwrap();
        write(&path, &index).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let reverse_entry = graph_artifact::COMMON_HEADER_BYTES
            + REQUIRED_SECTIONS.len() * graph_artifact::SECTION_TABLE_ENTRY_BYTES;
        let reverse_offset_entry =
            graph_artifact::COMMON_HEADER_BYTES + 2 * graph_artifact::SECTION_TABLE_ENTRY_BYTES + 8;
        let reverse_offset = u64::from_le_bytes(
            bytes[reverse_offset_entry..reverse_offset_entry + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        assert!(reverse_offset >= reverse_entry);
        bytes[reverse_offset..reverse_offset + 8].copy_from_slice(&nid(2).raw().to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn nid_index_rejects_bloom_flag_section_disagreement_and_count_overflow() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(NID_FILE);
        let index = NidIndex::build(vec![nid(1)], false).unwrap();
        write(&path, &index).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[12..16].copy_from_slice(&FLAG_BLOOM.to_le_bytes());
        refresh_header_crc(&mut bytes);
        fs::write(&path, &bytes).unwrap();
        assert!(open(&path).is_err());

        write(&path, &index).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let reverse_count = graph_artifact::COMMON_HEADER_BYTES
            + 2 * graph_artifact::SECTION_TABLE_ENTRY_BYTES
            + 24;
        bytes[reverse_count..reverse_count + 8]
            .copy_from_slice(&(u32::MAX as u64 + 1).to_le_bytes());
        refresh_header_crc(&mut bytes);
        fs::write(&path, bytes).unwrap();
        assert!(open(&path).is_err());
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

    #[test]
    fn nid_index_uses_authenticated_chunks_when_encryption_is_enabled() {
        if env::var_os(ENCRYPTED_HELPER_ENV).is_some() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("graph_nid::tests::encrypted_nid_roundtrip_helper")
            .arg("--nocapture")
            .env(ENCRYPTED_HELPER_ENV, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "encrypted nid.gdx helper failed: {status}"
        );
    }

    #[test]
    fn encrypted_nid_roundtrip_helper() {
        let Some(root) = env::var_os(ENCRYPTED_HELPER_ENV) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let keyring_path = root.join("keyring.json");
        fs::write(
            &keyring_path,
            json!({
                "version": 1,
                "active_key_id": "g1-test",
                "keys": [{
                    "id": "g1-test",
                    "key_base64": STANDARD.encode([41_u8; 32]),
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
        let path = root.join(NID_FILE);
        let reverse = (1..=20_000).map(nid).collect::<Vec<_>>();
        let index = NidIndex::build(reverse, true).unwrap();
        write(&path, &index).unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], crate::encryption::MAGIC);
        let reopened = open(&path).unwrap();
        assert_eq!(reopened.lookup(nid(20_000)), Some(19_999));
        let mut ciphertext = fs::read(&path).unwrap();
        let final_byte = ciphertext
            .last_mut()
            .expect("encrypted nid.gdx is non-empty");
        *final_byte ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(open(&path).is_err());
    }
}
