//! Fuzz-only facade over the production graph artifact writers and checked loaders.
//!
//! This module is compiled only with the `fuzzing` feature. It deliberately keeps
//! all format internals crate-private while giving the isolated cargo-fuzz
//! workspace one stable entrypoint that exercises the real production parsers.

use std::{fs, num::NonZeroU64, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};

use crate::{
    Result,
    encryption::{Keyring, install_process_keyring},
    graph::{EdgeId, GraphEpoch, GraphNamespace, Nid, TypeId},
    graph_edge::{
        self, BaseAdjacency, BaseEdgeInput, BaseGroupInput, BaseNeighborInput, BaseRowInput,
    },
    graph_edgeid::{self, EdgeLedgerRun, EdgeLedgerRunKind, EdgeLedgerRunMetadata},
    graph_edgeprop::{self, EdgePropertyInput, EdgePropertyTable},
    graph_fragdir::{
        self, FragmentDirectory, FragmentDirectoryRunKind, FragmentGroupInput, FragmentReference,
        FragmentRowInput,
    },
    graph_identity::{GRAPH_IDENTITY_FILE, GraphIdentityStore},
    graph_nid::{self, NidIndex},
    graph_tdelta::{self, DeltaEdgeInput, DeltaGroupInput, TopologyDelta},
};

const MAX_DERIVED_FILE_BYTES: usize = 8 * 1024 * 1024;
const FULL_EDGE_COUNT: u32 = 9_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Artifact {
    TopologyDelta,
    EdgeLedger,
    EdgeProperties,
    FragmentDirectory,
    Identity,
    Nid,
    BaseAdjacency,
}

impl Artifact {
    fn from_selector(selector: u8) -> Self {
        match selector {
            b'A' => Self::TopologyDelta,
            b'B' => Self::EdgeLedger,
            b'C' => Self::EdgeProperties,
            b'D' => Self::FragmentDirectory,
            b'E' => Self::Identity,
            b'F' => Self::Nid,
            b'G' => Self::BaseAdjacency,
            other => match other % 7 {
                0 => Self::TopologyDelta,
                1 => Self::EdgeLedger,
                2 => Self::EdgeProperties,
                3 => Self::FragmentDirectory,
                4 => Self::Identity,
                5 => Self::Nid,
                _ => Self::BaseAdjacency,
            },
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::TopologyDelta => graph_tdelta::TOPOLOGY_DELTA_FILE,
            Self::EdgeLedger => graph_edgeid::EDGEID_FILE,
            Self::EdgeProperties => graph_edgeprop::EDGE_PROPERTY_FILE,
            Self::FragmentDirectory => graph_fragdir::FRAGMENT_DIRECTORY_FILE,
            Self::Identity => GRAPH_IDENTITY_FILE,
            Self::Nid => graph_nid::NID_FILE,
            Self::BaseAdjacency => graph_edge::EDGE_FILE,
        }
    }
}

enum LoaderContext {
    None,
    BaseAdjacency(NidIndex),
}

/// Install one deterministic fuzz-only keyring. Encryption enforcement remains
/// disabled so the encrypted arm can exercise both raw plaintext rejection and
/// production-written `CHIRENC1` artifacts in the same process.
pub fn install_fixed_fuzz_keyring(root: &Path) -> Result<()> {
    fs::create_dir_all(root)?;
    let path = root.join("graph-gdx-fuzz-keyring.json");
    fs::write(
        &path,
        json!({
            "version": 1,
            "active_key_id": "g1-fuzz",
            "keys": [{
                "id": "g1-fuzz",
                "key_base64": STANDARD.encode([0x47_u8; 32]),
            }],
        })
        .to_string(),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    install_process_keyring(Keyring::load(&path)?, false)
}

/// Exercise exactly one production graph loader. Corruption is an expected
/// result and is ignored; panics, aborts, timeouts, and memory-safety failures
/// remain visible to libFuzzer.
pub fn exercise_graph_loader(root: &Path, data: &[u8]) {
    let _ = exercise_graph_loader_result(root, data);
}

fn exercise_graph_loader_result(root: &Path, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(root)?;
    let artifact = Artifact::from_selector(data[0]);
    let mode = data.get(1).copied().unwrap_or(b'R');
    let derived = mode == b'D' || (mode != b'R' && mode & 1 == 1);
    let variant = data.get(2).copied().unwrap_or_default() & 1;
    let payload = data.get(3..).unwrap_or_default();
    let path = root.join(artifact.file_name());

    let context = if derived {
        let context = write_canonical(root, artifact, variant)?;
        let mut bytes = fs::read(&path)?;
        mutate_derived_file(&mut bytes, payload);
        if bytes.len() > MAX_DERIVED_FILE_BYTES {
            bytes.truncate(MAX_DERIVED_FILE_BYTES);
        }
        fs::write(&path, bytes)?;
        context
    } else {
        fs::write(&path, payload)?;
        raw_context(artifact, variant)?
    };

    load_deep(root, &path, artifact, context)
}

fn write_canonical(root: &Path, artifact: Artifact, variant: u8) -> Result<LoaderContext> {
    let path = root.join(artifact.file_name());
    match artifact {
        Artifact::TopologyDelta => {
            graph_tdelta::write(&path, &topology_delta_fixture(variant)?)?;
            Ok(LoaderContext::None)
        }
        Artifact::EdgeLedger => {
            graph_edgeid::write(&path, &edge_ledger_fixture(variant)?)?;
            Ok(LoaderContext::None)
        }
        Artifact::EdgeProperties => {
            graph_edgeprop::write(&path, &edge_property_fixture(variant)?)?;
            Ok(LoaderContext::None)
        }
        Artifact::FragmentDirectory => {
            graph_fragdir::write(&path, &fragment_directory_fixture(variant)?)?;
            Ok(LoaderContext::None)
        }
        Artifact::Identity => {
            let store = GraphIdentityStore::open(root)?;
            if variant == 1 {
                store.allocate_nids(NonZeroU64::new(3).expect("non-zero fixture count"))?;
                store.allocate_edge_ids(NonZeroU64::new(2).expect("non-zero fixture count"))?;
            }
            Ok(LoaderContext::None)
        }
        Artifact::Nid => {
            graph_nid::write(&path, &nid_fixture(variant)?)?;
            Ok(LoaderContext::None)
        }
        Artifact::BaseAdjacency => {
            let (nid_index, adjacency) = base_adjacency_fixture(variant)?;
            graph_edge::write(&path, &adjacency)?;
            Ok(LoaderContext::BaseAdjacency(nid_index))
        }
    }
}

fn raw_context(artifact: Artifact, variant: u8) -> Result<LoaderContext> {
    match artifact {
        Artifact::BaseAdjacency => Ok(LoaderContext::BaseAdjacency(edge_nid_index(variant)?)),
        _ => Ok(LoaderContext::None),
    }
}

fn load_deep(root: &Path, path: &Path, artifact: Artifact, context: LoaderContext) -> Result<()> {
    match artifact {
        Artifact::TopologyDelta => {
            let opened = graph_tdelta::open(path, u64::MAX)?;
            for group in 0..opened.group_count() {
                let decoded = opened.read_group(path, group)?;
                let _ = decoded.rows.iter().fold(0_usize, |count, row| {
                    count + row.outgoing.len() + row.incoming.len()
                });
            }
        }
        Artifact::EdgeLedger => {
            let opened = graph_edgeid::open(path)?;
            let metadata = opened.metadata();
            let _ = metadata.graph_epoch.raw();
            for counter in [1, 2, 10_000, 20_001] {
                let _ = opened.contains(edge_id(23, counter))?;
            }
        }
        Artifact::EdgeProperties => {
            let opened = graph_edgeprop::open(path)?;
            for row in 0..opened.edge_count() {
                let edge_id = opened.edge_id_at(path, row)?;
                let _ = opened.find_edge(path, edge_id)?;
                let _ = opened.read_properties(path, row)?;
            }
        }
        Artifact::FragmentDirectory => {
            let opened = graph_fragdir::open(path)?;
            for group_index in 0..opened.group_count() {
                let group = opened.read_group(path, group_index)?;
                if let Some(row) = group.rows.first() {
                    let _ = opened.lookup(path, &group.namespace, row.nid)?;
                }
            }
        }
        Artifact::Identity => {
            let store = GraphIdentityStore::open(root)?;
            let _ = store.snapshot();
            let _ = store.reserve_new_epoch()?;
            let _ = store.allocate_nids(NonZeroU64::new(1).expect("non-zero probe count"))?;
            let _ = store.allocate_edge_ids(NonZeroU64::new(1).expect("non-zero probe count"))?;
        }
        Artifact::Nid => {
            let index = graph_nid::open(path)?;
            if index.len() != 0 {
                for ordinal in [0, index.len() / 2, index.len() - 1] {
                    let ordinal = u32::try_from(ordinal).expect("nid.gdx caps fit u32");
                    if let Some(nid) = index.nid_for_ordinal(ordinal) {
                        let _ = index.lookup(nid);
                    }
                }
            }
            let _ = index.lookup(nid(83, 20_001));
        }
        Artifact::BaseAdjacency => {
            let LoaderContext::BaseAdjacency(nid_index) = context else {
                unreachable!("base adjacency loader always receives its Nid index");
            };
            let opened = graph_edge::open(path, &nid_index)?;
            for group in 0..opened.group_count() {
                let decoded = opened.read_group(path, &nid_index, group)?;
                let _ = decoded.rows.iter().fold(0_usize, |count, row| {
                    count + row.outgoing.len() + row.incoming.len()
                });
            }
        }
    }
    Ok(())
}

fn mutate_derived_file(bytes: &mut Vec<u8>, mutations: &[u8]) {
    if mutations.is_empty() || mutations == b"\n" {
        return;
    }
    for (step, chunk) in mutations.chunks(4).enumerate() {
        let control = chunk[0];
        let mut selector = step;
        for byte in chunk.iter().skip(1) {
            selector = selector.rotate_left(5) ^ usize::from(*byte);
        }
        match control & 3 {
            0 => {
                if !bytes.is_empty() {
                    bytes.truncate(selector % (bytes.len() + 1));
                }
            }
            1 => {
                let appended = if chunk.len() == 1 { chunk } else { &chunk[1..] };
                let remaining = MAX_DERIVED_FILE_BYTES.saturating_sub(bytes.len());
                bytes.extend_from_slice(&appended[..appended.len().min(remaining)]);
            }
            2 => {
                if !bytes.is_empty() {
                    let index = selector % bytes.len();
                    bytes[index] = *chunk.last().expect("mutation chunk is non-empty");
                }
            }
            _ => {
                if !bytes.is_empty() {
                    let index = selector % bytes.len();
                    bytes[index] ^= control | 1;
                }
            }
        }
    }
}

fn nid_fixture(variant: u8) -> Result<NidIndex> {
    if variant == 0 {
        NidIndex::build(
            vec![nid(83, 1), Nid::UNASSIGNED, nid(83, 3), nid(83, 2)],
            false,
        )
    } else {
        NidIndex::build((1..=9_000).map(|counter| nid(83, counter)).collect(), true)
    }
}

fn edge_nid_index(variant: u8) -> Result<NidIndex> {
    if variant == 0 {
        NidIndex::build(
            vec![nid(31, 1), nid(31, 2), nid(31, 3), Nid::UNASSIGNED],
            true,
        )
    } else {
        NidIndex::build(vec![nid(31, 1), nid(31, 2)], true)
    }
}

fn base_adjacency_fixture(variant: u8) -> Result<(NidIndex, BaseAdjacency)> {
    let nid_index = edge_nid_index(variant)?;
    let adjacency = if variant == 0 {
        BaseAdjacency::build(
            &nid_index,
            vec![
                BaseGroupInput {
                    namespace: GraphNamespace::AdminCrossTenant,
                    rows: vec![BaseRowInput {
                        node_ordinal: 2,
                        outgoing: vec![base_edge(
                            BaseNeighborInput::GlobalNid(nid(31, 91)),
                            6,
                            3,
                            None,
                        )],
                        incoming: vec![],
                    }],
                },
                BaseGroupInput {
                    namespace: GraphNamespace::Tenant("acme".to_string()),
                    rows: vec![
                        BaseRowInput {
                            node_ordinal: 0,
                            outgoing: vec![
                                base_edge(BaseNeighborInput::LocalOrdinal(1), 1, 1, None),
                                base_edge(BaseNeighborInput::LocalOrdinal(1), 2, 2, None),
                            ],
                            incoming: vec![],
                        },
                        BaseRowInput {
                            node_ordinal: 1,
                            outgoing: vec![],
                            incoming: vec![],
                        },
                    ],
                },
            ],
        )?
    } else {
        let outgoing = (0..FULL_EDGE_COUNT)
            .map(|index| {
                base_edge(
                    BaseNeighborInput::LocalOrdinal(1),
                    1 + u64::from(index),
                    7,
                    Some(1.25),
                )
            })
            .collect::<Vec<_>>();
        let incoming = (0..FULL_EDGE_COUNT)
            .map(|index| {
                base_edge(
                    BaseNeighborInput::LocalOrdinal(0),
                    1 + u64::from(index),
                    7,
                    Some(1.25),
                )
            })
            .collect::<Vec<_>>();
        BaseAdjacency::build_with_options(
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
        )?
    };
    Ok((nid_index, adjacency))
}

fn base_edge(
    neighbor: BaseNeighborInput,
    counter: u64,
    type_id: u32,
    weight: Option<f32>,
) -> BaseEdgeInput {
    BaseEdgeInput {
        neighbor,
        edge_id: edge_id(31, counter),
        type_id: TypeId::from_raw(type_id),
        weight,
    }
}

fn topology_delta_fixture(variant: u8) -> Result<TopologyDelta> {
    let mut groups = vec![DeltaGroupInput {
        namespace: GraphNamespace::Tenant("acme".to_string()),
        edges: vec![
            DeltaEdgeInput {
                source_nid: nid(41, 1),
                target_nid: nid(41, 2),
                edge_id: edge_id(41, 1),
                type_id: TypeId::from_raw(1),
            },
            DeltaEdgeInput {
                source_nid: nid(41, 1),
                target_nid: nid(41, 2),
                edge_id: edge_id(41, 2),
                type_id: TypeId::from_raw(2),
            },
            DeltaEdgeInput {
                source_nid: nid(41, 2),
                target_nid: nid(41, 2),
                edge_id: edge_id(41, 3),
                type_id: TypeId::from_raw(1),
            },
        ],
    }];
    if variant == 1 {
        groups.push(DeltaGroupInput {
            namespace: GraphNamespace::AdminCrossTenant,
            edges: vec![DeltaEdgeInput {
                source_nid: nid(41, 10),
                target_nid: nid(41, 11),
                edge_id: edge_id(41, 4),
                type_id: TypeId::from_raw(3),
            }],
        });
    }
    TopologyDelta::build(77 + u64::from(variant), groups)
}

fn edge_ledger_fixture(variant: u8) -> Result<EdgeLedgerRun> {
    let kind = if variant == 0 {
        EdgeLedgerRunKind::Base
    } else {
        EdgeLedgerRunKind::Delta
    };
    EdgeLedgerRun::build(
        EdgeLedgerRunMetadata {
            graph_epoch: GraphEpoch::from_raw(17).expect("non-zero graph epoch"),
            first_lsn: 41,
            last_lsn: 99,
            kind,
        },
        (1..=10_000)
            .rev()
            .map(|counter| edge_id(23, counter))
            .collect(),
    )
}

fn edge_property_fixture(variant: u8) -> Result<EdgePropertyTable> {
    if variant == 0 {
        return EdgePropertyTable::build(Vec::new());
    }
    EdgePropertyTable::build(vec![
        EdgePropertyInput {
            edge_id: edge_id(43, 2),
            properties: object(json!({
                "big": u64::MAX - 1,
                "count": 3,
                "flag": true,
                "mixed": "scalar",
                "name": "beta",
                "ratio": 1.25,
            })),
        },
        EdgePropertyInput {
            edge_id: edge_id(43, 1),
            properties: object(json!({
                "big": u64::MAX,
                "count": -2,
                "flag": false,
                "mixed": {"z": 1, "a": [2]},
                "name": "alpha",
                "nullish": null,
            })),
        },
    ])
}

fn fragment_directory_fixture(variant: u8) -> Result<FragmentDirectory> {
    let kind = if variant == 0 {
        FragmentDirectoryRunKind::Base
    } else {
        FragmentDirectoryRunKind::Overlay
    };
    FragmentDirectory::build(
        kind,
        variant == 0,
        vec![
            FragmentGroupInput {
                namespace: GraphNamespace::AdminCrossTenant,
                rows: vec![FragmentRowInput {
                    nid: nid(73, 1),
                    fragments: vec![fragment_reference(90, 7)],
                }],
            },
            FragmentGroupInput {
                namespace: GraphNamespace::Tenant("acme".to_string()),
                rows: vec![
                    FragmentRowInput {
                        nid: nid(73, 2),
                        fragments: vec![fragment_reference(20, 1)],
                    },
                    FragmentRowInput {
                        nid: nid(73, 1),
                        fragments: vec![fragment_reference(11, 3), fragment_reference(10, 8)],
                    },
                ],
            },
        ],
    )
}

fn fragment_reference(fragment_id: u64, row_hint: u32) -> FragmentReference {
    FragmentReference {
        fragment_id,
        row_hint,
    }
}

fn object(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .expect("fixture value is an object")
        .clone()
}

fn nid(epoch: u32, counter: u64) -> Nid {
    Nid::from_parts(epoch, counter).expect("fixture Nid is valid")
}

fn edge_id(epoch: u32, counter: u64) -> EdgeId {
    EdgeId::from_parts(epoch, counter).expect("fixture EdgeId is valid")
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf, process::Command};

    use super::*;

    const HELPER_MODE: &str = "CHIRONDB_GRAPH_FUZZ_SELF_TEST_MODE";
    const HELPER_ROOT: &str = "CHIRONDB_GRAPH_FUZZ_SELF_TEST_ROOT";
    const TEST_NAME: &str =
        "graph_fuzz::tests::canonical_corpus_reaches_plaintext_and_encrypted_loaders";
    const DERIVED_CORPUS: [[u8; 4]; 14] = [
        *b"AD0\n", *b"AD1\n", *b"BD0\n", *b"BD1\n", *b"CD0\n", *b"CD1\n", *b"DD0\n", *b"DD1\n",
        *b"ED0\n", *b"ED1\n", *b"FD0\n", *b"FD1\n", *b"GD0\n", *b"GD1\n",
    ];

    #[test]
    fn canonical_corpus_reaches_plaintext_and_encrypted_loaders() {
        if let Some(mode) = env::var_os(HELPER_MODE) {
            let root = PathBuf::from(env::var_os(HELPER_ROOT).expect("helper root is set"));
            let encrypted = mode == "encrypted";
            if encrypted {
                install_fixed_fuzz_keyring(&root).unwrap();
            }
            for (index, seed) in DERIVED_CORPUS.iter().enumerate() {
                let iteration = root.join(format!("seed-{index}"));
                exercise_graph_loader_result(&iteration, seed).unwrap();
                let artifact = Artifact::from_selector(seed[0]);
                let bytes = fs::read(iteration.join(artifact.file_name())).unwrap();
                assert_eq!(bytes.starts_with(crate::encryption::MAGIC), encrypted);
            }
            return;
        }

        for mode in ["plaintext", "encrypted"] {
            let root = tempfile::tempdir().unwrap();
            let status = Command::new(env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .env(HELPER_MODE, mode)
                .env(HELPER_ROOT, root.path())
                .status()
                .unwrap();
            assert!(status.success(), "{mode} graph fuzz self-test failed");
        }
    }

    #[test]
    fn raw_and_mutated_inputs_fail_closed_without_harness_panics() {
        for input in [
            b"AR0raw".as_slice(),
            b"BR1\0\0\0".as_slice(),
            b"CR0[]".as_slice(),
            b"DR1short".as_slice(),
            b"ER0bad identity".as_slice(),
            b"FR1bad nid".as_slice(),
            b"GR0bad edge".as_slice(),
            b"GD1\x03\x00\x00\x01".as_slice(),
        ] {
            let root = tempfile::tempdir().unwrap();
            exercise_graph_loader(root.path(), input);
        }
    }
}
