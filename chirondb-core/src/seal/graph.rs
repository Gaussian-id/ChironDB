//! Checked graph group promotion for a private, unpublished seal candidate.
//!
//! This does not install a collection generation or advance its WAL watermark.
//! Collection recovery remains fail-closed until the single graph manifest and
//! pinned graph read state are integrated.

use std::path::Path;

use crate::{
    Result, graph_edge, graph_edgeprop, graph_nid,
    seal::{SEAL_FILE, SealMarker, corrupt, file_entry, read_marker, sync_directory, write_marker},
};

pub(super) const FILES: [&str; 3] = [
    graph_nid::NID_FILE,
    graph_edge::EDGE_FILE,
    graph_edgeprop::EDGE_PROPERTY_FILE,
];

pub(super) fn validate_group(dir: &Path, points: usize) -> Result<()> {
    let nid_path = dir.join(graph_nid::NID_FILE);
    let nids = graph_nid::open(&nid_path)?;
    if nids.len() != points {
        return Err(corrupt(
            &nid_path,
            "graph Nid count disagrees with seal marker point count",
        ));
    }
    graph_edge::open(&dir.join(graph_edge::EDGE_FILE), &nids)?;
    graph_edgeprop::open(&dir.join(graph_edgeprop::EDGE_PROPERTY_FILE))?;
    Ok(())
}

/// Promote a vector marker only after all graph peers are durably written and
/// independently readable. The caller owns the private staging directory and
/// must publish this candidate with the collection's graph manifest, never by
/// installing a directory alone. A retry validates the existing graph marker.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn seal_candidate(dir: &Path) -> Result<SealMarker> {
    let path = dir.join(SEAL_FILE);
    let mut marker = read_marker(&path)?;
    if marker.has_graph() {
        return Ok(marker);
    }
    validate_group(dir, marker.points)?;
    for name in FILES {
        marker.files.push(file_entry(dir, name)?);
    }
    marker.version += 6;
    // The graph writers fsync their files; persist directory entries before
    // making the marker capable of naming the complete immutable peer group.
    sync_directory(dir)?;
    write_marker(&path, &marker)?;
    sync_directory(dir)?;
    read_marker(&path)
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf, process::Command};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        DistanceMetric, Point, encryption,
        graph::{EdgeId, GraphNamespace, Nid, TypeId},
        graph_edge::{
            BaseAdjacency, BaseEdgeInput, BaseGroupInput, BaseNeighborInput, BaseRowInput,
        },
        graph_edgeprop::{EdgePropertyInput, EdgePropertyTable},
        graph_nid::NidIndex,
        seal::{
            DenseVectorEncoding, SealConfig, SealIndexKind, V4Store, build_segment_with_encoding,
            thin_algorithm2_segment_for_cold,
        },
    };

    fn vector_candidate(dir: &Path, version: u32) -> SealMarker {
        let points = (0..8)
            .map(|i| {
                let vector = vec![i as f32 + 0.5, 1.0, 2.0, 3.0];
                Point {
                    id: format!("p{i}"),
                    vectors: if matches!(version, 8 | 9) {
                        [("image".to_string(), vector.clone())].into()
                    } else {
                        Default::default()
                    },
                    vector,
                    sparse_vector: None,
                    payload: json!({"ordinal": i}),
                }
            })
            .collect::<Vec<_>>();
        build_segment_with_encoding(
            points.as_slice(),
            dir,
            SealConfig {
                vector_dim: 4,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: if version <= 5 {
                    SealIndexKind::Hnsw
                } else {
                    SealIndexKind::Algorithm2
                },
                base_lsn: 10,
                end_lsn: 20,
            },
            if version == 4 {
                DenseVectorEncoding::F32
            } else {
                DenseVectorEncoding::ScaledF16
            },
        )
        .unwrap();
        if matches!(version, 7 | 9) {
            assert!(thin_algorithm2_segment_for_cold(dir).unwrap());
        }
        let marker = read_marker(&dir.join(SEAL_FILE)).unwrap();
        assert_eq!(marker.version, version);
        assert_eq!(V4Store::open(dir).unwrap().len(), 8);
        marker
    }

    fn graph_peers(dir: &Path, points: usize, with_edge: bool) {
        let nids = NidIndex::build(
            (0..points)
                .map(|i| Nid::from_parts(1, i as u64 + 1).unwrap())
                .collect(),
            true,
        )
        .unwrap();
        graph_nid::write(&dir.join(graph_nid::NID_FILE), &nids).unwrap();
        let edge_id = EdgeId::from_parts(1, 1).unwrap();
        let edge = |ordinal| BaseEdgeInput {
            neighbor: BaseNeighborInput::LocalOrdinal(ordinal),
            edge_id,
            type_id: TypeId::from_raw(1),
            weight: Some(1.25),
        };
        let groups = if with_edge {
            vec![BaseGroupInput {
                namespace: GraphNamespace::Tenant("acme".into()),
                rows: vec![
                    BaseRowInput {
                        node_ordinal: 0,
                        outgoing: vec![edge(1)],
                        incoming: vec![],
                    },
                    BaseRowInput {
                        node_ordinal: 1,
                        outgoing: vec![],
                        incoming: vec![edge(0)],
                    },
                ],
            }]
        } else {
            vec![]
        };
        graph_edge::write(
            &dir.join(graph_edge::EDGE_FILE),
            &BaseAdjacency::build_with_options(&nids, groups, true, with_edge).unwrap(),
        )
        .unwrap();
        graph_edgeprop::write(
            &dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
            &EdgePropertyTable::build(if with_edge {
                vec![EdgePropertyInput {
                    edge_id,
                    properties: json!({"source": "fixture", "optional": null})
                        .as_object()
                        .unwrap()
                        .clone(),
                }]
            } else {
                vec![]
            })
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn graph_markers_roundtrip_all_versions_plaintext_and_encrypted() {
        const MODE: &str = "CHIRONDB_GRAPH_SEAL_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_SEAL_TEST_ROOT";
        const TEST: &str =
            "seal::graph::tests::graph_markers_roundtrip_all_versions_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = TempDir::new().unwrap();
                let status = Command::new(env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(MODE, mode)
                    .env(ROOT, root.path())
                    .status()
                    .unwrap();
                assert!(status.success(), "{mode} graph marker checks failed");
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).expect("isolated helper root"));
        let encrypted = mode == "encrypted";
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(
                &keyring,
                json!({
                    "version": 1,
                    "active_key_id": "graph-seal-test",
                    "keys": [{"id": "graph-seal-test", "key_base64": STANDARD.encode([67; 32])}],
                })
                .to_string(),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        for vector_version in 4..=9 {
            let dir = root.join(format!("v{vector_version}"));
            let original = vector_candidate(&dir, vector_version);
            graph_peers(&dir, original.points, vector_version != 4);
            let marker = seal_candidate(&dir).unwrap();
            assert_eq!(marker.version, vector_version + 6);
            assert_eq!(marker.vector_version(), vector_version);
            assert_eq!(marker.points, original.points);
            assert_eq!((marker.base_lsn, marker.end_lsn), (10, 20));
            assert_eq!(marker.files.len(), original.files.len() + FILES.len());
            let before_retry = fs::read(dir.join(SEAL_FILE)).unwrap();
            seal_candidate(&dir).unwrap();
            assert_eq!(fs::read(dir.join(SEAL_FILE)).unwrap(), before_retry);
            for name in FILES.into_iter().chain([SEAL_FILE]) {
                assert_eq!(
                    fs::read(dir.join(name))
                        .unwrap()
                        .starts_with(encryption::MAGIC),
                    encrypted,
                );
            }
            // A standalone graph marker must not let the existing vector-only
            // collection loader silently drop topology before manifest wiring.
            assert!(V4Store::open(&dir).is_err());
            if matches!(vector_version, 6 | 8) {
                let peers = FILES.map(|name| fs::read(dir.join(name)).unwrap());
                assert!(thin_algorithm2_segment_for_cold(&dir).unwrap());
                assert_eq!(
                    read_marker(&dir.join(SEAL_FILE)).unwrap().version,
                    marker.version + 1
                );
                assert_eq!(FILES.map(|name| fs::read(dir.join(name)).unwrap()), peers);
                assert!(!thin_algorithm2_segment_for_cold(&dir).unwrap());
            }
            if encrypted {
                let peer = dir.join(graph_edge::EDGE_FILE);
                let mut ciphertext = fs::read(&peer).unwrap();
                *ciphertext.last_mut().unwrap() ^= 1;
                fs::write(&peer, ciphertext).unwrap();
                assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
            }
        }
    }

    #[test]
    fn graph_marker_requires_all_peers_before_promotion() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("candidate");
        let original = vector_candidate(&dir, 5);
        let marker_bytes = fs::read(dir.join(SEAL_FILE)).unwrap();
        for name in FILES {
            graph_peers(&dir, original.points, true);
            fs::remove_file(dir.join(name)).unwrap();
            assert!(seal_candidate(&dir).is_err());
            assert_eq!(fs::read(dir.join(SEAL_FILE)).unwrap(), marker_bytes);
        }
        graph_peers(&dir, original.points - 1, true);
        assert!(seal_candidate(&dir).is_err());
        assert_eq!(fs::read(dir.join(SEAL_FILE)).unwrap(), marker_bytes);
        assert_eq!(V4Store::open(&dir).unwrap().len(), original.points);
    }

    #[test]
    fn graph_marker_rejects_invalid_versions_and_peer_sets() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("candidate");
        vector_candidate(&dir, 5);
        graph_peers(&dir, 8, true);
        let marker = seal_candidate(&dir).unwrap();
        for version in [0, 3, 5, 12, 16, u32::MAX] {
            let mut invalid = marker.clone();
            invalid.version = version;
            write_marker(&dir.join(SEAL_FILE), &invalid).unwrap();
            assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
        }
        for name in FILES {
            let mut incomplete = marker.clone();
            incomplete.files.retain(|entry| entry.name != name);
            write_marker(&dir.join(SEAL_FILE), &incomplete).unwrap();
            assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
        }
        let mut duplicate = marker.clone();
        duplicate.files.push(marker.files.last().unwrap().clone());
        write_marker(&dir.join(SEAL_FILE), &duplicate).unwrap();
        assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
        let mut escaped = marker.clone();
        escaped.files.last_mut().unwrap().name = "../edgeprop.gdx".into();
        write_marker(&dir.join(SEAL_FILE), &escaped).unwrap();
        assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
        let mut oversized = marker;
        oversized.points = u32::MAX as usize + 1;
        write_marker(&dir.join(SEAL_FILE), &oversized).unwrap();
        assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
    }

    #[test]
    fn graph_marker_checks_peer_crc_and_parser_not_only_manifest_entries() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("candidate");
        vector_candidate(&dir, 5);
        graph_peers(&dir, 8, true);
        let marker = seal_candidate(&dir).unwrap();
        for name in FILES {
            let peer = dir.join(name);
            let original = fs::read(&peer).unwrap();
            let mut corrupted = original.clone();
            corrupted[0] ^= 1;
            fs::write(&peer, corrupted).unwrap();
            assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
            let mut rebound = marker.clone();
            *rebound
                .files
                .iter_mut()
                .find(|entry| entry.name == name)
                .unwrap() = file_entry(&dir, name).unwrap();
            write_marker(&dir.join(SEAL_FILE), &rebound).unwrap();
            assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
            fs::write(&peer, original).unwrap();
            write_marker(&dir.join(SEAL_FILE), &marker).unwrap();
        }
        graph_peers(&dir, 7, true);
        let mut wrong_nid_count = marker;
        for entry in &mut wrong_nid_count.files {
            if FILES.contains(&entry.name.as_str()) {
                *entry = file_entry(&dir, &entry.name).unwrap();
            }
        }
        write_marker(&dir.join(SEAL_FILE), &wrong_nid_count).unwrap();
        assert!(read_marker(&dir.join(SEAL_FILE)).is_err());
    }

    #[test]
    fn graph_marker_size_cap_precedes_payload_read() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join(SEAL_FILE);
        let file = fs::File::create(&marker).unwrap();
        file.set_len((super::super::MAX_MARKER_BYTES + 21) as u64)
            .unwrap();
        let error = read_marker(&marker).unwrap_err();
        assert!(error.to_string().contains("size cap"));
        let oversized = SealMarker {
            version: 11,
            points: 0,
            vector_dim: 1,
            base_lsn: 0,
            end_lsn: 0,
            files: vec![crate::seal::SealFile {
                name: "x".repeat(super::super::MAX_MARKER_BYTES),
                bytes: 0,
                crc: 0,
            }],
        };
        let absent = temp.path().join("unwritten.gdx");
        assert!(write_marker(&absent, &oversized).is_err());
        assert!(!absent.exists());
    }
}
