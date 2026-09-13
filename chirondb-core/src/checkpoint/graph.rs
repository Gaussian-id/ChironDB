//! Graph descriptors in the sole collection manifest (Rev 3.4 G1).
//!
//! These validate metadata, not the referenced graph artifacts. A publisher
//! must check those artifacts before installing the manifest. Db admits only
//! complete version-2/3 recovery authority; v1 remains immutable staging.

use std::{collections::HashSet, path::Path};

use serde::{Deserialize, Serialize};

use super::{SegmentsManifest, manifest_corruption};
use crate::{Result, graph::GraphEpoch};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    pub version: u32,
    pub epoch: GraphEpoch,
    /// Exclusive covered WAL prefix / next replay frame start. Versions 2/3 may
    /// retire it only with complete graph/control/vector/visibility authority.
    /// Run descriptors retain inclusive bounds, normally ending at cut - 1.
    pub graph_batch_watermark: u64,
    pub overlay_version: u64,
    pub base_segments: Vec<String>,
    /// Version 3 permits contiguous, lexically ID-ordered parts with exactly
    /// equal LSN bounds. All other overlaps (and all v1/v2 overlaps) reject.
    pub topology_deltas: Vec<GraphRunDescriptor>,
    pub edge_ledger: GraphRunManifest,
    pub edge_properties: GraphRunManifest,
    pub fragment_directory: FragmentDirectoryManifest,
    /// Stable file identity for directory references. Older absent-directory
    /// generations may omit it; a present directory must bind every source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_catalog: Option<GraphFragmentCatalog>,
    /// Versions 2/3 require the complete recovery catalog; version 1 remains
    /// immutable-artifact staging only and cannot carry this descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<GraphRunDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_overlay_generation: Option<u64>,
    /// Reserved until the G2 sketch comparison authorizes persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sketch: Option<GraphSketchDescriptor>,
}

/// An immutable artifact identifier, not a caller-supplied filesystem path.
/// The owning artifact family supplies its directory and filename. CRC is of
/// the complete logical plaintext file, including its checked format envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRunDescriptor {
    pub id: String,
    pub first_lsn: u64,
    pub last_lsn: u64,
    pub crc32: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphRunManifest {
    pub base: GraphRunDescriptor,
    pub runs: Vec<GraphRunDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFragmentCatalog {
    pub high_watermark: u64,
    pub bindings: Vec<GraphFragmentBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFragmentBinding {
    pub fragment_id: u64,
    pub source: GraphFragmentSource,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphFragmentSource {
    Base { id: String },
    Delta { id: String },
}

/// Absence is explicit: a missing or misspelled directory descriptor cannot
/// silently select the all-fragments fallback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum FragmentDirectoryManifest {
    Absent,
    Present {
        base: GraphRunDescriptor,
        overlays: Vec<GraphRunDescriptor>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSketchDescriptor {
    pub generation: u64,
    pub built_at_lsn: u64,
}

impl GraphManifest {
    pub(super) fn validate(&self, path: &Path, manifest: &SegmentsManifest) -> Result<()> {
        let corrupt = |message| manifest_corruption(path, message);
        if !matches!(
            (self.version, self.recovery.is_some()),
            (1, false) | (2 | 3, true)
        ) {
            return Err(corrupt("unsupported graph manifest version"));
        }
        if GraphEpoch::from_raw(self.epoch.raw()).is_none()
            || manifest.generation == 0
            || self.overlay_version == 0
        {
            return Err(corrupt("zero graph epoch, generation, or overlay version"));
        }
        if self.sketch.is_some() {
            return Err(corrupt("persisted graph sketches are not yet authorized"));
        }
        if let Some(recovery) = &self.recovery {
            self.validate_runs(path, None, std::slice::from_ref(recovery), false)?;
            if recovery.first_lsn != 0 || recovery.last_lsn != self.graph_batch_watermark {
                return Err(corrupt(
                    "recovery catalog must cover the complete graph watermark",
                ));
            }
        }
        let installed = manifest
            .segments
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let mut bases = HashSet::new();
        for segment in &self.base_segments {
            if !valid_id(segment) || !installed.contains(segment.as_str()) || !bases.insert(segment)
            {
                return Err(corrupt(
                    "invalid, duplicate, or uninstalled graph base segment",
                ));
            }
        }
        // Overlay filenames use the same portable identifier vocabulary.
        if manifest.segments.iter().any(|id| !valid_id(id)) {
            return Err(corrupt(
                "graph generation contains a non-portable segment id",
            ));
        }
        match self.catalog_overlay_generation {
            Some(generation) if generation == 0 || generation > manifest.generation => {
                return Err(corrupt("invalid graph catalog-overlay generation"));
            }
            None if bases.len() != installed.len() => {
                return Err(corrupt(
                    "legacy graph segments require a catalog-overlay generation",
                ));
            }
            _ => {}
        }
        self.validate_runs(path, None, &self.topology_deltas, self.version == 3)?;
        self.validate_runs(
            path,
            Some(&self.edge_ledger.base),
            &self.edge_ledger.runs,
            false,
        )?;
        self.validate_runs(
            path,
            Some(&self.edge_properties.base),
            &self.edge_properties.runs,
            false,
        )?;
        if let FragmentDirectoryManifest::Present { base, overlays } = &self.fragment_directory {
            self.validate_runs(path, Some(base), overlays, false)?;
            if self.fragment_catalog.is_none() {
                return Err(corrupt("present fragment directory requires file bindings"));
            }
        }
        if let Some(catalog) = &self.fragment_catalog {
            let expected: HashSet<_> = self
                .base_segments
                .iter()
                .map(|id| GraphFragmentSource::Base { id: id.clone() })
                .chain(
                    self.topology_deltas
                        .iter()
                        .map(|run| GraphFragmentSource::Delta { id: run.id.clone() }),
                )
                .collect();
            let mut sources = HashSet::new();
            let mut last = 0;
            for binding in &catalog.bindings {
                if binding.fragment_id <= last
                    || binding.fragment_id > catalog.high_watermark
                    || !expected.contains(&binding.source)
                    || !sources.insert(binding.source.clone())
                {
                    return Err(corrupt(
                        "invalid, duplicate or uninstalled fragment binding",
                    ));
                }
                last = binding.fragment_id;
            }
            if sources != expected {
                return Err(corrupt("fragment catalog does not cover all graph sources"));
            }
        }
        Ok(())
    }

    fn validate_runs(
        &self,
        path: &Path,
        base: Option<&GraphRunDescriptor>,
        runs: &[GraphRunDescriptor],
        topology_cohorts: bool,
    ) -> Result<()> {
        let mut ids = HashSet::new();
        let mut previous: Option<&GraphRunDescriptor> = None;
        for run in base.into_iter().chain(runs) {
            if !valid_id(&run.id) || !ids.insert(&run.id) {
                return Err(manifest_corruption(
                    path,
                    "invalid or duplicate graph artifact id",
                ));
            }
            if run.first_lsn > run.last_lsn
                || run.last_lsn > self.graph_batch_watermark
                || previous.is_some_and(|prior| {
                    run.first_lsn <= prior.last_lsn
                        && !(topology_cohorts
                            && run.first_lsn == prior.first_lsn
                            && run.last_lsn == prior.last_lsn
                            && prior.id < run.id)
                })
            {
                return Err(manifest_corruption(
                    path,
                    "graph artifact LSN ranges are reversed, overlapping, unordered, or beyond watermark",
                ));
            }
            previous = Some(run);
        }
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf, process::Command};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use roaring::RoaringTreemap;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        Db,
        checkpoint::{
            MAX_MANIFEST_BYTES, SEGMENTS_MANIFEST_FILE, read_segments_manifest,
            write_segments_manifest,
        },
        encryption::{self, FileType},
        graph::EdgeId,
        ordinal::SegmentOrdinalSet,
        overlay::{self, OverlayOpenMode, OverlayStore},
    };

    fn run(id: &str, first_lsn: u64, last_lsn: u64) -> GraphRunDescriptor {
        GraphRunDescriptor {
            id: id.into(),
            first_lsn,
            last_lsn,
            crc32: 17,
        }
    }

    // Metadata fixture only; it must never be admitted as a live Db because
    // this slice does not publish the referenced graph files.
    fn manifest() -> SegmentsManifest {
        SegmentsManifest {
            generation: 7,
            segments: vec!["sg-1".into(), "sg-legacy".into()],
            graph: Some(GraphManifest {
                version: 1,
                epoch: GraphEpoch::INITIAL,
                graph_batch_watermark: 30,
                overlay_version: 1,
                base_segments: vec!["sg-1".into()],
                topology_deltas: vec![run("delta-1", 11, 20), run("delta-2", 21, 30)],
                edge_ledger: GraphRunManifest {
                    base: run("base", 0, 10),
                    runs: vec![run("delta-1", 11, 20), run("delta-2", 21, 30)],
                },
                edge_properties: GraphRunManifest {
                    base: run("base", 0, 10),
                    runs: vec![run("delta-1", 11, 20)],
                },
                fragment_directory: FragmentDirectoryManifest::Absent,
                fragment_catalog: None,
                recovery: None,
                catalog_overlay_generation: Some(7),
                sketch: None,
            }),
        }
    }

    fn selected_overlay(
        dir: &Path,
        manifest: &SegmentsManifest,
    ) -> std::sync::Arc<overlay::OverlaySet> {
        overlay::open_manifest_version(
            dir,
            manifest.graph.as_ref().unwrap().overlay_version,
            manifest.generation,
            &manifest.segments.iter().cloned().collect(),
        )
        .unwrap()
    }

    #[test]
    fn v3_topology_cohorts_preserve_strict_other_families_and_old_versions() {
        let temp = TempDir::new().unwrap();
        let mut valid = manifest();
        let graph = valid.graph.as_mut().unwrap();
        graph.version = 2;
        graph.recovery = Some(run("catalog", 0, 30));
        write_segments_manifest(temp.path(), &valid).unwrap();
        assert_eq!(
            read_segments_manifest(temp.path()).unwrap(),
            Some(valid.clone())
        );
        let graph = valid.graph.as_mut().unwrap();
        graph.version = 3;
        graph.topology_deltas = vec![
            run("part-a", 11, 20),
            run("part-b", 11, 20),
            run("next", 21, 30),
        ];
        write_segments_manifest(temp.path(), &valid).unwrap();
        assert_eq!(
            read_segments_manifest(temp.path()).unwrap(),
            Some(valid.clone())
        );
        let before = fs::read(temp.path().join(SEGMENTS_MANIFEST_FILE)).unwrap();
        let original = serde_json::to_value(valid).unwrap();
        for (pointer, value) in [
            ("/graph/version", json!(2)),
            ("/graph/version", json!(4)),
            ("/graph/recovery", json!(null)),
            ("/graph/topology_deltas/1/first_lsn", json!(12)),
            ("/graph/topology_deltas/1/last_lsn", json!(19)),
            ("/graph/topology_deltas/1/last_lsn", json!(21)),
            ("/graph/topology_deltas/1/id", json!("part-a")),
            ("/graph/topology_deltas/1/id", json!("part-0")),
            ("/graph/topology_deltas/2/last_lsn", json!(31)),
            (
                "/graph/topology_deltas",
                json!([run("a", 11, 20), run("b", 21, 30), run("c", 11, 20)]),
            ),
            (
                "/graph/edge_ledger/runs",
                json!([run("a", 11, 20), run("b", 11, 20)]),
            ),
            (
                "/graph/edge_properties/runs",
                json!([run("a", 11, 20), run("b", 11, 20)]),
            ),
            (
                "/graph/fragment_directory",
                json!({"state":"present", "base":run("base", 0, 10), "overlays":[run("a", 11, 20), run("b", 11, 20)]}),
            ),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            let invalid = serde_json::from_value(invalid).unwrap();
            assert!(
                write_segments_manifest(temp.path(), &invalid).is_err(),
                "{pointer}"
            );
            assert_eq!(
                fs::read(temp.path().join(SEGMENTS_MANIFEST_FILE)).unwrap(),
                before
            );
        }
    }

    #[test]
    fn graph_manifest_and_overlay_roundtrip_plaintext_and_encrypted() {
        const MODE: &str = "CHIRONDB_GRAPH_MANIFEST_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_MANIFEST_TEST_ROOT";
        const TEST: &str = "checkpoint::graph::tests::graph_manifest_and_overlay_roundtrip_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = TempDir::new().unwrap();
                let status = Command::new(env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(MODE, mode)
                    .env(ROOT, root.path())
                    .status()
                    .unwrap();
                assert!(status.success(), "{mode} graph manifest checks failed");
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        let encrypted = mode == "encrypted";
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(&keyring, json!({
                "version": 1,
                "active_key_id": "graph-manifest-test",
                "keys": [{"id": "graph-manifest-test", "key_base64": STANDARD.encode([73; 32])}],
            }).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let dir = root.join("docs");
        let mut first = manifest();
        let installed = first.segments.iter().cloned().collect();
        let mut points = SegmentOrdinalSet::new();
        points.insert("sg-1", 2);
        let mut store = OverlayStore::open(
            &dir,
            first.generation,
            &installed,
            points,
            OverlayOpenMode::Recover,
        )
        .unwrap();
        let edge = EdgeId::from_parts(1, 19).unwrap();
        store
            .replace_edges(&RoaringTreemap::from_iter([edge.raw()]))
            .unwrap();
        store.publish_pending().unwrap();
        first.graph.as_mut().unwrap().overlay_version = store.current().version();
        write_segments_manifest(&dir, &first).unwrap();
        let recovered = read_segments_manifest(&dir).unwrap().unwrap();
        assert_eq!(recovered, first);
        let pinned = selected_overlay(&dir, &recovered);
        assert!(pinned.point_tombstones().contains("sg-1", 2));
        assert!(pinned.edge_tombstones().contains(edge.raw()));

        // A candidate's CURRENT can lead the installed manifest. Exact reads
        // must preserve the old edge tombstone instead of resetting it.
        store
            .replace_generation(8, SegmentOrdinalSet::new())
            .unwrap();
        store.publish_pending().unwrap();
        assert_eq!(*selected_overlay(&dir, &first), *pinned);
        let mut next = first.clone();
        next.generation = 8;
        next.graph.as_mut().unwrap().overlay_version = store.current().version();
        write_segments_manifest(&dir, &next).unwrap();
        assert_eq!(read_segments_manifest(&dir).unwrap(), Some(next.clone()));
        assert!(selected_overlay(&dir, &next).edge_tombstones().is_empty());
        assert!(pinned.edge_tombstones().contains(edge.raw()));

        // Missing or malformed CURRENT is irrelevant to a manifest-pinned
        // read. The selected bundle, however, must remain intact.
        let current_path = dir.join("overlays/CURRENT");
        fs::remove_file(&current_path).unwrap();
        assert_eq!(*selected_overlay(&dir, &first), *pinned);
        encryption::atomic_write_persistent(&current_path, FileType::Metadata, b"not-a-version\n")
            .unwrap();
        assert_eq!(*selected_overlay(&dir, &first), *pinned);
        let edge_path = dir.join(format!("overlays/{:020}/edges.roar", pinned.version()));
        let mut bytes = fs::read(&edge_path).unwrap();
        assert_eq!(bytes.starts_with(encryption::MAGIC), encrypted);
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&edge_path, bytes).unwrap();
        assert!(
            overlay::open_manifest_version(&dir, pinned.version(), first.generation, &installed)
                .is_err()
        );
        let manifest_path = dir.join(SEGMENTS_MANIFEST_FILE);
        let mut bytes = fs::read(&manifest_path).unwrap();
        assert_eq!(bytes.starts_with(encryption::MAGIC), encrypted);
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&manifest_path, bytes).unwrap();
        assert!(read_segments_manifest(&dir).is_err());
    }

    #[test]
    fn invalid_graph_descriptors_do_not_replace_installed_manifest() {
        let temp = TempDir::new().unwrap();
        let valid = manifest();
        write_segments_manifest(temp.path(), &valid).unwrap();
        let before = fs::read(temp.path().join(SEGMENTS_MANIFEST_FILE)).unwrap();
        let original = serde_json::to_value(&valid).unwrap();
        let corrupt_dir = temp.path().join("corrupt");
        fs::create_dir(&corrupt_dir).unwrap();
        let cases = [
            ("/generation", json!(0)),
            ("/graph/version", json!(2)),
            ("/graph/epoch", json!(0)),
            ("/graph/overlay_version", json!(0)),
            ("/graph/graph_batch_watermark", json!(19)),
            ("/graph/base_segments", json!(["sg-1", "sg-1"])),
            ("/graph/base_segments", json!(["sg-missing"])),
            ("/graph/catalog_overlay_generation", json!(null)),
            ("/graph/catalog_overlay_generation", json!(0)),
            ("/graph/catalog_overlay_generation", json!(8)),
            ("/graph/topology_deltas/1/id", json!("delta-1")),
            ("/graph/topology_deltas/0/id", json!("../escape")),
            ("/graph/topology_deltas/0/id", json!("C:\\escape")),
            ("/graph/topology_deltas/0/id", json!("x".repeat(256))),
            ("/graph/topology_deltas/0/last_lsn", json!(9)),
            ("/graph/topology_deltas/1/first_lsn", json!(20)),
            ("/graph/edge_ledger/runs/0/first_lsn", json!(10)),
            ("/graph/edge_properties/base/last_lsn", json!(31)),
            (
                "/graph/fragment_directory",
                json!({"state":"present", "base":run("base", 0, 10), "overlays":[run("overlay", 9, 15)]}),
            ),
        ];
        for (pointer, value) in cases {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            let invalid: SegmentsManifest = serde_json::from_value(invalid).unwrap();
            assert!(
                write_segments_manifest(temp.path(), &invalid).is_err(),
                "{pointer}"
            );
            assert_eq!(
                fs::read(temp.path().join(SEGMENTS_MANIFEST_FILE)).unwrap(),
                before
            );
            fs::write(
                corrupt_dir.join(SEGMENTS_MANIFEST_FILE),
                serde_json::to_vec(&invalid).unwrap(),
            )
            .unwrap();
            assert!(read_segments_manifest(&corrupt_dir).is_err(), "{pointer}");
        }
        let mut sketched = valid.clone();
        sketched.graph.as_mut().unwrap().sketch = Some(GraphSketchDescriptor {
            generation: 7,
            built_at_lsn: 30,
        });
        assert!(write_segments_manifest(temp.path(), &sketched).is_err());
        let mut downgrade = valid;
        downgrade.graph = None;
        assert!(write_segments_manifest(temp.path(), &downgrade).is_err());
        assert_eq!(
            fs::read(temp.path().join(SEGMENTS_MANIFEST_FILE)).unwrap(),
            before
        );
    }

    #[test]
    fn manifest_json_is_strict_but_legacy_vector_manifest_is_unchanged() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(SEGMENTS_MANIFEST_FILE);
        let legacy = b"{\"generation\":0,\"segments\":[\"sg-1\"]}\n";
        fs::write(&path, legacy).unwrap();
        let recovered = read_segments_manifest(temp.path()).unwrap().unwrap();
        assert!(recovered.graph.is_none());
        write_segments_manifest(temp.path(), &recovered).unwrap();
        assert_eq!(fs::read(&path).unwrap(), legacy);
        let original = serde_json::to_value(manifest()).unwrap();
        let mut missing_directory = original.clone();
        missing_directory["graph"]
            .as_object_mut()
            .unwrap()
            .remove("fragment_directory");
        let mut unknown = original.clone();
        unknown["graph"]["topology_deltas"][0]["unknown"] = json!(true);
        let mut unknown_root = original.clone();
        unknown_root["future_graph"] = json!({});
        for value in [missing_directory, unknown, unknown_root] {
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(read_segments_manifest(temp.path()).is_err());
        }
        for bytes in [
            br#"{"generation":7,"segments":[],"graph":{},"graph":null}"#.as_slice(),
            br#"{"generation":7,"segments":[],"graph":{}}"#.as_slice(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(read_segments_manifest(temp.path()).is_err());
        }
        let mut complete = manifest();
        complete.graph.as_mut().unwrap().base_segments = complete.segments.clone();
        complete.graph.as_mut().unwrap().catalog_overlay_generation = None;
        complete.graph.as_mut().unwrap().fragment_directory = FragmentDirectoryManifest::Present {
            base: run("base", 0, 10),
            overlays: vec![run("overlay", 11, 30)],
        };
        let graph = complete.graph.as_mut().unwrap();
        let sources = graph
            .base_segments
            .iter()
            .map(|id| GraphFragmentSource::Base { id: id.clone() })
            .chain(
                graph
                    .topology_deltas
                    .iter()
                    .map(|run| GraphFragmentSource::Delta { id: run.id.clone() }),
            );
        let bindings: Vec<_> = sources
            .enumerate()
            .map(|(i, source)| GraphFragmentBinding {
                fragment_id: i as u64 + 1,
                source,
            })
            .collect();
        graph.fragment_catalog = Some(GraphFragmentCatalog {
            high_watermark: bindings.len() as u64,
            bindings,
        });
        write_segments_manifest(temp.path(), &complete).unwrap();
        assert_eq!(
            read_segments_manifest(temp.path()).unwrap(),
            Some(complete.clone())
        );

        let original = serde_json::to_value(&complete).unwrap();
        for (pointer, replacement) in [
            ("/graph/fragment_catalog", json!(null)),
            ("/graph/fragment_catalog/high_watermark", json!(1)),
            ("/graph/fragment_catalog/bindings", json!([])),
            ("/graph/fragment_catalog/bindings/0/fragment_id", json!(0)),
            ("/graph/fragment_catalog/bindings/1/fragment_id", json!(1)),
            (
                "/graph/fragment_catalog/bindings/0/source/id",
                json!("uninstalled"),
            ),
            (
                "/graph/fragment_catalog/bindings/0/source/kind",
                json!("unknown"),
            ),
            (
                "/graph/fragment_catalog/bindings/1/source/id",
                json!("sg-1"),
            ),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(read_segments_manifest(temp.path()).is_err(), "{pointer}");
        }
    }

    #[test]
    fn manifest_size_caps_fail_before_payload_decode_or_publication() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join(SEGMENTS_MANIFEST_FILE);
        let file = fs::File::create(&path).unwrap();
        file.set_len((MAX_MANIFEST_BYTES + 1) as u64).unwrap();
        assert!(
            read_segments_manifest(temp.path())
                .unwrap_err()
                .to_string()
                .contains("size cap")
        );
        let unwritten = temp.path().join("unwritten");
        let oversized = SegmentsManifest {
            generation: 0,
            segments: vec!["x".repeat(MAX_MANIFEST_BYTES)],
            graph: None,
        };
        assert!(
            write_segments_manifest(&unwritten, &oversized)
                .unwrap_err()
                .to_string()
                .contains("size cap")
        );
        assert!(!unwritten.join(SEGMENTS_MANIFEST_FILE).exists());
    }

    #[test]
    fn vector_recovery_rejects_graph_manifest_before_segment_cleanup() {
        let temp = TempDir::new().unwrap();
        let db = Db::open(temp.path()).unwrap();
        db.create_collection(
            serde_json::from_value(json!({"name":"docs", "vector_dim":4})).unwrap(),
        )
        .unwrap();
        drop(db);
        let dir = temp.path().join("collections/docs");
        let pending = dir.join("searchers/sg-unpublished");
        fs::create_dir_all(&pending).unwrap();
        fs::write(pending.join("keep"), b"unpublished graph state").unwrap();
        let checkpoint = fs::read(dir.join(crate::checkpoint::CHECKPOINT_FILE)).unwrap();
        write_segments_manifest(&dir, &manifest()).unwrap();
        let before = fs::read(dir.join(SEGMENTS_MANIFEST_FILE)).unwrap();
        let error = match Db::open(temp.path()) {
            Ok(_) => panic!("vector recovery admitted graph manifest"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("graph-aware collection recovery"),
            "{error}"
        );
        assert_eq!(
            fs::read(pending.join("keep")).unwrap(),
            b"unpublished graph state"
        );
        assert_eq!(fs::read(dir.join(SEGMENTS_MANIFEST_FILE)).unwrap(), before);
        assert_eq!(
            fs::read(dir.join(crate::checkpoint::CHECKPOINT_FILE)).unwrap(),
            checkpoint
        );
    }
}
