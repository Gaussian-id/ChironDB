use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    encryption::{FileType, PersistentFile, atomic_write_persistent},
    error::{GaussError, Result},
    model::CollectionConfig,
};

const SNAPSHOT_MAGIC: &[u8; 8] = b"GAUSSSN1";
const GRAPH_SNAPSHOT_MAGIC: &[u8; 8] = b"GAUSSSN2";
const HEADER_LEN: usize = 20;
pub const SNAPSHOT_FILE: &str = "snapshot.gdx";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMarker {
    #[serde(default = "legacy_version", skip_serializing_if = "is_legacy_version")]
    pub version: u32,
    pub created_unix_ms: u64,
    pub collections: Vec<SnapshotCollection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotCollection {
    pub collection: String,
    pub schema_epoch: u64,
    pub wal_lsn: u64,
    pub points: usize,
    pub segment_id: Option<String>,
    pub config_crc: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<SnapshotGraph>,
}

/// Bind the selected graph/vector generation and the lifecycle after WAL tail
/// replay. The manifest remains the sole authority for immutable peer files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotGraph {
    pub epoch: crate::graph::GraphEpoch,
    pub enabled: bool,
    pub manifest_sha256: Option<[u8; 32]>,
}

impl SnapshotGraph {
    pub(crate) fn capture(
        epoch: crate::graph::GraphEpoch,
        enabled: bool,
        manifest: Option<&crate::checkpoint::SegmentsManifest>,
    ) -> Result<Self> {
        crate::graph_lifecycle::GraphLifecycleState::from_checkpoint(epoch, enabled)?;
        Ok(Self {
            epoch,
            enabled,
            manifest_sha256: manifest
                .map(|manifest| {
                    serde_json::to_vec(manifest).map(|bytes| Sha256::digest(bytes).into())
                })
                .transpose()?,
        })
    }
}

impl SnapshotMarker {
    pub fn new(collections: Vec<SnapshotCollection>) -> Self {
        Self {
            version: if collections
                .iter()
                .any(|collection| collection.graph.is_some())
            {
                2
            } else {
                1
            },
            created_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            collections,
        }
    }

    fn magic(&self) -> Result<&'static [u8; 8]> {
        let has_graph = self
            .collections
            .iter()
            .any(|collection| collection.graph.is_some());
        match (self.version, has_graph) {
            (1, false) => Ok(SNAPSHOT_MAGIC),
            (2, true) => {
                for graph in self
                    .collections
                    .iter()
                    .filter_map(|collection| collection.graph.as_ref())
                {
                    crate::graph_lifecycle::GraphLifecycleState::from_checkpoint(
                        graph.epoch,
                        graph.enabled,
                    )?;
                }
                Ok(GRAPH_SNAPSHOT_MAGIC)
            }
            _ => Err(GaussError::InvalidRequest(
                "snapshot version disagrees with graph binding".into(),
            )),
        }
    }
}

impl SnapshotCollection {
    pub fn new(
        config: &CollectionConfig,
        schema_epoch: u64,
        wal_lsn: u64,
        points: usize,
        segment_id: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            collection: config.name.clone(),
            schema_epoch,
            wal_lsn,
            points,
            segment_id,
            config_crc: checksum(&serde_json::to_vec(config)?),
            graph: None,
        })
    }
}

pub fn snapshot_marker_path(root: &Path) -> PathBuf {
    root.join(SNAPSHOT_FILE)
}

pub fn write_snapshot_marker(root: &Path, marker: &SnapshotMarker) -> Result<()> {
    let magic = marker.magic()?;
    fs::create_dir_all(root)?;
    let path = snapshot_marker_path(root);
    let payload = serde_json::to_vec(marker)?;
    let crc = checksum(&payload);
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&payload);
    atomic_write_persistent(&path, FileType::Snapshot, &bytes)
}

pub fn read_snapshot_marker(root: &Path) -> Result<Option<SnapshotMarker>> {
    let path = snapshot_marker_path(root);
    if !path.exists() {
        return Ok(None);
    }

    let file = PersistentFile::open(&path)?;
    if file.len() < HEADER_LEN {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "snapshot marker shorter than header".to_string(),
        });
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != SNAPSHOT_MAGIC && &header[0..8] != GRAPH_SNAPSHOT_MAGIC {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "bad snapshot marker magic".to_string(),
        });
    }

    let len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("snapshot marker length"),
    ))
    .map_err(|_| GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: "snapshot marker length exceeds usize".to_string(),
    })?;
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("snapshot marker crc"));
    if HEADER_LEN.checked_add(len) != Some(file.len()) {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "snapshot marker length mismatch".to_string(),
        });
    }

    let actual_crc = file.crc32(HEADER_LEN..file.len())?;
    if actual_crc != expected_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "snapshot marker crc mismatch".to_string(),
        });
    }

    let marker: SnapshotMarker =
        serde_json::from_reader(file.reader_at(HEADER_LEN)?.take(len as u64))?;
    if &header[0..8] != marker.magic()? {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "snapshot magic disagrees with payload version".into(),
        });
    }
    Ok(Some(marker))
}

fn legacy_version() -> u32 {
    1
}

fn is_legacy_version(version: &u32) -> bool {
    *version == 1
}

fn checksum(payload: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(payload);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write};

    use tempfile::TempDir;

    use crate::{DistanceMetric, snapshot, snapshot::SnapshotCollection};

    #[test]
    fn writes_and_reads_snapshot_marker() {
        let temp = TempDir::new().unwrap();
        let config = crate::CollectionConfig {
            name: "docs".to_string(),
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            shards: 1,
            replicas: 1,
            quantization: None,
            payload_schema: Default::default(),
            named_vector_dims: Default::default(),
            hnsw_m: None,
            hnsw_ef_construction: None,
            hnsw_ef_search: None,
            recall_sla: None,
            index_kind: None,
            streamer_max_bytes: 0,
        };
        let marker = snapshot::SnapshotMarker::new(vec![
            SnapshotCollection::new(&config, 2, 128, 7, Some("sg-00000001".to_string())).unwrap(),
        ]);

        snapshot::write_snapshot_marker(temp.path(), &marker).unwrap();
        assert_eq!(marker.version, 1);
        let value = serde_json::to_value(&marker).unwrap();
        assert!(value.get("version").is_none());
        assert!(value["collections"][0].get("graph").is_none());
        assert!(
            std::fs::read(snapshot::snapshot_marker_path(temp.path()))
                .unwrap()
                .starts_with(b"GAUSSSN1")
        );
        assert_eq!(
            snapshot::read_snapshot_marker(temp.path()).unwrap(),
            Some(marker)
        );
    }

    #[test]
    fn rejects_corrupt_snapshot_marker() {
        let temp = TempDir::new().unwrap();
        snapshot::write_snapshot_marker(temp.path(), &snapshot::SnapshotMarker::new(Vec::new()))
            .unwrap();

        let mut file = OpenOptions::new()
            .write(true)
            .open(snapshot::snapshot_marker_path(temp.path()))
            .unwrap();
        file.write_all(b"x").unwrap();

        let error = snapshot::read_snapshot_marker(temp.path()).unwrap_err();
        assert!(error.to_string().contains("bad snapshot marker magic"));
    }

    #[test]
    fn graph_marker_roundtrip_and_version_binding_refuse_downgrade() {
        use super::*;
        let temp = TempDir::new().unwrap();
        let marked = SnapshotCollection {
            collection: "docs".into(),
            schema_epoch: 1,
            wal_lsn: 20,
            points: 2,
            segment_id: None,
            config_crc: 7,
            graph: Some(SnapshotGraph {
                epoch: crate::graph::GraphEpoch::INITIAL,
                enabled: true,
                manifest_sha256: Some([3; 32]),
            }),
        };
        let marker = SnapshotMarker::new(vec![marked]);
        assert_eq!(marker.version, 2);
        write_snapshot_marker(temp.path(), &marker).unwrap();
        assert_eq!(
            read_snapshot_marker(temp.path()).unwrap(),
            Some(marker.clone())
        );
        let path = snapshot_marker_path(temp.path());
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.starts_with(GRAPH_SNAPSHOT_MAGIC));
        assert!(
            !bytes.starts_with(SNAPSHOT_MAGIC),
            "legacy readers must reject graph snapshots"
        );
        for version in [0, 1, 3] {
            let mut invalid = marker.clone();
            invalid.version = version;
            assert!(write_snapshot_marker(temp.path(), &invalid).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let mut invalid = marker.clone();
        invalid.collections[0].graph = None;
        assert!(write_snapshot_marker(temp.path(), &invalid).is_err());
        invalid = marker;
        invalid.collections[0].graph.as_mut().unwrap().enabled = false;
        assert!(write_snapshot_marker(temp.path(), &invalid).is_err());
        let mut wrong_magic = bytes.clone();
        wrong_magic[..8].copy_from_slice(SNAPSHOT_MAGIC);
        fs::write(&path, wrong_magic).unwrap();
        assert!(
            read_snapshot_marker(temp.path())
                .unwrap_err()
                .to_string()
                .contains("magic disagrees")
        );
        let mut overflowing = bytes;
        overflowing[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        fs::write(&path, overflowing).unwrap();
        assert!(read_snapshot_marker(temp.path()).is_err());
    }

    #[test]
    fn graph_snapshot_digest_binds_the_complete_typed_manifest() {
        use super::*;
        let mut manifest = crate::checkpoint::SegmentsManifest {
            generation: 1,
            segments: vec!["sg-1".into()],
            graph: None,
        };
        let epoch = crate::graph::GraphEpoch::INITIAL;
        let before = SnapshotGraph::capture(epoch, true, Some(&manifest)).unwrap();
        let decoded =
            serde_json::from_str(&serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
        assert_eq!(
            before,
            SnapshotGraph::capture(epoch, true, Some(&decoded)).unwrap()
        );
        manifest.segments.push("sg-2".into());
        assert_ne!(
            before,
            SnapshotGraph::capture(epoch, true, Some(&manifest)).unwrap()
        );
        assert_ne!(before, SnapshotGraph::capture(epoch, true, None).unwrap());
        assert!(SnapshotGraph::capture(epoch, false, None).is_err());
    }
}
