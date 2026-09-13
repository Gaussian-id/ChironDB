use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};

use crate::{
    encryption::{FileType, PersistentFile, atomic_write_persistent},
    error::{GaussError, Result},
    model::CollectionConfig,
};

const CHECKPOINT_MAGIC: &[u8; 8] = b"GAUSSCP1";
const HEADER_LEN: usize = 20;
pub const CHECKPOINT_FILE: &str = "checkpoint.gdx";
pub const SEGMENTS_MANIFEST_FILE: &str = "segments.json";
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

mod graph;
pub use graph::{
    FragmentDirectoryManifest, GraphFragmentBinding, GraphFragmentCatalog, GraphFragmentSource,
    GraphManifest, GraphRunDescriptor, GraphRunManifest, GraphSketchDescriptor,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentsManifest {
    pub generation: u64,
    pub segments: Vec<String>,
    /// Absent in legacy vector-only generations. Never discard this field
    /// while installing a new vector generation over a graph generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<GraphManifest>,
}

impl SegmentsManifest {
    pub(crate) fn validate(&self, collection_dir: &Path) -> Result<()> {
        validate_segments_manifest(&collection_dir.join(SEGMENTS_MANIFEST_FILE), self)
    }

    /// Temporary admission boundary until sealed graph recovery is integrated.
    /// Call before recovery cleanup or any vector-only generation mutation.
    pub(crate) fn require_vector_only(&self, collection_dir: &Path) -> Result<()> {
        if self.graph.is_some() {
            return Err(manifest_corruption(
                &collection_dir.join(SEGMENTS_MANIFEST_FILE),
                "graph manifest requires graph-aware collection recovery",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollectionCheckpoint {
    pub collection: String,
    pub schema_epoch: u64,
    pub last_applied_lsn: u64,
    pub points: usize,
    pub segment_id: Option<String>,
    /// Immutable segments installed for this checkpoint. `None` means a
    /// legacy checkpoint whose single segment is carried by `segment_id`.
    #[serde(default)]
    pub segments: Option<Vec<String>>,
    /// WAL prefix already represented by installed immutable segments.
    #[serde(default)]
    pub wal_watermark: u64,
    pub schema_crc: u32,
}

impl CollectionCheckpoint {
    pub fn new(
        config: &CollectionConfig,
        schema_epoch: u64,
        last_applied_lsn: u64,
        points: usize,
        segment_id: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            collection: config.name.clone(),
            schema_epoch,
            last_applied_lsn,
            points,
            segment_id,
            segments: None,
            wal_watermark: 0,
            schema_crc: schema_crc(config)?,
        })
    }
}

pub fn checkpoint_path(collection_dir: &Path) -> PathBuf {
    collection_dir.join(CHECKPOINT_FILE)
}

pub fn write_checkpoint(collection_dir: &Path, checkpoint: &CollectionCheckpoint) -> Result<()> {
    fs::create_dir_all(collection_dir)?;
    let path = checkpoint_path(collection_dir);
    let payload = serde_json::to_vec(checkpoint)?;
    let crc = checksum(&payload);
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&payload);
    atomic_write_persistent(&path, FileType::Metadata, &bytes)
}

pub fn read_checkpoint(collection_dir: &Path) -> Result<Option<CollectionCheckpoint>> {
    let path = checkpoint_path(collection_dir);
    if !path.exists() {
        return Ok(None);
    }

    let file = PersistentFile::open(&path)?;
    if file.len() < HEADER_LEN {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "checkpoint shorter than header".to_string(),
        });
    }
    let header = file.read_range(0..HEADER_LEN)?;
    if &header[0..8] != CHECKPOINT_MAGIC {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "bad checkpoint magic".to_string(),
        });
    }

    let len = usize::try_from(u64::from_le_bytes(
        header[8..16].try_into().expect("checkpoint length"),
    ))
    .map_err(|_| GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: "checkpoint length exceeds usize".to_string(),
    })?;
    let expected_crc = u32::from_le_bytes(header[16..20].try_into().expect("checkpoint crc"));
    if file.len() != HEADER_LEN + len {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "checkpoint length mismatch".to_string(),
        });
    }

    let actual_crc = file.crc32(HEADER_LEN..file.len())?;
    if actual_crc != expected_crc {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "checkpoint crc mismatch".to_string(),
        });
    }

    let checkpoint = serde_json::from_reader::<_, CollectionCheckpoint>(
        file.reader_at(HEADER_LEN)?.take(len as u64),
    )?;
    if collection_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|collection| collection != checkpoint.collection)
    {
        return Err(GaussError::SegmentCorruption {
            path: path.display().to_string(),
            message: "checkpoint collection mismatch".to_string(),
        });
    }
    Ok(Some(checkpoint))
}

pub fn read_segments_manifest(collection_dir: &Path) -> Result<Option<SegmentsManifest>> {
    let path = collection_dir.join(SEGMENTS_MANIFEST_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let file = PersistentFile::open(&path)?;
    if file.len() > MAX_MANIFEST_BYTES {
        return Err(manifest_corruption(
            &path,
            "segments manifest exceeds size cap",
        ));
    }
    let manifest: SegmentsManifest =
        serde_json::from_reader(file.reader_at(0)?).map_err(|error| {
            manifest_corruption(&path, &format!("invalid segments manifest: {error}"))
        })?;
    manifest.validate(collection_dir)?;
    Ok(Some(manifest))
}

pub fn write_segments_manifest(collection_dir: &Path, manifest: &SegmentsManifest) -> Result<()> {
    fs::create_dir_all(collection_dir)?;
    let path = collection_dir.join(SEGMENTS_MANIFEST_FILE);
    manifest.validate(collection_dir)?;
    let mut bytes = serde_json::to_vec(manifest)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(manifest_corruption(
            &path,
            "segments manifest exceeds size cap",
        ));
    }
    // The existing writer is also used by vector compaction/sealing. It must
    // not silently erase a graph descriptor, even if its caller missed the
    // recovery admission check. Graph retirement needs its own atomic path.
    if manifest.graph.is_none()
        && let Some(previous) = read_segments_manifest(collection_dir)?
    {
        previous.require_vector_only(collection_dir)?;
    }
    atomic_write_persistent(&path, FileType::Metadata, &bytes)
}

fn validate_segments_manifest(path: &Path, manifest: &SegmentsManifest) -> Result<()> {
    let mut unique = std::collections::HashSet::with_capacity(manifest.segments.len());
    for segment in &manifest.segments {
        if segment.is_empty()
            || segment.starts_with('.')
            || Path::new(segment).components().count() != 1
            || !unique.insert(segment)
        {
            return Err(GaussError::SegmentCorruption {
                path: path.display().to_string(),
                message: format!("invalid or duplicate installed segment id: {segment}"),
            });
        }
    }
    if let Some(graph) = &manifest.graph {
        graph.validate(path, manifest)?;
    }
    Ok(())
}

fn manifest_corruption(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

fn schema_crc(config: &CollectionConfig) -> Result<u32> {
    Ok(checksum(&serde_json::to_vec(config)?))
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

    use crate::{DistanceMetric, checkpoint, model::CollectionConfig};

    #[test]
    fn writes_and_reads_checkpoint() {
        let temp = TempDir::new().unwrap();
        let collection_dir = temp.path().join("docs");
        let config = CollectionConfig {
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
        let checkpoint = checkpoint::CollectionCheckpoint::new(
            &config,
            2,
            128,
            7,
            Some("sg-00000001".to_string()),
        )
        .unwrap();

        checkpoint::write_checkpoint(&collection_dir, &checkpoint).unwrap();
        assert_eq!(
            checkpoint::read_checkpoint(&collection_dir).unwrap(),
            Some(checkpoint)
        );
    }

    #[test]
    fn roundtrips_segment_list_and_wal_watermark() {
        let temp = TempDir::new().unwrap();
        let collection_dir = temp.path().join("docs");
        let config = CollectionConfig {
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
        let mut checkpoint =
            checkpoint::CollectionCheckpoint::new(&config, 3, 512, 11, Some("sg-new".to_string()))
                .unwrap();
        checkpoint.segments = Some(vec!["sg-old".to_string(), "sg-new".to_string()]);
        checkpoint.wal_watermark = 256;

        checkpoint::write_checkpoint(&collection_dir, &checkpoint).unwrap();

        assert_eq!(
            checkpoint::read_checkpoint(&collection_dir).unwrap(),
            Some(checkpoint)
        );
    }

    #[test]
    fn legacy_checkpoint_defaults_new_recovery_fields() {
        let checkpoint: checkpoint::CollectionCheckpoint =
            serde_json::from_value(serde_json::json!({
                "collection": "docs",
                "schema_epoch": 1,
                "last_applied_lsn": 0,
                "points": 0,
                "segment_id": null,
                "schema_crc": 0
            }))
            .unwrap();

        assert_eq!(checkpoint.segments, None);
        assert_eq!(checkpoint.wal_watermark, 0);
    }

    #[test]
    fn rejects_corrupt_checkpoint() {
        let temp = TempDir::new().unwrap();
        let collection_dir = temp.path().join("docs");
        let config = CollectionConfig {
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
        let checkpoint = checkpoint::CollectionCheckpoint::new(&config, 1, 0, 0, None).unwrap();
        checkpoint::write_checkpoint(&collection_dir, &checkpoint).unwrap();

        let mut file = OpenOptions::new()
            .write(true)
            .open(checkpoint::checkpoint_path(&collection_dir))
            .unwrap();
        file.write_all(b"x").unwrap();

        let error = checkpoint::read_checkpoint(&collection_dir).unwrap_err();
        assert!(error.to_string().contains("bad checkpoint magic"));
    }
}
