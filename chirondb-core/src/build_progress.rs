//! Durable, fail-closed progress for resumable immutable-segment builds.
//!
//! Progress artifacts live outside the candidate segment directory. They are
//! never published to readers and may be removed after the candidate is
//! installed. Every reusable artifact is content-bound to the exact build
//! input and verified before it can skip work.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    DistanceMetric, GaussError, Result,
    encryption::{self, FileType, PersistentFile},
    fs_util::{durable_create_dir, durable_remove_dir_all, durable_remove_file},
    model::Point,
    seal::{SealConfig, SealIndexKind, VectorInput},
};

pub(crate) const BUILDS_DIR: &str = ".builds";
pub(crate) const CANDIDATE_DIR: &str = "candidate";
pub(crate) const VAMANA_CELLS_DIR: &str = "vamana-cells";
const PROGRESS_FILE: &str = "progress.gdx";
const PROGRESS_MAGIC: &[u8; 8] = b"CHIRBP02";
const PROGRESS_VERSION: u32 = 2;
const MAX_PROGRESS_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildIdentity {
    version: u32,
    segment_id: String,
    input_sha256: String,
    graph_seed_sha256: Option<String>,
    points: usize,
    vector_dim: usize,
    metric: DistanceMetric,
    hnsw_m: Option<u32>,
    hnsw_ef_construction: Option<u32>,
    index_kind: String,
    base_lsn: u64,
    end_lsn: u64,
}

impl BuildIdentity {
    #[cfg(test)]
    pub(crate) fn new<I: VectorInput + ?Sized>(
        segment_id: &str,
        input: &I,
        config: SealConfig,
    ) -> Result<Self> {
        Self::new_with_graph_seed(segment_id, input, config, None)
    }

    pub(crate) fn new_with_graph_seed<I: VectorInput + ?Sized>(
        segment_id: &str,
        input: &I,
        config: SealConfig,
        graph_seed: Option<&crate::index::vamana::StableGraphSeed>,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, b"chirondb-build-input-v1");
        hash_usize(&mut hasher, input.len());
        for ordinal in 0..input.len() {
            let point = input.point(ordinal)?;
            hash_point(&mut hasher, point.as_ref())?;
        }
        let graph_seed_sha256 = graph_seed.map(|seed| {
            let mut hasher = Sha256::new();
            hash_bytes(&mut hasher, b"chirondb-vamana-stable-seed-v2");
            hash_usize(&mut hasher, seed.rows().len());
            for (ordinal, neighbors) in seed.rows().iter().enumerate() {
                hash_usize(&mut hasher, ordinal);
                hash_usize(&mut hasher, neighbors.len());
                for neighbor in neighbors {
                    hasher.update(neighbor.to_le_bytes());
                }
            }
            hex_digest(hasher.finalize().as_slice())
        });
        Ok(Self {
            version: PROGRESS_VERSION,
            segment_id: segment_id.to_string(),
            input_sha256: hex_digest(hasher.finalize().as_slice()),
            graph_seed_sha256,
            points: input.len(),
            vector_dim: config.vector_dim,
            metric: config.metric,
            hnsw_m: config.hnsw_m,
            hnsw_ef_construction: config.hnsw_ef_construction,
            index_kind: match config.index_kind {
                SealIndexKind::Hnsw => "hnsw",
                SealIndexKind::Algorithm2 => "algorithm2",
            }
            .to_string(),
            base_lsn: config.base_lsn,
            end_lsn: config.end_lsn,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BuildStage {
    #[default]
    Prepared,
    BaseStore,
    Ivf,
    Rabitq,
    VamanaCells,
    Vamana,
    DiskAnn,
    NamedIndexes,
    Tombstones,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFingerprint {
    plaintext_bytes: u64,
    crc32: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildProgress {
    version: u32,
    identity: BuildIdentity,
    stage: BuildStage,
    artifacts: BTreeMap<String, ArtifactFingerprint>,
    completed_vamana_cells: BTreeSet<u32>,
}

impl BuildProgress {
    /// Open matching progress or atomically reset a stale/corrupt workspace.
    /// Corruption never falls through to artifact reuse.
    pub(crate) fn open_or_reset(workspace: &Path, identity: BuildIdentity) -> Result<Self> {
        validate_workspace_paths(workspace)?;
        match Self::read(&workspace.join(PROGRESS_FILE)) {
            Ok(progress) if progress.identity == identity => {
                durable_create_dir(&workspace.join(CANDIDATE_DIR))?;
                durable_create_dir(&workspace.join(VAMANA_CELLS_DIR))?;
                remove_interrupted_atomic_temps(workspace)?;
                Ok(progress)
            }
            Ok(_) => Self::reset(workspace, identity),
            Err(GaussError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::reset(workspace, identity)
            }
            Err(GaussError::SegmentCorruption { .. } | GaussError::Json(_)) => {
                Self::reset(workspace, identity)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn candidate_dir(workspace: &Path) -> PathBuf {
        workspace.join(CANDIDATE_DIR)
    }

    pub(crate) fn cells_dir(workspace: &Path) -> PathBuf {
        workspace.join(VAMANA_CELLS_DIR)
    }

    pub(crate) fn stage(&self) -> BuildStage {
        self.stage
    }

    pub(crate) fn begin_resume(&mut self, workspace: &Path) -> Result<()> {
        self.stage = BuildStage::Prepared;
        self.persist(workspace)
    }

    pub(crate) fn advance_stage(&mut self, workspace: &Path, stage: BuildStage) -> Result<()> {
        self.stage = self.stage.max(stage);
        self.persist(workspace)
    }

    pub(crate) fn artifact_is_valid(&self, root: &Path, relative: &str) -> bool {
        let Some(expected) = self.artifacts.get(relative) else {
            return false;
        };
        fingerprint(&root.join(relative)).is_ok_and(|actual| actual == *expected)
    }

    pub(crate) fn record_artifacts(
        &mut self,
        workspace: &Path,
        root: &Path,
        relatives: &[&str],
        stage: BuildStage,
    ) -> Result<()> {
        for relative in relatives {
            self.artifacts
                .insert((*relative).to_string(), fingerprint(&root.join(relative))?);
        }
        self.stage = self.stage.max(stage);
        self.persist(workspace)
    }

    pub(crate) fn record_vamana_cell(
        &mut self,
        workspace: &Path,
        cell: u32,
        path: &Path,
    ) -> Result<()> {
        let relative = cell_artifact_name(cell);
        self.artifacts.insert(relative, fingerprint(path)?);
        self.completed_vamana_cells.insert(cell);
        self.stage = self.stage.max(BuildStage::VamanaCells);
        self.persist(workspace)?;
        #[cfg(any(test, feature = "fault-injection"))]
        if let Some(fault) = crate::fs_util::fault_injection::take_if(|fault| {
            fault == crate::fs_util::fault_injection::Fault::Enospc
        }) {
            return Err(crate::fs_util::fault_injection::injected_error(fault).into());
        }
        Ok(())
    }

    pub(crate) fn vamana_cell_is_valid(&self, cells_dir: &Path, cell: u32) -> bool {
        self.completed_vamana_cells.contains(&cell)
            && self
                .artifacts
                .get(&cell_artifact_name(cell))
                .is_some_and(|expected| {
                    fingerprint(&cells_dir.join(cell_file_name(cell)))
                        .is_ok_and(|actual| actual == *expected)
                })
    }

    fn persist(&self, workspace: &Path) -> Result<()> {
        let payload = serde_json::to_vec(self)?;
        if payload.len() > MAX_PROGRESS_BYTES {
            return Err(GaussError::InvalidRequest(format!(
                "build progress exceeds {MAX_PROGRESS_BYTES} bytes"
            )));
        }
        let mut bytes = Vec::with_capacity(20 + payload.len());
        bytes.extend_from_slice(PROGRESS_MAGIC);
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&crc32(&payload).to_le_bytes());
        bytes.extend_from_slice(&payload);
        encryption::atomic_write_persistent(
            &workspace.join(PROGRESS_FILE),
            FileType::Metadata,
            &bytes,
        )
    }

    fn reset(workspace: &Path, identity: BuildIdentity) -> Result<Self> {
        if workspace.exists() {
            durable_remove_dir_all(workspace)?;
        }
        if let Some(builds_dir) = workspace.parent() {
            durable_create_dir(builds_dir)?;
        }
        durable_create_dir(workspace)?;
        durable_create_dir(&workspace.join(CANDIDATE_DIR))?;
        durable_create_dir(&workspace.join(VAMANA_CELLS_DIR))?;
        let progress = Self {
            version: PROGRESS_VERSION,
            identity,
            stage: BuildStage::Prepared,
            artifacts: BTreeMap::new(),
            completed_vamana_cells: BTreeSet::new(),
        };
        progress.persist(workspace)?;
        Ok(progress)
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = encryption::read_persistent(path)?;
        if bytes.len() < 20 || &bytes[..8] != PROGRESS_MAGIC {
            return Err(corrupt(path, "bad or truncated build-progress header"));
        }
        let payload_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        if payload_len > MAX_PROGRESS_BYTES || bytes.len() != 20 + payload_len {
            return Err(corrupt(path, "invalid build-progress payload length"));
        }
        let expected_crc = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let payload = &bytes[20..];
        if crc32(payload) != expected_crc {
            return Err(corrupt(path, "build-progress CRC mismatch"));
        }
        let progress: Self = serde_json::from_slice(payload)?;
        if progress.version != PROGRESS_VERSION || progress.identity.version != PROGRESS_VERSION {
            return Err(corrupt(path, "unsupported build-progress version"));
        }
        Ok(progress)
    }
}

pub(crate) fn workspace(searchers_dir: &Path, segment_id: &str) -> PathBuf {
    searchers_dir.join(BUILDS_DIR).join(segment_id)
}

pub(crate) fn remove_workspace(workspace: &Path) -> Result<()> {
    match fs::symlink_metadata(workspace) {
        Ok(metadata) if metadata.file_type().is_dir() => durable_remove_dir_all(workspace)?,
        Ok(_) => {
            return Err(GaussError::InvalidRequest(format!(
                "refusing to remove non-directory build workspace {}",
                workspace.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let Some(builds_dir) = workspace.parent() else {
        return Ok(());
    };
    if fs::read_dir(builds_dir)?.next().is_none() {
        durable_remove_dir_all(builds_dir)?;
    }
    Ok(())
}

pub(crate) fn cell_file_name(cell: u32) -> String {
    format!("cell-{cell:08}.gdx")
}

fn cell_artifact_name(cell: u32) -> String {
    format!("{VAMANA_CELLS_DIR}/{}", cell_file_name(cell))
}

fn fingerprint(path: &Path) -> Result<ArtifactFingerprint> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(GaussError::InvalidRequest(format!(
            "build artifact is not a regular file: {}",
            path.display()
        )));
    }
    let file = PersistentFile::open(path)?;
    Ok(ArtifactFingerprint {
        plaintext_bytes: file.len() as u64,
        crc32: file.crc32(0..file.len())?,
    })
}

fn validate_workspace_paths(workspace: &Path) -> Result<()> {
    if let Some(builds_dir) = workspace.parent() {
        validate_directory_or_absent(builds_dir)?;
    }
    validate_directory_or_absent(workspace)?;
    validate_directory_or_absent(&workspace.join(CANDIDATE_DIR))?;
    validate_directory_or_absent(&workspace.join(VAMANA_CELLS_DIR))?;
    validate_regular_file_or_absent(&workspace.join(PROGRESS_FILE))?;
    for directory in [
        workspace.join(CANDIDATE_DIR),
        workspace.join(VAMANA_CELLS_DIR),
    ] {
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(GaussError::InvalidRequest(format!(
                    "build workspace contains a non-file entry: {}",
                    entry.path().display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_directory_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(GaussError::InvalidRequest(format!(
            "build workspace path is not a directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_regular_file_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(GaussError::InvalidRequest(format!(
            "build progress path is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_interrupted_atomic_temps(workspace: &Path) -> Result<()> {
    for directory in [
        workspace.to_path_buf(),
        workspace.join(CANDIDATE_DIR),
        workspace.join(VAMANA_CELLS_DIR),
    ] {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with('.') && name.ends_with(".tmp"))
            {
                durable_remove_file(&entry.path())?;
            }
        }
    }
    Ok(())
}

fn hash_point(hasher: &mut Sha256, point: &Point) -> Result<()> {
    hash_string(hasher, &point.id);
    hash_vector(hasher, &point.vector);
    let mut names = point.vectors.keys().collect::<Vec<_>>();
    names.sort_unstable();
    hash_usize(hasher, names.len());
    for name in names {
        hash_string(hasher, name);
        hash_vector(hasher, &point.vectors[name]);
    }
    match &point.sparse_vector {
        Some(sparse) => {
            hasher.update([1]);
            hash_usize(hasher, sparse.indices.len());
            for index in &sparse.indices {
                hasher.update(index.to_le_bytes());
            }
            hash_vector(hasher, &sparse.values);
        }
        None => hasher.update([0]),
    }
    hash_json(hasher, &point.payload)
}

fn hash_json(hasher: &mut Sha256, value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Null => hasher.update([0]),
        serde_json::Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        serde_json::Value::Number(value) => {
            hasher.update([2]);
            hash_string(hasher, &value.to_string());
        }
        serde_json::Value::String(value) => {
            hasher.update([3]);
            hash_string(hasher, value);
        }
        serde_json::Value::Array(values) => {
            hasher.update([4]);
            hash_usize(hasher, values.len());
            for value in values {
                hash_json(hasher, value)?;
            }
        }
        serde_json::Value::Object(values) => {
            hasher.update([5]);
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            hash_usize(hasher, keys.len());
            for key in keys {
                hash_string(hasher, key);
                hash_json(hasher, &values[key])?;
            }
        }
    }
    Ok(())
}

fn hash_vector(hasher: &mut Sha256, values: &[f32]) {
    hash_usize(hasher, values.len());
    for value in values {
        hasher.update(value.to_bits().to_le_bytes());
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_usize(hasher, value.len());
    hasher.update(value);
}

fn hash_usize(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn points(payload: serde_json::Value) -> Vec<Point> {
        vec![Point {
            id: "p1".into(),
            vector: vec![1.0, 2.0],
            vectors: [("title".into(), vec![3.0, 4.0])].into(),
            sparse_vector: None,
            payload,
        }]
    }

    fn config() -> SealConfig {
        SealConfig {
            vector_dim: 2,
            metric: DistanceMetric::Cosine,
            hnsw_m: None,
            hnsw_ef_construction: None,
            index_kind: SealIndexKind::Algorithm2,
            base_lsn: 4,
            end_lsn: 8,
        }
    }

    #[test]
    fn identity_canonicalizes_payload_object_order() {
        let a = points(json!({"a": 1, "b": 2}));
        let b = points(json!({"b": 2, "a": 1}));
        assert_eq!(
            BuildIdentity::new("sg", a.as_slice(), config()).unwrap(),
            BuildIdentity::new("sg", b.as_slice(), config()).unwrap()
        );
    }

    #[test]
    fn identity_binds_prior_graph_adjacency() {
        let input = points(json!({}));
        let mut first = crate::index::vamana::StableGraphSeed::new(1);
        first.insert(0, vec![7]).unwrap();
        let mut second = crate::index::vamana::StableGraphSeed::new(1);
        second.insert(0, vec![8]).unwrap();

        assert_ne!(
            BuildIdentity::new_with_graph_seed("sg", input.as_slice(), config(), Some(&first),)
                .unwrap(),
            BuildIdentity::new_with_graph_seed("sg", input.as_slice(), config(), Some(&second),)
                .unwrap()
        );
    }

    #[test]
    fn mismatched_identity_resets_workspace() {
        let temp = tempdir().unwrap();
        let workspace = temp.path().join("build");
        let first = points(json!({"version": 1}));
        BuildProgress::open_or_reset(
            &workspace,
            BuildIdentity::new("sg", first.as_slice(), config()).unwrap(),
        )
        .unwrap();
        fs::write(workspace.join(CANDIDATE_DIR).join("stale"), b"stale").unwrap();

        let second = points(json!({"version": 2}));
        let reset = BuildProgress::open_or_reset(
            &workspace,
            BuildIdentity::new("sg", second.as_slice(), config()).unwrap(),
        )
        .unwrap();
        assert_eq!(reset.stage(), BuildStage::Prepared);
        assert!(!workspace.join(CANDIDATE_DIR).join("stale").exists());
    }

    #[test]
    fn corrupt_progress_resets_instead_of_reusing_candidate() {
        let temp = tempdir().unwrap();
        let workspace = temp.path().join("build");
        let input = points(json!({}));
        let identity = BuildIdentity::new("sg", input.as_slice(), config()).unwrap();
        BuildProgress::open_or_reset(&workspace, identity.clone()).unwrap();
        fs::write(workspace.join(PROGRESS_FILE), b"corrupt").unwrap();
        fs::write(workspace.join(CANDIDATE_DIR).join("stale"), b"stale").unwrap();

        let reset = BuildProgress::open_or_reset(&workspace, identity).unwrap();
        assert_eq!(reset.stage(), BuildStage::Prepared);
        assert!(!workspace.join(CANDIDATE_DIR).join("stale").exists());
    }

    #[test]
    fn matching_progress_cleans_interrupted_atomic_temp_files() {
        let temp = tempdir().unwrap();
        let workspace = temp.path().join("build");
        let input = points(json!({}));
        let identity = BuildIdentity::new("sg", input.as_slice(), config()).unwrap();
        BuildProgress::open_or_reset(&workspace, identity.clone()).unwrap();
        let interrupted = workspace
            .join(CANDIDATE_DIR)
            .join(".seal.gdx.interrupted.tmp");
        fs::write(&interrupted, b"partial").unwrap();

        BuildProgress::open_or_reset(&workspace, identity).unwrap();
        assert!(!interrupted.exists());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let workspace = temp.path().join("build");
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), b"safe").unwrap();
        let input = points(json!({}));
        let identity = BuildIdentity::new("sg", input.as_slice(), config()).unwrap();
        BuildProgress::open_or_reset(&workspace, identity.clone()).unwrap();
        fs::remove_dir(workspace.join(CANDIDATE_DIR)).unwrap();
        symlink(&external, workspace.join(CANDIDATE_DIR)).unwrap();

        assert!(BuildProgress::open_or_reset(&workspace, identity).is_err());
        assert_eq!(fs::read(external.join("keep")).unwrap(), b"safe");
    }
}
