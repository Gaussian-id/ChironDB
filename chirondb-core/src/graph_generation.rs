//! Checked graph artifact generations behind the single segments manifest.
//!
//! Version 2 reconstructs checkpointed graph control and mutable indexes for
//! Db admission and tail replay. Production sealing prepares a frozen cut off
//! the publication lock; v1 remains staging-only.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    GaussError, Result,
    checkpoint::{self, FragmentDirectoryManifest, GraphRunDescriptor, SegmentsManifest},
    encryption::PersistentFile,
    graph::EdgeId,
    graph_edge::{self, OpenedBaseAdjacency},
    graph_edgeid::{self, EdgeLedgerRunKind},
    graph_edgeprop::{self, OpenedEdgeProperties},
    graph_fragdir::{self, FragmentDirectoryRunKind, OpenedFragmentDirectory},
    graph_nid::{self, NidIndex},
    graph_tdelta::{self, OpenedTopologyDelta},
    mutable_graph::recovery::{GraphRecoveryControl, RecoveredGraph},
    overlay::{self, OverlaySet},
    seal,
};

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "D3b prepared compaction input is consumed by the following D3c publisher slice"
    )
)]
pub(crate) mod compaction;
mod compaction_sort;
pub(crate) mod cursor;
pub(crate) mod fragments;
pub(crate) mod ledger;
pub(crate) mod maintenance;
pub(crate) mod namespaces;
pub(crate) mod properties;

#[derive(Clone, Copy)]
pub(crate) enum ArtifactFamily {
    Topology,
    Ledger,
    Properties,
    Fragments,
    Recovery,
}

impl ArtifactFamily {
    fn directory(self) -> &'static str {
        match self {
            Self::Topology => "topology",
            Self::Ledger => "ledger",
            Self::Properties => "properties",
            Self::Fragments => "fragments",
            Self::Recovery => "recovery",
        }
    }
    fn file(self) -> &'static str {
        match self {
            Self::Topology => graph_tdelta::TOPOLOGY_DELTA_FILE,
            Self::Ledger => graph_edgeid::EDGEID_FILE,
            Self::Properties => graph_edgeprop::EDGE_PROPERTY_FILE,
            Self::Fragments => graph_fragdir::FRAGMENT_DIRECTORY_FILE,
            Self::Recovery => crate::mutable_graph::recovery::FILE,
        }
    }
}

pub(crate) fn artifact_path(
    collection: &Path,
    family: ArtifactFamily,
    id: &str,
) -> Result<PathBuf> {
    if id.is_empty()
        || id.len() > 255
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(corrupt(collection, "invalid graph artifact identifier"));
    }
    Ok(collection
        .join("graph")
        .join(family.directory())
        .join(id)
        .join(family.file()))
}

pub(crate) struct GraphBaseSegment {
    pub(crate) id: String,
    pub(crate) dir: PathBuf,
    pub(crate) nids: NidIndex,
    pub(crate) adjacency: OpenedBaseAdjacency,
    pub(crate) properties: Arc<OpenedEdgeProperties>,
    pub(crate) vectors: Arc<seal::V4Store>,
}

pub(crate) struct GraphRun<T> {
    pub(crate) path: PathBuf,
    pub(crate) reader: T,
}

struct LegacyVectorSegment {
    id: String,
    dir: PathBuf,
    vectors: Arc<seal::V4Store>,
}

/// Pins actual checked file handles and one overlay, not only descriptor IDs.
pub(crate) struct GraphGeneration {
    pub(crate) manifest: Arc<SegmentsManifest>,
    pub(crate) overlay: Arc<OverlaySet>,
    pub(crate) bases: Vec<GraphBaseSegment>,
    legacy: Vec<LegacyVectorSegment>,
    pub(crate) deltas: Vec<GraphRun<OpenedTopologyDelta>>,
    pub(crate) ledger: ledger::SealedLedger,
    pub(crate) edge_namespaces: namespaces::SealedNamespaces,
    pub(crate) properties: Vec<GraphRun<Arc<OpenedEdgeProperties>>>,
    pub(crate) fragments: Vec<GraphRun<OpenedFragmentDirectory>>,
    fragment_bindings: std::collections::HashMap<u64, fragments::FragmentLocation>,
    pub(crate) recovered: Option<RecoveredGraph>,
    files: BTreeSet<PathBuf>,
}

impl std::fmt::Debug for GraphGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphGeneration")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl GraphGeneration {
    fn vector_segments(
        &self,
    ) -> impl Iterator<Item = (&str, &Path, &Arc<seal::V4Store>, Option<&NidIndex>)> {
        self.bases
            .iter()
            .map(|base| {
                (
                    base.id.as_str(),
                    base.dir.as_path(),
                    &base.vectors,
                    Some(&base.nids),
                )
            })
            .chain(
                self.legacy
                    .iter()
                    .map(|base| (base.id.as_str(), base.dir.as_path(), &base.vectors, None)),
            )
    }

    /// Build vector queries from already admitted graph files. Mutable
    /// tombstone sidecars are ignored: visibility comes from the pinned
    /// overlay and the subsequent WAL tail.
    pub(crate) fn searchers(
        &self,
        metric: crate::DistanceMetric,
    ) -> Result<Vec<crate::searcher::SegmentSearcher>> {
        use crate::searcher::{SegmentIndex, SegmentSearcher, SegmentStore};
        let pinned = self
            .vector_segments()
            .map(|(id, dir, vectors, _)| (id, (dir, vectors)))
            .collect::<std::collections::HashMap<_, _>>();
        let mut searchers = Vec::with_capacity(self.manifest.segments.len());
        for id in &self.manifest.segments {
            let (dir, vectors) = pinned.get(id.as_str()).copied().ok_or_else(|| {
                corrupt(
                    Path::new(id),
                    "graph generation has no admitted vector base",
                )
            })?;
            let algorithm2 = dir.join(crate::index::ivf::IVF_FILE).exists();
            let index = if algorithm2 {
                let store = Arc::clone(vectors);
                let index = if store.diskann().is_some() {
                    crate::index::ivf_segment::IvfSegmentIndex::open_cold(dir, store, metric)?
                } else {
                    crate::index::ivf_segment::IvfSegmentIndex::open(dir, store, metric)?
                };
                SegmentIndex::Ivf(Box::new(index))
            } else {
                SegmentIndex::LegacyH2qg(Box::new(crate::h2qg::read_index_paged(dir)?))
            };
            let named = if algorithm2 {
                crate::searcher::load_named_algorithm2_indexes(dir, metric)?
            } else {
                std::collections::HashMap::new()
            };
            let ordinals = self
                .overlay
                .point_tombstones()
                .bitmap(id)
                .cloned()
                .unwrap_or_default();
            let tombstones = ordinals
                .iter()
                .map(|ordinal| {
                    vectors
                        .id(ordinal as usize)
                        .expect("validated graph visibility ordinal")
                        .to_owned()
                })
                .collect();
            searchers.push(SegmentSearcher::new(
                id.clone(),
                dir.to_owned(),
                index,
                named,
                SegmentStore::V4(Arc::clone(vectors)),
                tombstones,
                ordinals,
            ));
        }
        Ok(searchers)
    }

    pub(crate) fn open(collection: &Path) -> Result<Option<Self>> {
        let Some(manifest) = checkpoint::read_segments_manifest(collection)? else {
            return Ok(None);
        };
        if manifest.graph.is_none() {
            return Ok(None);
        }
        Self::load_candidate(collection, manifest).map(Some)
    }

    pub(crate) fn load_candidate(collection: &Path, manifest: SegmentsManifest) -> Result<Self> {
        Self::load_candidate_with_remote_diskann(collection, manifest, &HashMap::new())
    }

    pub(crate) fn load_candidate_with_remote_diskann(
        collection: &Path,
        manifest: SegmentsManifest,
        remote_diskann: &HashMap<String, Arc<crate::index::diskann::DiskAnnArtifact>>,
    ) -> Result<Self> {
        manifest.validate(collection)?;
        let graph = manifest
            .graph
            .as_ref()
            .ok_or_else(|| corrupt(collection, "graph generation requires graph descriptors"))?;
        if graph
            .catalog_overlay_generation
            .is_some_and(|generation| generation != manifest.generation || graph.recovery.is_none())
        {
            return Err(corrupt(
                collection,
                "catalog overlay must name this generation's complete recovery authority",
            ));
        }
        let installed = manifest.segments.iter().cloned().collect::<HashSet<_>>();
        let overlay_dir = collection
            .join("overlays")
            .join(format!("{:020}", graph.overlay_version));
        check_directory(collection, &overlay_dir.join("points"))?;
        let mut files = BTreeSet::new();
        for entry in fs::read_dir(&overlay_dir)? {
            let entry = entry?;
            if entry.file_name() == "points" {
                for point in fs::read_dir(entry.path())? {
                    files.insert(point?.path());
                }
            } else {
                files.insert(entry.path());
            }
        }
        for file in &files {
            check_file(collection, file)?;
        }
        let overlay = overlay::open_manifest_version(
            collection,
            graph.overlay_version,
            manifest.generation,
            &installed,
        )?;
        let control = if let Some(descriptor) = &graph.recovery {
            let path = checked_run(collection, ArtifactFamily::Recovery, descriptor, &mut files)?;
            let name = collection
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| corrupt(collection, "invalid recovery collection name"))?;
            Some(GraphRecoveryControl::open(
                &path,
                name,
                graph.epoch,
                graph.graph_batch_watermark,
            )?)
        } else {
            None
        };

        let mut bases = Vec::new();
        for id in &graph.base_segments {
            let (dir, marker) =
                checked_segment_with_remote_diskann(collection, id, &mut files, remote_diskann)?;
            if !marker.has_graph() {
                return Err(corrupt(
                    &dir,
                    "graph base descriptor points to a vector-only marker",
                ));
            }
            let nids = graph_nid::open(&dir.join(graph_nid::NID_FILE))?;
            if overlay
                .point_tombstones()
                .bitmap(id)
                .and_then(|bitmap| bitmap.max())
                .is_some_and(|ordinal| ordinal as usize >= nids.len())
            {
                return Err(corrupt(
                    &dir,
                    "point overlay ordinal exceeds graph base point count",
                ));
            }
            // This path has no catalog overlay; every ordinal must be bound.
            if (0..nids.len()).any(|i| {
                nids.nid_for_ordinal(i as u32)
                    .is_none_or(|nid| !nid.is_assigned())
            }) {
                return Err(corrupt(
                    &dir,
                    "graph base contains unassigned Nids without a catalog overlay",
                ));
            }
            let adjacency = graph_edge::open(&dir.join(graph_edge::EDGE_FILE), &nids)?;
            let properties = Arc::new(graph_edgeprop::open(
                &dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
            )?);
            let vectors = Arc::new(match remote_diskann.get(id) {
                Some(diskann) => {
                    seal::V4Store::open_graph_base_with_diskann(&dir, Arc::clone(diskann))?
                }
                None => seal::V4Store::open_graph_base(&dir)?,
            });
            bases.push(GraphBaseSegment {
                id: id.clone(),
                dir,
                nids,
                adjacency,
                properties,
                vectors,
            });
        }

        let mut legacy = Vec::new();
        let active_bases = graph
            .base_segments
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        for id in manifest
            .segments
            .iter()
            .filter(|id| !active_bases.contains(id.as_str()))
        {
            let (dir, marker) =
                checked_segment_with_remote_diskann(collection, id, &mut files, remote_diskann)?;
            let vectors = match (marker.has_graph(), remote_diskann.get(id)) {
                (true, Some(diskann)) => {
                    seal::V4Store::open_graph_base_with_diskann(&dir, Arc::clone(diskann))?
                }
                (true, None) => seal::V4Store::open_graph_base(&dir)?,
                (false, Some(diskann)) => {
                    seal::V4Store::open_with_diskann(&dir, Arc::clone(diskann))?
                }
                (false, None) => seal::V4Store::open(&dir)?,
            };
            if overlay
                .point_tombstones()
                .bitmap(id)
                .and_then(|bitmap| bitmap.max())
                .is_some_and(|ordinal| ordinal as usize >= vectors.len())
            {
                return Err(corrupt(
                    &dir,
                    "catalog vector visibility ordinal exceeds point count",
                ));
            }
            legacy.push(LegacyVectorSegment {
                id: id.clone(),
                dir,
                vectors: Arc::new(vectors),
            });
        }

        let mut ledger = Vec::new();
        for (index, descriptor) in std::iter::once(&graph.edge_ledger.base)
            .chain(&graph.edge_ledger.runs)
            .enumerate()
        {
            let path = checked_run(collection, ArtifactFamily::Ledger, descriptor, &mut files)?;
            let reader = graph_edgeid::open(&path)?;
            let metadata = reader.metadata();
            let expected_kind = if index == 0 {
                EdgeLedgerRunKind::Base
            } else {
                EdgeLedgerRunKind::Delta
            };
            if metadata.graph_epoch != graph.epoch
                || metadata.first_lsn != descriptor.first_lsn
                || metadata.last_lsn != descriptor.last_lsn
                || metadata.kind != expected_kind
            {
                return Err(corrupt(
                    &path,
                    "edge ledger epoch/LSN/kind disagrees with manifest",
                ));
            }
            ledger.push(Arc::new(reader));
        }
        let mut deltas = Vec::new();
        for descriptor in &graph.topology_deltas {
            let path = checked_run(collection, ArtifactFamily::Topology, descriptor, &mut files)?;
            let reader = graph_tdelta::open(&path, descriptor.last_lsn)?;
            if reader.base_lsn() != descriptor.first_lsn {
                return Err(corrupt(
                    &path,
                    "topology delta base LSN disagrees with manifest first LSN",
                ));
            }
            deltas.push(GraphRun { path, reader });
        }
        let mut properties = Vec::new();
        for descriptor in
            std::iter::once(&graph.edge_properties.base).chain(&graph.edge_properties.runs)
        {
            let path = checked_run(
                collection,
                ArtifactFamily::Properties,
                descriptor,
                &mut files,
            )?;
            let reader = Arc::new(graph_edgeprop::open(&path)?);
            properties.push(GraphRun { path, reader });
        }
        let mut fragments = Vec::new();
        if let FragmentDirectoryManifest::Present { base, overlays } = &graph.fragment_directory {
            for (index, descriptor) in std::iter::once(base).chain(overlays).enumerate() {
                let path = checked_run(
                    collection,
                    ArtifactFamily::Fragments,
                    descriptor,
                    &mut files,
                )?;
                let reader = graph_fragdir::open(&path)?;
                let expected_kind = if index == 0 {
                    FragmentDirectoryRunKind::Base
                } else {
                    FragmentDirectoryRunKind::Overlay
                };
                if reader.kind() != expected_kind {
                    return Err(corrupt(
                        &path,
                        "fragment directory kind disagrees with manifest",
                    ));
                }
                fragments.push(GraphRun { path, reader });
            }
        }
        let fragment_bindings = fragments::bind(&manifest, &bases, &deltas)?;
        let mut generation = Self {
            manifest: Arc::new(manifest),
            overlay,
            bases,
            legacy,
            deltas,
            ledger: ledger::SealedLedger::new(ledger)?,
            edge_namespaces: Default::default(),
            properties,
            fragments,
            fragment_bindings,
            recovered: None,
            files,
        };
        generation.validate_fragments(collection)?;
        generation.edge_namespaces = namespaces::SealedNamespaces::build(&generation)?;
        // Cross-file existence checks include tombstoned keys: ledger identity
        // survives deletion and is not inferred by scanning adjacency.
        for base in &generation.bases {
            generation.validate_property_keys(
                &base.dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
                &base.properties,
            )?;
        }
        for run in &generation.properties {
            generation.validate_property_keys(&run.path, &run.reader)?;
        }
        for raw in generation.overlay.edge_tombstones().iter() {
            generation.require_edge(&overlay_dir, EdgeId::from_raw(raw))?;
        }
        if let Some(control) = control {
            let mut points = std::collections::HashMap::new();
            let mut visible_ids = HashSet::new();
            for (segment_id, dir, vectors, nids) in generation.vector_segments() {
                let hidden = generation.overlay.point_tombstones().bitmap(segment_id);
                for ordinal in 0..vectors.len() {
                    if hidden.is_some_and(|hidden| hidden.contains(ordinal as u32)) {
                        continue;
                    }
                    let id = vectors.id(ordinal).expect("validated vector ordinal");
                    if !visible_ids.insert(id) {
                        return Err(corrupt(
                            dir,
                            "point ID has multiple visible vector locations",
                        ));
                    }
                    let nid = match nids {
                        Some(nids) => nids
                            .nid_for_ordinal(ordinal as u32)
                            .ok_or_else(|| corrupt(dir, "missing point Nid"))?,
                        None => match control.live_nid(id) {
                            Some(nid) => nid,
                            None => continue,
                        },
                    };
                    let point = vectors
                        .get_ordinal_for_aux_indexes(ordinal)
                        .ok_or_else(|| corrupt(dir, "missing vector point for recovery"))?;
                    let tenant = point
                        .payload
                        .get(crate::tenant::TENANT_FIELD)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    if points.insert(nid, (id.to_owned(), tenant)).is_some() {
                        return Err(corrupt(dir, "Nid has multiple visible vector locations"));
                    }
                }
            }
            control
                .validate_points(&points)
                .map_err(|error| corrupt(collection, &error.to_string()))?;
            generation.recovered = Some(
                control
                    .restore(&generation, |nid| {
                        points.get(&nid).and_then(|(_, tenant)| tenant.clone())
                    })
                    .map_err(|error| corrupt(collection, &error.to_string()))?,
            );
        }
        Ok(generation)
    }

    pub(crate) fn edge_properties(
        &self,
        edge_id: EdgeId,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
        for run in self.properties.iter().rev() {
            if let Some(row) = run.reader.find_edge(&run.path, edge_id)? {
                return run.reader.read_properties(&run.path, row).map(Some);
            }
        }
        for base in &self.bases {
            let path = base.dir.join(graph_edgeprop::EDGE_PROPERTY_FILE);
            if let Some(row) = base.properties.find_edge(&path, edge_id)? {
                return base.properties.read_properties(&path, row).map(Some);
            }
        }
        Ok(None)
    }

    pub(crate) fn contains_edge(&self, edge_id: EdgeId) -> Result<bool> {
        self.ledger.contains(edge_id)
    }

    fn require_edge(&self, path: &Path, edge_id: EdgeId) -> Result<()> {
        if !self.contains_edge(edge_id)? {
            return Err(corrupt(
                path,
                "graph artifact references an EdgeId absent from the pinned ledger",
            ));
        }
        Ok(())
    }

    fn validate_property_keys(&self, path: &Path, reader: &OpenedEdgeProperties) -> Result<()> {
        for row in 0..reader.edge_count() {
            self.require_edge(path, reader.edge_id_at(path, row)?)?;
        }
        Ok(())
    }

    /// Caller holds the collection publication lock. No CURRENT switch or WAL
    /// truncation occurs here. A committed rename is never rolled back because
    /// a subsequent parent-directory sync reported failure.
    pub(crate) fn publish(
        collection: &Path,
        expected: Option<&SegmentsManifest>,
        candidate: SegmentsManifest,
    ) -> Result<Self> {
        Self::validate_publication(collection, expected, &candidate)?;
        let opened = Self::prepare_publication(collection, candidate)?;
        Self::publish_prepared(collection, expected, opened)
    }

    /// Expensive validation and file synchronization run outside the collection lock.
    pub(crate) fn prepare_publication(
        collection: &Path,
        candidate: SegmentsManifest,
    ) -> Result<Self> {
        let opened = Self::load_candidate(collection, candidate)?;
        let mut directories = BTreeSet::new();
        for path in &opened.files {
            fs::File::open(path)?.sync_all()?;
            let mut parent = path.parent();
            while let Some(dir) = parent {
                directories.insert(dir.to_path_buf());
                if dir == collection {
                    break;
                }
                parent = dir.parent();
            }
        }
        let mut directories = directories.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
        for dir in directories {
            seal::sync_directory(&dir)?;
        }
        Ok(opened)
    }

    /// Caller holds the collection lock, including against maintenance publishers.
    pub(crate) fn publish_prepared(
        collection: &Path,
        expected: Option<&SegmentsManifest>,
        opened: Self,
    ) -> Result<Self> {
        Self::validate_publication(collection, expected, &opened.manifest)?;
        crate::failpoint::check("graph_generation.before_manifest")?;
        if let Err(error) = checkpoint::write_segments_manifest(collection, &opened.manifest) {
            if checkpoint::read_segments_manifest(collection)?.as_ref()
                != Some(opened.manifest.as_ref())
            {
                return Err(error);
            }
            tracing::warn!(%error, "graph manifest rename committed but parent sync failed; refusing rollback");
        }
        Ok(opened)
    }

    /// Preflight before candidate I/O, and recheck at the locked commit boundary.
    fn validate_publication(
        collection: &Path,
        expected: Option<&SegmentsManifest>,
        candidate: &SegmentsManifest,
    ) -> Result<()> {
        let current = checkpoint::read_segments_manifest(collection)?;
        if current.as_ref() != expected {
            return Err(corrupt(
                collection,
                "graph publication expected manifest is stale",
            ));
        }
        let next = expected
            .map_or(0, |m| m.generation)
            .checked_add(1)
            .ok_or_else(|| corrupt(collection, "graph generation overflow"))?;
        if candidate.generation != next {
            return Err(corrupt(
                collection,
                "graph publication must advance exactly one generation",
            ));
        }
        if let (Some(previous), Some(graph)) = (
            expected.and_then(|m| m.graph.as_ref()),
            candidate.graph.as_ref(),
        ) && (graph.version < previous.version
            || graph.epoch < previous.epoch
            || graph.overlay_version <= previous.overlay_version
            || (graph.epoch == previous.epoch
                && graph.graph_batch_watermark < previous.graph_batch_watermark))
        {
            return Err(corrupt(
                collection,
                "graph format, epoch, overlay, or watermark regressed",
            ));
        }
        fragments::validate_transition(collection, expected, candidate)?;
        Ok(())
    }
}

fn checked_segment(
    collection: &Path,
    id: &str,
    files: &mut BTreeSet<PathBuf>,
) -> Result<(PathBuf, seal::SealMarker)> {
    checked_segment_with_remote_diskann(collection, id, files, &HashMap::new())
}

fn checked_segment_with_remote_diskann(
    collection: &Path,
    id: &str,
    files: &mut BTreeSet<PathBuf>,
    remote_diskann: &HashMap<String, Arc<crate::index::diskann::DiskAnnArtifact>>,
) -> Result<(PathBuf, seal::SealMarker)> {
    let hot = collection.join("searchers").join(id);
    let cold = collection.join("cold").join(id);
    let dir = match (hot.try_exists()?, cold.try_exists()?) {
        (true, false) => hot,
        (false, true) => cold,
        _ => {
            return Err(corrupt(
                collection,
                "graph vector segment is missing or duplicated across tiers",
            ));
        }
    };
    check_directory(collection, &dir)?;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            return Err(corrupt(
                &entry.path(),
                "graph segment peers must not be symlinks",
            ));
        }
    }
    let path = dir.join(seal::SEAL_FILE);
    check_file(collection, &path)?;
    let marker = match remote_diskann.get(id) {
        Some(diskann) => seal::read_marker_with_diskann_len(&path, diskann.object_len())?,
        None => seal::read_marker(&path)?,
    };
    files.insert(path);
    for peer in &marker.files {
        let file = dir.join(&peer.name);
        if peer.name == crate::index::diskann::DISKANN_FILE
            && remote_diskann.contains_key(id)
            && !file.exists()
        {
            continue;
        }
        check_file(collection, &file)?;
        files.insert(file);
    }
    Ok((dir, marker))
}

fn checked_run(
    collection: &Path,
    family: ArtifactFamily,
    descriptor: &GraphRunDescriptor,
    files: &mut BTreeSet<PathBuf>,
) -> Result<PathBuf> {
    let path = artifact_path(collection, family, &descriptor.id)?;
    check_file(collection, &path)?;
    let file = PersistentFile::open(&path)?;
    if file.crc32(0..file.len())? != descriptor.crc32 {
        return Err(corrupt(&path, "graph run CRC disagrees with manifest"));
    }
    files.insert(path.clone());
    Ok(path)
}

fn check_file(collection: &Path, file: &Path) -> Result<()> {
    check_directory(
        collection,
        file.parent()
            .ok_or_else(|| corrupt(file, "missing artifact parent"))?,
    )?;
    if !fs::symlink_metadata(file)?.file_type().is_file() {
        return Err(corrupt(file, "graph artifact must be a regular file"));
    }
    Ok(())
}

fn check_directory(collection: &Path, dir: &Path) -> Result<()> {
    let relative = dir
        .strip_prefix(collection)
        .map_err(|_| corrupt(dir, "graph artifact escaped collection"))?;
    let mut current = collection.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if !fs::symlink_metadata(&current)?.file_type().is_dir() {
            return Err(corrupt(
                &current,
                "graph artifact parent must be a directory, not a symlink",
            ));
        }
    }
    Ok(())
}

fn corrupt(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        DistanceMetric, Point,
        checkpoint::{GraphManifest, GraphRunManifest},
        encryption,
        graph::{GraphEpoch, GraphNamespace, Nid, TypeId},
        graph_edge::{
            BaseAdjacency, BaseEdgeInput, BaseGroupInput, BaseNeighborInput, BaseRowInput,
        },
        graph_edgeid::{EdgeLedgerRun, EdgeLedgerRunMetadata},
        graph_edgeprop::{EdgePropertyInput, EdgePropertyTable},
        graph_fragdir::{
            FragmentDirectory, FragmentGroupInput, FragmentReference, FragmentRowInput,
        },
        graph_tdelta::{DeltaEdgeInput, DeltaGroupInput, TopologyDelta},
        ordinal::SegmentOrdinalSet,
        overlay::{OverlayOpenMode, OverlayStore},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use roaring::RoaringTreemap;
    use serde_json::json;
    use std::{env, process::Command};
    use tempfile::TempDir;

    fn edge(id: u64) -> EdgeId {
        EdgeId::from_parts(1, id).unwrap()
    }
    fn nid(id: u64) -> Nid {
        Nid::from_parts(1, id).unwrap()
    }
    pub(crate) fn descriptor(
        dir: &Path,
        family: ArtifactFamily,
        id: &str,
        first: u64,
        last: u64,
    ) -> GraphRunDescriptor {
        let file = PersistentFile::open(&artifact_path(dir, family, id).unwrap()).unwrap();
        GraphRunDescriptor {
            id: id.into(),
            first_lsn: first,
            last_lsn: last,
            crc32: file.crc32(0..file.len()).unwrap(),
        }
    }
    pub(crate) fn ledger(
        dir: &Path,
        id: &str,
        kind: EdgeLedgerRunKind,
        first: u64,
        last: u64,
        keys: Vec<EdgeId>,
    ) -> GraphRunDescriptor {
        let file = artifact_path(dir, ArtifactFamily::Ledger, id).unwrap();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let run = EdgeLedgerRun::build(
            EdgeLedgerRunMetadata {
                graph_epoch: GraphEpoch::INITIAL,
                first_lsn: first,
                last_lsn: last,
                kind,
            },
            keys,
        )
        .unwrap();
        graph_edgeid::write(&file, &run).unwrap();
        descriptor(dir, ArtifactFamily::Ledger, id, first, last)
    }
    fn properties(
        dir: &Path,
        id: &str,
        first: u64,
        last: u64,
        keys: Vec<EdgeId>,
    ) -> GraphRunDescriptor {
        let file = artifact_path(dir, ArtifactFamily::Properties, id).unwrap();
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let table = EdgePropertyTable::build(
            keys.into_iter()
                .map(|edge_id| EdgePropertyInput {
                    edge_id,
                    properties: json!({"name":"fixture","optional":null})
                        .as_object()
                        .unwrap()
                        .clone(),
                })
                .collect(),
        )
        .unwrap();
        graph_edgeprop::write(&file, &table).unwrap();
        descriptor(dir, ArtifactFamily::Properties, id, first, last)
    }
    pub(crate) fn fixture(dir: &Path) -> (SegmentsManifest, OverlayStore) {
        fixture_with_csc(dir, true)
    }

    pub(crate) fn fixture_with_csc(
        dir: &Path,
        include_csc: bool,
    ) -> (SegmentsManifest, OverlayStore) {
        let base_dir = dir.join("searchers/sg-1");
        let points = (0..2)
            .map(|i| Point {
                id: format!("p{i}"),
                vector: vec![i as f32, 1.0, 2.0, 3.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: json!({"tenant_id":"acme"}),
            })
            .collect::<Vec<_>>();
        seal::build_segment(
            &points[..],
            &base_dir,
            seal::SealConfig {
                vector_dim: 4,
                metric: DistanceMetric::L2,
                hnsw_m: None,
                hnsw_ef_construction: None,
                index_kind: seal::SealIndexKind::Hnsw,
                base_lsn: 0,
                end_lsn: 10,
            },
        )
        .unwrap();
        let nids = NidIndex::build(vec![nid(1), nid(2)], true).unwrap();
        graph_nid::write(&base_dir.join(graph_nid::NID_FILE), &nids).unwrap();
        let base_edge = |ordinal| BaseEdgeInput {
            neighbor: BaseNeighborInput::LocalOrdinal(ordinal),
            edge_id: edge(1),
            type_id: TypeId::from_raw(1),
            weight: None,
        };
        let adjacency = BaseAdjacency::build_with_options(
            &nids,
            vec![BaseGroupInput {
                namespace: GraphNamespace::Tenant("acme".into()),
                rows: vec![
                    BaseRowInput {
                        node_ordinal: 0,
                        outgoing: vec![base_edge(1)],
                        incoming: vec![],
                    },
                    BaseRowInput {
                        node_ordinal: 1,
                        outgoing: vec![],
                        incoming: if include_csc {
                            vec![base_edge(0)]
                        } else {
                            vec![]
                        },
                    },
                ],
            }],
            include_csc,
            false,
        )
        .unwrap();
        graph_edge::write(&base_dir.join(graph_edge::EDGE_FILE), &adjacency).unwrap();
        graph_edgeprop::write(
            &base_dir.join(graph_edgeprop::EDGE_PROPERTY_FILE),
            &EdgePropertyTable::build(vec![EdgePropertyInput {
                edge_id: edge(1),
                properties: json!({"base":true}).as_object().unwrap().clone(),
            }])
            .unwrap(),
        )
        .unwrap();
        seal::graph::seal_candidate(&base_dir).unwrap();
        let base = ledger(dir, "base-1", EdgeLedgerRunKind::Base, 0, 10, vec![edge(1)]);
        let delta_ledger = ledger(
            dir,
            "delta-1",
            EdgeLedgerRunKind::Delta,
            11,
            20,
            vec![edge(2)],
        );
        let delta_path = artifact_path(dir, ArtifactFamily::Topology, "delta-1").unwrap();
        fs::create_dir_all(delta_path.parent().unwrap()).unwrap();
        graph_tdelta::write(
            &delta_path,
            &TopologyDelta::build(
                11,
                vec![DeltaGroupInput {
                    namespace: GraphNamespace::Tenant("acme".into()),
                    edges: vec![DeltaEdgeInput {
                        source_nid: nid(1),
                        target_nid: nid(2),
                        edge_id: edge(2),
                        type_id: TypeId::from_raw(1),
                    }],
                }],
            )
            .unwrap(),
        )
        .unwrap();
        let property_base = properties(dir, "base-1", 0, 10, vec![edge(1)]);
        let property_delta = properties(dir, "delta-1", 11, 20, vec![edge(2)]);
        let mut fragments = Vec::new();
        for (id, kind, first, last, fragment_id) in [
            ("base-1", FragmentDirectoryRunKind::Base, 0, 10, 1),
            ("overlay-1", FragmentDirectoryRunKind::Overlay, 11, 20, 2),
        ] {
            let file = artifact_path(dir, ArtifactFamily::Fragments, id).unwrap();
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            graph_fragdir::write(
                &file,
                &FragmentDirectory::build(
                    kind,
                    true,
                    vec![FragmentGroupInput {
                        namespace: GraphNamespace::Tenant("acme".into()),
                        rows: (0..2)
                            .map(|row_hint| FragmentRowInput {
                                nid: nid(u64::from(row_hint) + 1),
                                fragments: vec![FragmentReference {
                                    fragment_id,
                                    row_hint,
                                }],
                            })
                            .collect(),
                    }],
                )
                .unwrap(),
            )
            .unwrap();
            fragments.push(descriptor(dir, ArtifactFamily::Fragments, id, first, last));
        }
        let mut store = OverlayStore::open(
            dir,
            0,
            &HashSet::new(),
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        store
            .advance_generation(1, SegmentOrdinalSet::new())
            .unwrap();
        store
            .replace_edges(&RoaringTreemap::from_iter([edge(1).raw()]))
            .unwrap();
        let version = store.stage_pending().unwrap().version();
        let graph = GraphManifest {
            version: 1,
            epoch: GraphEpoch::INITIAL,
            graph_batch_watermark: 20,
            overlay_version: version,
            base_segments: vec!["sg-1".into()],
            topology_deltas: vec![descriptor(dir, ArtifactFamily::Topology, "delta-1", 11, 20)],
            edge_ledger: GraphRunManifest {
                base,
                runs: vec![delta_ledger],
            },
            edge_properties: GraphRunManifest {
                base: property_base,
                runs: vec![property_delta],
            },
            fragment_directory: FragmentDirectoryManifest::Present {
                base: fragments.remove(0),
                overlays: fragments,
            },
            fragment_catalog: Some(crate::checkpoint::GraphFragmentCatalog {
                high_watermark: 2,
                bindings: vec![
                    crate::checkpoint::GraphFragmentBinding {
                        fragment_id: 1,
                        source: crate::checkpoint::GraphFragmentSource::Base { id: "sg-1".into() },
                    },
                    crate::checkpoint::GraphFragmentBinding {
                        fragment_id: 2,
                        source: crate::checkpoint::GraphFragmentSource::Delta {
                            id: "delta-1".into(),
                        },
                    },
                ],
            }),
            recovery: None,
            catalog_overlay_generation: None,
            sketch: None,
        };
        (
            SegmentsManifest {
                generation: 1,
                segments: vec!["sg-1".into()],
                graph: Some(graph),
            },
            store,
        )
    }

    #[test]
    fn publishes_and_reopens_checked_graph_group_plaintext_and_encrypted() {
        const MODE: &str = "CHIRONDB_GRAPH_GENERATION_TEST_MODE";
        const ROOT: &str = "CHIRONDB_GRAPH_GENERATION_TEST_ROOT";
        const TEST: &str = "graph_generation::tests::publishes_and_reopens_checked_graph_group_plaintext_and_encrypted";
        let Some(mode) = env::var_os(MODE) else {
            for mode in ["plaintext", "encrypted"] {
                let root = TempDir::new().unwrap();
                assert!(
                    Command::new(env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture"])
                        .env(MODE, mode)
                        .env(ROOT, root.path())
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        };
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        let encrypted = mode == "encrypted";
        if encrypted {
            let keyring = root.join("keyring.json");
            fs::write(&keyring, json!({"version":1,"active_key_id":"generation-test","keys":[{"id":"generation-test","key_base64":STANDARD.encode([83;32])}]}).to_string()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&keyring, fs::Permissions::from_mode(0o600)).unwrap();
            }
            encryption::install_process_keyring(encryption::Keyring::load(&keyring).unwrap(), true)
                .unwrap();
        }
        let dir = root.join("docs");
        assert!(GraphGeneration::open(&dir).unwrap().is_none());
        let (first, mut store) = fixture(&dir);
        let old_current = fs::read(dir.join("overlays/CURRENT")).unwrap();
        let pinned = GraphGeneration::publish(&dir, None, first.clone()).unwrap();
        assert_eq!(fs::read(dir.join("overlays/CURRENT")).unwrap(), old_current);
        assert_eq!(*pinned.manifest, first);
        assert_eq!(pinned.bases[0].id, "sg-1");
        assert_eq!(pinned.deltas.len(), 1);
        assert_eq!(pinned.properties.len(), 2);
        assert_eq!(pinned.fragments.len(), 2);
        for id in [1, 2] {
            let rows = pinned
                .fragment_rows(&GraphNamespace::Tenant("acme".into()), nid(id))
                .unwrap();
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().all(|row| row.row_hint == id as u32 - 1));
        }
        assert!(pinned.contains_edge(edge(1)).unwrap());
        assert!(pinned.contains_edge(edge(2)).unwrap());
        assert!(!pinned.contains_edge(edge(3)).unwrap());
        assert!(pinned.overlay.edge_tombstones().contains(edge(1).raw()));
        assert_eq!(
            *GraphGeneration::open(&dir).unwrap().unwrap().manifest,
            first
        );
        for file in &pinned.files {
            assert_eq!(
                fs::read(file).unwrap().starts_with(encryption::MAGIC),
                encrypted
            );
        }
        let mut points = SegmentOrdinalSet::new();
        points.insert("sg-1", 1);
        store.advance_generation(2, points).unwrap();
        store
            .replace_edges(&RoaringTreemap::from_iter([edge(1).raw(), edge(2).raw()]))
            .unwrap();
        let staged = store.stage_pending().unwrap();
        assert_eq!(
            *store.stage_pending().unwrap(),
            *staged,
            "staging retry must be idempotent"
        );
        let mut second = first.clone();
        second.generation = 2;
        second.graph.as_mut().unwrap().overlay_version = staged.version();
        let next = GraphGeneration::publish(&dir, Some(&first), second.clone()).unwrap();
        assert_eq!(
            *GraphGeneration::open(&dir).unwrap().unwrap().manifest,
            second
        );
        assert!(next.overlay.point_tombstones().contains("sg-1", 1));
        assert!(next.overlay.edge_tombstones().contains(edge(2).raw()));
        assert!(!pinned.overlay.edge_tombstones().contains(edge(2).raw()));
        assert!(pinned.overlay.point_tombstones().is_empty());
        assert_eq!(fs::read(dir.join("overlays/CURRENT")).unwrap(), old_current);
        // A later mutation cannot overwrite the already staged immutable version.
        store.tombstone_point("sg-1", 0).unwrap();
        assert!(store.stage_pending().unwrap().version() > staged.version());
        let path = artifact_path(&dir, ArtifactFamily::Ledger, "base-1").unwrap();
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(GraphGeneration::open(&dir).is_err());
    }

    #[test]
    fn rejected_candidates_leave_the_old_graph_generation_installed() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        let (first, mut store) = fixture(dir);
        GraphGeneration::publish(dir, None, first.clone()).unwrap();
        let before = fs::read(dir.join(checkpoint::SEGMENTS_MANIFEST_FILE)).unwrap();
        store
            .advance_generation(2, SegmentOrdinalSet::new())
            .unwrap();
        let mut candidate = first.clone();
        candidate.generation = 2;
        candidate.graph.as_mut().unwrap().overlay_version =
            store.stage_pending().unwrap().version();
        let reject = |candidate| {
            assert!(GraphGeneration::publish(dir, Some(&first), candidate).is_err());
            assert_eq!(
                fs::read(dir.join(checkpoint::SEGMENTS_MANIFEST_FILE)).unwrap(),
                before
            );
            assert_eq!(
                *GraphGeneration::open(dir).unwrap().unwrap().manifest,
                first
            );
        };
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_ledger.base.crc32 ^= 1;
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().epoch = GraphEpoch::from_raw(2).unwrap();
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_ledger.base.last_lsn = 9;
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().topology_deltas[0].first_lsn = 12;
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_ledger.base = ledger(
            dir,
            "wrong-kind",
            EdgeLedgerRunKind::Delta,
            0,
            10,
            vec![edge(1)],
        );
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_properties.runs[0] =
            properties(dir, "unknown-edge", 11, 20, vec![edge(99)]);
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_ledger.base =
            ledger(dir, "missing-edge", EdgeLedgerRunKind::Base, 0, 10, vec![]);
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().fragment_directory = FragmentDirectoryManifest::Present {
            base: descriptor(dir, ArtifactFamily::Fragments, "overlay-1", 11, 20),
            overlays: vec![],
        };
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().edge_properties.base.id = "missing".into();
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.graph.as_mut().unwrap().catalog_overlay_generation = Some(1);
        reject(invalid);
        let mut invalid = candidate.clone();
        invalid.generation = 3;
        reject(invalid);
        assert!(GraphGeneration::publish(dir, None, candidate).is_err());
        assert_eq!(
            fs::read(dir.join(checkpoint::SEGMENTS_MANIFEST_FILE)).unwrap(),
            before
        );
    }

    #[test]
    fn point_and_edge_visibility_must_be_addressable_in_selected_generation() {
        let temp = TempDir::new().unwrap();
        let (mut candidate, mut store) = fixture(temp.path());
        store.tombstone_point("sg-1", 2).unwrap();
        candidate.graph.as_mut().unwrap().overlay_version =
            store.stage_pending().unwrap().version();
        assert!(GraphGeneration::publish(temp.path(), None, candidate.clone()).is_err());
        store
            .replace_generation(1, SegmentOrdinalSet::new())
            .unwrap();
        store
            .replace_edges(&RoaringTreemap::from_iter([edge(99).raw()]))
            .unwrap();
        candidate.graph.as_mut().unwrap().overlay_version =
            store.stage_pending().unwrap().version();
        assert!(GraphGeneration::publish(temp.path(), None, candidate).is_err());
        assert!(
            !temp
                .path()
                .join(checkpoint::SEGMENTS_MANIFEST_FILE)
                .exists()
        );
    }

    #[test]
    fn directory_absence_is_supported_but_missing_present_peer_is_not() {
        let temp = TempDir::new().unwrap();
        let (mut candidate, _store) = fixture(temp.path());
        let selected = artifact_path(temp.path(), ArtifactFamily::Fragments, "base-1").unwrap();
        fs::remove_file(selected).unwrap();
        assert!(GraphGeneration::load_candidate(temp.path(), candidate.clone()).is_err());
        candidate.graph.as_mut().unwrap().fragment_directory = FragmentDirectoryManifest::Absent;
        assert!(
            GraphGeneration::publish(temp.path(), None, candidate)
                .unwrap()
                .fragments
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn graph_run_symlinks_are_not_followed() {
        let temp = TempDir::new().unwrap();
        let (mut candidate, _store) = fixture(temp.path());
        let original = artifact_path(temp.path(), ArtifactFamily::Properties, "base-1").unwrap();
        let linked = artifact_path(temp.path(), ArtifactFamily::Properties, "linked").unwrap();
        fs::create_dir_all(linked.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(original, &linked).unwrap();
        candidate.graph.as_mut().unwrap().edge_properties.base.id = "linked".into();
        assert!(GraphGeneration::publish(temp.path(), None, candidate).is_err());
    }
}
