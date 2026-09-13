//! Versioned collection visibility overlays (property-graph paper Rev 3.4 §6.9).
//!
//! Point-location and future stable-EdgeId tombstones publish as one bundle.
//! Immutable segment markers never cover this directory: the complete next
//! version is synced first, then one `CURRENT` atomically selects it. Collection
//! readers pin the returned [`Arc<OverlaySet>`] through the collection read
//! state rather than reopening `CURRENT` during a query.

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use roaring::{RoaringBitmap, RoaringTreemap};

use crate::{
    GaussError, Result,
    encryption::{self, FileType, PersistentFile},
    graph::EdgeId,
    ordinal::SegmentOrdinalSet,
};

pub(crate) const OVERLAYS_DIR: &str = "overlays";
pub(crate) const CURRENT_FILE: &str = "CURRENT";
const BUNDLE_FILE: &str = "bundle.gdx";
const POINTS_DIR: &str = "points";
const EDGES_FILE: &str = "edges.roar";
const MAGIC: &[u8; 8] = b"GAUSOV01";
const FORMAT_VERSION: u32 = 1;
const FLAG_POINT_BITMAP: u32 = 1;
const FLAG_EDGE_BITMAP: u32 = 2;
const FLAG_BUNDLE: u32 = 3;
const SECTION_PAYLOAD: u32 = 1;
const SECTION_COUNT: u32 = 1;
const COMMON_HEADER_BYTES: usize = 32;
const SECTION_BYTES: usize = 32;
const ARTIFACT_HEADER_BYTES: usize = COMMON_HEADER_BYTES + SECTION_BYTES;
const MAX_OVERLAY_FILE_BYTES: usize = 1024 * 1024 * 1024;
const MAX_OVERLAY_SEGMENTS: usize = 65_536;
const MAX_CURRENT_BYTES: u64 = 64;
const MAX_SEGMENT_ID_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OverlayOpenMode {
    Recover,
    ResetToSegmentBase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OverlaySet {
    version: u64,
    generation: u64,
    point_tombstones: SegmentOrdinalSet,
    edge_tombstones: RoaringTreemap,
}

/// One query-pinned view of mutable collection visibility.
///
/// `CURRENT` is consulted only while constructing this state. Point
/// tombstones are resolved from collection segment ids to direct bitmap
/// handles once, so sealed candidate loops never repeat the collection-wide
/// string lookup. Keeping the complete overlay alive also pins the matching
/// future EdgeId tombstone set at the same publication version.
#[derive(Clone, Debug)]
pub(crate) struct OverlayReadState {
    overlay: Arc<OverlaySet>,
    point_tombstones: Vec<Option<Arc<RoaringBitmap>>>,
}

impl OverlayReadState {
    pub(crate) fn generation(&self) -> u64 {
        self.overlay.generation
    }

    pub(crate) fn point_tombstones(&self, searcher_index: usize) -> Option<&RoaringBitmap> {
        // The direct bitmap handles below pin their payloads; retaining this
        // Arc additionally pins the matching edge tombstones and bundle
        // version as the single visibility authority.
        let _pinned_bundle = &self.overlay;
        self.point_tombstones
            .get(searcher_index)
            .and_then(Option::as_deref)
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "consumed by the G0 traversal slice")
    )]
    pub(crate) fn edge_is_tombstoned(&self, edge_id: EdgeId) -> bool {
        self.overlay.edge_tombstones.contains(edge_id.raw())
    }

    pub(crate) fn version(&self) -> u64 {
        self.overlay.version
    }

    #[cfg(test)]
    pub(crate) fn point_segment_count(&self) -> usize {
        self.point_tombstones
            .iter()
            .filter(|bitmap| bitmap.is_some())
            .count()
    }
}

impl OverlaySet {
    fn new(
        version: u64,
        generation: u64,
        point_tombstones: SegmentOrdinalSet,
        edge_tombstones: RoaringTreemap,
    ) -> Self {
        Self {
            version,
            generation,
            point_tombstones,
            edge_tombstones,
        }
    }

    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn point_tombstones(&self) -> &SegmentOrdinalSet {
        &self.point_tombstones
    }

    pub(crate) fn edge_tombstones(&self) -> &RoaringTreemap {
        &self.edge_tombstones
    }
}

#[derive(Debug)]
pub(crate) struct OverlayStore {
    root: PathBuf,
    current: Arc<OverlaySet>,
    dirty: bool,
    next_version: u64,
}

impl OverlayStore {
    /// Resume from the sole graph manifest's pinned visibility, never from a
    /// later CURRENT or mutable segment tombstone sidecar. WAL replay applies
    /// the tail, allocating above every on-disk version before any write.
    pub(crate) fn from_graph_manifest(
        collection_dir: &Path,
        snapshot: Arc<OverlaySet>,
    ) -> Result<Self> {
        let root = collection_dir.join(OVERLAYS_DIR);
        let next_version = next_overlay_version(&root)?;
        Ok(Self {
            root,
            current: snapshot,
            dirty: false,
            next_version,
        })
    }

    pub(crate) fn open(
        collection_dir: &Path,
        generation: u64,
        installed_segments: &HashSet<String>,
        segment_base: SegmentOrdinalSet,
        mode: OverlayOpenMode,
    ) -> Result<Self> {
        let root = collection_dir.join(OVERLAYS_DIR);
        fs::create_dir_all(&root)?;
        let next_version = next_overlay_version(&root)?;
        let loaded = match mode {
            OverlayOpenMode::Recover => load_current(&root)?,
            OverlayOpenMode::ResetToSegmentBase => None,
        };
        let (mut points, edges, requires_publish) = match loaded.as_ref() {
            Some(loaded) if loaded.generation == generation => {
                let mut points = loaded.point_tombstones.clone();
                points.retain_segments(|segment| installed_segments.contains(segment));
                let before = points.clone();
                points.union_with(&segment_base);
                let changed = before != points;
                (points, loaded.edge_tombstones.clone(), changed)
            }
            Some(_) => (segment_base, RoaringTreemap::new(), true),
            None => (segment_base, RoaringTreemap::new(), true),
        };
        points.retain_segments(|segment| installed_segments.contains(segment));

        let version = if requires_publish {
            next_version
        } else {
            loaded
                .as_ref()
                .expect("unchanged overlay came from CURRENT")
                .version
        };
        let mut store = Self {
            root,
            current: Arc::new(OverlaySet::new(version, generation, points, edges)),
            dirty: requires_publish,
            next_version: if requires_publish {
                version
                    .checked_add(1)
                    .ok_or_else(|| invalid("overlay version overflow"))?
            } else {
                next_version
            },
        };
        store.publish_pending()?;
        Ok(store)
    }

    pub(crate) fn current(&self) -> Arc<OverlaySet> {
        Arc::clone(&self.current)
    }

    pub(crate) fn current_ref(&self) -> &OverlaySet {
        &self.current
    }

    /// Pin one overlay version and resolve its point bitmaps to the current
    /// searcher order. An empty point overlay retains no per-segment vector,
    /// making the common all-visible path allocation-free apart from the
    /// single `Arc` snapshot pin.
    pub(crate) fn read_state<'a>(
        &self,
        segment_ids: impl ExactSizeIterator<Item = &'a str>,
    ) -> OverlayReadState {
        let overlay = self.current();
        let point_tombstones = if overlay.point_tombstones.is_empty() {
            Vec::new()
        } else {
            let mut resolved = Vec::with_capacity(segment_ids.len());
            resolved
                .extend(segment_ids.map(|segment| overlay.point_tombstones.bitmap_arc(segment)));
            resolved
        };
        OverlayReadState {
            overlay,
            point_tombstones,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(crate) fn tombstone_point(&mut self, segment: &str, ordinal: u32) -> Result<bool> {
        validate_segment_id(segment)?;
        if self.current.point_tombstones.contains(segment, ordinal) {
            return Ok(false);
        }
        let mut points = self.current.point_tombstones.clone();
        points.insert(segment.to_string(), ordinal);
        self.install_pending(
            self.current.generation,
            points,
            self.current.edge_tombstones.clone(),
        )?;
        Ok(true)
    }

    pub(crate) fn reconcile_points(&mut self, points: &SegmentOrdinalSet) -> Result<bool> {
        let mut reconciled = self.current.point_tombstones.clone();
        reconciled.union_with(points);
        if reconciled == self.current.point_tombstones {
            return Ok(false);
        }
        self.install_pending(
            self.current.generation,
            reconciled,
            self.current.edge_tombstones.clone(),
        )?;
        Ok(true)
    }

    /// Replace the complete active-epoch EdgeId visibility set. G0 has no
    /// sealed graph base yet, so recovery reconstructs this exact bitmap from
    /// the WAL-owned mutable ledger. G1 will supply the sealed+delta union to
    /// the same publication boundary.
    pub(crate) fn replace_edges(&mut self, edges: &RoaringTreemap) -> Result<bool> {
        validate_edge_tombstones(edges)?;
        if edges == &self.current.edge_tombstones {
            return Ok(false);
        }
        self.install_pending(
            self.current.generation,
            self.current.point_tombstones.clone(),
            edges.clone(),
        )?;
        Ok(true)
    }

    pub(crate) fn replace_generation(
        &mut self,
        generation: u64,
        point_tombstones: SegmentOrdinalSet,
    ) -> Result<()> {
        self.install_pending(generation, point_tombstones, RoaringTreemap::new())
    }

    pub(crate) fn advance_generation(
        &mut self,
        generation: u64,
        point_tombstones: SegmentOrdinalSet,
    ) -> Result<()> {
        self.install_pending(
            generation,
            point_tombstones,
            self.current.edge_tombstones.clone(),
        )
    }

    pub(crate) fn restore_snapshot(&mut self, snapshot: &OverlaySet) -> Result<()> {
        self.install_pending(
            snapshot.generation,
            snapshot.point_tombstones.clone(),
            snapshot.edge_tombstones.clone(),
        )?;
        self.publish_pending()
    }

    fn install_pending(
        &mut self,
        generation: u64,
        points: SegmentOrdinalSet,
        edges: RoaringTreemap,
    ) -> Result<()> {
        let version = if self.dirty {
            self.current.version
        } else {
            let version = self.next_version;
            self.next_version = self
                .next_version
                .checked_add(1)
                .ok_or_else(|| invalid("overlay version overflow"))?;
            version
        };
        self.current = Arc::new(OverlaySet::new(version, generation, points, edges));
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn publish_pending(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        publish(&self.root, &self.current)?;
        self.dirty = false;
        Ok(())
    }

    /// Reserve a frozen generation without changing live visibility or CURRENT.
    /// Later tail mutations must never reuse this immutable version.
    pub(crate) fn stage_cut(
        &mut self,
        generation: u64,
        points: SegmentOrdinalSet,
    ) -> Result<Arc<OverlaySet>> {
        let cut = self.prepare_generation(generation, points)?;
        stage_version(&self.root, &cut)?;
        if load_version(&self.root, cut.version)? != *cut {
            return Err(corruption(
                &self.root,
                "staged cut differs from frozen visibility",
            ));
        }
        Ok(cut)
    }

    /// Stage the exact visibility bundle owned by a replacement generation.
    /// Compaction physically removes every visibility record supplied here as
    /// absent, so it must not inherit the current generation's tombstones.
    pub(crate) fn stage_replacement_generation(
        &mut self,
        generation: u64,
        points: SegmentOrdinalSet,
        edges: RoaringTreemap,
    ) -> Result<Arc<OverlaySet>> {
        let replacement = self.prepare_replacement_generation(generation, points, edges)?;
        stage_version(&self.root, &replacement)?;
        if load_version(&self.root, replacement.version)? != *replacement {
            return Err(corruption(
                &self.root,
                "staged replacement differs from frozen visibility",
            ));
        }
        Ok(replacement)
    }

    /// Reserve runtime tail visibility before a manifest commit; installation
    /// after commit is infallible and does not touch CURRENT until requested.
    pub(crate) fn prepare_generation(
        &mut self,
        generation: u64,
        points: SegmentOrdinalSet,
    ) -> Result<Arc<OverlaySet>> {
        self.prepare_replacement_generation(
            generation,
            points,
            self.current.edge_tombstones.clone(),
        )
    }

    pub(crate) fn prepare_replacement_generation(
        &mut self,
        generation: u64,
        points: SegmentOrdinalSet,
        edges: RoaringTreemap,
    ) -> Result<Arc<OverlaySet>> {
        validate_edge_tombstones(&edges)?;
        let version = self.next_version;
        self.next_version = version
            .checked_add(1)
            .ok_or_else(|| invalid("overlay version overflow"))?;
        Ok(Arc::new(OverlaySet::new(
            version, generation, points, edges,
        )))
    }

    pub(crate) fn install_prepared(&mut self, prepared: Arc<OverlaySet>) {
        self.current = prepared;
        self.dirty = true;
    }

    /// Durably stage an immutable bundle for a graph manifest switch without
    /// advancing CURRENT. Further mutations must allocate a new version.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "graph generation publication integration")
    )]
    pub(crate) fn stage_pending(&mut self) -> Result<Arc<OverlaySet>> {
        stage_version(&self.root, &self.current)?;
        if load_version(&self.root, self.current.version)? != *self.current {
            return Err(corruption(
                &self.root,
                "staged overlay differs from candidate visibility",
            ));
        }
        self.dirty = false;
        Ok(self.current())
    }
}

fn next_overlay_version(root: &Path) -> Result<u64> {
    let mut maximum = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let version = name
            .parse::<u64>()
            .map_err(|_| corruption(&entry.path(), "unknown overlay version directory"))?;
        maximum = maximum.max(version);
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| invalid("overlay version overflow"))
}

fn load_current(root: &Path) -> Result<Option<OverlaySet>> {
    let current_path = root.join(CURRENT_FILE);
    let _metadata = match fs::metadata(&current_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bytes = encryption::read_persistent(&current_path)?;
    if bytes.len() as u64 > MAX_CURRENT_BYTES {
        return Err(corruption(
            &current_path,
            "overlay CURRENT exceeds size cap",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| corruption(&current_path, "overlay CURRENT is not UTF-8"))?;
    let version = text
        .trim()
        .parse::<u64>()
        .map_err(|_| corruption(&current_path, "overlay CURRENT is not a version"))?;
    load_version(root, version).map(Some)
}

fn load_version(root: &Path, version: u64) -> Result<OverlaySet> {
    load_version_for_segments(root, version, None)
}

fn load_version_for_segments(
    root: &Path,
    version: u64,
    installed_segments: Option<&HashSet<String>>,
) -> Result<OverlaySet> {
    let dir = root.join(version_name(version));
    let bundle_path = dir.join(BUNDLE_FILE);
    let bundle = read_artifact(&bundle_path, FLAG_BUNDLE)?;
    let (stored_version, generation, segments) = decode_bundle_metadata(&bundle.payload)
        .map_err(|error| corruption(&bundle_path, &format!("overlay bundle metadata: {error}")))?;
    if stored_version != version {
        return Err(corruption(
            &bundle_path,
            "overlay directory and bundle version disagree",
        ));
    }
    if bundle.elem_count != segments.len() as u64 {
        return Err(corruption(
            &bundle_path,
            "overlay bundle segment count disagrees with section metadata",
        ));
    }
    if installed_segments.is_some_and(|installed| segments.iter().any(|id| !installed.contains(id)))
    {
        return Err(corruption(
            &bundle_path,
            "manifest overlay references an uninstalled segment",
        ));
    }
    validate_version_directory(&dir, &segments)?;

    let mut point_tombstones = SegmentOrdinalSet::new();
    for segment in &segments {
        let point_path = dir.join(POINTS_DIR).join(format!("{segment}.roar"));
        let artifact = read_artifact(&point_path, FLAG_POINT_BITMAP)?;
        let bitmap = RoaringBitmap::deserialize_from(Cursor::new(artifact.payload))
            .map_err(|error| corruption(&point_path, &format!("point bitmap: {error}")))?;
        if bitmap.len() != artifact.elem_count {
            return Err(corruption(
                &point_path,
                "point bitmap cardinality disagrees with artifact header",
            ));
        }
        point_tombstones.insert_bitmap(segment.clone(), bitmap);
    }
    let edge_path = dir.join(EDGES_FILE);
    let edge_artifact = read_artifact(&edge_path, FLAG_EDGE_BITMAP)?;
    let edge_tombstones = RoaringTreemap::deserialize_from(Cursor::new(edge_artifact.payload))
        .map_err(|error| corruption(&edge_path, &format!("edge bitmap: {error}")))?;
    if edge_tombstones.len() != edge_artifact.elem_count {
        return Err(corruption(
            &edge_path,
            "edge bitmap cardinality disagrees with artifact header",
        ));
    }
    validate_edge_tombstones(&edge_tombstones)
        .map_err(|error| corruption(&edge_path, &error.to_string()))?;
    Ok(OverlaySet::new(
        version,
        generation,
        point_tombstones,
        edge_tombstones,
    ))
}

/// Read the exact immutable visibility bundle selected by a graph manifest.
/// CURRENT may lead or lag a generation switch and is deliberately not read.
/// This path never repairs, filters, unions, or publishes visibility state.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "G1 manifest-pinned recovery integration pending")
)]
pub(crate) fn open_manifest_version(
    collection_dir: &Path,
    version: u64,
    generation: u64,
    installed_segments: &HashSet<String>,
) -> Result<Arc<OverlaySet>> {
    let root = collection_dir.join(OVERLAYS_DIR);
    if version == 0 {
        return Err(corruption(
            &root,
            "graph manifest selects zero overlay version",
        ));
    }
    let overlay = load_version_for_segments(&root, version, Some(installed_segments))?;
    if overlay.generation != generation {
        return Err(corruption(
            &root,
            "manifest and overlay generations disagree",
        ));
    }
    Ok(Arc::new(overlay))
}

fn validate_edge_tombstones(edges: &RoaringTreemap) -> Result<()> {
    if let Some(raw) = edges.iter().find(|raw| {
        let edge_id = EdgeId::from_raw(*raw);
        EdgeId::from_parts(edge_id.epoch(), edge_id.counter()) != Some(edge_id)
    }) {
        return Err(invalid(&format!(
            "edge tombstone bitmap contains invalid EdgeId {raw}"
        )));
    }
    Ok(())
}

fn publish(root: &Path, overlay: &OverlaySet) -> Result<()> {
    stage_version(root, overlay)?;
    encryption::atomic_write_persistent(
        &root.join(CURRENT_FILE),
        FileType::Metadata,
        format!("{}\n", overlay.version).as_bytes(),
    )?;
    Ok(())
}

fn stage_version(root: &Path, overlay: &OverlaySet) -> Result<()> {
    let final_dir = root.join(version_name(overlay.version));
    let tmp_dir = root.join(format!(
        ".{}.tmp-{}",
        version_name(overlay.version),
        std::process::id()
    ));
    if final_dir.exists() {
        // A failed sync/CURRENT write may leave the exact immutable version
        // durable. Retry may reuse it, but never overwrite different state.
        if load_version(root, overlay.version)? != *overlay {
            return Err(corruption(
                &final_dir,
                "refusing to overwrite a different overlay version",
            ));
        }
        return crate::seal::sync_directory(root);
    }
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::create_dir_all(tmp_dir.join(POINTS_DIR))?;

    let mut segments = overlay
        .point_tombstones
        .iter()
        .map(|(segment, _)| segment.to_string())
        .collect::<Vec<_>>();
    segments.sort();
    if segments.len() > MAX_OVERLAY_SEGMENTS {
        return Err(invalid("overlay segment count exceeds fixed cap"));
    }
    for segment in &segments {
        validate_segment_id(segment)?;
        let bitmap = overlay
            .point_tombstones
            .bitmap(segment)
            .expect("segment came from overlay bitmap keys");
        let mut payload = Vec::with_capacity(bitmap.serialized_size());
        bitmap.serialize_into(&mut payload)?;
        let artifact = encode_artifact(FLAG_POINT_BITMAP, bitmap.len(), &payload)?;
        encryption::atomic_write_persistent(
            &tmp_dir.join(POINTS_DIR).join(format!("{segment}.roar")),
            FileType::Segment,
            &artifact,
        )?;
    }
    let mut edge_payload = Vec::with_capacity(overlay.edge_tombstones.serialized_size());
    overlay.edge_tombstones.serialize_into(&mut edge_payload)?;
    let edge_artifact = encode_artifact(
        FLAG_EDGE_BITMAP,
        overlay.edge_tombstones.len(),
        &edge_payload,
    )?;
    encryption::atomic_write_persistent(
        &tmp_dir.join(EDGES_FILE),
        FileType::Segment,
        &edge_artifact,
    )?;
    let metadata = encode_bundle_metadata(overlay.version, overlay.generation, &segments)?;
    let bundle = encode_artifact(FLAG_BUNDLE, segments.len() as u64, &metadata)?;
    encryption::atomic_write_persistent(&tmp_dir.join(BUNDLE_FILE), FileType::Segment, &bundle)?;
    crate::seal::sync_directory(&tmp_dir.join(POINTS_DIR))?;
    crate::seal::sync_directory(&tmp_dir)?;
    fs::rename(&tmp_dir, &final_dir)?;
    crate::seal::sync_directory(root)?;
    Ok(())
}

fn version_name(version: u64) -> String {
    format!("{version:020}")
}

fn validate_segment_id(segment: &str) -> Result<()> {
    if segment.is_empty()
        || segment.len() > MAX_SEGMENT_ID_BYTES
        || !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid("invalid segment id in visibility overlay"));
    }
    Ok(())
}

fn validate_version_directory(dir: &Path, segments: &[String]) -> Result<()> {
    let expected_root = BTreeSet::from([
        BUNDLE_FILE.to_string(),
        EDGES_FILE.to_string(),
        POINTS_DIR.to_string(),
    ]);
    let actual_root = fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if actual_root != expected_root {
        return Err(corruption(
            dir,
            "overlay version contains unknown artifact groups",
        ));
    }
    let expected_points = segments
        .iter()
        .map(|segment| format!("{segment}.roar"))
        .collect::<BTreeSet<_>>();
    let points_dir = dir.join(POINTS_DIR);
    let actual_points = fs::read_dir(&points_dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if actual_points != expected_points {
        return Err(corruption(
            &points_dir,
            "overlay point group disagrees with bundle manifest",
        ));
    }
    Ok(())
}

fn encode_bundle_metadata(version: u64, generation: u64, segments: &[String]) -> Result<Vec<u8>> {
    let count =
        u32::try_from(segments.len()).map_err(|_| invalid("overlay segment count exceeds u32"))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&version.to_le_bytes());
    payload.extend_from_slice(&generation.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    for segment in segments {
        validate_segment_id(segment)?;
        let len =
            u16::try_from(segment.len()).map_err(|_| invalid("overlay segment id exceeds u16"))?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(segment.as_bytes());
    }
    Ok(payload)
}

fn decode_bundle_metadata(payload: &[u8]) -> Result<(u64, u64, Vec<String>)> {
    let mut cursor = Cursor::new(payload);
    let version = read_u64(&mut cursor, "overlay version")?;
    let generation = read_u64(&mut cursor, "overlay generation")?;
    let count = read_u32(&mut cursor, "overlay segment count")? as usize;
    if count > MAX_OVERLAY_SEGMENTS {
        return Err(invalid("overlay segment count exceeds fixed cap"));
    }
    let mut segments = Vec::with_capacity(count);
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let len = read_u16(&mut cursor, "overlay segment id length")? as usize;
        if len == 0 || len > MAX_SEGMENT_ID_BYTES {
            return Err(invalid("overlay segment id length exceeds fixed cap"));
        }
        let mut bytes = vec![0_u8; len];
        cursor.read_exact(&mut bytes)?;
        let segment =
            String::from_utf8(bytes).map_err(|_| invalid("overlay segment id is not UTF-8"))?;
        validate_segment_id(&segment)?;
        if previous.as_ref().is_some_and(|value| value >= &segment) {
            return Err(invalid("overlay segment ids are not strictly sorted"));
        }
        previous = Some(segment.clone());
        segments.push(segment);
    }
    if cursor.position() as usize != payload.len() {
        return Err(invalid("overlay bundle has trailing metadata bytes"));
    }
    Ok((version, generation, segments))
}

struct DecodedArtifact {
    elem_count: u64,
    payload: Vec<u8>,
}

fn encode_artifact(flags: u32, elem_count: u64, payload: &[u8]) -> Result<Vec<u8>> {
    validate_flags(flags)?;
    let payload_len = payload
        .len()
        .checked_add(std::mem::size_of::<u32>())
        .ok_or_else(|| invalid("overlay payload length overflow"))?;
    let file_len = ARTIFACT_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| invalid("overlay file length overflow"))?;
    if file_len > MAX_OVERLAY_FILE_BYTES {
        return Err(invalid("overlay artifact exceeds fixed size cap"));
    }
    let file_len_u64 = u64::try_from(file_len).map_err(|_| invalid("overlay file too large"))?;
    let payload_len_u64 =
        u64::try_from(payload_len).map_err(|_| invalid("overlay payload too large"))?;
    let mut prefix = Vec::with_capacity(28);
    prefix.extend_from_slice(MAGIC);
    prefix.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    prefix.extend_from_slice(&flags.to_le_bytes());
    prefix.extend_from_slice(&file_len_u64.to_le_bytes());
    prefix.extend_from_slice(&SECTION_COUNT.to_le_bytes());
    let mut section = Vec::with_capacity(SECTION_BYTES);
    section.extend_from_slice(&SECTION_PAYLOAD.to_le_bytes());
    section.extend_from_slice(&0_u32.to_le_bytes());
    section.extend_from_slice(&(ARTIFACT_HEADER_BYTES as u64).to_le_bytes());
    section.extend_from_slice(&payload_len_u64.to_le_bytes());
    section.extend_from_slice(&elem_count.to_le_bytes());
    let mut header_crc_input = prefix.clone();
    header_crc_input.extend_from_slice(&section);
    let header_crc = crc_fast::crc32_iscsi(&header_crc_input);
    let mut bytes = Vec::with_capacity(file_len);
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(&header_crc.to_le_bytes());
    bytes.extend_from_slice(&section);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&crc_fast::crc32_iscsi(payload).to_le_bytes());
    Ok(bytes)
}

fn read_artifact(path: &Path, expected_flags: u32) -> Result<DecodedArtifact> {
    let file = PersistentFile::open(path)?;
    if file.len() < ARTIFACT_HEADER_BYTES || file.len() > MAX_OVERLAY_FILE_BYTES {
        return Err(corruption(
            path,
            "overlay artifact length violates fixed limits",
        ));
    }
    let header = file.read_range(0..ARTIFACT_HEADER_BYTES)?;
    if &header[..8] != MAGIC {
        return Err(corruption(path, "bad overlay magic"));
    }
    let version = u32::from_le_bytes(header[8..12].try_into().expect("overlay version"));
    if version != FORMAT_VERSION {
        return Err(corruption(path, "unsupported overlay format version"));
    }
    let flags = u32::from_le_bytes(header[12..16].try_into().expect("overlay flags"));
    validate_flags(flags).map_err(|_| corruption(path, "unknown overlay artifact group"))?;
    if flags != expected_flags {
        return Err(corruption(path, "overlay artifact group mismatch"));
    }
    let file_len = u64::from_le_bytes(header[16..24].try_into().expect("overlay file length"));
    if file_len != file.len() as u64 {
        return Err(corruption(path, "overlay file length mismatch"));
    }
    let section_count =
        u32::from_le_bytes(header[24..28].try_into().expect("overlay section count"));
    if section_count != SECTION_COUNT {
        return Err(corruption(path, "unsupported overlay section count"));
    }
    let expected_header_crc =
        u32::from_le_bytes(header[28..32].try_into().expect("overlay header CRC"));
    let mut header_crc_input = Vec::with_capacity(28 + SECTION_BYTES);
    header_crc_input.extend_from_slice(&header[..28]);
    header_crc_input.extend_from_slice(&header[32..ARTIFACT_HEADER_BYTES]);
    if crc_fast::crc32_iscsi(&header_crc_input) != expected_header_crc {
        return Err(corruption(path, "overlay header CRC32C mismatch"));
    }
    let section = &header[32..ARTIFACT_HEADER_BYTES];
    let section_id = u32::from_le_bytes(section[0..4].try_into().expect("overlay section id"));
    let section_flags =
        u32::from_le_bytes(section[4..8].try_into().expect("overlay section flags"));
    let offset = u64::from_le_bytes(section[8..16].try_into().expect("overlay section offset"));
    let length = u64::from_le_bytes(section[16..24].try_into().expect("overlay section length"));
    let elem_count = u64::from_le_bytes(section[24..32].try_into().expect("overlay element count"));
    if section_id != SECTION_PAYLOAD || section_flags != 0 || offset != ARTIFACT_HEADER_BYTES as u64
    {
        return Err(corruption(path, "unsupported overlay section table"));
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| corruption(path, "overlay section range overflow"))?;
    if end != file_len || length < 4 {
        return Err(corruption(path, "overlay section range mismatch"));
    }
    let section_bytes = file.read_range(offset as usize..end as usize)?;
    let payload_len = section_bytes.len() - 4;
    let expected_payload_crc = u32::from_le_bytes(
        section_bytes[payload_len..]
            .try_into()
            .expect("overlay payload CRC"),
    );
    let payload = &section_bytes[..payload_len];
    if crc_fast::crc32_iscsi(payload) != expected_payload_crc {
        return Err(corruption(path, "overlay payload CRC32C mismatch"));
    }
    Ok(DecodedArtifact {
        elem_count,
        payload: payload.to_vec(),
    })
}

fn validate_flags(flags: u32) -> Result<()> {
    match flags {
        FLAG_POINT_BITMAP | FLAG_EDGE_BITMAP | FLAG_BUNDLE => Ok(()),
        _ => Err(invalid("unknown overlay artifact group")),
    }
}

fn read_u16(reader: &mut impl Read, field: &str) -> Result<u16> {
    let mut bytes = [0_u8; 2];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| invalid(&format!("truncated {field}: {error}")))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(reader: &mut impl Read, field: &str) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| invalid(&format!("truncated {field}: {error}")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read, field: &str) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| invalid(&format!("truncated {field}: {error}")))?;
    Ok(u64::from_le_bytes(bytes))
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.to_string())
}

fn corruption(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use roaring::RoaringTreemap;

    use super::{
        CURRENT_FILE, FLAG_POINT_BITMAP, OverlayOpenMode, OverlayStore, load_current, read_artifact,
    };
    use crate::{graph::EdgeId, ordinal::SegmentOrdinalSet};

    #[test]
    fn manifest_selected_overlay_rejects_missing_or_mismatched_state_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        assert!(super::open_manifest_version(temp.path(), 1, 7, &HashSet::new()).is_err());
        assert!(!temp.path().join("overlays").exists());
        let installed = HashSet::from(["sg-1".to_string()]);
        let mut points = SegmentOrdinalSet::new();
        points.insert("sg-1", 2);
        let store =
            OverlayStore::open(temp.path(), 7, &installed, points, OverlayOpenMode::Recover)
                .unwrap();
        let current = fs::read(temp.path().join("overlays/CURRENT")).unwrap();
        let version = store.current().version();
        for (version, generation, installed) in [
            (0, 7, installed.clone()),
            (version + 1, 7, installed.clone()),
            (version, 8, installed.clone()),
            (version, 7, HashSet::new()),
        ] {
            assert!(
                super::open_manifest_version(temp.path(), version, generation, &installed).is_err()
            );
            assert_eq!(
                fs::read(temp.path().join("overlays/CURRENT")).unwrap(),
                current
            );
        }
        let bundle = temp
            .path()
            .join(format!("overlays/{version:020}/bundle.gdx"));
        fs::remove_file(&bundle).unwrap();
        assert!(super::open_manifest_version(temp.path(), version, 7, &installed).is_err());
        assert!(!bundle.exists());
        assert_eq!(
            fs::read(temp.path().join("overlays/CURRENT")).unwrap(),
            current
        );
    }

    #[test]
    fn manifest_selected_overlay_checks_even_empty_declared_segment_groups() {
        let temp = tempfile::tempdir().unwrap();
        let store = OverlayStore::open(
            temp.path(),
            7,
            &HashSet::new(),
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        let version = store.current().version();
        let dir = temp
            .path()
            .join("overlays")
            .join(super::version_name(version));
        let payload = super::encode_bundle_metadata(version, 7, &["sg-unknown".into()]).unwrap();
        let bundle = super::encode_artifact(super::FLAG_BUNDLE, 1, &payload).unwrap();
        let mut empty = Vec::new();
        roaring::RoaringBitmap::new()
            .serialize_into(&mut empty)
            .unwrap();
        let point = super::encode_artifact(super::FLAG_POINT_BITMAP, 0, &empty).unwrap();
        fs::write(dir.join(super::BUNDLE_FILE), bundle).unwrap();
        fs::write(dir.join("points/sg-unknown.roar"), point).unwrap();
        // The ordinary loader elides empty bitmaps, so the manifest check
        // must inspect declared metadata rather than the resulting map.
        assert!(
            super::load_version(&temp.path().join("overlays"), version)
                .unwrap()
                .point_tombstones()
                .is_empty()
        );
        assert!(super::open_manifest_version(temp.path(), version, 7, &HashSet::new()).is_err());
    }

    #[test]
    fn staged_cut_and_prepared_tail_do_not_publish_or_mutate_live_visibility() {
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let mut store = OverlayStore::open(
            temp.path(),
            1,
            &HashSet::new(),
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        let before = store.current();
        let cut = store.stage_cut(2, SegmentOrdinalSet::new()).unwrap();
        assert!(Arc::ptr_eq(&before, &store.current()));
        assert_eq!(
            load_current(&temp.path().join("overlays")).unwrap(),
            Some((*before).clone())
        );
        let edges = RoaringTreemap::from_iter([EdgeId::from_parts(1, 7).unwrap().raw()]);
        store.replace_edges(&edges).unwrap();
        assert!(store.current().version() > cut.version());
        let tail_before = store.current();
        let tail = store
            .prepare_generation(2, SegmentOrdinalSet::new())
            .unwrap();
        assert!(Arc::ptr_eq(&tail_before, &store.current()));
        assert!(tail.version() > tail_before.version());
        store.install_prepared(tail);
        store.publish_pending().unwrap();
        assert_eq!(store.current().edge_tombstones(), &edges);
        assert_eq!(
            super::load_version(&temp.path().join("overlays"), cut.version()).unwrap(),
            *cut
        );
        assert!(cut.edge_tombstones().is_empty());
    }

    #[test]
    fn one_current_publishes_point_and_edge_visibility_together() {
        let temp = tempfile::tempdir().unwrap();
        let installed = HashSet::from(["sg-1".to_string()]);
        let mut base = SegmentOrdinalSet::new();
        base.insert("sg-1", 2);
        let mut store =
            OverlayStore::open(temp.path(), 7, &installed, base, OverlayOpenMode::Recover).unwrap();
        let first = store.current();
        assert!(first.point_tombstones().contains("sg-1", 2));
        assert!(first.edge_tombstones().is_empty());

        let edge_id = EdgeId::from_parts(1, 9).unwrap();
        let mut edges = RoaringTreemap::new();
        edges.insert(edge_id.raw());
        store.tombstone_point("sg-1", 9).unwrap();
        store.replace_edges(&edges).unwrap();
        assert!(store.is_dirty());
        assert_eq!(
            load_current(&temp.path().join("overlays")).unwrap(),
            Some((*first).clone())
        );
        store.publish_pending().unwrap();

        let reopened = OverlayStore::open(
            temp.path(),
            7,
            &installed,
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        assert!(reopened.current().point_tombstones().contains("sg-1", 9));
        assert!(reopened.current().edge_tombstones().contains(edge_id.raw()));
        assert!(temp.path().join("overlays").join(CURRENT_FILE).exists());
    }

    #[test]
    fn generation_replacement_drops_old_segment_tombstones() {
        let temp = tempfile::tempdir().unwrap();
        let installed = HashSet::from(["sg-old".to_string()]);
        let mut base = SegmentOrdinalSet::new();
        base.insert("sg-old", 1);
        OverlayStore::open(temp.path(), 3, &installed, base, OverlayOpenMode::Recover).unwrap();

        let replacement = OverlayStore::open(
            temp.path(),
            4,
            &HashSet::from(["sg-new".to_string()]),
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        assert_eq!(replacement.current().generation(), 4);
        assert!(replacement.current().point_tombstones().is_empty());
    }

    #[test]
    fn read_state_resolves_once_and_pins_its_overlay_version() {
        let temp = tempfile::tempdir().unwrap();
        let installed = HashSet::from(["sg-1".to_string()]);
        let mut store = OverlayStore::open(
            temp.path(),
            8,
            &installed,
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();

        let empty = store.read_state(["sg-1"].into_iter());
        let empty_version = empty.version();
        let first_edge = EdgeId::from_parts(1, 1).unwrap();
        let second_edge = EdgeId::from_parts(1, 2).unwrap();
        assert_eq!(empty.point_segment_count(), 0);
        assert!(empty.point_tombstones(0).is_none());
        assert!(!empty.edge_is_tombstoned(first_edge));

        store.tombstone_point("sg-1", 7).unwrap();
        let mut first_edges = RoaringTreemap::new();
        first_edges.insert(first_edge.raw());
        store.replace_edges(&first_edges).unwrap();
        store.publish_pending().unwrap();
        let updated = store.read_state(["sg-1"].into_iter());

        assert!(updated.version() > empty_version);
        assert!(empty.point_tombstones(0).is_none());
        assert!(
            updated
                .point_tombstones(0)
                .is_some_and(|bitmap| bitmap.contains(7))
        );
        assert!(!empty.edge_is_tombstoned(first_edge));
        assert!(updated.edge_is_tombstoned(first_edge));

        store.tombstone_point("sg-1", 11).unwrap();
        first_edges.insert(second_edge.raw());
        store.replace_edges(&first_edges).unwrap();
        let newest = store.read_state(["sg-1"].into_iter());
        assert!(
            !updated
                .point_tombstones(0)
                .is_some_and(|bitmap| bitmap.contains(11))
        );
        assert!(!updated.edge_is_tombstoned(second_edge));
        assert!(newest.edge_is_tombstoned(second_edge));
        assert!(
            newest
                .point_tombstones(0)
                .is_some_and(|bitmap| bitmap.contains(11))
        );
    }

    #[test]
    fn crc_corruption_and_unknown_groups_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let installed = HashSet::from(["sg-1".to_string()]);
        let mut base = SegmentOrdinalSet::new();
        base.insert("sg-1", 1);
        let store =
            OverlayStore::open(temp.path(), 1, &installed, base, OverlayOpenMode::Recover).unwrap();
        let point_path = temp
            .path()
            .join("overlays")
            .join(format!("{:020}", store.current().version()))
            .join("points/sg-1.roar");
        let mut bytes = fs::read(&point_path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        fs::write(&point_path, bytes).unwrap();
        assert!(read_artifact(&point_path, FLAG_POINT_BITMAP).is_err());

        fs::write(
            temp.path()
                .join("overlays")
                .join(format!("{:020}", store.current().version()))
                .join("unknown.gdx"),
            [],
        )
        .unwrap();
        assert!(
            OverlayStore::open(
                temp.path(),
                1,
                &installed,
                SegmentOrdinalSet::new(),
                OverlayOpenMode::Recover,
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_edge_identity_is_rejected_before_overlay_publication() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = OverlayStore::open(
            temp.path(),
            1,
            &HashSet::new(),
            SegmentOrdinalSet::new(),
            OverlayOpenMode::Recover,
        )
        .unwrap();
        let before = store.current();
        let mut invalid = RoaringTreemap::new();
        invalid.insert(0);

        assert!(store.replace_edges(&invalid).is_err());
        assert_eq!(store.current(), before);
        assert!(!store.is_dirty());
    }
}
