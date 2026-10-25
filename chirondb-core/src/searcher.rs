//! Immutable searcher segments (paper §VII.F / LS-Vec rework D3).
//!
//! A `SegmentSearcher` is one sealed, immutable segment served at query
//! time: its own index, its own point store, and its own tombstone set.
//! `Collection` holds a `Vec<SegmentSearcher>` (oldest → newest) and fans
//! queries out across all of them plus the mutable streamer, merging into
//! a global top-k — replacing the old single-`h2qg`-slot serving where
//! `load_searchers_from_dirs` overwrote one index per segment dir and only
//! the last survived.
//!
//! Legacy segments use `SegmentStore::Heap`; v4-v6/v8 hot segments keep
//! plaintext vectors mmap-backed and encrypted vectors range-backed, while
//! v7/v9 cold segments read through bounded DiskANN pages. V8/v9 named search
//! rows use scaled f16. Auxiliary records follow the same persistent reader.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use roaring::RoaringBitmap;

use crate::Point;
use crate::h2qg::H2qgIndex;

/// Which segment (or the streamer) currently owns a live point id.
/// A point id is live in exactly one place — upserting an existing id
/// tombstones its old location and inserts into the streamer, so query-time
/// dedup stays a plain seen-set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegLoc {
    /// Live in the active streamer.
    Streamer,
    /// Live in the frozen streamer currently being sealed.
    Sealing,
    /// Live in `Collection.searchers[i]`.
    Searcher(u32),
}

/// Per-segment dense index.
#[derive(Debug)]
pub enum SegmentIndex {
    /// Legacy single-segment format: the `h2qg.gdx` graph (flat or HNSW
    /// mode) read by `h2qg::read_index_paged`.
    LegacyH2qg(Box<H2qgIndex>),
    /// LS-Vec Algorithm 2 persisted cascade (`ivf.gdx` + `rabitq.gdx` +
    /// stitched `vamana.gdx`) over the shared mmap store.
    Ivf(Box<crate::index::ivf_segment::IvfSegmentIndex>),
    /// Segment has no dense index artifact (defensive: legacy dirs written
    /// before the index file existed). Queries fall back to a store scan.
    None,
}

impl SegmentIndex {
    pub fn as_backend(&self) -> Option<&dyn crate::index::IndexBackend> {
        match self {
            SegmentIndex::LegacyH2qg(h) => Some(h.as_ref() as &dyn crate::index::IndexBackend),
            SegmentIndex::Ivf(index) => Some(index.as_ref() as &dyn crate::index::IndexBackend),
            SegmentIndex::None => None,
        }
    }
}

/// Per-segment point store.
#[derive(Debug)]
pub enum SegmentStore {
    /// Legacy format: full points deserialized into heap, keyed by id —
    /// the same memory profile the old merged map had. Replaced by the
    /// mmap store for sealed segments in Phase 2.
    Heap(HashMap<String, Point>),
    /// V4+ format: immutable records are mmap-backed when plaintext and use
    /// bounded authenticated ranges when encrypted. DiskANN serves v7/v9 cold
    /// segments; only requested candidates become owned points.
    V4(Arc<crate::seal::V4Store>),
}

impl SegmentStore {
    pub fn get(&self, id: &str) -> Option<Cow<'_, Point>> {
        self.try_get(id).ok().flatten()
    }

    pub fn try_get(&self, id: &str) -> crate::Result<Option<Cow<'_, Point>>> {
        match self {
            SegmentStore::Heap(points) => Ok(points.get(id).map(Cow::Borrowed)),
            SegmentStore::V4(store) => store.try_get(id).map(|point| point.map(Cow::Owned)),
        }
    }

    pub(crate) fn try_get_admitted(
        &self,
        id: &str,
    ) -> crate::Result<Option<crate::seal::AdmittedPoint>> {
        match self {
            SegmentStore::Heap(points) => points
                .get(id)
                .map(crate::seal::AdmittedPoint::copy)
                .transpose(),
            SegmentStore::V4(store) => store.try_get_admitted(id),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            SegmentStore::Heap(points) => points.len(),
            SegmentStore::V4(store) => store.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cheap ID membership used to size multi-tier ANN overfetch without
    /// materialising a sealed point or reading its vector payload.
    pub(crate) fn contains_id(&self, id: &str) -> bool {
        match self {
            SegmentStore::Heap(points) => points.contains_key(id),
            SegmentStore::V4(store) => store.ordinal(id).is_some(),
        }
    }

    pub fn iter_points(&self) -> Box<dyn Iterator<Item = Cow<'_, Point>> + '_> {
        Box::new(self.try_iter_points().filter_map(crate::Result::ok))
    }

    pub fn try_iter_points(&self) -> Box<dyn Iterator<Item = crate::Result<Cow<'_, Point>>> + '_> {
        match self {
            SegmentStore::Heap(points) => {
                Box::new(points.values().map(|point| Ok(Cow::Borrowed(point))))
            }
            SegmentStore::V4(store) => Box::new(
                (0..store.len()).map(|ordinal| store.try_get_ordinal(ordinal).map(Cow::Owned)),
            ),
        }
    }

    pub(crate) fn iter_ids(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            SegmentStore::Heap(points) => Box::new(points.keys().map(String::as_str)),
            SegmentStore::V4(store) => Box::new(store.ids().iter().map(String::as_str)),
        }
    }

    pub(crate) fn iter_aux_index_points(
        &self,
    ) -> Box<dyn Iterator<Item = crate::Result<Cow<'_, Point>>> + '_> {
        match self {
            SegmentStore::Heap(points) => {
                Box::new(points.values().map(|point| Ok(Cow::Borrowed(point))))
            }
            SegmentStore::V4(store) => Box::new(
                (0..store.len())
                    .map(|ordinal| store.get_ordinal_for_aux_indexes(ordinal).map(Cow::Owned)),
            ),
        }
    }

    fn ordinal_payload_index(
        &self,
    ) -> crate::Result<Option<crate::payload_index::OrdinalPayloadIndex>> {
        match self {
            SegmentStore::V4(store) => crate::payload_index::try_build_ordinal_payload_index(
                (0..store.len()).map(|ordinal| {
                    let ordinal_u32 = u32::try_from(ordinal).map_err(|_| {
                        crate::GaussError::InvalidRequest("payload ordinal exceeds u32".into())
                    })?;
                    store
                        .get_ordinal_for_aux_indexes(ordinal)
                        .map(|point| (ordinal_u32, point))
                }),
            )
            .map(Some),
            SegmentStore::Heap(_) => Ok(None),
        }
    }
}

/// One sealed, immutable segment served at query time.
#[derive(Debug)]
pub struct SegmentSearcher {
    pub id: String,
    pub dir: PathBuf,
    pub index: SegmentIndex,
    /// Per-named-vector-field indexes for this segment.
    pub named_index: HashMap<String, SegmentIndex>,
    pub store: SegmentStore,
    /// Ordinal-native payload postings for current sealed stores. Legacy heap
    /// segments retain the collection's string-keyed compatibility index.
    pub(crate) ordinal_payload_index: Option<crate::payload_index::OrdinalPayloadIndex>,
    /// Ids deleted (or superseded by a newer upsert) since this segment was
    /// sealed. Consulted at query time; folded into `tomb.gdx` and dropped
    /// at the next merge compaction.
    pub tombstones: HashSet<String>,
    /// Canonical visibility mask for stores with stable ordinals. The string
    /// set above remains as the compatibility view until the collection-level
    /// P0 overlay migration owns publication.
    pub tombstone_ordinals: RoaringBitmap,
}

impl SegmentSearcher {
    pub fn from_loaded(
        loaded: crate::segment::LoadedSegment,
        metric: crate::DistanceMetric,
    ) -> crate::Result<Self> {
        let crate::segment::LoadedSegment {
            id,
            dir,
            points,
            h2qg,
            named_h2qg,
            payload_index: _,
            v4_store,
            tombstones,
            tombstone_ordinals,
        } = loaded;
        let algorithm2 = dir.join(crate::index::ivf::IVF_FILE).exists();
        let v4_store = v4_store.map(Arc::new);
        let index =
            if algorithm2 {
                let store = v4_store.as_ref().cloned().ok_or_else(|| {
                    crate::GaussError::SegmentCorruption {
                        path: dir.display().to_string(),
                        message: "Algorithm 2 index requires a v4 store".to_string(),
                    }
                })?;
                let cold = dir.parent().is_some_and(|parent| {
                    parent
                        .file_name()
                        .is_some_and(|name| name == std::ffi::OsStr::new("cold"))
                });
                let index = if cold && store.diskann().is_some() {
                    crate::index::ivf_segment::IvfSegmentIndex::open_cold(&dir, store, metric)?
                } else {
                    crate::index::ivf_segment::IvfSegmentIndex::open(&dir, store, metric)?
                };
                SegmentIndex::Ivf(Box::new(index))
            } else {
                match h2qg {
                    Some(h) => SegmentIndex::LegacyH2qg(Box::new(h)),
                    None => SegmentIndex::None,
                }
            };
        let store = match v4_store {
            Some(store) => SegmentStore::V4(store),
            None => SegmentStore::Heap(points),
        };
        let ordinal_payload_index = store.ordinal_payload_index()?;
        let named_index = if algorithm2 {
            load_named_algorithm2_indexes(&dir, metric)?
        } else {
            named_h2qg
                .into_iter()
                .map(|(name, index)| (name, SegmentIndex::LegacyH2qg(Box::new(index))))
                .collect()
        };
        Ok(Self {
            id,
            dir,
            index,
            named_index,
            store,
            ordinal_payload_index,
            tombstones,
            tombstone_ordinals,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: String,
        dir: PathBuf,
        index: SegmentIndex,
        named_index: HashMap<String, SegmentIndex>,
        store: SegmentStore,
        tombstones: HashSet<String>,
        tombstone_ordinals: RoaringBitmap,
    ) -> crate::Result<Self> {
        let ordinal_payload_index = store.ordinal_payload_index()?;
        Ok(Self {
            id,
            dir,
            index,
            named_index,
            store,
            ordinal_payload_index,
            tombstones,
            tombstone_ordinals,
        })
    }

    pub(crate) fn payload_ordinal_candidates(
        &self,
        filter: Option<&crate::Filter>,
        point_tombstones: Option<&RoaringBitmap>,
    ) -> Option<RoaringBitmap> {
        let mut candidates = crate::payload_index::payload_filter_ordinal_candidates(
            self.ordinal_payload_index.as_ref()?,
            filter,
        )?;
        if let Some(tombstones) = point_tombstones {
            candidates -= tombstones;
        }
        Some(candidates)
    }

    pub(crate) fn ordinal(&self, id: &str) -> Option<u32> {
        let SegmentStore::V4(store) = &self.store else {
            return None;
        };
        u32::try_from(store.ordinal(id)?).ok()
    }

    pub(crate) fn get_ordinal_visible(
        &self,
        ordinal: u32,
        point_tombstones: Option<&RoaringBitmap>,
    ) -> crate::Result<Option<Cow<'_, Point>>> {
        if point_tombstones.is_some_and(|tombstones| tombstones.contains(ordinal)) {
            return Ok(None);
        }
        match &self.store {
            SegmentStore::V4(store) => store
                .try_get_ordinal(ordinal as usize)
                .map(|point| Some(Cow::Owned(point))),
            SegmentStore::Heap(_) => Ok(None),
        }
    }

    pub(crate) fn tombstone(&mut self, id: &str) -> bool {
        let inserted = self.tombstones.insert(id.to_string());
        if let Some(ordinal) = self.ordinal(id) {
            self.tombstone_ordinals.insert(ordinal);
        }
        inserted
    }

    pub(crate) fn install_point_tombstones(&mut self, tombstones: &RoaringBitmap) {
        self.tombstone_ordinals |= tombstones;
        if let SegmentStore::V4(store) = &self.store {
            self.tombstones.extend(
                tombstones
                    .iter()
                    .filter_map(|ordinal| store.id(ordinal as usize).map(str::to_string)),
            );
        }
    }

    fn is_tombstoned(&self, id: &str) -> bool {
        self.ordinal(id)
            .is_some_and(|ordinal| self.tombstone_ordinals.contains(ordinal))
            || self.tombstones.contains(id)
    }

    fn is_hidden(&self, id: &str, point_tombstones: Option<&RoaringBitmap>) -> bool {
        match &self.store {
            SegmentStore::V4(store) => point_tombstones.is_some_and(|tombstones| {
                store
                    .ordinal(id)
                    .and_then(|ordinal| u32::try_from(ordinal).ok())
                    .is_some_and(|ordinal| tombstones.contains(ordinal))
            }),
            SegmentStore::Heap(_) => self.tombstones.contains(id),
        }
    }

    /// Index backend for the given (possibly named) vector field.
    pub fn backend_for(
        &self,
        vector_name: Option<&str>,
    ) -> Option<&dyn crate::index::IndexBackend> {
        match vector_name {
            Some(name) => self
                .named_index
                .get(name)
                .and_then(SegmentIndex::as_backend),
            None => self.index.as_backend(),
        }
    }

    /// Live (non-tombstoned) point lookup, retained for source compatibility.
    pub fn get_live(&self, id: &str) -> Option<Cow<'_, Point>> {
        self.try_get_live(id).ok().flatten()
    }

    pub fn try_get_live(&self, id: &str) -> crate::Result<Option<Cow<'_, Point>>> {
        if self.is_tombstoned(id) {
            return Ok(None);
        }
        self.read_point(id)
    }

    pub(crate) fn get_visible(
        &self,
        id: &str,
        point_tombstones: Option<&RoaringBitmap>,
    ) -> crate::Result<Option<Cow<'_, Point>>> {
        if self.is_hidden(id, point_tombstones) {
            return Ok(None);
        }
        self.read_point(id)
    }

    pub(crate) fn visible_ids<'a>(
        &'a self,
        tombstones: Option<&'a RoaringBitmap>,
    ) -> impl Iterator<Item = &'a str> {
        self.store
            .iter_ids()
            .filter(move |id| !self.is_hidden(id, tombstones))
    }

    pub(crate) fn get_live_admitted(
        &self,
        id: &str,
    ) -> crate::Result<Option<crate::search::CandidatePoint<'_>>> {
        if self.is_tombstoned(id) {
            return Ok(None);
        }
        self.read_point_admitted(id)
    }

    pub(crate) fn get_visible_admitted(
        &self,
        id: &str,
        tombstones: Option<&RoaringBitmap>,
    ) -> crate::Result<Option<crate::search::CandidatePoint<'_>>> {
        if self.is_hidden(id, tombstones) {
            return Ok(None);
        }
        self.read_point_admitted(id)
    }

    pub(crate) fn vector_visible(
        &self,
        id: &str,
        tombstones: Option<&RoaringBitmap>,
        name: Option<&str>,
    ) -> crate::Result<Option<crate::index::VectorRead<'_>>> {
        if !self.contains_visible(id, tombstones) {
            return Ok(None);
        }
        if name.is_none()
            && let SegmentStore::V4(store) = &self.store
        {
            let ordinal = store.ordinal(id).expect("visible ID has a store ordinal");
            if let SegmentIndex::Ivf(index) = &self.index
                && index.uses_diskann()
            {
                return index.diskann_vector_read(ordinal).map(Some);
            }
            return store.vector_cow(ordinal).map(Some);
        }
        match self.read_point_admitted(id)? {
            Some(point) => point.vector_read(name),
            None => Ok(None),
        }
    }

    fn read_point_admitted(
        &self,
        id: &str,
    ) -> crate::Result<Option<crate::search::CandidatePoint<'_>>> {
        use crate::search::CandidatePoint;
        if let (SegmentIndex::Ivf(index), SegmentStore::V4(store)) = (&self.index, &self.store)
            && index.uses_diskann()
        {
            let Some(ordinal) = store.ordinal(id) else {
                return Ok(None);
            };
            return store
                .get_ordinal_admitted_with(ordinal, || index.diskann_vector(ordinal))
                .map(|point| Some(CandidatePoint::Owned(point)));
        }
        match &self.store {
            SegmentStore::Heap(points) => Ok(points.get(id).map(CandidatePoint::Borrowed)),
            SegmentStore::V4(store) => store
                .try_get_admitted(id)
                .map(|point| point.map(CandidatePoint::Owned)),
        }
    }

    fn read_point(&self, id: &str) -> crate::Result<Option<Cow<'_, Point>>> {
        if let (SegmentIndex::Ivf(index), SegmentStore::V4(store)) = (&self.index, &self.store)
            && index.uses_diskann()
        {
            let Some(ordinal) = store.ordinal(id) else {
                return Ok(None);
            };
            let vector = index.diskann_vector(ordinal)?;
            return store
                .get_ordinal_with_vector(ordinal, vector)
                .map(|point| Some(Cow::Owned(point)));
        }
        self.store.try_get(id)
    }

    /// Read-state visibility without materializing a sealed point. Sparse
    /// postings use this until a filter or final response needs the payload.
    pub(crate) fn contains_visible(
        &self,
        id: &str,
        point_tombstones: Option<&RoaringBitmap>,
    ) -> bool {
        !self.is_hidden(id, point_tombstones) && self.store.contains_id(id)
    }

    pub fn live_len(&self) -> usize {
        self.store.len()
            - usize::try_from(self.tombstone_ordinals.len())
                .unwrap_or(usize::MAX)
                .max(self.tombstones.len())
    }

    /// Iterate live points, retained for source compatibility.
    pub fn iter_live(&self) -> Box<dyn Iterator<Item = Cow<'_, Point>> + '_> {
        Box::new(self.try_iter_live().filter_map(crate::Result::ok))
    }

    pub fn try_iter_live(&self) -> Box<dyn Iterator<Item = crate::Result<Cow<'_, Point>>> + '_> {
        Box::new(
            self.store
                .iter_ids()
                .filter(|id| !self.is_tombstoned(id))
                .map(|id| {
                    self.read_point(id).and_then(|point| {
                        point.ok_or_else(|| crate::GaussError::PointNotFound(id.to_owned()))
                    })
                }),
        )
    }

    pub(crate) fn iter_visible<'a>(
        &'a self,
        point_tombstones: Option<&'a RoaringBitmap>,
    ) -> Box<dyn Iterator<Item = crate::Result<Cow<'a, Point>>> + 'a> {
        Box::new(
            self.store
                .iter_ids()
                .filter(move |id| !self.is_hidden(id, point_tombstones))
                .map(|id| {
                    self.read_point(id).and_then(|point| {
                        point.ok_or_else(|| crate::GaussError::PointNotFound(id.to_owned()))
                    })
                }),
        )
    }

    pub(crate) fn iter_visible_aux_index_points<'a>(
        &'a self,
        point_tombstones: Option<&'a RoaringBitmap>,
    ) -> Box<dyn Iterator<Item = crate::Result<Cow<'a, Point>>> + 'a> {
        match &self.store {
            SegmentStore::Heap(points) => Box::new(
                points
                    .values()
                    .filter(move |point| !self.is_hidden(&point.id, point_tombstones))
                    .map(|point| Ok(Cow::Borrowed(point))),
            ),
            SegmentStore::V4(store) => Box::new(
                store
                    .ids()
                    .iter()
                    .enumerate()
                    .filter(move |(_, id)| !self.is_hidden(id, point_tombstones))
                    .map(|(ordinal, _)| store.get_ordinal_for_aux_indexes(ordinal).map(Cow::Owned)),
            ),
        }
    }
}

pub(crate) fn load_named_algorithm2_indexes(
    dir: &std::path::Path,
    metric: crate::DistanceMetric,
) -> crate::Result<HashMap<String, SegmentIndex>> {
    crate::seal::named_algorithm2_names(dir)?
        .into_iter()
        .map(|name| {
            crate::index::ivf_segment::IvfSegmentIndex::open_named(dir, &name, metric)
                .map(|index| (name, SegmentIndex::Ivf(Box::new(index))))
        })
        .collect()
}
